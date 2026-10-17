import Foundation
import NIOCore
import NIOHTTP1
import NIOHTTP2
import NIOPosix
import NIOSSL
import NIOTLS
import Synchronization
import UniformTypeIdentifiers

/// Which CONNECTs to decrypt, read by each connection as it starts, and the rules for
/// requests, read by each request.
struct ProxyPolicy: Sendable {
    var decrypt = HostPatterns([])
    var bypass = HostPatterns(HostPatterns.appleServices)
    /// Nil until the user has a trusted CA: until then everything tunnels.
    var authority: CertificateAuthority?
    var mapLocalRules: [MapLocalRule] = []
    var mapRemoteRules: [MapRemoteRule] = []
    var breakpointRules: [BreakpointRule] = []
    var scriptRules: [ScriptRule] = []

    func authority(toDecrypt host: String) -> CertificateAuthority? {
        decrypt.matches(host) && !bypass.matches(host) ? authority : nil
    }

    /// The first enabled rule decides, so a specific rule placed above a broad one wins.
    func localFile(for url: String) -> String? {
        mapLocalRules.first { $0.isEnabled && $0.matches(url) }?.path
    }

    /// As with Map Local, the first enabled rule decides.
    func remoteOrigin(for url: String) -> RemoteOrigin? {
        mapRemoteRules.first { $0.isEnabled && $0.matches(url) }.flatMap { RemoteOrigin($0.destination) }
    }

    /// Every enabled rule that matches has its say, so one rule can hold a URL's
    /// requests and another its responses.
    func breakpoints(for url: String) -> (request: Bool, response: Bool) {
        let rules = breakpointRules.filter { $0.isEnabled && $0.matches(url) }
        return (rules.contains { $0.request }, rules.contains { $0.response })
    }

    /// As with Map Local, the first enabled rule decides, for requests and responses apart:
    /// chained, one script's edit would be the next one's input, which is hard to follow.
    func scripts(for url: String) -> (request: String?, response: String?) {
        let rules = scriptRules.filter { $0.isEnabled && $0.matches(url) }
        return (rules.first { $0.request }?.source, rules.first { $0.response }?.source)
    }
}

/// An HTTP/1.1 proxy on 127.0.0.1 (architecture §3): absolute-form requests are
/// forwarded and recorded; a CONNECT to an allowed host is decrypted with a
/// certificate from the CA and its requests recorded, in HTTP/2 if the client chooses
/// it; any other CONNECT is passed through as bytes.
final class ProxyServer: Sendable {
    let log = ProxyLog()
    let policy = Mutex(ProxyPolicy())
    let throttle = Throttle()
    let scripts = ScriptRunner()
    /// How the proxy checks the servers it decrypts for: against the system's roots,
    /// as the client would have. It never vouches for a server the client wouldn't trust.
    let upstreamTLS: NIOSSLContext
    /// The same, offering HTTP/2 first, for requests that came in over HTTP/2: gRPC needs
    /// it end to end. An HTTP/1.1 client's requests never offer it, so they reach the
    /// server as they always have, WebSocket upgrades included.
    let upstreamH2TLS: NIOSSLContext
    private let listener = Mutex<Channel?>(nil)
    /// Flows held at a breakpoint, each waiting on the user.
    private let held = Mutex<[Int: EventLoopPromise<BreakpointDecision>]>([:])

    init(upstreamRoots: NIOSSLTrustRoots = .default) throws {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = upstreamRoots
        configuration.applicationProtocols = ["http/1.1"]
        upstreamTLS = try NIOSSLContext(configuration: configuration)
        configuration.applicationProtocols = ["h2", "http/1.1"]
        upstreamH2TLS = try NIOSSLContext(configuration: configuration)
    }

    /// Returns the port listened on: port 0 picks a free one.
    func start(port: Int) async throws -> Int {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    // Ahead of everything, TLS included, and there for the connection's life,
                    // whatever it turns into: a tunnel's bytes are slowed as an exchange's are.
                    try channel.pipeline.syncOperations.addHandler(ThrottleHandler(self.throttle, .up))
                    try ClientConnection.configure(channel.pipeline.syncOperations, server: self, origin: nil)
                }
            }
            .bind(host: "127.0.0.1", port: port)
            .get()
        listener.withLock { $0 = channel }
        return channel.localAddress?.port ?? port
    }

    /// Stops accepting; connections already open run to their end.
    func stop() async {
        let channel = listener.withLock { channel in
            defer { channel = nil }
            return channel
        }
        try? await channel?.close()
    }

    /// Sends a held flow on, or answers it with a 502. Does nothing once the flow isn't
    /// held any more, as when its client hung up.
    func resume(_ flow: Int, _ decision: BreakpointDecision) {
        held.withLock { $0.removeValue(forKey: flow) }?.succeed(decision)
    }

    fileprivate func hold(_ flow: Int, on eventLoop: EventLoop) -> EventLoopFuture<BreakpointDecision> {
        let promise = eventLoop.makePromise(of: BreakpointDecision.self)
        held.withLock { $0[flow] = promise }
        return promise.futureResult
    }
}

/// The HTTP side of a client connection.
enum ClientConnection {
    /// Framing is set by hand on every response (see `ForwardHandler.respond`): the
    /// encoder can't tell a reply to HEAD or CONNECT from any other on its own, and
    /// would give a CONNECT's 200 a chunked body that corrupts the tunnel.
    static let encoderConfiguration: HTTPResponseEncoder.Configuration = {
        var configuration = HTTPResponseEncoder.Configuration()
        configuration.automaticallySetFramingHeaders = false
        return configuration
    }()

    static func configure(_ pipeline: ChannelPipeline.SynchronousOperations, server: ProxyServer, origin: Origin?) throws {
        let encoder = HTTPResponseEncoder(configuration: encoderConfiguration)
        // Forwarding bytes: after a CONNECT the client may already have sent the start
        // of its TLS handshake, and those bytes must reach whatever comes next.
        let decoder = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
        // Holds a pipelined request back until the response before it is done.
        let pipelining = HTTPServerPipelineHandler()
        let handler = ForwardHandler(server: server, origin: origin, codec: [encoder, decoder, pipelining])
        try pipeline.addHandlers([encoder, decoder, pipelining, handler])
    }

    /// A decrypted connection whose client chose HTTP/2: each stream is a channel of its
    /// own, with the same `ForwardHandler` as an HTTP/1.1 connection behind a codec that
    /// turns its frames into HTTP/1 parts. Recording, rules and breakpoints then work per
    /// stream, and a held stream holds up none of the others. NIO's default settings
    /// leave out SETTINGS_ENABLE_CONNECT_PROTOCOL, so no WebSocket comes this way.
    static func configureHTTP2(_ channel: Channel, server: ProxyServer, origin: Origin) throws {
        _ = try channel.pipeline.syncOperations.configureHTTP2Pipeline(mode: .server, connectionConfiguration: .init(), streamConfiguration: .init()) { stream in
            stream.eventLoop.makeCompletedFuture {
                try stream.pipeline.syncOperations.addHandlers([HTTP2FramePayloadToHTTP1ServerCodec(), ForwardHandler(server: server, origin: origin, codec: [])])
            }
        }
    }
}

/// Where every request of a decrypted CONNECT goes.
struct Origin: Sendable {
    let host: String
    let port: Int
    /// Named by the network extension when it captured the connection.
    var app: String? = nil
}

/// Serves one client connection, or one HTTP/2 stream, one request at a time. Each
/// request gets its own upstream connection, closed when the response ends.
// ponytail: an upstream connection (and for HTTPS a handshake) per request, HTTP/2
// ones too, so a page's hundred streams open a hundred; pool them per origin, or share
// one HTTP/2 connection per client connection, if decrypted sites feel slow.
final class ForwardHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let server: ProxyServer
    private let origin: Origin?
    /// The handlers that parse HTTP on this connection, removed when it turns into a
    /// tunnel or into TLS. None on an HTTP/2 stream, which turns into neither: CONNECT
    /// only comes before TLS, and HTTP/2 refuses Upgrade, so no WebSocket either.
    private let codec: [RemovableChannelHandler]
    private var context: ChannelHandlerContext?
    private var exchange: Exchange?
    private var connectTarget: Origin?

    init(server: ProxyServer, origin: Origin?, codec: [RemovableChannelHandler]) {
        self.server = server
        self.origin = origin
        self.codec = codec
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head) where head.method == .CONNECT && origin == nil:
            connectTarget = Self.authority(head.uri)
            // Only this Mac's apps reach the listener. The header goes no further: a
            // CONNECT's headers are never passed on.
            connectTarget?.app = head.headers.first(name: ConnectPreface.appHeader)?.removingPercentEncoding
            if connectTarget == nil {
                respond(context, .badRequest, String(localized: "Expected CONNECT host:port."), close: true)
            }
        case .head(let head):
            begin(context, head)
        case .body(let buffer):
            guard let exchange else { return }
            var whole = true
            server.log.update(exchange.flow) { flow in
                flow.request.append(buffer.readableBytesView)
                whole = !flow.request.truncated
            }
            exchange.send(.body(.byteBuffer(buffer)))
            if exchange.waitsForRequest && !whole {
                // Past what the log keeps, the inspector couldn't show the body to edit, nor
                // a script be given all of it.
                let (held, scripted) = (exchange.holdsRequest, exchange.requestScript != nil)
                exchange.holdsRequest = false
                exchange.requestScript = nil
                server.log.update(exchange.flow) { flow in
                    if held { flow.breakpointNotes.append(String(localized: "Request not held: its body is over 10 MB.")) }
                    if scripted { flow.scriptNotes.append(String(localized: "Request script not run: its body is over 10 MB.")) }
                }
                if exchange.localFile == nil {
                    forward(context, exchange, method: exchange.head.method, path: exchange.target.path, headers: exchange.head.headers)
                }
            }
        case .end(let trailers):
            if let target = connectTarget {
                connectTarget = nil
                connect(context, to: target)
            } else if let exchange, exchange.waitsForRequest {
                exchange.heldTrailers = trailers
                script(context, exchange, at: .request)
            } else if let exchange, let file = exchange.localFile {
                answerLocally(context, exchange, from: file)
            } else {
                exchange?.send(.end(trailers))
            }
        }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        // The client caught up: let the response flow again.
        if context.channel.isWritable, let upstream = exchange?.upstream {
            upstream.setOption(ChannelOptions.autoRead, value: true).whenFailure { _ in }
            // An HTTP/2 stream, unlike a socket, doesn't read again on its own once autoRead
            // is back on, and its server waits for the window that reading reopens.
            upstream.read()
        }
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let exchange {
            server.log.update(exchange.flow) { flow in
                flow.paused = nil
                if flow.finished == nil {
                    flow.finished = .now
                    // An HTTP/2 stream ends this way when the client resets it, as a browser
                    // does for a fetch it no longer needs; the connection carries on.
                    flow.error = flow.error ?? (codec.isEmpty ? String(localized: "The client cancelled the request.") : String(localized: "The client closed the connection."))
                }
            }
            exchange.upstream?.close(promise: nil)
            self.exchange = nil
            // A breakpoint holding it lets go: there's no one left to send it to.
            server.resume(exchange.flow, .abort)
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    // MARK: Forwarding requests

    private func begin(_ context: ChannelHandlerContext, _ head: HTTPRequestHead) {
        guard let target = Target(head.uri, origin: origin, hostHeader: head.headers.first(name: "host")) else {
            respond(context, .badRequest, String(localized: "This is a proxy: send it requests with absolute URLs."), close: true)
            return
        }
        let flow = server.log.begin(kind: origin == nil ? .http : .https, method: head.method.rawValue, url: target.url, host: target.host, app: origin?.app)
        let (file, remote, breakpoints, scripts) = server.policy.withLock { policy in
            let file = policy.localFile(for: target.url)
            // Map Local answers without a server, so there's none for Map Remote to change.
            return (file, file == nil ? policy.remoteOrigin(for: target.url) : nil, policy.breakpoints(for: target.url), policy.scripts(for: target.url))
        }
        server.log.update(flow) { flow in
            flow.version = Self.name(head.version)
            flow.request.headers = head.headers.map { ($0.name, $0.value) }
            flow.mapLocal = file
            flow.mapRemote = remote.map { $0.url + target.path }
        }
        let webSocket = file == nil && head.headers["upgrade"].contains { $0.lowercased() == "websocket" }
        let exchange = Exchange(flow: flow, head: head, target: target, localFile: file, remote: remote, webSocket: webSocket, breakpoints: breakpoints, scripts: scripts)
        self.exchange = exchange
        // A mapped request is answered once it has ended (see channelRead), so its body
        // is recorded too, and nothing is sent upstream. A held one goes on then too,
        // as the user or a script edited it.
        if file == nil && !exchange.waitsForRequest {
            forward(context, exchange, method: head.method, path: target.path, headers: head.headers)
        }
    }

    /// Opens a connection to the server and sends it the request: the head now, the
    /// body as it comes, or as it came while a breakpoint held the request.
    private func forward(_ context: ChannelHandlerContext, _ exchange: Exchange, method: HTTPMethod, path: String, headers: HTTPHeaders, body: ByteBuffer? = nil) {
        let target = exchange.target
        let remote = exchange.remote
        // A WebSocket handshake keeps what makes it one; the server's 101 then turns both
        // connections into a relay (see `relay`). Other upgrades, such as h2c, are
        // dropped with the rest of the hop-by-hop headers, and the server answers in
        // HTTP/1.1.
        let http2 = exchange.head.version.major == 2
        // TE as HTTP/2 allows it, "trailers" only, is how gRPC servers learn that trailers
        // get through; the HTTP/2 codecs drop the rest that's about the connection.
        let trailers = http2 && headers["te"].contains("trailers")
        var headers = headers
        Self.removeHopByHop(&headers)
        if trailers {
            headers.add(name: "te", value: "trailers")
        }
        headers.remove(name: "proxy-authorization")
        if let remote {
            // Its own name: a staging server sharing an address with others is picked by it.
            // ponytail: no option to keep the original Host; add one if a setup needs it.
            headers.replaceOrAdd(name: "host", value: remote.authority)
        } else if !headers.contains(name: "host") {
            headers.add(name: "host", value: target.hostHeader)
        }
        if exchange.webSocket {
            headers.replaceOrAdd(name: "connection", value: "Upgrade")
            headers.replaceOrAdd(name: "upgrade", value: "websocket")
            // permessage-deflate would compress every message past reading. Without
            // the offer the two ends agree on no extension, as RFC 6455 §9.1 allows.
            // ponytail: inflate permessage-deflate instead if a server insists on it.
            headers.remove(name: "sec-websocket-extensions")
        } else {
            // One connection per request (see the type's note), so the server can close it.
            headers.replaceOrAdd(name: "connection", value: "close")
        }
        exchange.open(HTTPRequestHead(version: .http1_1, method: method, uri: path, headers: headers), body: body)

        let link = NIOLoopBound((handler: self, exchange: exchange), eventLoop: context.eventLoop)
        let host = remote?.host ?? target.host
        let port = remote?.port ?? target.port
        let tls = (remote?.secure ?? (origin != nil)) ? (http2 ? server.upstreamH2TLS : server.upstreamTLS) : nil
        // Only TLS settles on a protocol with the server; plain HTTP goes as HTTP/1.1.
        let negotiates = http2 && tls != nil
        let throttle = server.throttle
        ClientBootstrap(group: context.eventLoop)
            .connectTimeout(Self.connectTimeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let pipeline = channel.pipeline.syncOperations
                    try pipeline.addHandler(ThrottleHandler(throttle, .down))
                    if let tls {
                        // SNI can't carry an address; NIOSSL then checks the certificate
                        // against the address it connected to.
                        let name = IPAddress(host) == nil ? host : nil
                        try pipeline.addHandler(NIOSSLClientHandler(context: tls, serverHostname: name))
                    }
                    if negotiates {
                        try pipeline.addHandler(UpstreamNegotiator(link: link))
                    } else {
                        try UpstreamHandler.addHTTP1(pipeline, link: link)
                    }
                }
            }
            .connect(host: host, port: port)
            .assumeIsolated()
            .whenComplete { [self] result in
                guard self.exchange === exchange else {
                    (try? result.get())?.close(promise: nil)
                    return
                }
                switch result {
                case .success(let channel):
                    // A negotiating connection hands itself over once TLS is through.
                    if !negotiates {
                        exchange.connected(channel)
                    }
                case .failure(let error):
                    fail(exchange, error)
                }
            }
    }

    /// Map Local: the file stands in for the server's response, read now so an edit to
    /// it shows on the next request. Read off the event loop, which every connection on
    /// it shares, and handed to `upstreamRead` so it's framed and recorded exactly like a
    /// response from a server.
    // ponytail: the whole file in memory at once; stream it with NonBlockingFileIO if
    // someone maps files of hundreds of MB.
    private func answerLocally(_ context: ChannelHandlerContext, _ exchange: Exchange, from file: String) {
        NIOThreadPool.singleton.runIfActive(eventLoop: context.eventLoop) { try Data(contentsOf: URL(filePath: file)) }
            .assumeIsolated()
            .whenComplete { [self] result in
                switch result {
                case .success(let data):
                    let type = UTType(filenameExtension: URL(filePath: file).pathExtension)?.preferredMIMEType ?? "application/octet-stream"
                    let headers = HTTPHeaders([("content-type", type), ("content-length", String(data.count))])
                    upstreamRead(.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)), of: exchange)
                    if !exchange.isHead {
                        upstreamRead(.body(ByteBuffer(bytes: data)), of: exchange)
                    }
                    upstreamRead(.end(nil), of: exchange)
                case .failure(let error):
                    // 502, not 404: the proxy failed to make the response, as when a server
                    // can't be reached. A 404 would pass for the server's own answer and
                    // send the developer looking for a bug on the server.
                    fail(exchange, ProxyFailure(String(localized: "Map Local couldn't read \(file): \(error.localizedDescription)")))
                }
            }
    }

    fileprivate func upstreamRead(_ part: HTTPClientResponsePart, of exchange: Exchange) {
        guard let context, self.exchange === exchange else { return }
        switch part {
        case .head(let head):
            exchange.upgraded = exchange.webSocket && head.status == .switchingProtocols
            if exchange.webSocket && !exchange.upgraded {
                // The client's decoder stopped reading at the handshake, waiting for the
                // switch, so this connection can't carry another request.
                exchange.keepAlive = false
            }
            server.log.update(exchange.flow) { flow in
                flow.status = Int(head.status.code)
                flow.reason = head.status.reasonPhrase
                flow.response.headers = head.headers.map { ($0.name, $0.value) }
                flow.responded = .now
                // Map Local's head is made up here: no server answered.
                flow.serverVersion = exchange.localFile == nil ? Self.name(head.version) : nil
            }
            // An informational head, such as 100 Continue or a 101, goes straight on:
            // the final response is the one to hold.
            if exchange.waitsForResponse && head.status.code / 100 != 1 {
                exchange.heldResponse = head
            } else {
                writeHead(context, exchange, head)
            }
        case .body(let buffer):
            var whole = true
            server.log.update(exchange.flow) { flow in
                flow.response.append(buffer.readableBytesView)
                whole = !flow.response.truncated
            }
            if let held = exchange.heldResponse {
                exchange.heldBody.append(buffer)
                guard !whole else { return }
                // Past what the log keeps, the inspector couldn't show the body to edit, nor
                // a script be given all of it.
                exchange.heldResponse = nil
                let (breakpoint, scripted) = (exchange.holdsResponse, exchange.responseScript != nil)
                server.log.update(exchange.flow) { flow in
                    if breakpoint { flow.breakpointNotes.append(String(localized: "Response not held: its body is over 10 MB.")) }
                    if scripted { flow.scriptNotes.append(String(localized: "Response script not run: its body is over 10 MB.")) }
                }
                writeHead(context, exchange, held)
                for buffer in exchange.heldBody {
                    context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
                }
                exchange.heldBody = []
            } else {
                context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            }
            if !context.channel.isWritable {
                exchange.upstream?.setOption(ChannelOptions.autoRead, value: false).whenFailure { _ in }
            }
        case .end(let trailers):
            if exchange.heldResponse != nil {
                exchange.heldTrailers = trailers
                script(context, exchange, at: .response)
            } else {
                end(context, exchange, trailers)
            }
        }
    }

    /// Frames a response head for the client's connection and writes it.
    private func writeHead(_ context: ChannelHandlerContext, _ exchange: Exchange, _ head: HTTPResponseHead) {
        var headers = head.headers
        Self.removeHopByHop(&headers)
        if exchange.hasNoBody(head.status) {
            // No body follows, so no chunk terminator may either.
            headers.remove(name: "transfer-encoding")
        } else if headers.contains(name: "transfer-encoding") || !headers.contains(name: "content-length") {
            // NIO hands over the body de-chunked; a body that ran until the server
            // closed must be framed too, since this connection stays open.
            headers.remove(name: "content-length")
            headers.replaceOrAdd(name: "transfer-encoding", value: "chunked")
        }
        if exchange.upgraded {
            headers.replaceOrAdd(name: "connection", value: "Upgrade")
            headers.replaceOrAdd(name: "upgrade", value: head.headers.first(name: "upgrade") ?? "websocket")
        } else if !exchange.keepAlive {
            headers.replaceOrAdd(name: "connection", value: "close")
        }
        exchange.responded = true
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: head.status, headers: headers))), promise: nil)
    }

    private func end(_ context: ChannelHandlerContext, _ exchange: Exchange, _ trailers: HTTPHeaders?) {
        if exchange.upgraded {
            context.writeAndFlush(wrapOutboundOut(.end(trailers)), promise: nil)
            relay(context, exchange)
            return
        }
        // Over before the end goes out: on an HTTP/2 stream the client is done with, writing
        // it closes the stream there and then, and channelInactive must not take that for
        // the client giving up.
        server.log.update(exchange.flow) { $0.finished = .now }
        finish(exchange)
        let written = context.writeAndFlush(wrapOutboundOut(.end(trailers)))
        if !exchange.keepAlive {
            // The client asked for the connection to end with this response. Last: a
            // close fires channelInactive at once, which must find the exchange over,
            // not record the client as having hung up.
            written.assumeIsolated().whenComplete { _ in context.close(promise: nil) }
        }
    }

    // MARK: Scripts

    /// Runs the phase's script on the whole message, off the event loop, then sends on what
    /// it made. A breakpoint holds that instead, so the user sees the script's edit and has
    /// the last word on it. A script that throws leaves the message as it came, with a note
    /// on the flow and a mark in the list: matched by a broad pattern, a 502 would take down
    /// every request of the app being debugged over one slip in a script.
    private func script(_ context: ChannelHandlerContext, _ exchange: Exchange, at phase: BreakpointPhase) {
        guard let source = phase == .request ? exchange.requestScript : exchange.responseScript else {
            hold(context, exchange, at: phase)
            return
        }
        let unchanged = if phase == .request {
            EditedMessage(method: exchange.head.method.rawValue, path: exchange.target.path, headers: exchange.head.headers.map { ($0.name, $0.value) })
        } else {
            EditedMessage(status: Int(exchange.heldResponse!.status.code), headers: exchange.heldResponse!.headers.map { ($0.name, $0.value) })
        }
        let started = ContinuousClock.now
        let run = server.log.state.withLock { $0.flows[exchange.flow] }.map { flow in
            // The path as last sent: a request script or breakpoint may have changed it.
            let path = String(flow.url.dropFirst(exchange.target.url.count - exchange.target.path.count))
            return server.scripts.run(source, phase, flow, path: path, on: context.eventLoop)
        }
        (run ?? context.eventLoop.makeFailedFuture(ProxyFailure(String(localized: "Its flow had already left the list."))))
            .assumeIsolated()
            .whenComplete { [self] result in
                guard let context = self.context, self.exchange === exchange else { return }
                // A whole sentence for each phase, here and at breakpoints: English wants
                // "Request" to start one and "request" inside one, which a translation
                // pieced together from a word can't follow.
                let edit: EditedMessage
                switch result {
                case .success(let scripted?):
                    edit = scripted
                    let took = (ContinuousClock.now - started).formatted(.units(allowed: [.seconds, .milliseconds], width: .abbreviated, maximumUnitCount: 2))
                    server.log.update(exchange.flow) {
                        $0.scriptNotes.append(phase == .request ? String(localized: "Request script ran in \(took).") : String(localized: "Response script ran in \(took)."))
                    }
                case .success(nil):
                    edit = unchanged
                    // Said, though not marked: a misspelt function name ends up here too.
                    server.log.update(exchange.flow) {
                        $0.scriptNotes.append(phase == .request
                            ? String(localized: "The script has no onRequest function, so the request went on as it came.")
                            : String(localized: "The script has no onResponse function, so the response went on as it came."))
                    }
                case .failure(let error):
                    edit = unchanged
                    server.log.update(exchange.flow) { flow in
                        flow.scriptNotes.append(phase == .request
                            ? String(localized: "Request script failed, so the request went on as it came: \(String(describing: error))")
                            : String(localized: "Response script failed, so the response went on as it came: \(String(describing: error))"))
                        flow.scriptFailed = true
                    }
                }
                if phase == .request {
                    sendHeldRequest(context, exchange, edit, holding: exchange.holdsRequest)
                } else {
                    sendHeldResponse(context, exchange, edit, holding: exchange.holdsResponse)
                }
            }
    }

    // MARK: Breakpoints

    /// Waits, with the whole request or response in hand, for the user to send it on
    /// or abort it. The other side waits too. Nothing here times out: a client that
    /// gives up closes its connection, and `channelInactive` lets go.
    private func hold(_ context: ChannelHandlerContext, _ exchange: Exchange, at phase: BreakpointPhase) {
        let since = Date.now
        server.log.update(exchange.flow) { $0.paused = phase }
        // HTTPServerPipelineHandler holds back reads until the response is out, so a
        // client hanging up would go unseen for as long as the hold lasts. One read from
        // below it lets the close through; a pipelined request that comes instead waits
        // in that handler, as it would anyway. An HTTP/2 stream has no such handler: a
        // reset or a closed connection reaches channelInactive on its own.
        if codec.count > 1 {
            try? context.pipeline.syncOperations.context(handler: codec[1]).read()
        }
        server.hold(exchange.flow, on: context.eventLoop).assumeIsolated().whenSuccess { [self] decision in
            guard let context = self.context, self.exchange === exchange else { return }
            let held = Duration.seconds(Date.now.timeIntervalSince(since)).formatted(.units(allowed: [.minutes, .seconds, .milliseconds], width: .abbreviated, maximumUnitCount: 2))
            server.log.update(exchange.flow) { flow in
                flow.paused = nil
                flow.breakpointNotes.append(phase == .request ? String(localized: "Request held for \(held).") : String(localized: "Response held for \(held)."))
            }
            switch (decision, phase) {
            case (.abort, _):
                fail(exchange, ProxyFailure(phase == .request ? String(localized: "Aborted at the request breakpoint.") : String(localized: "Aborted at the response breakpoint.")))
            case (.proceed(let edit), .request):
                sendHeldRequest(context, exchange, edit)
            case (.proceed(let edit), .response):
                sendHeldResponse(context, exchange, edit)
            }
        }
    }

    /// `holding`: a script made the edit and a breakpoint shows it next, instead of sending.
    private func sendHeldRequest(_ context: ChannelHandlerContext, _ exchange: Exchange, _ edit: EditedMessage, holding: Bool = false) {
        let method = HTTPMethod(rawValue: edit.method)
        var headers = HTTPHeaders(edit.headers.map { ($0.name, $0.value) })
        let body = edit.body.map { body in
            Self.frame(&headers, length: body.count)
            return ByteBuffer(bytes: body)
        }
        exchange.isHead = method == .HEAD
        let url = exchange.target.url(path: edit.path)
        server.log.update(exchange.flow) { flow in
            flow.method = edit.method
            flow.url = url
            flow.mapRemote = exchange.remote.map { $0.url + edit.path }
            if let body = edit.body {
                flow.request = HTTPMessage()
                flow.request.append(body)
            }
            flow.request.headers = headers.map { ($0.name, $0.value) }
        }
        if holding {
            // The script's body is now the one held, so it goes on unless the user changes it.
            if let body {
                exchange.replaceBody(body)
            }
            hold(context, exchange, at: .request)
        } else if let file = exchange.localFile {
            answerLocally(context, exchange, from: file)
        } else {
            forward(context, exchange, method: method, path: edit.path, headers: headers, body: body)
            exchange.send(.end(exchange.heldTrailers))
        }
    }

    private func sendHeldResponse(_ context: ChannelHandlerContext, _ exchange: Exchange, _ edit: EditedMessage, holding: Bool = false) {
        let status = HTTPResponseStatus(statusCode: edit.status)
        var headers = HTTPHeaders(edit.headers.map { ($0.name, $0.value) })
        // A status edited to one without a body, such as 204, leaves the body behind.
        let noBody = exchange.hasNoBody(status)
        let edited = noBody ? Data() : edit.body
        let body = noBody ? [] : edited.map { [ByteBuffer(bytes: $0)] } ?? exchange.heldBody
        if !noBody {
            // All of it is here, so its length is known, edited or not.
            Self.frame(&headers, length: body.reduce(0) { $0 + $1.readableBytes }, encoded: edited == nil)
        }
        server.log.update(exchange.flow) { flow in
            flow.status = edit.status
            flow.reason = status.reasonPhrase
            if let body = edited {
                flow.response = HTTPMessage()
                flow.response.append(body)
            }
            flow.response.headers = headers.map { ($0.name, $0.value) }
        }
        if holding {
            // As with a request: the script's body is now the one held.
            exchange.heldBody = body
            hold(context, exchange, at: .response)
            return
        }
        writeHead(context, exchange, HTTPResponseHead(version: .http1_1, status: status, headers: headers))
        for buffer in body {
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        // An HTTP/1.1 client gets them only when the body is chunked, and a held one is
        // framed by its length: NIO's encoder then leaves them out, as before.
        end(context, exchange, exchange.heldTrailers)
    }

    /// Frames a whole body by its length. An edited body was typed as decoded text, so
    /// it goes on without the encoding the original came in.
    private static func frame(_ headers: inout HTTPHeaders, length: Int, encoded: Bool = false) {
        if !encoded {
            headers.remove(name: "content-encoding")
        }
        headers.remove(name: "transfer-encoding")
        headers.replaceOrAdd(name: "content-length", value: String(length))
    }

    /// After a 101 both connections carry WebSocket frames. They pass through as they
    /// came, as a tunnel's bytes do, and a parser on each side records the messages.
    private func relay(_ context: ChannelHandlerContext, _ exchange: Exchange) {
        guard let upstream = exchange.upstream else { return }
        // Over as an HTTP exchange: from here the connections close on their own.
        self.exchange = nil
        let log = server.log
        let flow = exchange.flow
        var fromClient = WebSocketParser(fromClient: true)
        var fromServer = WebSocketParser(fromClient: false)
        let glue = GlueHandler.pair(
            fromClient: { bytes in
                let messages = fromClient.read(bytes)
                log.update(flow) { flow in
                    flow.bytesUp += bytes.readableBytes
                    messages.forEach { flow.record($0) }
                }
            },
            fromServer: { bytes in
                let messages = fromServer.read(bytes)
                log.update(flow) { flow in
                    flow.bytesDown += bytes.readableBytes
                    messages.forEach { flow.record($0) }
                }
            }
        )
        // Each decoder goes last, and hands the glue what arrived after the handshake.
        // By then nothing that expects HTTP parts may sit on either side's way out: the
        // glue writes raw bytes into the other pipeline.
        let pipeline = upstream.pipeline.syncOperations
        for name in [UpstreamHandler.name, UpstreamHandler.validator, UpstreamHandler.encoder] {
            pipeline.removeHandler(name: name, promise: nil)
        }
        do {
            try pipeline.addHandler(glue.server)
            try context.pipeline.syncOperations.addHandler(glue.client)
        } catch {
            upstream.close(promise: nil)
            context.close(promise: nil)
            return
        }
        // The server side's decoder also watches what goes out, to know a HEAD's answer
        // has no body, and a decoder leaves a loop tick after it's asked to: the
        // client's bytes may only come through once it's gone.
        let serverDecoderGone = context.eventLoop.makePromise(of: Void.self)
        pipeline.removeHandler(name: UpstreamHandler.decoder, promise: serverDecoderGone)
        removeHTTP(context, decoderAfter: serverDecoderGone.futureResult)
        context.channel.closeFuture.whenComplete { _ in
            log.update(flow) { $0.finished = .now }
        }
    }

    fileprivate func upstreamReadComplete(of exchange: Exchange) {
        guard self.exchange === exchange else { return }
        context?.flush()
    }

    /// TLS has settled the protocol with the server: `channel` is the connection, or
    /// for HTTP/2 the stream opened on it.
    fileprivate func upstreamReady(_ channel: Channel, for exchange: Exchange) {
        // The client may have hung up during the handshake.
        guard self.exchange === exchange else {
            channel.close(promise: nil)
            return
        }
        exchange.connected(channel)
    }

    fileprivate func fail(_ exchange: Exchange, _ error: Error) {
        guard let context, self.exchange === exchange else { return }
        let message = Self.describe(error)
        server.log.update(exchange.flow) { flow in
            flow.finished = .now
            flow.error = message
        }
        finish(exchange)
        if exchange.responded {
            // Halfway through a response there's no way to say so but to cut it off.
            context.close(promise: nil)
        } else {
            respond(context, .badGateway, message)
        }
    }

    private func finish(_ exchange: Exchange) {
        exchange.upstream?.close(promise: nil)
        self.exchange = nil
    }

    /// A response the proxy itself makes, framed by hand like every response here.
    /// `close`: after a malformed request or a failed CONNECT the connection is no use.
    private func respond(_ context: ChannelHandlerContext, _ status: HTTPResponseStatus, _ message: String, close: Bool = false) {
        let body = context.channel.allocator.buffer(string: message + "\n")
        var headers = HTTPHeaders([("content-type", "text/plain; charset=utf-8"), ("content-length", String(body.readableBytes))])
        if close {
            headers.add(name: "connection", value: "close")
        }
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))), promise: nil)
        context.write(wrapOutboundOut(.body(.byteBuffer(body))), promise: nil)
        let done = context.writeAndFlush(wrapOutboundOut(.end(nil)))
        if close {
            done.assumeIsolated().whenComplete { _ in context.close(promise: nil) }
        }
    }

    // MARK: CONNECT

    private func connect(_ context: ChannelHandlerContext, to target: Origin) {
        let authority = server.policy.withLock { $0.authority(toDecrypt: target.host) }
        if let authority {
            decrypt(context, target, with: authority)
        } else {
            tunnel(context, to: target)
        }
    }

    /// Answers the CONNECT itself and becomes the TLS server for `target`, with a
    /// certificate from the CA; the decrypted requests go through a new
    /// `ForwardHandler` bound to that origin, one per HTTP/2 stream.
    private func decrypt(_ context: ChannelHandlerContext, _ target: Origin, with authority: CertificateAuthority) {
        do {
            let tls = try authority.serverContext(for: target.host)
            established(context)
            let pipeline = context.pipeline.syncOperations
            try pipeline.addHandler(NIOSSLServerHandler(context: tls))
            // The client picks HTTP/2 or HTTP/1.1 in the handshake; its codec goes on then,
            // and what it sent meanwhile waits in the negotiation handler.
            let server = server
            try pipeline.addHandler(ApplicationProtocolNegotiationHandler { result, channel in
                channel.eventLoop.makeCompletedFuture {
                    if result == .negotiated("h2") {
                        try ClientConnection.configureHTTP2(channel, server: server, origin: target)
                    } else {
                        try ClientConnection.configure(channel.pipeline.syncOperations, server: server, origin: target)
                    }
                }
            })
            removeHTTP(context)
        } catch {
            respond(context, .badGateway, String(localized: "Couldn't decrypt \(target.host): \(Self.describe(error))"), close: true)
        }
    }

    /// Passes the bytes through unread: only the host and how much went each way are
    /// recorded.
    private func tunnel(_ context: ChannelHandlerContext, to target: Origin) {
        let log = server.log
        let flow = log.begin(kind: .tunnel, method: "CONNECT", url: "\(target.host):\(target.port)", host: target.host, app: target.app)
        let (client, upstream) = GlueHandler.pair(
            fromClient: { bytes in log.update(flow) { $0.bytesUp += bytes.readableBytes } },
            fromServer: { bytes in log.update(flow) { $0.bytesDown += bytes.readableBytes } }
        )
        let throttle = server.throttle
        ClientBootstrap(group: context.eventLoop)
            .connectTimeout(Self.connectTimeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(ThrottleHandler(throttle, .down)) }
            }
            .connect(host: target.host, port: target.port)
            .assumeIsolated()
            .whenComplete { [self] result in
                switch result {
                case .success(let channel):
                    // The client may have given up while the server was slow to answer;
                    // nothing would ever close the server side then.
                    guard context.channel.isActive else {
                        channel.close(promise: nil)
                        log.update(flow) { flow in
                            flow.finished = .now
                            flow.error = String(localized: "The client closed the connection.")
                        }
                        return
                    }
                    do {
                        try channel.pipeline.syncOperations.addHandler(upstream)
                        established(context)
                        try context.pipeline.syncOperations.addHandler(client)
                        removeHTTP(context)
                        context.channel.closeFuture.whenComplete { _ in
                            log.update(flow) { $0.finished = .now }
                        }
                    } catch {
                        channel.close(promise: nil)
                        context.close(promise: nil)
                    }
                case .failure(let error):
                    log.update(flow) { flow in
                        flow.finished = .now
                        flow.error = Self.describe(error)
                    }
                    respond(context, .badGateway, Self.describe(error), close: true)
                }
            }
    }

    private func established(_ context: ChannelHandlerContext) {
        // No body and no framing headers: what follows is the tunnel.
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .ok))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    /// Takes HTTP off this connection, decoder last: when it goes it hands the bytes
    /// it buffered past the CONNECT to whatever now follows it.
    private func removeHTTP(_ context: ChannelHandlerContext, decoderAfter ready: EventLoopFuture<Void>? = nil) {
        let pipeline = context.pipeline.syncOperations
        for handler in codec.dropFirst(2) {
            pipeline.removeHandler(handler, promise: nil)
        }
        pipeline.removeHandler(context: context, promise: nil)
        pipeline.removeHandler(codec[0], promise: nil)
        let decoder = codec[1]
        guard let ready else {
            pipeline.removeHandler(decoder, promise: nil)
            return
        }
        // Failure too means go ahead: the other side closed first, taking its decoder.
        ready.assumeIsolated().whenComplete { _ in pipeline.removeHandler(decoder, promise: nil) }
    }

    // MARK: Helpers

    /// `host:port` of a CONNECT.
    static func authority(_ text: String) -> Origin? {
        guard let colon = text.lastIndex(of: ":"), let port = Int(text[text.index(after: colon)...]), (1 ... 65535).contains(port) else { return nil }
        var host = String(text[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        return host.isEmpty ? nil : Origin(host: host, port: port)
    }

    /// As people write it: "HTTP/2", not NIO's "HTTP/2.0".
    static func name(_ version: HTTPVersion) -> String {
        version.major == 2 ? "HTTP/2" : "HTTP/\(version.major).\(version.minor)"
    }

    /// Headers about this hop, not the message (RFC 9110 §7.6.1), including any the
    /// Connection header names.
    static func removeHopByHop(_ headers: inout HTTPHeaders) {
        let named = headers["connection"].flatMap { $0.split(separator: ",") }.map { $0.trimmingCharacters(in: .whitespaces) }
        for name in named + ["connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"] {
            headers.remove(name: name)
        }
    }

    /// The kernel's own limit (net.inet.tcp.keepinit). Servers that drop SYNs still answer
    /// a direct connection after 20 s; giving up sooner would fail requests only because
    /// they went through the proxy. Clients that want less hang up themselves.
    static let connectTimeout = TimeAmount.seconds(75)

    static func describe(_ error: Error) -> String {
        if let error = error as? NIOConnectionError {
            return String(localized: "Couldn't connect to \(error.host):\(error.port).")
        }
        if error is ChannelError, case .connectTimeout = error as! ChannelError {
            return String(localized: "The server didn't answer within \(connectTimeout.nanoseconds / 1_000_000_000) seconds.")
        }
        return String(describing: error)
    }
}

/// Where one request goes, from its request line.
struct Target {
    let host: String
    let port: Int
    /// Origin-form: what the server sees in its request line.
    let path: String
    let url: String
    let hostHeader: String

    init?(_ uri: String, origin: Origin?, hostHeader: String?) {
        if let origin {
            // Inside a decrypted CONNECT the request line is origin-form.
            host = origin.host
            port = origin.port
            path = uri.hasPrefix("/") ? uri : "/"
            self.hostHeader = hostHeader ?? (port == 443 ? host : "\(host):\(port)")
            url = "https://\(port == 443 ? host : "\(host):\(port)")\(path)"
            return
        }
        guard let components = URLComponents(string: uri), components.scheme?.lowercased() == "http", let host = components.host, !host.isEmpty else { return nil }
        self.host = host
        port = components.port ?? 80
        let query = components.percentEncodedQuery.map { "?\($0)" } ?? ""
        path = (components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath) + query
        let authority = port == 80 ? host : "\(host):\(port)"
        self.hostHeader = authority
        url = "http://\(authority)\(path)"
    }

    /// The same origin with another path, as edited at a breakpoint.
    func url(path newPath: String) -> String {
        String(url.dropLast(path.count)) + newPath
    }
}

/// One request and its response.
final class Exchange {
    let flow: Int
    /// The request as the client sent it.
    let head: HTTPRequestHead
    let target: Target
    var isHead: Bool
    /// Whether the client's connection stays open after this response.
    var keepAlive: Bool
    /// Map Local's file, which answers instead of a server: no upstream ever opens.
    let localFile: String?
    /// Map Remote's server, which the request goes to instead of `target`'s.
    let remote: RemoteOrigin?
    /// The request asks to become a WebSocket.
    let webSocket: Bool
    /// The server agreed: after this response both connections carry frames.
    var upgraded = false
    /// A breakpoint holds the request once it has all come in.
    var holdsRequest: Bool
    /// A breakpoint holds the final response once it has all come in.
    let holdsResponse: Bool
    /// Scripts that edit the request and the final response once each has all come in,
    /// before a breakpoint holds it.
    var requestScript: String?
    let responseScript: String?
    var waitsForRequest: Bool { holdsRequest || requestScript != nil }
    var waitsForResponse: Bool { holdsResponse || responseScript != nil }
    var heldResponse: HTTPResponseHead?
    var heldBody: [ByteBuffer] = []
    /// What came after the held request's or response's body, sent on after it: gRPC's
    /// status rides in the response's.
    var heldTrailers: HTTPHeaders?
    var upstream: Channel?
    /// Parts held until the upstream connection is up.
    private var pending: [HTTPClientRequestPart] = []
    var responded = false

    init(flow: Int, head: HTTPRequestHead, target: Target, localFile: String? = nil, remote: RemoteOrigin? = nil, webSocket: Bool = false, breakpoints: (request: Bool, response: Bool) = (false, false), scripts: (request: String?, response: String?) = (nil, nil)) {
        self.flow = flow
        self.head = head
        self.target = target
        isHead = head.method == .HEAD
        keepAlive = head.isKeepAlive
        self.localFile = localFile
        self.remote = remote
        self.webSocket = webSocket
        holdsRequest = breakpoints.request
        holdsResponse = breakpoints.response
        requestScript = scripts.request
        responseScript = scripts.response
    }

    /// The head goes before any body that came while a breakpoint held the request;
    /// an edited body replaces that.
    func open(_ head: HTTPRequestHead, body: ByteBuffer?) {
        if let body {
            pending = [.body(.byteBuffer(body))]
        }
        pending.insert(.head(head), at: 0)
    }

    /// A script's body in place of the one that came, while a breakpoint holds the request.
    func replaceBody(_ body: ByteBuffer) {
        pending = [.body(.byteBuffer(body))]
    }

    func hasNoBody(_ status: HTTPResponseStatus) -> Bool {
        isHead || status.code / 100 == 1 || status.code == 204 || status.code == 304
    }

    func send(_ part: HTTPClientRequestPart) {
        // A mapped request's body has nowhere to go; held, an upload would sit in memory.
        guard localFile == nil else { return }
        if let upstream {
            upstream.writeAndFlush(part, promise: nil)
        } else {
            pending.append(part)
        }
    }

    func connected(_ channel: Channel) {
        upstream = channel
        for part in pending {
            channel.write(part, promise: nil)
        }
        pending = []
        channel.flush()
    }
}

/// The upstream end of an `Exchange`, reporting back to the client's handler on the
/// same event loop.
private final class UpstreamHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPClientResponsePart

    /// Names in the upstream pipeline, for taking HTTP off it after a 101.
    static let name = "upstream"
    static let encoder = "http-encoder"
    static let decoder = "http-decoder"
    static let validator = "http-validator"

    private let link: NIOLoopBound<(handler: ForwardHandler, exchange: Exchange)>
    private var ended = false

    init(link: NIOLoopBound<(handler: ForwardHandler, exchange: Exchange)>) {
        self.link = link
    }

    /// addHTTPClientHandlers' three, named so a 101 can take them off, and forwarding
    /// what the server sends after the 101 instead of dropping it; then this.
    static func addHTTP1(_ pipeline: ChannelPipeline.SynchronousOperations, link: NIOLoopBound<(handler: ForwardHandler, exchange: Exchange)>) throws {
        try pipeline.addHandler(HTTPRequestEncoder(), name: encoder)
        try pipeline.addHandler(ByteToMessageHandler(HTTPResponseDecoder(leftOverBytesStrategy: .forwardBytes)), name: decoder)
        try pipeline.addHandler(NIOHTTPRequestHeadersValidator(), name: validator)
        try pipeline.addHandler(UpstreamHandler(link: link), name: name)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        if case .end = part { ended = true }
        link.value.handler.upstreamRead(part, of: link.value.exchange)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        link.value.handler.upstreamReadComplete(of: link.value.exchange)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !ended {
            link.value.handler.fail(link.value.exchange, ProxyFailure(String(localized: "The server closed the connection before the response ended.")))
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Once the response has ended it's whole, even if a breakpoint holds it and the
        // server then hangs up without TLS's close_notify.
        if !ended {
            link.value.handler.fail(link.value.exchange, error)
        }
        context.close(promise: nil)
    }
}

/// The upstream end of a request that came in over HTTP/2, until the server's TLS
/// handshake says which protocol it took: HTTP/2 gets a stream, which gRPC needs end
/// to end, trailers and all; anything else gets HTTP/1.1, as every other request does.
/// Then this leaves, and the exchange gets the channel to send on.
private final class UpstreamNegotiator: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    private let link: NIOLoopBound<(handler: ForwardHandler, exchange: Exchange)>

    init(link: NIOLoopBound<(handler: ForwardHandler, exchange: Exchange)>) {
        self.link = link
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard case TLSUserEvent.handshakeCompleted(let negotiated) = event else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        let (handler, exchange) = link.value
        let link = link
        let connection = context.channel
        let pipeline = context.pipeline.syncOperations
        // Set up before this returns: a server's SETTINGS can come in the same read as
        // the end of the handshake, and must find HTTP/2 there.
        do {
            if negotiated == "h2" {
                var connectionConfiguration = NIOHTTP2Handler.ConnectionConfiguration()
                var streamConfiguration = NIOHTTP2Handler.StreamConfiguration()
                // Nothing here would read what a server pushed.
                connectionConfiguration.initialSettings.append(HTTP2Setting(parameter: .enablePush, value: 0))
                // NIO's 64 KB windows would let a distant server send 64 KB a round trip,
                // slower than the HTTP/1.1 it replaces: this is what the kernel lets that
                // connection hold (net.inet.tcp.autorcvbufmax).
                connectionConfiguration.targetWindowSize = 4 << 20
                streamConfiguration.targetWindowSize = 4 << 20
                let streams = try pipeline.configureHTTP2Pipeline(mode: .client, connectionConfiguration: connectionConfiguration, streamConfiguration: streamConfiguration) { $0.close() }
                pipeline.removeHandler(context: context, promise: nil)
                streams.createStreamChannel { stream in
                    stream.eventLoop.makeCompletedFuture {
                        try stream.pipeline.syncOperations.addHandlers([HTTP2FramePayloadToHTTP1ClientCodec(httpProtocol: .https), UpstreamHandler(link: link)])
                        // The connection is this request's alone (see ForwardHandler).
                        stream.closeFuture.whenComplete { _ in connection.close(promise: nil) }
                    }
                }
                .assumeIsolated()
                .whenComplete { result in
                    switch result {
                    case .success(let stream):
                        handler.upstreamReady(stream, for: exchange)
                    case .failure(let error):
                        handler.fail(exchange, error)
                        connection.close(promise: nil)
                    }
                }
            } else {
                try UpstreamHandler.addHTTP1(pipeline, link: link)
                pipeline.removeHandler(context: context, promise: nil)
                handler.upstreamReady(connection, for: exchange)
            }
        } catch {
            handler.fail(exchange, error)
            context.close(promise: nil)
        }
    }

    /// A failed handshake, such as a certificate the system doesn't trust: the 502 says
    /// which, as it does for an HTTP/1.1 client.
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        link.value.handler.fail(link.value.exchange, error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        link.value.handler.fail(link.value.exchange, ProxyFailure(String(localized: "The server closed the connection during the TLS handshake.")))
        context.fireChannelInactive()
    }
}

struct ProxyFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Copies bytes between two channels on one event loop, reading from one side only
/// while the other can take more. Shows each side's bytes to `observe` as they pass.
final class GlueHandler: ChannelDuplexHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var partner: GlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead = false
    private let observe: (ByteBuffer) -> Void

    private init(observe: @escaping (ByteBuffer) -> Void) {
        self.observe = observe
    }

    static func pair(fromClient: @escaping (ByteBuffer) -> Void, fromServer: @escaping (ByteBuffer) -> Void) -> (client: GlueHandler, server: GlueHandler) {
        let client = GlueHandler(observe: fromClient)
        let server = GlueHandler(observe: fromServer)
        client.partner = server
        server.partner = client
        return (client, server)
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        partner = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        observe(unwrapInboundIn(data))
        // Flushed read by read: what a decoder hands over as it leaves comes with no
        // read-complete after it, and would wait for the sender's next bytes.
        partner?.context?.writeAndFlush(data, promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        partner?.context?.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        partner?.context?.close(promise: nil)
        context.close(promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable, let partner, partner.pendingRead {
            partner.pendingRead = false
            partner.context?.read()
        }
    }

    func read(context: ChannelHandlerContext) {
        if partner?.context?.channel.isWritable ?? false {
            context.read()
        } else {
            pendingRead = true
        }
    }
}
