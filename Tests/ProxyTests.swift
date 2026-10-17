import Compression
import CryptoKit
import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOHTTP2
import NIOPosix
import NIOSSL
import Security
import SwiftASN1
import Synchronization
import Testing
import X509
@testable import WiFiDetect

// MARK: Host patterns

struct HostPatternsTests {
    @Test(arguments: [
        ("example.com", true), ("EXAMPLE.com.", true), ("api.example.com", false),
        ("a.api.test", true), ("deep.a.api.test", true), ("api.test", false), ("notapi.test", false),
    ])
    func matchesAsWritten(host: String, expected: Bool) {
        // The apex isn't under its own wildcard, and a suffix must start at a dot:
        // "notapi.test" is somebody else's domain.
        let patterns = HostPatterns(["example.com", " *.api.test ", ""])
        #expect(patterns.matches(host) == expected)
    }

    @Test func starMatchesEverything() {
        #expect(HostPatterns(["*"]).matches("anything.example"))
        #expect(!HostPatterns([]).matches("anything.example"))
    }

    @Test func appleServicesAreNeverDecrypted() {
        var policy = ProxyPolicy()
        policy.decrypt = HostPatterns(["*"])
        policy.authority = try? TestCA.make().authority
        #expect(policy.authority(toDecrypt: "apps.apple.com") == nil)
        #expect(policy.authority(toDecrypt: "p42-content.icloud.com") == nil)
        #expect(policy.authority(toDecrypt: "example.com") != nil)
    }
}

// MARK: Map Local

struct MapLocalTests {
    @Test(arguments: [
        // * is any run, the empty one too, and the query is part of what it covers.
        ("https://api.example.com/v1/users*", "https://api.example.com/v1/users", true),
        ("https://api.example.com/v1/users*", "https://api.example.com/v1/users/42?full=1", true),
        ("https://api.example.com/v1/users*", "https://api.example.com/v2/users", false),
        // No scheme: either one. A scheme: that one only.
        ("api.example.com/v1/*", "http://api.example.com/v1/users", true),
        ("api.example.com/v1/*", "https://api.example.com/v1/users", true),
        ("*.example.com/config.json", "http://cdn.example.com/config.json", true),
        ("*.example.com/config.json", "https://a.b.example.com/config.json", true),
        ("*.example.com/config.json", "https://example.com/config.json", false),
        ("https://api.example.com/x", "http://api.example.com/x", false),
        // The whole URL must match: a query the pattern leaves out is a different request.
        ("https://api.example.com/search", "https://api.example.com/search?q=wifi", false),
        ("https://api.example.com/search?q=*", "https://api.example.com/search?q=wifi", true),
        // Only * is special: . and ? are the characters themselves.
        ("https://api.example.com/a.json", "https://api.example.com/aXjson", false),
        ("https://api.example.com/a?b", "https://api.example.com/ab", false),
        // Hosts are case-insensitive like DNS; paths aren't, like the servers behind them.
        ("HTTPS://API.Example.com/Users", "https://api.example.COM/Users", true),
        ("https://api.example.com/Users", "https://api.example.com/users", false),
    ])
    func patternCoversTheWholeURL(pattern: String, url: String, expected: Bool) {
        #expect(MapLocalRule(pattern: pattern, path: "/tmp/mock").matches(url) == expected)
    }

    @Test func firstEnabledRuleWins() {
        // Rules are an ordered list so a specific rule can sit above a broad one; a
        // switched-off rule must not answer, however early it sits.
        var policy = ProxyPolicy()
        policy.mapLocalRules = [
            MapLocalRule(isEnabled: false, pattern: "*", path: "/off"),
            MapLocalRule(pattern: "*/users*", path: "/users"),
            MapLocalRule(pattern: "*", path: "/everything"),
        ]
        #expect(policy.localFile(for: "https://api.example.com/users/1") == "/users")
        #expect(policy.localFile(for: "https://api.example.com/other") == "/everything")
        policy.mapLocalRules[2].isEnabled = false
        #expect(policy.localFile(for: "https://api.example.com/other") == nil)
    }
}

// MARK: Map Remote

struct MapRemoteTests {
    @Test(arguments: [
        ("http://localhost:3000", "http://localhost:3000"),
        ("https://Staging.Example.com/", "https://staging.example.com"),
        // The usual port goes unwritten, so the Host header is the one a browser would send.
        ("https://staging.example.com:443", "https://staging.example.com"),
        ("http://staging.example.com:8443", "http://staging.example.com:8443"),
    ])
    func destinationIsAnOrigin(text: String, url: String) {
        #expect(RemoteOrigin(text)?.url == url)
    }

    @Test(arguments: [
        // Without a scheme "localhost" would be read as one.
        "localhost:3000", "ftp://example.com", "http://",
        // The request keeps its own path and query; the destination's would be dropped unseen.
        "https://staging.example.com/v2", "https://staging.example.com?x=1",
    ])
    func anythingMoreIsRefused(text: String) {
        #expect(RemoteOrigin(text) == nil)
    }

    @Test func firstEnabledRuleWins() {
        var policy = ProxyPolicy()
        policy.mapRemoteRules = [
            MapRemoteRule(isEnabled: false, pattern: "*", destination: "http://off"),
            MapRemoteRule(pattern: "*/users*", destination: "http://localhost:3000"),
            MapRemoteRule(pattern: "*", destination: "https://staging.example.com"),
        ]
        #expect(policy.remoteOrigin(for: "https://api.example.com/users/1")?.url == "http://localhost:3000")
        #expect(policy.remoteOrigin(for: "https://api.example.com/other")?.url == "https://staging.example.com")
    }
}

// MARK: Breakpoints

struct BreakpointTests {
    @Test func everyMatchingRuleHasItsSay() {
        // Unlike Map Local, there's no answer to pick between: one rule may hold a URL's
        // requests and another its responses, and both must apply.
        var policy = ProxyPolicy()
        policy.breakpointRules = [
            BreakpointRule(pattern: "*/users*", response: false),
            BreakpointRule(pattern: "*", request: false),
            BreakpointRule(isEnabled: false, pattern: "*/admin*"),
        ]
        let users = policy.breakpoints(for: "https://api.example.com/users/1")
        #expect(users.request && users.response)
        let other = policy.breakpoints(for: "https://api.example.com/admin/1")
        #expect(!other.request && other.response)
        policy.breakpointRules = []
        let none = policy.breakpoints(for: "https://api.example.com/users/1")
        #expect(!none.request && !none.response)
    }

    @Test func typedHeadersSplitAtTheFirstColon() throws {
        // A Host carries its port after a second colon; cutting there would send the
        // server a different host.
        let headers = try #require(EditedMessage.headers(from: "Host: 127.0.0.1:8000\n\n  \nX-Empty:\nAccept:*/*"))
        #expect(headers.map { "\($0.name)=\($0.value)" } == ["Host=127.0.0.1:8000", "X-Empty=", "Accept=*/*"])
        // Anything else would reach NIO's validator and come back as a 502.
        #expect(EditedMessage.headers(from: "no colon here") == nil)
        #expect(EditedMessage.headers(from: ": no name") == nil)
        #expect(EditedMessage.headers(from: "Bad Name: x") == nil)
    }

    @Test func pausedFlowsOutlastClearAndTheFlowLimit() {
        // Gone from the list, a paused flow could never be sent on: its client would wait
        // until it gave up.
        let log = ProxyLog()
        let paused = log.begin(kind: .http, method: "GET", url: "http://a.test/", host: "a.test")
        log.update(paused) { $0.paused = .request }
        _ = log.begin(kind: .http, method: "GET", url: "http://a.test/", host: "a.test")
        log.clear()
        #expect(log.state.withLock { Array($0.flows.keys) } == [paused])
        for _ in 0 ..< ProxyLog.flowLimit {
            _ = log.begin(kind: .http, method: "GET", url: "http://a.test/", host: "a.test")
        }
        #expect(log.state.withLock { $0.flows[paused] != nil && $0.flows.count == ProxyLog.flowLimit })
    }
}

// MARK: Scripts

struct ScriptTests {
    let loop = MultiThreadedEventLoopGroup.singleton.next()

    static func flow() -> ProxyFlow {
        var flow = ProxyFlow(id: 1, kind: .http, started: .now, method: "POST", url: "http://a.test/p", host: "a.test")
        flow.request.headers = [("Host", "a.test")]
        flow.request.append(Data("hello".utf8))
        return flow
    }

    @Test func firstEnabledScriptForEachPhase() {
        // One script edits a message, not a chain: a later script working on an earlier
        // one's edit would be hard to follow. Requests and responses pick apart.
        var policy = ProxyPolicy()
        policy.scriptRules = [
            ScriptRule(isEnabled: false, pattern: "*", source: "off"),
            ScriptRule(pattern: "*/users*", response: false, source: "users"),
            ScriptRule(pattern: "*", source: "everything"),
        ]
        let users = policy.scripts(for: "https://api.example.com/users/1")
        #expect(users.request == "users" && users.response == "everything")
        policy.scriptRules[2].isEnabled = false
        let other = policy.scripts(for: "https://api.example.com/other")
        #expect(other.request == nil && other.response == nil)
    }

    @Test func runawayScriptIsGivenUpOnAndTheNextOneRuns() async throws {
        // JavaScriptCore can't stop a script through public API: the message has to go on
        // without it, and scripts after it mustn't queue behind it. Busy for two seconds
        // rather than for ever, so the test leaves no core spinning.
        let runner = ScriptRunner(timeout: .milliseconds(300))
        let spin = "function onRequest(r) { const end = Date.now() + 2000; while (Date.now() < end) {} }"
        let error = await #expect(throws: ProxyFailure.self) {
            try await runner.run(spin, .request, Self.flow(), path: "/p", on: loop).get()
        }
        #expect(error?.description.contains("didn't finish") == true)
        let edit = try await runner.run("function onRequest(r) { r.path = '/next' }", .request, Self.flow(), path: "/p", on: loop).get()
        #expect(edit?.path == "/next")
    }

    @Test func scriptsGetNoNetworkOrFiles() async throws {
        // Nothing beyond the language: a script from a blog post can't phone home.
        let script = "function onRequest(r) { r.headers.push(['X-Globals', [typeof fetch, typeof XMLHttpRequest, typeof WebSocket, typeof require, typeof process].join()]) }"
        let edit = try await ScriptRunner().run(script, .request, Self.flow(), path: "/p", on: loop).get()
        #expect(edit?.headers.last?.value == "undefined,undefined,undefined,undefined,undefined")
    }

    @Test(arguments: [
        // A line break would let a script write headers of its own past the encoder.
        (BreakpointPhase.request, "r.headers.push(['X-Note', 'a\\r\\nInjected: 1'])"),
        (.request, "r.headers.push(['Bad Name', 'x'])"),
        (.request, "r.headers.push(['X-Lone'])"),
        (.request, "r.path = 'no-slash'"),
        (.request, "r.method = ''"),
        (.request, "r.body = 42"),
        (.request, "return 'text'"),
        (.response, "r.status = 99"),
    ])
    func malformedEditsAreRefused(phase: BreakpointPhase, body: String) async throws {
        // Refused, they leave the message as it came; let through, they'd go out broken.
        var flow = Self.flow()
        flow.status = 200
        let script = phase == .request ? "function onRequest(r) { \(body) }" : "function onResponse(q, r) { \(body) }"
        await #expect(throws: ProxyFailure.self) {
            try await ScriptRunner().run(script, phase, flow, path: "/p", on: loop).get()
        }
    }

    @Test func syntaxIsCheckedWithoutRunning() {
        // The editor checks as you type; running the script to find out would hang the
        // window on a loop at its top level.
        #expect(ScriptRunner.syntaxError(in: "while (true) {}") == nil)
        #expect(ScriptRunner.syntaxError(in: "function onRequest(r) {")?.contains("SyntaxError") == true)
    }
}

// MARK: Throttling

struct ThrottleTests {
    /// Counts the reads that get past the throttle to the socket.
    private final class ReadCounter: ChannelOutboundHandler {
        typealias OutboundIn = ByteBuffer
        var reads = 0

        func read(context: ChannelHandlerContext) {
            reads += 1
            context.read()
        }
    }

    @Test func stopsReadingWhileTheLinkIsFull() throws {
        // Over a slow link a fast server has to be slowed by TCP, not buffered in the proxy:
        // a large download would otherwise fill the Mac's memory at the server's pace.
        let throttle = Throttle()
        throttle.set(ThrottleSettings(isEnabled: true, downloadKbps: 8, uploadKbps: 8, latencyMs: 0))
        let counter = ReadCounter()
        let channel = EmbeddedChannel(handlers: [counter, ThrottleHandler(throttle, .down)])
        channel.read()
        #expect(counter.reads == 1)
        try channel.writeInbound(ByteBuffer(repeating: 0x61, count: 4096))
        channel.read()
        #expect(counter.reads == 1)
        #expect(try channel.readInbound(as: ByteBuffer.self) == nil)
        _ = try? channel.finish()
    }
}

// MARK: Certificates

/// A CA held in memory, so tests never touch the keychain.
struct TestCA {
    let authority: CertificateAuthority
    let key: Certificate.PrivateKey

    static func make() throws -> TestCA {
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        return TestCA(authority: try CertificateAuthority(certificate: try CertificateAuthority.makeRoot(key: key), key: key), key: key)
    }

    /// A server at 127.0.0.1 that offers only `protocols`, as one that predates HTTP/2
    /// would: the CA's own contexts always offer HTTP/2.
    func originContext(protocols: [String]) throws -> NIOSSLContext {
        let leafKey = P256.Signing.PrivateKey()
        let leaf = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: Date.now.addingTimeInterval(-3600),
            notValidAfter: Date.now.addingTimeInterval(3600),
            issuer: authority.certificate.subject,
            subject: try DistinguishedName { CommonName("127.0.0.1") },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                SubjectAlternativeNames([.ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1]))])
            },
            issuerPrivateKey: key
        )
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: try leaf.derBytes, format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leafKey.pemRepresentation.utf8), format: .pem))
        )
        configuration.applicationProtocols = protocols
        return try NIOSSLContext(configuration: configuration)
    }

    var secCertificate: SecCertificate {
        SecCertificateCreateWithData(nil, Data(authority.der) as CFData)!
    }
}

struct CertificateTests {
    @Test func leafHasWhatAppleRequires() throws {
        let ca = try TestCA.make()
        let now = Date()
        let leaf = try ca.authority.issue(for: "example.com", now: now)
        // Apple 103769: SAN, serverAuth, at most 825 days. Each is a hard failure in Safari.
        #expect(try leaf.extensions.subjectAlternativeNames == SubjectAlternativeNames([.dnsName("example.com")]))
        #expect(try leaf.extensions.extendedKeyUsage?.contains(.serverAuth) == true)
        #expect(try leaf.extensions.basicConstraints == .notCertificateAuthority)
        #expect(leaf.notValidAfter.timeIntervalSince(leaf.notValidBefore) <= 825 * 86_400)
        #expect(leaf.notValidBefore < now && now < leaf.notValidAfter)
        #expect(leaf.issuer == ca.authority.certificate.subject)
        #expect(ca.authority.certificate.publicKey.isValidSignature(leaf.signature, for: leaf))
    }

    @Test func rootCanOnlySignLeaves() throws {
        let root = try TestCA.make().authority.certificate
        #expect(try root.extensions.basicConstraints == .isCertificateAuthority(maxPathLength: 0))
        #expect(try root.extensions.keyUsage?.keyCertSign == true)
    }

    /// The real check: Apple's own TLS evaluation, with the CA as the only anchor.
    @Test(arguments: [("example.com", "example.com", true), ("example.com", "other.com", false), ("127.0.0.1", "127.0.0.1", true)])
    func secTrustAcceptsLeafOnlyForItsHost(issuedFor: String, checkedAs: String, expected: Bool) throws {
        let ca = try TestCA.make()
        let leaf = SecCertificateCreateWithData(nil, Data(try ca.authority.issue(for: issuedFor).derBytes) as CFData)!
        var trust: SecTrust?
        #expect(SecTrustCreateWithCertificates([leaf, ca.secCertificate] as CFArray, SecPolicyCreateSSL(true, checkedAs as CFString), &trust) == errSecSuccess)
        SecTrustSetAnchorCertificates(trust!, [ca.secCertificate] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust!, true)
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust!, &error)
        #expect(trusted == expected, "\(String(describing: error))")
    }
}

// MARK: Bodies and HAR

struct BodyDecodingTests {
    static let text = Data(String(repeating: "Hello, proxy! ", count: 200).utf8)

    static func compress(_ data: Data, _ algorithm: Algorithm) throws -> Data {
        var output = Data()
        let filter = try OutputFilter(.compress, using: algorithm) { output.append($0 ?? Data()) }
        try filter.write(data)
        try filter.finalize()
        return output
    }

    static func message(_ body: Data, encoding: String) -> HTTPMessage {
        var message = HTTPMessage()
        message.headers = [("Content-Encoding", encoding)]
        message.append(body)
        return message
    }

    @Test func gzipWithFileName() throws {
        // FNAME set: the header runs on to a zero-terminated name before the data.
        let header: [UInt8] = [0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3] + Array("body.txt".utf8) + [0]
        let gzip = Data(header) + (try Self.compress(Self.text, .zlib)) + Data(count: 8)
        #expect(Self.message(gzip, encoding: "gzip").decodedBody == Self.text)
    }

    @Test func deflateZlibWrappedOrRaw() throws {
        let raw = try Self.compress(Self.text, .zlib)
        #expect(Self.message(Data([0x78, 0x9c]) + raw, encoding: "deflate").decodedBody == Self.text)
        #expect(Self.message(raw, encoding: "deflate").decodedBody == Self.text)
    }

    @Test func brotli() throws {
        #expect(Self.message(try Self.compress(Self.text, .brotli), encoding: "br").decodedBody == Self.text)
    }

    @Test func unknownEncodingIsNotGuessed() {
        #expect(Self.message(Self.text, encoding: "zstd").decodedBody == nil)
        #expect(Self.message(Self.text, encoding: "identity").decodedBody == Self.text)
    }

    @Test func bodyStopsAtLimitButCountsEverything() {
        var message = HTTPMessage()
        message.append(Data(count: ProxyLog.bodyLimit + 5))
        #expect(message.body.count == ProxyLog.bodyLimit)
        #expect(message.size == ProxyLog.bodyLimit + 5)
        #expect(message.truncated)
    }

    @Test func harHasDecodedTextAndSkipsTunnels() throws {
        let log = ProxyLog()
        let request = log.begin(kind: .https, method: "GET", url: "https://example.com/a?b=1", host: "example.com")
        log.update(request) { flow in
            flow.status = 200
            flow.reason = "OK"
            flow.response = Self.message(try! Self.compress(Self.text, .brotli), encoding: "br")
            flow.response.headers.append(("Content-Type", "text/plain"))
            flow.finished = .now
        }
        _ = log.begin(kind: .tunnel, method: "CONNECT", url: "apple.com:443", host: "apple.com")
        let flows = log.state.withLock { Array($0.flows.values) }

        let json = try JSONSerialization.jsonObject(with: HAR(flows).encoded()) as! [String: Any]
        let entries = (json["log"] as! [String: Any])["entries"] as! [[String: Any]]
        #expect(entries.count == 1)
        let content = (entries[0]["response"] as! [String: Any])["content"] as! [String: Any]
        #expect(content["text"] as? String == String(decoding: Self.text, as: UTF8.self))
        #expect(content["mimeType"] as? String == "text/plain")
        let query = (entries[0]["request"] as! [String: Any])["queryString"] as! [[String: String]]
        #expect(query == [["name": "b", "value": "1"]])
    }
}

// MARK: WebSocket

/// One frame as RFC 6455 §5.2 lays it out; a client's is masked.
func webSocketFrame(_ opcode: UInt8, _ payload: [UInt8], fin: Bool = true, mask: [UInt8]? = nil) -> [UInt8] {
    var bytes: [UInt8] = [(fin ? 0x80 : 0) | opcode]
    let masked: UInt8 = mask == nil ? 0 : 0x80
    switch payload.count {
    case ..<126: bytes.append(masked | UInt8(payload.count))
    case ..<65536: bytes += [masked | 126, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)]
    default: bytes += [masked | 127] + (0 ..< 8).reversed().map { UInt8(truncatingIfNeeded: payload.count >> ($0 * 8)) }
    }
    guard let mask else { return bytes + payload }
    return bytes + mask + payload.enumerated().map { $1 ^ mask[$0 % 4] }
}

struct WebSocketParserTests {
    let mask: [UInt8] = [0x37, 0xfa, 0x21, 0x3d]

    @Test func maskedTextArrivingByteByByte() {
        // TCP can split anywhere, the header included, and the mask has to carry on
        // across reads.
        var parser = WebSocketParser(fromClient: true)
        let messages = webSocketFrame(1, Array("Hello".utf8), mask: mask).flatMap { parser.read(ByteBuffer(bytes: [$0])) }
        #expect(messages.map(\.kind) == ["Text"])
        #expect(messages.first?.payload == Data("Hello".utf8))
        #expect(messages.first?.fromClient == true)
    }

    @Test func pingBetweenFragmentsLeavesTheMessageWhole() {
        // RFC 6455 §5.4: control frames may come between a fragmented message's frames.
        var parser = WebSocketParser(fromClient: false)
        let bytes = webSocketFrame(1, Array("Hel".utf8), fin: false) + webSocketFrame(9, Array("p".utf8)) + webSocketFrame(0, Array("lo".utf8))
        let messages = parser.read(ByteBuffer(bytes: bytes))
        #expect(messages.map(\.kind) == ["Ping", "Text"])
        #expect(messages.map { String(decoding: $0.payload, as: UTF8.self) } == ["p", "Hello"])
    }

    @Test func longFramesAreCountedButKeptOnlyToTheLimit() {
        var parser = WebSocketParser(fromClient: false)
        let medium = [UInt8](repeating: 0x61, count: 300) // a 16-bit length
        let large = [UInt8](repeating: 0x62, count: WebSocketParser.payloadLimit + 10) // a 64-bit length
        let messages = parser.read(ByteBuffer(bytes: webSocketFrame(2, medium) + webSocketFrame(2, large)))
        #expect(messages.map(\.size) == [300, large.count])
        #expect(messages.map(\.payload.count) == [300, WebSocketParser.payloadLimit])
        #expect(messages.last?.payload.allSatisfy { $0 == 0x62 } == true)
    }

    @Test func emptyFrameIsAMessageAndReadingGoesOn() {
        var parser = WebSocketParser(fromClient: true)
        let bytes = webSocketFrame(8, [], mask: mask) + webSocketFrame(1, Array("after".utf8), mask: mask)
        let messages = parser.read(ByteBuffer(bytes: bytes))
        #expect(messages.map(\.kind) == ["Close", "Text"])
        #expect(messages.first?.payload.isEmpty == true)
        #expect(messages.last?.payload == Data("after".utf8))
    }

    @Test func flowLetsTheOldestGoPastItsLimits() {
        // A chatty socket left open for hours must not fill the memory, by count or by size.
        var flow = ProxyFlow(id: 1, kind: .http, started: .now, method: "GET", url: "ws://x/", host: "x")
        for i in 0 ..< ProxyLog.messageLimit + 2 {
            flow.record(WebSocketMessage(fromClient: true, opcode: 1, payload: Data(String(i).utf8)))
        }
        #expect(flow.messages.count == ProxyLog.messageLimit)
        #expect(flow.droppedMessages == 2)
        #expect(flow.messages.first?.payload == Data("2".utf8))
        for _ in 0 ..< 200 {
            flow.record(WebSocketMessage(fromClient: false, opcode: 2, payload: Data(count: WebSocketParser.payloadLimit)))
        }
        #expect(flow.messages.count == ProxyLog.bodyLimit / WebSocketParser.payloadLimit)
        #expect(flow.messages.allSatisfy { $0.opcode == 2 })
    }
}

// MARK: The proxy, end to end

/// A local origin server: answers every request with what it received, saying in
/// headers which HTTP version and TE it got. Trailers come back with gRPC's status
/// added, after a body that then runs to its end instead of a length.
private final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    private var head: HTTPRequestHead?
    private var body = ""

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            self.head = head
            body = ""
        case .body(let buffer):
            body += String(buffer: buffer)
        case .end(var trailers):
            guard let head else { return }
            let text = "\(head.method.rawValue) \(head.uri) \(body)"
            var headers = HTTPHeaders([("content-length", String(text.utf8.count)), ("x-origin", "echo"), ("x-host", head.headers.first(name: "host") ?? "")])
            headers.add(name: "x-version", value: "\(head.version)")
            headers.add(name: "x-te", value: head.headers.first(name: "te") ?? "")
            if trailers != nil {
                headers.remove(name: "content-length")
                trailers?.add(name: "grpc-status", value: "0")
            }
            if !head.isKeepAlive { headers.add(name: "connection", value: "close") }
            context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers))), promise: nil)
            if head.method != .HEAD {
                context.write(wrapOutboundOut(.body(.byteBuffer(context.channel.allocator.buffer(string: text)))), promise: nil)
            }
            let done = context.writeAndFlush(wrapOutboundOut(.end(trailers)))
            if !head.isKeepAlive { done.assumeIsolated().whenComplete { _ in context.close(promise: nil) } }
        }
    }
}

/// Collects what a client connection receives, in order.
final class Collector: ChannelInboundHandler, RemovableChannelHandler, Sendable {
    typealias InboundIn = ByteBuffer
    let received = Mutex(ByteBuffer())

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        _ = received.withLock { $0.writeBuffer(&buffer) }
    }

    var text: String { received.withLock { String(buffer: $0) } }

    func reset() { received.withLock { $0.clear() } }
}

/// How many connections an origin accepted, and how many of them have closed.
final class Connections: Sendable {
    let count = Mutex(0)
    let closed = Mutex(0)
}

/// What one HTTP/2 stream got back.
final class StreamResponse: ChannelInboundHandler, Sendable {
    typealias InboundIn = HTTPClientResponsePart
    let head = Mutex<HTTPResponseHead?>(nil)
    let body = Mutex("")
    let trailers = Mutex<HTTPHeaders?>(nil)
    private let ended = Atomic(false)

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            self.head.withLock { $0 = head }
        case .body(let buffer):
            body.withLock { $0 += String(buffer: buffer) }
        case .end(let trailers):
            self.trailers.withLock { $0 = trailers }
            ended.store(true, ordering: .relaxed)
        }
    }

    var isEnded: Bool { ended.load(ordering: .relaxed) }
    var status: HTTPResponseStatus? { head.withLock { $0?.status } }
    var text: String { body.withLock { $0 } }
    func header(_ name: String) -> String? { head.withLock { $0?.headers.first(name: name) } }
}

/// What a peer sent about the connection as a whole: frames on stream 0 reach the
/// connection's own pipeline.
final class ConnectionFrames: ChannelInboundHandler, Sendable {
    typealias InboundIn = HTTP2Frame
    let settings = Mutex<[HTTP2Setting]?>(nil)
    let windowIncrements = Mutex<[Int]>([])

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data).payload {
        case .settings(.settings(let settings)): self.settings.withLock { $0 = ($0 ?? []) + settings }
        case .windowUpdate(let increment): windowIncrements.withLock { $0.append(increment) }
        default: break
        }
    }
}

/// The WINDOW_UPDATEs a peer sent on streams, ahead of the HTTP/1 codec that drops them.
final class StreamWindowUpdates: ChannelInboundHandler, Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    let increments = Mutex<[Int]>([])

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .windowUpdate(let increment) = unwrapInboundIn(data) { increments.withLock { $0.append(increment) } }
        context.fireChannelRead(data)
    }
}

/// A WebSocket origin at the byte level: answers the upgrade with its 101 and first frame
/// in one write, then keeps whatever arrives.
private final class WebSocketOrigin: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    static let greeting = webSocketFrame(1, Array("hi".utf8))
    let received = Mutex<[UInt8]>([])
    private let answered = Atomic(false)

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = unwrapInboundIn(data).readableBytesView
        let hasHead = received.withLock { received in
            received += bytes
            return splitHead(received) != nil
        }
        guard hasHead, !answered.exchange(true, ordering: .relaxed) else { return }
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        context.writeAndFlush(wrapOutboundOut(ByteBuffer(bytes: Array(head.utf8) + Self.greeting)), promise: nil)
    }
}

/// An HTTP head, lowercased, and the bytes after it.
private func splitHead(_ bytes: [UInt8]) -> (head: String, rest: [UInt8])? {
    guard let end = bytes.firstRange(of: Array("\r\n\r\n".utf8)) else { return nil }
    return (String(decoding: bytes[..<end.upperBound], as: UTF8.self).lowercased(), Array(bytes[end.upperBound...]))
}

struct ProxyServerTests {
    let group = MultiThreadedEventLoopGroup.singleton

    /// Starts an echo origin, plain or with TLS; returns its port. `http2` serves HTTP/2
    /// too, to a client that picks it in the TLS handshake, and `windows` keeps the
    /// window updates that client sends.
    func origin(tls: NIOSSLContext? = nil, connections: Connections? = nil, http2: Bool = false, windows: (ConnectionFrames, StreamWindowUpdates)? = nil) async throws -> (Channel, Int) {
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                connections?.count.withLock { $0 += 1 }
                channel.closeFuture.whenComplete { _ in connections?.closed.withLock { $0 += 1 } }
                if http2, let tls {
                    do {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls))
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                    return channel.configureCommonHTTPServerPipeline(h2ConnectionChannelConfigurator: { channel in
                        channel.eventLoop.makeCompletedFuture { if let windows { try channel.pipeline.syncOperations.addHandler(windows.0) } }
                    }) { channel in
                        channel.eventLoop.makeCompletedFuture {
                            let pipeline = channel.pipeline.syncOperations
                            // HTTP/2 streams only, which come with this codec: a client that
                            // picked HTTP/1.1 sends no frames.
                            if let windows, (try? pipeline.handler(type: HTTP2FramePayloadToHTTP1ServerCodec.self)) != nil {
                                try pipeline.addHandler(windows.1, position: .first)
                            }
                            try pipeline.addHandler(EchoHandler())
                        }
                    }
                }
                return channel.eventLoop.makeCompletedFuture {
                    if let tls { try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls)) }
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(EchoHandler())
                }
            }
            .bind(host: "127.0.0.1", port: 0).get()
        return (channel, channel.localAddress!.port!)
    }

    func connect(_ port: Int, _ collector: Collector) async throws -> Channel {
        try await ClientBootstrap(group: group)
            .channelInitializer { channel in channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(collector) } }
            .connect(host: "127.0.0.1", port: port).get()
    }

    /// Waits until the received bytes satisfy `done`, for up to five seconds.
    func wait(_ collector: Collector, until done: (String) -> Bool) async throws -> String {
        for _ in 0 ..< 100 {
            if done(collector.text) { return collector.text }
            try await Task.sleep(for: .milliseconds(50))
        }
        return collector.text
    }

    @Test func forwardsAbsoluteFormAsOriginForm() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        let request = "POST http://127.0.0.1:\(port)/echo?x=1 HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nProxy-Connection: keep-alive\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        try await client.writeAndFlush(ByteBuffer(string: request))
        try await client.closeFuture.get()

        // The origin saw origin-form and the body; the hop-by-hop header stayed behind.
        #expect(collector.text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(collector.text.hasSuffix("POST /echo?x=1 hello"))
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.kind == .http)
        #expect(flow.status == 200)
        #expect(flow.url == "http://127.0.0.1:\(port)/echo?x=1")
        #expect(flow.request.body == Data("hello".utf8))
        #expect(flow.response.body == Data("POST /echo?x=1 hello".utf8))
        #expect(flow.response.header("x-origin") == "echo")
        #expect(flow.finished != nil)
    }

    @Test func keepsTheClientConnectionAcrossRequests() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        for path in ["/one", "/two"] {
            try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)\(path) HTTP/1.1\r\nHost: x\r\n\r\n"))
            _ = try await wait(collector) { $0.hasSuffix("GET \(path) ") }
        }
        // Both answers arrived on one connection, each framed so the next could follow.
        #expect(collector.text.components(separatedBy: "HTTP/1.1 200 OK").count == 3)
        #expect(collector.text.hasSuffix("GET /two "))
        try await client.close()
    }

    @Test func unreachableOriginIs502() async throws {
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }
        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        // Port 1 on loopback: nothing listens, so the connection is refused at once.
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        let text = try await wait(collector) { $0.contains("\r\n\r\n") }
        #expect(text.hasPrefix("HTTP/1.1 502 Bad Gateway"))
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.error != nil)
        try? await client.close()
    }

    @Test func tunnelsHostsNotOnTheList() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "CONNECT 127.0.0.1:\(port) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n"))
        let established = try await wait(collector) { $0.hasSuffix("\r\n\r\n") }
        // A bare 200: any framing header here would be read as the tunnel's first bytes.
        #expect(established == "HTTP/1.1 200 OK\r\n\r\n")
        collector.reset()
        try await client.writeAndFlush(ByteBuffer(string: "GET /through HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await client.closeFuture.get()

        #expect(collector.text.hasSuffix("GET /through "))
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.kind == .tunnel)
        #expect(flow.bytesUp > 0 && flow.bytesDown > 0)
        #expect(flow.app == nil)
    }

    /// The network extension names the app it captured a connection from; the Requests
    /// list shows it, for tunnels and for every request of a decrypted connection.
    @Test func capturedConnectionsCarryTheirApp() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(bytes: Array(ConnectPreface.request(host: "127.0.0.1", port: UInt16(port), app: "/Applications/My App.app"))))
        _ = try await wait(collector) { $0.hasSuffix("\r\n\r\n") }
        try await client.writeAndFlush(ByteBuffer(string: "GET /through HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await client.closeFuture.get()

        // The header ended at the proxy: the origin echoed only the request it was sent.
        #expect(collector.text.hasSuffix("GET /through "))
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.app == "/Applications/My App.app")
    }

    @Test func decryptsHostsOnTheList() async throws {
        // The origin presents a certificate from its own CA, which the proxy is told to
        // trust, as it trusts the system's roots in the app.
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"))
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer(upstreamRoots: .certificates([try NIOSSLCertificate(bytes: originCA.authority.der, format: .der)]))
        let proxyCA = try TestCA.make()
        proxy.policy.withLock { policy in
            policy.decrypt = HostPatterns(["127.0.0.1"])
            policy.authority = proxyCA.authority
        }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(bytes: Array(ConnectPreface.request(host: "127.0.0.1", port: UInt16(port), app: "/usr/bin/curl"))))
        #expect(try await wait(collector) { $0.hasSuffix("\r\n\r\n") } == "HTTP/1.1 200 OK\r\n\r\n")
        collector.reset()

        // The client trusts only the proxy's CA: the handshake succeeding proves the
        // proxy presented a certificate it issued for this host.
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.trustRoots = .certificates([try NIOSSLCertificate(bytes: proxyCA.authority.der, format: .der)])
        let context = try NIOSSLContext(configuration: tls)
        try await client.eventLoop.submit {
            try client.pipeline.syncOperations.addHandler(try NIOSSLClientHandler(context: context, serverHostname: nil), position: .first)
        }.get()
        try await client.writeAndFlush(ByteBuffer(string: "GET /secret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
        let text = try await wait(collector) { $0.hasSuffix("GET /secret ") }

        #expect(text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(text.hasSuffix("GET /secret "))
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.kind == .https)
        #expect(flow.url == "https://127.0.0.1:\(port)/secret")
        #expect(flow.response.body == Data("GET /secret ".utf8))
        // Named by the network extension's CONNECT, as a captured connection is.
        #expect(flow.app == "/usr/bin/curl")
        try? await client.close()
    }

    @Test func mapLocalAnswersFromTheFileAndForwardsTheRest() async throws {
        let connections = Connections()
        let (origin, port) = try await origin(connections: connections)
        defer { origin.close(promise: nil) }
        let mock = #"{"mocked":true}"#
        let file = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).json")
        try Data(mock.utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.mapLocalRules = [MapLocalRule(pattern: "http://127.0.0.1:\(port)/mapped*", path: file.path)] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "POST http://127.0.0.1:\(port)/mapped?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"))
        let mapped = try await wait(collector) { $0.hasSuffix(mock) }
        // The type comes from the file's extension, so clients parse the mock as they
        // would the real response.
        #expect(mapped.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(mapped.contains("content-type: application/json\r\n"))
        #expect(mapped.contains("content-length: \(mock.utf8.count)\r\n"))
        #expect(mapped.hasSuffix(mock))
        collector.reset()

        // Framed so the connection carries on, and a URL no rule matches still reaches
        // the server.
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await client.closeFuture.get()
        #expect(collector.text.hasSuffix("GET /other "))
        // Only that second request: the mapped one never opened a connection upstream.
        #expect(connections.count.withLock { $0 } == 1)

        let flows = proxy.log.state.withLock { $0.flows.values.sorted { $0.id < $1.id } }
        try #require(flows.count == 2)
        #expect(flows[0].mapLocal == file.path)
        #expect(flows[0].status == 200)
        #expect(flows[0].request.body == Data("hello".utf8))
        #expect(flows[0].response.body == Data(mock.utf8))
        #expect(flows[0].response.header("content-type") == "application/json")
        #expect(flows[0].finished != nil && flows[0].error == nil)
        #expect(flows[1].mapLocal == nil)
    }

    @Test func mapLocalWithoutTheFileIs502() async throws {
        let connections = Connections()
        let (origin, port) = try await origin(connections: connections)
        defer { origin.close(promise: nil) }
        let missing = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).json").path
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.mapLocalRules = [MapLocalRule(pattern: "*/mapped", path: missing)] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/mapped HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        let text = try await wait(collector) { $0.hasSuffix("\n") && $0.contains("\r\n\r\n") }

        // A broken rule says so, rather than quietly falling back to the server: the
        // developer would otherwise think the mock was in use.
        #expect(text.hasPrefix("HTTP/1.1 502 Bad Gateway"))
        #expect(text.contains("Map Local"))
        #expect(connections.count.withLock { $0 } == 0)
        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.mapLocal == missing)
        #expect(flow.error?.contains("Map Local") == true)
        #expect(flow.finished != nil)
        try? await client.close()
    }

    @Test func mapRemoteSendsTheRequestToAnotherServer() async throws {
        // Asked for over plain HTTP, sent to a server that speaks only TLS: the
        // destination's scheme decides, not the request's.
        let asked = Connections()
        let (origin, port) = try await origin(connections: asked)
        defer { origin.close(promise: nil) }
        let remoteCA = try TestCA.make()
        let reached = Connections()
        let (remote, remotePort) = try await self.origin(tls: try remoteCA.authority.serverContext(for: "127.0.0.1"), connections: reached)
        defer { remote.close(promise: nil) }
        let mock = "mocked"
        let file = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).txt")
        try Data(mock.utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let proxy = try ProxyServer(upstreamRoots: .certificates([try NIOSSLCertificate(bytes: remoteCA.authority.der, format: .der)]))
        proxy.policy.withLock { policy in
            policy.mapRemoteRules = [MapRemoteRule(pattern: "*/api/*", destination: "https://127.0.0.1:\(remotePort)")]
            policy.mapLocalRules = [MapLocalRule(pattern: "*/api/local", path: file.path)]
        }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "POST http://127.0.0.1:\(port)/api/users?x=1 HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nContent-Length: 5\r\n\r\nhello"))
        let remapped = try await wait(collector) { $0.hasSuffix("POST /api/users?x=1 hello") }
        // Path, query and body as sent, under the new server's own name.
        #expect(remapped.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(remapped.contains("x-host: 127.0.0.1:\(remotePort)\r\n"))
        collector.reset()

        // Map Local answers first, so its request goes nowhere at all.
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/api/local HTTP/1.1\r\nHost: x\r\n\r\n"))
        _ = try await wait(collector) { $0.hasSuffix(mock) }
        collector.reset()
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await client.closeFuture.get()
        #expect(collector.text.hasSuffix("GET /other "))
        #expect(reached.count.withLock { $0 } == 1)
        #expect(asked.count.withLock { $0 } == 1)

        // Listed as the app asked for it, with where it went beside.
        let flows = proxy.log.state.withLock { $0.flows.values.sorted { $0.id < $1.id } }
        try #require(flows.count == 3)
        #expect(flows[0].url == "http://127.0.0.1:\(port)/api/users?x=1")
        #expect(flows[0].mapRemote == "https://127.0.0.1:\(remotePort)/api/users?x=1")
        #expect(flows[0].finished != nil && flows[0].error == nil)
        #expect(flows[1].mapLocal == file.path && flows[1].mapRemote == nil)
        #expect(flows[2].mapRemote == nil)
    }

    /// Polls `done` for up to five seconds; the expectations after it say what was missing.
    func eventually(_ done: () -> Bool) async throws {
        for _ in 0 ..< 100 where !done() {
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    @Test func relaysAWebSocketAndRecordsItsMessages() async throws {
        let ws = WebSocketOrigin()
        let origin = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(ws) } }
            .bind(host: "127.0.0.1", port: 0).get()
        defer { origin.close(promise: nil) }
        let port = origin.localAddress!.port!
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        let answer = { collector.received.withLock { Array($0.readableBytesView) } }
        let mask: [UInt8] = [1, 2, 3, 4]
        let ping = webSocketFrame(1, Array("ping-me".utf8), mask: mask)
        let close = webSocketFrame(8, [], mask: mask)
        // The first frame rides with the upgrade request, as the origin's rides with its
        // 101: both have to get past the HTTP decoders intact.
        let upgrade = "GET http://127.0.0.1:\(port)/chat HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        try await client.writeAndFlush(ByteBuffer(bytes: Array(upgrade.utf8) + ping))
        try await eventually { splitHead(answer())?.rest == WebSocketOrigin.greeting && splitHead(ws.received.withLock { $0 })?.rest == ping }
        try await client.writeAndFlush(ByteBuffer(bytes: close))
        try await eventually { splitHead(ws.received.withLock { $0 })?.rest == ping + close }
        try await client.close()
        try await eventually { proxy.log.state.withLock { $0.flows.values.first?.finished != nil } }

        let response = try #require(splitHead(answer()))
        #expect(response.head.hasPrefix("http/1.1 101 switching protocols\r\n"))
        #expect(response.head.contains("upgrade: websocket\r\n") && response.head.contains("connection: upgrade\r\n"))
        #expect(response.rest == WebSocketOrigin.greeting)
        // Upgrade and Connection are hop-by-hop, so the proxy sends them on itself; the
        // extension goes, as the inspector can't read compressed frames.
        let request = try #require(splitHead(ws.received.withLock { $0 }))
        #expect(request.head.hasPrefix("get /chat http/1.1\r\n"))
        #expect(request.head.contains("upgrade: websocket\r\n") && request.head.contains("connection: upgrade\r\n"))
        #expect(!request.head.contains("sec-websocket-extensions"))
        #expect(request.rest == ping + close)

        let flow = try #require(proxy.log.state.withLock { $0.flows.values.first })
        #expect(flow.status == 101)
        #expect(flow.bytesUp == ping.count + close.count)
        #expect(flow.bytesDown == WebSocketOrigin.greeting.count)
        // Each way in order; the first two crossed, so their order between them is moot.
        let described = flow.messages.map { "\($0.fromClient ? "sent" : "received") \($0.kind) \(String(decoding: $0.payload, as: UTF8.self))" }
        #expect(described.filter { $0.hasPrefix("sent") } == ["sent Text ping-me", "sent Close "])
        #expect(described.filter { $0.hasPrefix("received") } == ["received Text hi"])
        #expect(flow.finished != nil)

        let har = try JSONSerialization.jsonObject(with: HAR([flow]).encoded()) as! [String: Any]
        let entry = ((har["log"] as! [String: Any])["entries"] as! [[String: Any]])[0]
        let frames = try #require(entry["_webSocketMessages"] as? [[String: Any]])
        #expect(Set(frames.map { "\($0["type"]!) \($0["opcode"]!) \($0["data"]!)" }) == ["send 1 ping-me", "receive 1 hi", "send 8 "])
    }

    @Test func refusedUpgradeEndsTheConnection() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
        try await eventually { !client.isActive }

        // The decoder stops reading at an upgrade request, so the connection can't carry
        // another one: when the server says no, the client has to be told it's over.
        #expect(collector.text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(collector.text.lowercased().contains("connection: close\r\n"))
        #expect(!client.isActive)
        #expect(proxy.log.state.withLock { $0.flows.values.first?.isWebSocket } == false)
    }

    // MARK: Breakpoints

    /// The proxy's flows, oldest first.
    func flows(_ proxy: ProxyServer) -> [ProxyFlow] {
        proxy.log.state.withLock { $0.flows.values.sorted { $0.id < $1.id } }
    }

    @Test func requestBreakpointHoldsTheRequestAndSendsOnTheEdit() async throws {
        let connections = Connections()
        let (origin, port) = try await origin(connections: connections)
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*/held*", response: false)] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "POST http://127.0.0.1:\(port)/held HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
        try await eventually { flows(proxy).first?.paused == .request }
        // Held whole, before the server is even asked: the inspector has all of it to edit.
        let held = try #require(flows(proxy).first)
        #expect(held.paused == .request)
        #expect(held.request.body == Data("hello".utf8))
        #expect(connections.count.withLock { $0 } == 0)

        proxy.resume(held.id, .proceed(EditedMessage(method: "PUT", path: "/edited?x=1", headers: held.request.headers, body: Data("changed".utf8))))
        try await eventually { !client.isActive }

        // The server got the edit, its length recounted: the client's Content-Length of 5
        // would have cut it to "chang".
        #expect(collector.text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(collector.text.hasSuffix("PUT /edited?x=1 changed"))
        let sent = try #require(flows(proxy).first)
        #expect(sent.paused == nil)
        #expect(sent.method == "PUT")
        #expect(sent.url == "http://127.0.0.1:\(port)/edited?x=1")
        #expect(sent.request.body == Data("changed".utf8))
        #expect(sent.request.header("content-length") == "7")
        #expect(sent.breakpointNotes.count == 1)
    }

    @Test func responseBreakpointHoldsTheResponseAndSendsOnTheEdit() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*/held", request: false)] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/held HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await eventually { flows(proxy).first?.paused == .response }
        // The server has answered in full; the client has nothing yet.
        let held = try #require(flows(proxy).first)
        #expect(held.status == 200 && held.response.body == Data("GET /held ".utf8))
        #expect(collector.text.isEmpty)

        // An edited body is typed as decoded text, so it goes on unencoded whatever the
        // headers say, framed by its own length.
        let headers = held.response.headers + [("content-encoding", "gzip"), ("x-edited", "yes")]
        proxy.resume(held.id, .proceed(EditedMessage(status: 201, headers: headers, body: Data("patched".utf8))))
        try await eventually { !client.isActive }

        let text = collector.text.lowercased()
        #expect(text.hasPrefix("http/1.1 201 created\r\n"))
        #expect(text.contains("x-edited: yes\r\n"))
        #expect(text.contains("content-length: 7\r\n"))
        #expect(!text.contains("content-encoding"))
        #expect(text.hasSuffix("\r\n\r\npatched"))
        let sent = try #require(flows(proxy).first)
        #expect(sent.status == 201)
        #expect(sent.response.body == Data("patched".utf8))
        #expect(sent.finished != nil && sent.error == nil)
    }

    @Test func heldExchangeSentOnUnchangedThenAnotherAborted() async throws {
        let connections = Connections()
        let (origin, port) = try await origin(connections: connections)
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*/held*")] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/held HTTP/1.1\r\nHost: x\r\n\r\n"))
        try await eventually { flows(proxy).first?.paused == .request }
        let request = try #require(flows(proxy).first)
        proxy.resume(request.id, .proceed(EditedMessage(method: "GET", path: "/held", headers: request.request.headers)))
        try await eventually { flows(proxy).first?.paused == .response }
        let response = try #require(flows(proxy).first)
        proxy.resume(response.id, .proceed(EditedMessage(status: 200, headers: response.response.headers)))
        // No body in the edit: the server's goes on as it came, framed so the connection
        // can carry the next request.
        let answer = try await wait(collector) { $0.hasSuffix("GET /held ") }
        #expect(answer.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(answer.contains("content-length: 10\r\n"))
        #expect(answer.hasSuffix("\r\n\r\nGET /held "))
        #expect(flows(proxy).first?.breakpointNotes.count == 2)
        collector.reset()

        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/held/again HTTP/1.1\r\nHost: x\r\n\r\n"))
        try await eventually { flows(proxy).last?.paused == .request }
        let aborted = try #require(flows(proxy).last)
        proxy.resume(aborted.id, .abort)
        let text = try await wait(collector) { $0.contains("\r\n\r\n") && $0.hasSuffix("\n") }

        // Aborting answers for the server, which never hears of the request.
        #expect(text.hasPrefix("HTTP/1.1 502 Bad Gateway"))
        #expect(text.contains("Aborted"))
        #expect(connections.count.withLock { $0 } == 1)
        let last = try #require(flows(proxy).last)
        #expect(last.error == "Aborted at the request breakpoint.")
        #expect(last.paused == nil && last.finished != nil)
        try await client.close()
    }

    @Test func clientHangingUpLetsTheBreakpointGo() async throws {
        let connections = Connections()
        let (origin, port) = try await origin(connections: connections)
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*")] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/x HTTP/1.1\r\nHost: x\r\n\r\n"))
        try await eventually { flows(proxy).first?.paused == .request }
        try await client.close()
        try await eventually { flows(proxy).first?.finished != nil }

        // No longer paused, so the inspector stops offering to send it to no one.
        let flow = try #require(flows(proxy).first)
        #expect(flow.paused == nil)
        #expect(flow.error == "The client closed the connection.")
        // A late Continue, as from an inspector that still showed it, goes nowhere.
        proxy.resume(flow.id, .proceed(EditedMessage(method: "GET", path: "/x")))
        try await Task.sleep(for: .milliseconds(200))
        #expect(connections.count.withLock { $0 } == 0)
    }

    @Test func bodiesTooBigToShowWholeAreNotHeld() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { policy in
            policy.breakpointRules = [BreakpointRule(pattern: "*")]
            policy.scriptRules = [ScriptRule(pattern: "*")]
        }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        let size = ProxyLog.bodyLimit + 1
        let head = "POST http://127.0.0.1:\(port)/big HTTP/1.1\r\nHost: x\r\nContent-Length: \(size)\r\nConnection: close\r\n\r\n"
        try await client.writeAndFlush(ByteBuffer(bytes: Array(head.utf8) + [UInt8](repeating: 0x61, count: size)))
        try await eventually { !client.isActive }

        // Past what the log keeps, neither could be shown whole to edit or handed whole to
        // a script, so both go straight on, and the flow says why it never paused.
        let echoed = "POST /big ".utf8.count + size
        let response = try #require(splitHead(collector.received.withLock { Array($0.readableBytesView) }))
        #expect(response.head.hasPrefix("http/1.1 200 ok\r\n"))
        #expect(response.rest.count == echoed)
        let flow = try #require(flows(proxy).first)
        #expect(flow.paused == nil && flow.error == nil)
        #expect(flow.breakpointNotes == ["Request not held: its body is over 10 MB.", "Response not held: its body is over 10 MB."])
        #expect(flow.scriptNotes == ["Request script not run: its body is over 10 MB.", "Response script not run: its body is over 10 MB."])
    }

    // MARK: Scripts

    @Test func scriptsEditTheRequestAndItsResponse() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        // The request is edited in place and nothing returned; the response is a new object.
        let source = """
            function onRequest(request) {
              request.path = "/edited?x=1"
              request.body = request.body.toUpperCase()
              request.headers = request.headers.filter(([name]) => name.toLowerCase() != "host").concat([["Host", "scripted.test"]])
            }
            function onResponse(request, response) {
              return {
                status: 201,
                headers: response.headers.filter(([name]) => name != "x-origin").concat([["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]),
                body: response.body + "|" + request.path,
              }
            }
            """
        let proxy = try ProxyServer()
        proxy.policy.withLock { $0.scriptRules = [ScriptRule(pattern: "*/scripted", source: source)] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "POST http://127.0.0.1:\(port)/scripted HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
        try await eventually { !client.isActive }

        // The server got the edited request, its Host too; the app gets the edited response,
        // its length recounted and both cookies apart and in order.
        let body = "POST /edited?x=1 HELLO|/edited?x=1"
        let text = collector.text
        #expect(text.hasPrefix("HTTP/1.1 201 Created\r\n"))
        #expect(text.contains("x-host: scripted.test\r\n"))
        #expect(!text.contains("x-origin"))
        #expect(text.contains("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"))
        #expect(text.contains("content-length: \(body.utf8.count)\r\n"))
        #expect(text.hasSuffix("\r\n\r\n" + body))
        let flow = try #require(flows(proxy).first)
        #expect(flow.url == "http://127.0.0.1:\(port)/edited?x=1")
        #expect(flow.status == 201 && flow.response.body == Data(body.utf8))
        #expect(flow.scriptNotes.count == 2 && flow.scriptNotes.allSatisfy { $0.contains("script ran") })
        #expect(!flow.scriptFailed && flow.error == nil)
        let har = try JSONSerialization.jsonObject(with: HAR([flow]).encoded()) as! [String: Any]
        let entry = ((har["log"] as! [String: Any])["entries"] as! [[String: Any]])[0]
        #expect((entry["comment"] as? String)?.contains("Response script ran") == true)
    }

    @Test func failingScriptLetsTheMessageThroughWithANote() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        // An empty body isn't JSON, and there's no onResponse at all.
        proxy.policy.withLock { $0.scriptRules = [ScriptRule(pattern: "*", source: "function onRequest(request) { request.path = JSON.parse(request.body).path }")] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/broken HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await eventually { !client.isActive }

        // A slip in a script mustn't take down the app being debugged: both go on as they
        // came, and the flow says why the script didn't apply.
        #expect(collector.text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(collector.text.hasSuffix("GET /broken "))
        let flow = try #require(flows(proxy).first)
        #expect(flow.error == nil && flow.scriptFailed)
        #expect(flow.scriptNotes.count == 2)
        #expect(flow.scriptNotes.first?.contains("SyntaxError") == true)
        #expect(flow.scriptNotes.last?.contains("no onResponse function") == true)
    }

    @Test func scriptWithoutAPhasesFunctionLeavesThatSideAloneUnmarked() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        // Request is ticked, as on every new rule, but the script only edits responses.
        proxy.policy.withLock { $0.scriptRules = [ScriptRule(pattern: "*", source: "function onResponse(request, response) { response.body = 'edited' }")] }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/plain HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await eventually { !client.isActive }

        // Marked, every request a broad pattern matches would look failed in the list and
        // hide the ones whose script did fail. The inspector still says why nothing ran.
        #expect(collector.text.hasSuffix("\r\n\r\nedited"))
        let flow = try #require(flows(proxy).first)
        #expect(!flow.scriptFailed)
        #expect(flow.scriptNotes.first?.contains("no onRequest function") == true)
        #expect(flow.scriptNotes.last?.contains("Response script ran") == true)
    }

    @Test func bodyThatIsNotTextIsLeftAsItCame() async throws {
        // Map Local answers with bytes that aren't UTF-8, and the response script runs on
        // its answer as on a server's.
        let bytes: [UInt8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00, 0x80]
        let file = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).png")
        try Data(bytes).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let proxy = try ProxyServer()
        proxy.policy.withLock { policy in
            policy.mapLocalRules = [MapLocalRule(pattern: "*/image.png", path: file.path)]
            policy.scriptRules = [ScriptRule(pattern: "*/image.png", request: false, source: "function onResponse(request, response) { response.headers.push(['X-Body', String(response.body)]) }")]
        }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:1/image.png HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        try await eventually { !client.isActive }

        // The script saw null, and the app got the file's bytes exactly, not their text.
        let response = try #require(splitHead(collector.received.withLock { Array($0.readableBytesView) }))
        #expect(response.head.contains("x-body: null\r\n"))
        #expect(response.head.contains("content-type: image/png\r\n"))
        #expect(response.rest == bytes)
        #expect(flows(proxy).first?.scriptNotes.first?.contains("Response script ran") == true)
    }

    @Test func scriptRunsBeforeTheBreakpointThatShowsItsEdit() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let source = """
            function onRequest(request) { request.path = "/scripted"; request.body = "scripted body" }
            function onResponse(request, response) { response.body = "seen: " + response.body }
            """
        let proxy = try ProxyServer()
        proxy.policy.withLock { policy in
            policy.scriptRules = [ScriptRule(pattern: "*/both*", source: source)]
            policy.breakpointRules = [BreakpointRule(pattern: "*/both*")]
        }
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "POST http://127.0.0.1:\(port)/both HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
        try await eventually { flows(proxy).first?.paused == .request }

        // The breakpoint shows what the script made, so the user has the last word on it;
        // sent on untouched, it's the script's body that goes, not the app's.
        let request = try #require(flows(proxy).first)
        #expect(request.url == "http://127.0.0.1:\(port)/scripted")
        #expect(request.request.body == Data("scripted body".utf8))
        proxy.resume(request.id, .proceed(EditedMessage(method: request.method, path: "/scripted", headers: request.request.headers)))
        try await eventually { flows(proxy).first?.paused == .response }
        let response = try #require(flows(proxy).first)
        let body = "seen: POST /scripted scripted body"
        #expect(response.response.body == Data(body.utf8))
        proxy.resume(response.id, .proceed(EditedMessage(status: 200, headers: response.response.headers)))
        try await eventually { !client.isActive }

        #expect(collector.text.contains("content-length: \(body.utf8.count)\r\n"))
        #expect(collector.text.hasSuffix("\r\n\r\n" + body))
        let flow = try #require(flows(proxy).first)
        #expect(flow.scriptNotes.count == 2 && flow.breakpointNotes.count == 2)
    }

    // MARK: Throttling

    /// Posts `size` bytes to the echo origin and waits for them to come back: how long it
    /// took, and whether all of them came.
    func echo(_ size: Int, through proxyPort: Int, to port: Int) async throws -> (seconds: Double, whole: Bool) {
        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        let head = "POST http://127.0.0.1:\(port)/echo HTTP/1.1\r\nHost: x\r\nContent-Length: \(size)\r\nConnection: close\r\n\r\n"
        let started = ContinuousClock.now
        try await client.writeAndFlush(ByteBuffer(bytes: Array(head.utf8) + [UInt8](repeating: 0x61, count: size)))
        try await eventually { !client.isActive }
        let seconds = (ContinuousClock.now - started) / .seconds(1)
        let response = splitHead(collector.received.withLock { Array($0.readableBytesView) })
        return (seconds, response?.rest.count == "POST /echo ".utf8.count + size)
    }

    @Test(arguments: [Throttle.Direction.down, .up])
    func throttlingHoldsTransfersToTheRate(_ direction: Throttle.Direction) async throws {
        // The same 2 MB goes up to the echo origin and comes back down, throttled one way
        // at a time to 2 MB/s: more than a connection may hold, so reading has to stop and
        // start again, and the ending has to wait its turn behind the bytes.
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        let kbps = 16_000
        proxy.throttle.set(ThrottleSettings(isEnabled: true, downloadKbps: direction == .down ? kbps : 0, uploadKbps: direction == .up ? kbps : 0, latencyMs: 0))
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        let size = 2_000_000
        let throttled = try await echo(size, through: proxyPort, to: port)
        #expect(throttled.whole)
        #expect(throttled.seconds >= Double(size) / Double(kbps * 125))
        // Off, the same transfer is limited by nothing but the Mac.
        proxy.throttle.set(ThrottleSettings())
        let free = try await echo(size, through: proxyPort, to: port)
        #expect(free.whole)
        #expect(free.seconds < throttled.seconds / 2)
    }

    @Test func latencyIsAddedToEveryRoundTripTunnelsToo() async throws {
        let (origin, port) = try await origin()
        defer { origin.close(promise: nil) }
        let proxy = try ProxyServer()
        proxy.throttle.set(ThrottleSettings(isEnabled: true, downloadKbps: 0, uploadKbps: 0, latencyMs: 400))
        let proxyPort = try await proxy.start(port: 0)
        defer { Task { await proxy.stop() } }

        // Half on the way to the server, half on the way back.
        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        var started = ContinuousClock.now
        try await client.writeAndFlush(ByteBuffer(string: "GET http://127.0.0.1:\(port)/plain HTTP/1.1\r\nHost: x\r\n\r\n"))
        #expect(try await wait(collector) { $0.hasSuffix("GET /plain ") }.hasSuffix("GET /plain "))
        #expect(ContinuousClock.now - started >= .milliseconds(400))
        try await client.close()

        // A tunnel's bytes pay it too: the way back is read on a connection of its own.
        let tunnel = Collector()
        let tunneled = try await connect(proxyPort, tunnel)
        try await tunneled.writeAndFlush(ByteBuffer(string: "CONNECT 127.0.0.1:\(port) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n"))
        _ = try await wait(tunnel) { $0.hasSuffix("\r\n\r\n") }
        tunnel.reset()
        started = ContinuousClock.now
        try await tunneled.writeAndFlush(ByteBuffer(string: "GET /through HTTP/1.1\r\nHost: x\r\n\r\n"))
        #expect(try await wait(tunnel) { $0.hasSuffix("GET /through ") }.hasSuffix("GET /through "))
        #expect(ContinuousClock.now - started >= .milliseconds(400))
        try await tunneled.close()
    }

    // MARK: HTTP/2

    /// A proxy that decrypts 127.0.0.1 with a CA of its own, trusting `originCA` for the
    /// servers behind it.
    func decryptingProxy(trusting originCA: TestCA) async throws -> (proxy: ProxyServer, port: Int, ca: TestCA) {
        let proxy = try ProxyServer(upstreamRoots: .certificates([try NIOSSLCertificate(bytes: originCA.authority.der, format: .der)]))
        let ca = try TestCA.make()
        proxy.policy.withLock { policy in
            policy.decrypt = HostPatterns(["127.0.0.1"])
            policy.authority = ca.authority
        }
        return (proxy, try await proxy.start(port: 0), ca)
    }

    /// CONNECTs through the proxy to 127.0.0.1:`port` and speaks HTTP/2 inside, trusting
    /// only the proxy's CA and offering nothing else in ALPN.
    func h2Client(_ proxyPort: Int, to port: Int, ca: TestCA, settings: ConnectionFrames? = nil) async throws -> (Channel, NIOHTTP2Handler.StreamMultiplexer) {
        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "CONNECT 127.0.0.1:\(port) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n"))
        _ = try await wait(collector) { $0.hasSuffix("\r\n\r\n") }
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.trustRoots = .certificates([try NIOSSLCertificate(bytes: ca.authority.der, format: .der)])
        tls.applicationProtocols = ["h2"]
        let context = try NIOSSLContext(configuration: tls)
        let streams = try await client.eventLoop.submit {
            let pipeline = client.pipeline.syncOperations
            pipeline.removeHandler(collector, promise: nil)
            try pipeline.addHandler(try NIOSSLClientHandler(context: context, serverHostname: nil))
            let streams = try pipeline.configureHTTP2Pipeline(mode: .client, connectionConfiguration: .init(), streamConfiguration: .init()) { $0.close() }
            if let settings { try pipeline.addHandler(settings) }
            return streams
        }.get()
        return (client, streams)
    }

    /// Sends a request on a stream of its own; the response fills in as it comes.
    func send(_ streams: NIOHTTP2Handler.StreamMultiplexer, _ method: HTTPMethod, _ path: String, port: Int, headers: [(String, String)] = [], body: String? = nil, trailers: HTTPHeaders? = nil) async throws -> (stream: Channel, response: StreamResponse) {
        let response = StreamResponse()
        let stream = try await streams.createStreamChannel { channel in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandlers([HTTP2FramePayloadToHTTP1ClientCodec(httpProtocol: .https), response])
            }
        }.get()
        let head = HTTPRequestHead(version: .init(major: 2, minor: 0), method: method, uri: path, headers: HTTPHeaders([("host", "127.0.0.1:\(port)")] + headers))
        stream.write(HTTPClientRequestPart.head(head), promise: nil)
        if let body {
            stream.write(HTTPClientRequestPart.body(.byteBuffer(ByteBuffer(string: body))), promise: nil)
        }
        try await stream.writeAndFlush(HTTPClientRequestPart.end(trailers))
        return (stream, response)
    }

    @Test func h2ClientReachesAnH2OriginInH2() async throws {
        let originCA = try TestCA.make()
        let connections = Connections()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), connections: connections, http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let settings = ConnectionFrames()
        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca, settings: settings)
        let (_, response) = try await send(streams, .POST, "/echo?x=1", port: port, body: "hello")
        try await eventually { response.isEnded && connections.closed.withLock { $0 } == 1 }

        // HTTP/2 the whole way: the proxy offered it upstream because the client spoke it,
        // and :authority reached the origin as its Host.
        #expect(response.status == .ok)
        #expect(response.text == "POST /echo?x=1 hello")
        #expect(response.header("x-version") == "HTTP/2.0")
        #expect(response.header("x-host") == "127.0.0.1:\(port)")
        let flow = try #require(flows(proxy).first)
        #expect(flow.kind == .https && flow.version == "HTTP/2" && flow.serverVersion == "HTTP/2")
        #expect(flow.url == "https://127.0.0.1:\(port)/echo?x=1")
        #expect(flow.request.body == Data("hello".utf8))
        #expect(flow.response.body == Data("POST /echo?x=1 hello".utf8))
        // Whole, not a client giving up: the stream closing as its end goes out is no hang-up.
        #expect(flow.finished != nil && flow.error == nil)
        // The upstream connection was this request's alone, and went with it.
        #expect(connections.count.withLock { $0 } == 1 && connections.closed.withLock { $0 } == 1)
        // No extended CONNECT: browsers keep WebSockets on HTTP/1.1, where the relay records them.
        let advertised = try #require(settings.settings.withLock { $0 })
        #expect(advertised.contains { $0.parameter == .maxConcurrentStreams })
        #expect(!advertised.contains { $0.parameter == .enableConnectProtocol })

        let har = try JSONSerialization.jsonObject(with: HAR([flow]).encoded()) as! [String: Any]
        let entry = ((har["log"] as! [String: Any])["entries"] as! [[String: Any]])[0]
        #expect((entry["request"] as! [String: Any])["httpVersion"] as? String == "HTTP/2")
        #expect((entry["response"] as! [String: Any])["httpVersion"] as? String == "HTTP/2")
        try await client.close()
    }

    @Test func h2ServerMayRunFarAheadOfTheProxyButNotPush() async throws {
        let originCA = try TestCA.make()
        let windows = (ConnectionFrames(), StreamWindowUpdates())
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true, windows: windows)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        // Echoed back past the 64 KB a server may send before it hears from the proxy.
        let body = String(repeating: "x", count: 200_000)
        let (_, response) = try await send(streams, .POST, "/", port: port, body: body)
        try await eventually { response.isEnded }

        #expect(response.text == "POST / \(body)")
        // Megabytes ahead, for the stream and the connection both, as the kernel lets an
        // HTTP/1.1 download run: 64 KB a round trip would crawl from a server far away.
        #expect(windows.0.windowIncrements.withLock { $0.max() ?? 0 } > 1 << 20)
        #expect(windows.1.increments.withLock { $0.max() ?? 0 } > 1 << 20)
        // Nothing would read what it pushed: those bytes would only be thrown away.
        #expect(windows.0.settings.withLock { $0 ?? [] }.contains { $0.parameter == .enablePush && $0.value == 0 })
        try await client.close()
    }

    @Test func responseBeyondTheWindowKeepsFlowingToAClientThatFallsBehind() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        // Past the 4 MB the origin may send unasked: it then waits on the proxy reading on,
        // which the client's 64 KB window has stopped and restarted many times by then.
        let body = String(repeating: "x", count: 5 << 20)
        let (_, response) = try await send(streams, .POST, "/", port: port, body: body)
        try await eventually { response.isEnded }

        // A download, or a gRPC stream, that outlasts the window mustn't hang for good.
        #expect(response.isEnded)
        #expect(response.text.utf8.count == body.utf8.count + "POST / ".utf8.count)
        try await client.close()
    }

    @Test func untrustedH2OriginIs502WithTheReason() async throws {
        let (origin, port) = try await origin(tls: try TestCA.make().authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        // The proxy trusts another CA: the origin's certificate is as bad as any the
        // client itself would have refused.
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: try TestCA.make())
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (_, response) = try await send(streams, .GET, "/", port: port)
        try await eventually { response.isEnded }

        // The developer reads why, as an HTTP/1.1 client's would, not just that it failed.
        #expect(response.status == .badGateway)
        let flow = try #require(flows(proxy).first)
        #expect(flow.error?.contains("CERTIFICATE_VERIFY_FAILED") == true)
        #expect(response.text == (flow.error ?? "") + "\n")
        try await client.close()
    }

    @Test func h2ClientFallsBackToHTTP1ForAnOriginWithoutH2() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.originContext(protocols: ["http/1.1"]))
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        // No Content-Length: HTTP/2 frames the body itself, HTTP/1.1 has to have it chunked.
        let (_, response) = try await send(streams, .POST, "/echo", port: port, body: "hello")
        try await eventually { response.isEnded }

        #expect(response.status == .ok)
        #expect(response.text == "POST /echo hello")
        #expect(response.header("x-version") == "HTTP/1.1")
        #expect(response.header("x-host") == "127.0.0.1:\(port)")
        // Said in the inspector, as it's why gRPC would fail here.
        let flow = try #require(flows(proxy).first)
        #expect(flow.version == "HTTP/2" && flow.serverVersion == "HTTP/1.1")
        #expect(flow.finished != nil && flow.error == nil)
        try await client.close()
    }

    @Test func http1ClientStaysOnHTTP1EvenToAnH2Origin() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let collector = Collector()
        let client = try await connect(proxyPort, collector)
        try await client.writeAndFlush(ByteBuffer(string: "CONNECT 127.0.0.1:\(port) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n"))
        _ = try await wait(collector) { $0.hasSuffix("\r\n\r\n") }
        collector.reset()
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.trustRoots = .certificates([try NIOSSLCertificate(bytes: ca.authority.der, format: .der)])
        tls.applicationProtocols = ["http/1.1"]
        let context = try NIOSSLContext(configuration: tls)
        try await client.eventLoop.submit {
            try client.pipeline.syncOperations.addHandler(try NIOSSLClientHandler(context: context, serverHostname: nil), position: .first)
        }.get()
        try await client.writeAndFlush(ByteBuffer(string: "GET /plain HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
        let text = try await wait(collector) { $0.hasSuffix("GET /plain ") }

        // Its requests never offer HTTP/2 upstream, so they reach servers as before: an
        // HTTP/1.1 client's WebSocket upgrade could go nowhere over HTTP/2.
        #expect(text.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(text.contains("x-version: HTTP/1.1\r\n"))
        let flow = try #require(flows(proxy).first)
        #expect(flow.version == "HTTP/1.1" && flow.serverVersion == "HTTP/1.1")
        try? await client.close()
    }

    @Test func concurrentStreamsOnOneConnectionGetTheirOwnAnswers() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        var responses: [StreamResponse] = []
        for i in 0 ..< 5 {
            responses.append(try await send(streams, .POST, "/s\(i)", port: port, body: "body \(i)").response)
        }
        try await eventually { responses.allSatisfy(\.isEnded) }

        // Each stream is an exchange of its own: no answer crosses to another stream.
        #expect(responses.map(\.text) == (0 ..< 5).map { "POST /s\($0) body \($0)" })
        let all = flows(proxy)
        #expect(Set(all.map(\.url)) == Set((0 ..< 5).map { "https://127.0.0.1:\(port)/s\($0)" }))
        #expect(all.allSatisfy { $0.version == "HTTP/2" && $0.finished != nil && $0.error == nil })
        try await client.close()
    }

    /// Scripted: a script that changes nothing waits for each whole message and sends on
    /// what it made, as a breakpoint does; the trailers must go on after it too.
    @Test(arguments: [false, true]) func trailersPassThroughBothWays(scripted: Bool) async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        if scripted {
            proxy.policy.withLock { $0.scriptRules = [ScriptRule(pattern: "*")] }
        }
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (_, response) = try await send(streams, .POST, "/echo.Echo/Say", port: port, headers: [("te", "trailers"), ("content-type", "application/grpc")], body: "message", trailers: HTTPHeaders([("x-checksum", "42")]))
        try await eventually { response.isEnded }

        // gRPC's status rides in trailers, and its servers look for TE: trailers to know
        // it will get through; the request's own trailers reached the origin too.
        #expect(response.header("x-te") == "trailers")
        let trailers = try #require(response.trailers.withLock { $0 })
        #expect(trailers.first(name: "grpc-status") == "0")
        #expect(trailers.first(name: "x-checksum") == "42")
        #expect(flows(proxy).first?.error == nil)
        #expect(flows(proxy).first?.scriptNotes.count == (scripted ? 2 : 0))
        try await client.close()
    }

    @Test func breakpointHoldsOneStreamWhileAnotherCompletes() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*/held", response: false)] }
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (_, held) = try await send(streams, .GET, "/held", port: port)
        try await eventually { flows(proxy).first?.paused == .request }
        let (_, free) = try await send(streams, .GET, "/free", port: port)
        try await eventually { free.isEnded }

        // A browser loads a page's resources over one connection: holding one of them
        // mustn't hold the rest.
        #expect(free.text == "GET /free ")
        #expect(!held.isEnded)
        let request = try #require(flows(proxy).first)
        #expect(request.paused == .request)

        proxy.resume(request.id, .proceed(EditedMessage(method: "GET", path: "/held", headers: request.request.headers)))
        try await eventually { held.isEnded }
        #expect(held.text == "GET /held ")
        #expect(flows(proxy).first?.error == nil)
        try await client.close()
    }

    @Test func scriptedResponseHeldOnAnH2StreamGoesOnWhenContinued() async throws {
        let originCA = try TestCA.make()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        proxy.policy.withLock { policy in
            policy.scriptRules = [ScriptRule(pattern: "*/both", request: false, source: "function onResponse(request, response) { response.headers.push(['x-script', 'ran']) }")]
            policy.breakpointRules = [BreakpointRule(pattern: "*/both", request: false)]
        }
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (_, response) = try await send(streams, .GET, "/both", port: port)
        try await eventually { flows(proxy).first?.paused == .response }

        // Sent on as the inspector does: the headers it shows, the body untouched.
        let held = try #require(flows(proxy).first)
        #expect(held.paused == .response && !response.isEnded)
        #expect(held.response.header("x-script") == "ran")
        proxy.resume(held.id, .proceed(EditedMessage(status: held.status ?? 0, headers: held.response.headers)))
        try await eventually { response.isEnded }
        #expect(response.isEnded)
        #expect(response.status == .ok)
        #expect(response.header("x-script") == "ran")
        #expect(response.text == "GET /both ")
        #expect(flows(proxy).first?.error == nil)
        try await client.close()
    }

    @Test func mapLocalAnswersAnH2Stream() async throws {
        let originCA = try TestCA.make()
        let connections = Connections()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), connections: connections, http2: true)
        defer { origin.close(promise: nil) }
        let mock = #"{"mocked":true}"#
        let file = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).json")
        try Data(mock.utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        proxy.policy.withLock { $0.mapLocalRules = [MapLocalRule(pattern: "https://127.0.0.1:\(port)/mapped*", path: file.path)] }
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (_, mapped) = try await send(streams, .GET, "/mapped?x=1", port: port)
        try await eventually { mapped.isEnded }

        #expect(mapped.status == .ok)
        #expect(mapped.header("content-type") == "application/json")
        #expect(mapped.header("content-length") == String(mock.utf8.count))
        #expect(mapped.text == mock)
        #expect(connections.count.withLock { $0 } == 0)
        // No server answered, so there's no server version to show.
        let flow = try #require(flows(proxy).first)
        #expect(flow.mapLocal == file.path && flow.version == "HTTP/2" && flow.serverVersion == nil)
        try await client.close()
    }

    @Test func clientResettingAStreamIsRecordedLikeAHangUp() async throws {
        let originCA = try TestCA.make()
        let connections = Connections()
        let (origin, port) = try await origin(tls: try originCA.authority.serverContext(for: "127.0.0.1"), connections: connections, http2: true)
        defer { origin.close(promise: nil) }
        let (proxy, proxyPort, ca) = try await decryptingProxy(trusting: originCA)
        proxy.policy.withLock { $0.breakpointRules = [BreakpointRule(pattern: "*/held", response: false)] }
        defer { Task { await proxy.stop() } }

        let (client, streams) = try await h2Client(proxyPort, to: port, ca: ca)
        let (stream, _) = try await send(streams, .GET, "/held", port: port)
        try await eventually { flows(proxy).first?.paused == .request }
        // RST_STREAM: how a browser drops a fetch it no longer needs, keeping the connection.
        // NIO completes the close with the CANCEL it sent.
        stream.close(promise: nil)
        try await eventually { flows(proxy).first?.finished != nil }

        let flow = try #require(flows(proxy).first)
        #expect(flow.paused == nil)
        #expect(flow.error == "The client cancelled the request.")
        // A late Continue goes nowhere, and the connection carries on.
        proxy.resume(flow.id, .proceed(EditedMessage(method: "GET", path: "/held")))
        let (_, after) = try await send(streams, .GET, "/after", port: port)
        try await eventually { after.isEnded }
        try await Task.sleep(for: .milliseconds(200))
        #expect(after.text == "GET /after ")
        #expect(connections.count.withLock { $0 } == 1)
        try await client.close()
    }
}

@Test func connectAuthorityParsing() {
    #expect(ForwardHandler.authority("example.com:443").map { "\($0.host) \($0.port)" } == "example.com 443")
    #expect(ForwardHandler.authority("[2606:4700::1111]:443").map { "\($0.host) \($0.port)" } == "2606:4700::1111 443")
    #expect(ForwardHandler.authority("example.com") == nil)
    #expect(ForwardHandler.authority(":443") == nil)
    #expect(ForwardHandler.authority("example.com:70000") == nil)
}
