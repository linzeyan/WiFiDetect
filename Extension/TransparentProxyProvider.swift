import Foundation
import Network
import NetworkExtension

/// Hands the HTTPS of the apps the user picked to the app's proxy, for apps that
/// ignore the system proxy. It runs only while capture is on: the network rules send
/// every HTTPS connection on the Mac through here, and one that comes while this
/// process is gone fails until macOS notices, so the app stops it with capture, and
/// it stops itself once the app is gone.
final class TransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling, @unchecked Sendable {
    // @unchecked: Network Extension calls in on its own queues; cancelProxyWithError,
    // all `stop` uses, is safe from any of them.

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        appLink.providerStarting(.proxy)
        setTunnelNetworkSettings(ProxyRules.settings) { error in
            if let error {
                log.error("proxy settings: \(error.localizedDescription, privacy: .public)")
            } else {
                appLink.proxyStarted { [weak self] in self?.cancelProxyWithError(nil) }
                log.notice("transparent proxy started")
            }
            completionHandler(error)
            if error != nil { appLink.providerStopped(.proxy) }
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        appLink.proxyStopped()
        log.notice("transparent proxy stopped: \(reason.rawValue)")
        completionHandler()
        appLink.providerStopped(.proxy)
    }

    /// False leaves the connection to go direct, as if there were no proxy at all.
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow, case .hostPort(let host, let port) = tcp.remoteFlowEndpoint else { return false }
        var app = ""
        let decision = appLink.decide(identifier: flow.metaData.sourceAppSigningIdentifier, remote: host, udp: false) {
            app = appLink.identity(flow.metaData.sourceAppAuditToken)?.path ?? ""
            return app
        }
        guard case .proxy(let proxyPort) = decision, let proxyPort = Network.NWEndpoint.Port(rawValue: UInt16(clamping: proxyPort)) else { return false }
        Relay(flow: tcp, host: host, port: port.rawValue, proxy: proxyPort, app: app).start()
        return true
    }

    /// QUIC from an app being captured is refused rather than let through: it would
    /// go around the proxy, and refused, browsers and URLSession fall back to TCP.
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint) -> Bool {
        guard case .hostPort(let host, _) = remoteEndpoint else { return false }
        let decision = appLink.decide(identifier: flow.metaData.sourceAppSigningIdentifier, remote: host, udp: true) {
            appLink.identity(flow.metaData.sourceAppAuditToken)?.path
        }
        guard decision == .refuse else { return false }
        flow.open(withLocalFlowEndpoint: nil) { _ in
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        return true
    }
}

/// One captured connection, relayed to the app's proxy as a CONNECT, or straight to
/// its server when the proxy can't take it: a connection once taken mustn't fail
/// because of the proxy.
final class Relay: @unchecked Sendable {
    // @unchecked: all state is used on `queue` only; Network Extension's callbacks come
    // on queues of its own and each hops here first.
    private enum Stage {
        case opening, connecting, relaying, done
    }

    private let flow: NEAppProxyTCPFlow
    private let host: Network.NWEndpoint.Host
    private let port: UInt16
    private let proxy: Network.NWEndpoint.Port
    private let app: String
    private let queue = DispatchQueue(label: "com.zeyanlin.wifidetect.relay")
    private var stage = Stage.opening
    private var connection: NWConnection?
    /// The app's first bytes, held until the proxy has answered.
    private var hello = Data()
    private var reply = Data()
    /// Directions still open; at zero the relay is done.
    private var open = 2

    /// How long the proxy has to answer before the connection goes direct instead.
    static let replyTimeout: TimeInterval = 5

    init(flow: NEAppProxyTCPFlow, host: Network.NWEndpoint.Host, port: UInt16, proxy: Network.NWEndpoint.Port, app: String) {
        self.flow = flow
        self.host = host
        self.port = port
        self.proxy = proxy
        self.app = app
    }

    func start() {
        flow.open(withLocalFlowEndpoint: nil) { error in
            self.queue.async {
                if let error {
                    self.finish(error)
                } else if self.flow.remoteHostname != nil {
                    self.toProxy()
                } else {
                    self.readHello()
                }
            }
        }
    }

    /// The first TLS record, for the server name the CONNECT asks for.
    // ponytail: a protocol whose server speaks first waits here until the app gives
    // up; time the wait out if one ever turns up on port 443.
    private func readHello() {
        flow.readData { data, error in
            self.queue.async {
                guard error == nil, let data, !data.isEmpty else { return self.finish(error) }
                self.hello.append(data)
                if TLS.hasWholeRecord(self.hello) || self.hello.count >= 16_389 {
                    self.toProxy()
                } else {
                    self.readHello()
                }
            }
        }
    }

    private func toProxy() {
        guard let target = ConnectPreface.host(remoteHostname: flow.remoteHostname, hello: hello, address: host) else { return direct() }
        stage = .connecting
        let connection = NWConnection(host: "127.0.0.1", port: proxy, using: .tcp)
        self.connection = connection
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: ConnectPreface.request(host: target, port: self.port, app: self.app), completion: .contentProcessed { _ in })
                self.readReply()
            // Waiting is how a refused loopback connection shows: nothing listens there.
            case .waiting, .failed:
                self.proxyFailed()
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.replyTimeout) {
            if self.stage == .connecting, self.connection === connection {
                self.proxyFailed()
            }
        }
    }

    private func readReply() {
        guard let connection else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
            // A proxy connection given up on still completes this, cancelled, once
            // `direct` has started over; it mustn't cancel the direct one.
            guard self.stage == .connecting, self.connection === connection else { return }
            self.reply.append(data ?? Data())
            switch ConnectPreface.reply(self.reply) {
            case .incomplete where isComplete || error != nil:
                self.proxyFailed()
            case .incomplete:
                self.readReply()
            case .established(let rest):
                self.relay(rest)
            case .refused(let status):
                // The proxy is up but couldn't reach the server, or didn't like the
                // request. Direct is what the app would have had; no backoff, since the
                // next connection may well work.
                log.notice("proxy answered \(status, privacy: .public); going direct")
                self.drop()
                self.direct()
            }
        }
    }

    private func proxyFailed() {
        guard stage == .connecting else { return }
        drop()
        appLink.proxyFailed()
        direct()
    }

    /// Lets go of the connection to the proxy without touching the app's side.
    private func drop() {
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
    }

    private func direct() {
        stage = .connecting
        let parameters = NWParameters.tcp
        // Attributed to the app, as its own connection would have been.
        flow.setMetadata(on: parameters)
        // Around the system proxy too: while capture runs it points at the app's proxy,
        // the one that just failed, and the app got here by not using it.
        parameters.preferNoProxies = true
        let connection = NWConnection(to: flow.remoteFlowEndpoint, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready where self.stage == .connecting:
                self.relay(Data())
            // The app's own connection would have failed the same way.
            case .waiting(let error), .failed(let error):
                self.finish(error)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// `rest`: what the server sent behind the proxy's answer, which is the app's.
    private func relay(_ rest: Data) {
        stage = .relaying
        if !hello.isEmpty {
            connection?.send(content: hello, completion: .contentProcessed { _ in })
            hello = Data()
        }
        pumpUp()
        if rest.isEmpty {
            pumpDown()
        } else {
            flow.write(rest) { error in self.queue.async { error == nil ? self.pumpDown() : self.finish(error) } }
        }
    }

    /// The app to the server.
    private func pumpUp() {
        flow.readData { data, error in
            self.queue.async {
                guard self.stage == .relaying, let connection = self.connection else { return }
                if let error { return self.finish(error) }
                guard let data, !data.isEmpty else {
                    // The app closed its side; the server hears the same.
                    connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                    return self.closed()
                }
                connection.send(content: data, completion: .contentProcessed { error in
                    error == nil ? self.pumpUp() : self.finish(error)
                })
            }
        }
    }

    /// The server to the app.
    private func pumpDown() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            guard self.stage == .relaying else { return }
            if let data, !data.isEmpty {
                self.flow.write(data) { writeError in
                    self.queue.async {
                        if let writeError {
                            self.finish(writeError)
                        } else if isComplete {
                            self.flow.closeWriteWithError(nil)
                            self.closed()
                        } else {
                            self.pumpDown()
                        }
                    }
                }
            } else if isComplete {
                self.flow.closeWriteWithError(nil)
                self.closed()
            } else {
                self.finish(error)
            }
        }
    }

    private func closed() {
        open -= 1
        if open == 0 {
            finish(nil)
        }
    }

    private func finish(_ error: Error?) {
        guard stage != .done else { return }
        stage = .done
        drop()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }
}
