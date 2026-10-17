import Foundation
import Network
import Synchronization
import os

let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "extension")

/// Both providers run in this one process, and share the app connection through it.
let appLink = AppLink()

/// The extension's side of the app connection: the capture lease the app renews, and
/// the filter's reports on their way to the app.
final class AppLink: NSObject, NSXPCListenerDelegate, ExtensionProtocol, Sendable {
    /// NSXPCConnection is thread-safe; the SDK just doesn't mark it Sendable.
    private struct Peer: @unchecked Sendable {
        let connection: NSXPCConnection
    }

    enum Provider {
        case filter, proxy
    }

    private struct State {
        var gate = CaptureGate()
        /// The app the reports go to: the one that renewed last.
        var peer: Peer?
        var reports = ReportBuffer()
        /// Set while the transparent proxy runs: without the app it has nothing to do.
        var stopProxy: (@Sendable () -> Void)?
        /// Those starting or running; the process ends once none are.
        var providers: Set<Provider> = []
    }

    private let state = Mutex(State())
    /// Per process rather than per connection, as a browser opens dozens a second. The
    /// audit token carries the pid's version, so a reused pid is looked up anew.
    private let identities = Mutex<[Data: FlowReport.Process]>([:])

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Enforced per message, as in the helper: a peer that isn't the team's app gets
        // its connection invalidated before `renew` runs.
        connection.setCodeSigningRequirement(HelperConstants.appRequirement)
        connection.exportedInterface = NSXPCInterface(with: ExtensionProtocol.self)
        connection.exportedObject = self
        connection.remoteObjectInterface = NSXPCInterface(with: ExtensionClientProtocol.self)
        let id = ObjectIdentifier(connection)
        connection.invalidationHandler = { [weak self] in self?.disconnected(id) }
        connection.resume()
        return true
    }

    func renew(_ settings: Data) {
        guard let settings = try? PropertyListDecoder().decode(CaptureSettings.self, from: settings),
              let connection = NSXPCConnection.current() else { return }
        let changed = state.withLock { state in
            state.peer = Peer(connection: connection)
            defer { state.gate.renew(settings, at: .now) }
            return state.gate.settings != settings
        }
        if changed {
            log.notice("capture: port \(settings.port), \(settings.apps.count) apps")
        }
    }

    /// The app quit, crashed or was killed: flows go direct from now on, and the
    /// transparent proxy stops, as the helper puts the system proxy back.
    private func disconnected(_ id: ObjectIdentifier) {
        let stop = state.withLock { state -> (@Sendable () -> Void)? in
            guard state.peer.map({ ObjectIdentifier($0.connection) }) == id else { return nil }
            state.peer = nil
            state.gate.disconnect()
            state.reports = ReportBuffer()
            return state.stopProxy
        }
        log.notice("app connection gone")
        stop?()
    }

    // MARK: Lifetime

    func providerStarting(_ provider: Provider) {
        state.withLock { _ = $0.providers.insert(provider) }
    }

    /// Ends the process a second after the last provider stops, unless one starts again
    /// meanwhile. Left to the system, an extension replaced by an update was sometimes
    /// kept for minutes, and every new inbound connection on the Mac waited until it
    /// was gone (spikes, Phase 4 third batch). The second lets the stop's reply reach
    /// Network Extension first.
    func providerStopped(_ provider: Provider) {
        let idle = state.withLock { state in
            state.providers.remove(provider)
            return state.providers.isEmpty
        }
        guard idle else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            guard self.state.withLock({ $0.providers.isEmpty }) else { return }
            log.notice("no provider running; exiting")
            exit(0)
        }
    }

    // MARK: Transparent proxy

    func proxyStarted(stop: @escaping @Sendable () -> Void) {
        state.withLock { $0.stopProxy = stop }
    }

    func proxyStopped() {
        state.withLock { $0.stopProxy = nil }
    }

    func decide(identifier: String?, remote: Network.NWEndpoint.Host?, udp: Bool, path: () -> String?) -> CaptureGate.Decision {
        state.withLock { $0.gate }.decide(identifier: identifier, remote: remote, udp: udp, at: .now, path: path)
    }

    func proxyFailed() {
        state.withLock { $0.gate.proxyFailed(at: .now) }
        log.error("the app's proxy didn't take a connection; new ones go direct for \(Int(CaptureGate.backoff)) s")
    }

    // MARK: Content filter

    /// Nothing to report to while no app listens.
    var isListening: Bool {
        state.withLock { $0.peer != nil }
    }

    func report(_ report: FlowReport) {
        let first = state.withLock { state in
            defer { state.reports.append(report) }
            return state.reports.isEmpty
        }
        // A send a quarter second after the first report, as the helper batches: no
        // timer ticks while the Mac is quiet.
        if first {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.25) { self.flush() }
        }
    }

    private func flush() {
        let (batch, peer) = state.withLock { ($0.reports.drain(), $0.peer) }
        guard let batch, let peer else { return }
        (peer.connection.remoteObjectProxy as? ExtensionClientProtocol)?.didReport(batch)
    }

    func identity(_ token: Data?) -> FlowReport.Process? {
        guard let token else { return nil }
        if let known = identities.withLock({ $0[token] }) {
            return known
        }
        guard let found = ProcessIdentity.lookup(token) else { return nil }
        identities.withLock { identities in
            if identities.count >= 512 { identities.removeAll() }
            identities[token] = found
        }
        return found
    }
}
