import Foundation
import Network
import Observation

/// Shares the Wi-Fi readings with the iPhone companion (spec F4.1). Opt-in, because
/// advertising them means anyone on the network can find this Mac and read them.
@MainActor @Observable
final class CompanionServer {
    /// Settings › Wi-Fi, remembered across launches.
    var isEnabled: Bool {
        didSet {
            UserDefaults.standard.set(isEnabled, forKey: SettingsKey.shareWithPhone)
            if isEnabled {
                Task { await startAdvertising() }
            } else {
                stop()
            }
        }
    }
    private(set) var error: String?
    /// Connected iPhones.
    private(set) var clients: [ObjectIdentifier: NWConnection] = [:]

    // ponytail: no per-client send queue cap. A suspended iPhone stops reading and its
    // sends pile up at ~100 B/s; cap or drop slow clients if that ever matters.
    private static let maxClients = 8

    @ObservationIgnored private let monitor: WiFiMonitor
    @ObservationIgnored private var listener: NWListener?
    @ObservationIgnored private var ready: CheckedContinuation<NWEndpoint.Port, Error>?

    init(monitor: WiFiMonitor) {
        self.monitor = monitor
        isEnabled = UserDefaults.standard.bool(forKey: SettingsKey.shareWithPhone)
        monitor.onSample = { [weak self] sample in self?.broadcast(sample) }
        if isEnabled {
            Task { await startAdvertising() }
        }
    }

    private func startAdvertising() async {
        // Turned off again before this task ran.
        guard isEnabled else { return }
        do {
            _ = try await start()
            error = nil
        } catch is CancellationError {
            // Stopped while starting.
        } catch {
            self.error = Self.describe(error)
        }
    }

    /// Advertised over Bonjour on every interface. With `advertise` off it listens on
    /// loopback only, unannounced: what the tests use, since it needs no local network
    /// access and the firewall doesn't ask about it.
    func start(advertise: Bool = true) async throws -> NWEndpoint.Port {
        stop()
        let parameters = NWParameters.tcp
        if !advertise {
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        }
        let listener = try NWListener(using: parameters)
        if advertise {
            // No name: Bonjour uses the Mac's, which is what the iPhone should list.
            listener.service = NWListener.Service(type: Companion.serviceType)
        }
        listener.newConnectionHandler = { [weak self] connection in
            MainActor.assumeIsolated { self?.accept(connection) }
        }
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            MainActor.assumeIsolated {
                guard let self, let listener, listener === self.listener else { return }
                self.listenerChanged(listener, state)
            }
        }
        self.listener = listener
        return try await withCheckedThrowingContinuation { continuation in
            ready = continuation
            listener.start(queue: .main)
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        ready?.resume(throwing: CancellationError())
        ready = nil
        for connection in clients.values { connection.cancel() }
        clients = [:]
    }

    private func listenerChanged(_ listener: NWListener, _ state: NWListener.State) {
        switch state {
        case .ready:
            error = nil
            ready?.resume(returning: listener.port!)
            ready = nil
        // Waiting is how a denied local network permission shows up: Bonjour can't
        // register, and the listener waits for that to change.
        case .failed(let failure), .waiting(let failure):
            if case .failed = state { self.listener = nil }
            if let ready {
                ready.resume(throwing: failure)
                self.ready = nil
            } else {
                error = Self.describe(failure)
            }
        default:
            break
        }
    }

    private func accept(_ connection: NWConnection) {
        guard clients.count < Self.maxClients else {
            connection.cancel()
            return
        }
        let id = ObjectIdentifier(connection)
        clients[id] = connection
        connection.stateUpdateHandler = { [weak self] state in
            MainActor.assumeIsolated {
                guard let self else { return }
                switch state {
                case .ready:
                    self.send(CompanionMessage(samples: self.monitor.history.samples, link: self.sharedLink), to: connection)
                case .failed, .cancelled:
                    self.clients[id] = nil
                default:
                    break
                }
            }
        }
        discardIncoming(connection)
        connection.start(queue: .main)
    }

    /// iPhones only listen. Reading anyway is how a disconnect is noticed right away
    /// rather than at the next failed send.
    private func discardIncoming(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] _, _, isComplete, error in
            MainActor.assumeIsolated {
                if isComplete || error != nil {
                    connection.cancel()
                } else {
                    self?.discardIncoming(connection)
                }
            }
        }
    }

    private func broadcast(_ sample: WiFiSample) {
        let message = CompanionMessage(samples: [sample], link: sharedLink)
        // A connection that isn't ready yet gets this sample in its history on ready.
        for connection in clients.values where connection.state == .ready {
            send(message, to: connection)
        }
    }

    private func send(_ message: CompanionMessage, to connection: NWConnection) {
        guard let line = try? message.line() else { return }
        connection.send(content: line, completion: .contentProcessed { _ in })
    }

    private var sharedLink: SharedLink? {
        monitor.link.map { SharedLink(isPoweredOn: $0.isPoweredOn, txRate: $0.txRate, channel: $0.channel?.label) }
    }

    private static func describe(_ error: Error) -> String {
        // kDNSServiceErr_PolicyDenied
        if case .dns(-65570) = error as? NWError {
            return String(localized: "macOS blocked local network access. Allow WiFiDetect in System Settings › Privacy & Security › Local Network, then turn sharing off and on.")
        }
        return error.localizedDescription
    }
}
