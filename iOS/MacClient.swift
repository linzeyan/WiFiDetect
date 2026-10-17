import Foundation
import Network
import Observation
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect.companion", category: "mac")

/// Finds Macs sharing their readings over Bonjour and follows one (spec F4.1).
@MainActor @Observable
final class MacClient {
    enum Status: Equatable {
        /// Nothing asked yet: browsing is what brings up the Local Network prompt, so it
        /// waits until the user knows why.
        case idle
        case searching
        /// Local Network access is off for the app.
        case denied
        case connecting
        case connected
        case failed(String)
    }

    private(set) var status = Status.idle
    /// Bonjour names, which are the Macs' own names.
    private(set) var macs: [String] = []
    var selected: String? {
        didSet { if selected != oldValue { connect() } }
    }
    /// The Mac's history: an hour at its fastest rate, 4 Hz.
    private(set) var history = SampleHistory(capacity: 3600 * 4)
    private(set) var link: SharedLink?

    @ObservationIgnored private var browser: NWBrowser?
    @ObservationIgnored private var endpoints: [String: NWEndpoint] = [:]
    @ObservationIgnored private var connection: NWConnection?
    @ObservationIgnored private var buffer = LineBuffer()
    @ObservationIgnored private var hasHistory = false

    func start() {
        #if DEBUG
        if Demo.isOn { return showDemo() }
        #endif
        guard browser == nil else { return }
        let browser = NWBrowser(for: .bonjour(type: Companion.serviceType, domain: nil), using: .tcp)
        browser.stateUpdateHandler = { [weak self] state in
            MainActor.assumeIsolated { self?.browserChanged(state) }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            MainActor.assumeIsolated { self?.resultsChanged(results) }
        }
        browser.start(queue: .main)
        self.browser = browser
        status = .searching
    }

    private func browserChanged(_ state: NWBrowser.State) {
        switch state {
        case .ready:
            if status == .denied { status = .searching }
        case .waiting(let error), .failed(let error):
            // kDNSServiceErr_PolicyDenied
            if case .dns(-65570) = error {
                status = .denied
            } else if connection == nil {
                status = .failed(error.localizedDescription)
            }
            if case .failed = state {
                browser = nil
            }
        default:
            break
        }
    }

    private func resultsChanged(_ results: Set<NWBrowser.Result>) {
        endpoints = [:]
        for result in results {
            if case .service(let name, _, _, _) = result.endpoint {
                endpoints[name] = result.endpoint
            }
        }
        macs = endpoints.keys.sorted()
        log.notice("found \(self.macs.count, privacy: .public) Mac(s)")
        if selected == nil || !macs.contains(selected!) && connection == nil {
            selected = macs.first
        } else if connection == nil {
            // The Mac it was following is back, say after sleeping.
            connect()
        }
    }

    private func connect() {
        connection?.cancel()
        connection = nil
        guard let selected, let endpoint = endpoints[selected] else {
            if let other = macs.first {
                // The Mac it followed left while a connection was still up or under way,
                // which resultsChanged leaves alone; follow one that's here.
                self.selected = other
            } else if status != .denied && status != .idle {
                status = .searching
            }
            return
        }
        let connection = NWConnection(to: endpoint, using: .tcp)
        buffer = LineBuffer()
        hasHistory = false
        status = .connecting
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            MainActor.assumeIsolated {
                guard let self, let connection, connection === self.connection else { return }
                switch state {
                case .failed, .cancelled:
                    self.lost()
                // Waiting retries on its own, but only when the network changes; a Mac
                // that stopped sharing never would.
                case .waiting:
                    connection.cancel()
                default:
                    break
                }
            }
        }
        receive(on: connection)
        self.connection = connection
        connection.start(queue: .main)
        // A connection started while iOS is still granting Local Network access fails its
        // Bonjour resolve and then sits in preparing for good, never reaching waiting or
        // failed (seen on iOS 18). On a LAN, connecting takes milliseconds.
        Task { [weak self, weak connection] in
            try? await Task.sleep(for: .seconds(5))
            guard let self, let connection, connection === self.connection, connection.state != .ready else { return }
            log.notice("connect timed out")
            connection.cancel()
        }
    }

    private func receive(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, isComplete, error in
            MainActor.assumeIsolated {
                guard let self, connection === self.connection else { return }
                do {
                    for line in try self.buffer.append(data ?? Data()) {
                        self.apply(try JSONDecoder().decode(CompanionMessage.self, from: line))
                    }
                } catch {
                    log.error("bad message: \(error.localizedDescription, privacy: .public)")
                    self.status = .failed(error.localizedDescription)
                    connection.cancel()
                    return
                }
                if isComplete || error != nil {
                    connection.cancel()
                } else {
                    self.receive(on: connection)
                }
            }
        }
    }

    private func apply(_ message: CompanionMessage) {
        // The first message is the Mac's whole history, which replaces whatever an
        // earlier connection left: the gap while disconnected shows as a gap.
        if !hasHistory {
            history = SampleHistory(capacity: history.capacity)
            hasHistory = true
            log.notice("history: \(message.samples.count, privacy: .public) samples")
        }
        for sample in message.samples {
            history.append(sample)
        }
        if let newest = message.samples.last {
            log.debug("delay \(Date.now.timeIntervalSince(newest.date) * 1000, format: .fixed(precision: 0), privacy: .public) ms")
        }
        if message.link != link { link = message.link }
        if status != .connected { status = .connected }
    }

    #if DEBUG
    /// A Mac sharing an hour of readings, with no network involved (Demo).
    private func showDemo() {
        macs = ["MacBook Pro"]
        // connect() finds no endpoint for it and leaves it at that.
        selected = macs.first
        for sample in Demo.macHistory(until: .now) {
            history.append(sample)
        }
        link = Demo.link
        status = .connected
    }
    #endif

    /// The Mac quit, slept, or stopped sharing, or the iPhone left the network. Try
    /// again shortly; if the Mac is gone from Bonjour, its return reconnects instead.
    private func lost() {
        connection = nil
        if case .failed = status {} else { status = .searching }
        Task {
            try? await Task.sleep(for: .seconds(2))
            if connection == nil { connect() }
        }
    }
}
