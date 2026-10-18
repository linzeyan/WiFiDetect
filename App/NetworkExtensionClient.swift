import Foundation
@preconcurrency import NetworkExtension
import Observation
@preconcurrency import SystemExtensions
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "extension")

/// The network extension from the app's side: installing it, its two configurations
/// (the content filter, and the transparent proxy while capture is on), and the XPC
/// connection the filter's reports come in on and the capture lease is renewed over.
@MainActor @Observable
final class NetworkExtensionClient: NSObject {
    enum Status: Equatable {
        /// A development build: only the Developer ID build carries the extension.
        case notIncluded
        case checking
        case notInstalled
        case installing
        /// Replacing the copy macOS has with this build's.
        case updating
        /// Until the user allows it in System Settings, nothing runs.
        case needsApproval
        case needsRestart
        case installed
        case removing
        case removalNeedsRestart
        case failed(String)
    }

    /// Whether this build carries the extension.
    static let isIncluded = FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appending(path: ExtensionConstants.bundlePath).path)

    private(set) var status: Status
    private(set) var isFilterOn = false
    /// What capture asks the extension for; port 0 while capture is off.
    private(set) var capture = CaptureSettings()
    /// The transparent proxy's own state, which lags `capture` while it starts.
    private(set) var captureStatus = NEVPNStatus.invalid
    /// From capture being asked for until the transparent proxy is told to start: the
    /// extension may first need installing, and the user allowing it, which takes
    /// as long as the user does.
    private(set) var isStartingCapture = false
    private(set) var error: String?
    /// The content filter's reports, on the main actor.
    @ObservationIgnored var onReports: ([FlowReport]) -> Void = { _ in }

    @ObservationIgnored private var connection: NSXPCConnection?
    @ObservationIgnored private var heartbeat: Task<Void, Never>?
    @ObservationIgnored private var proxyManager: NETransparentProxyManager?
    @ObservationIgnored private var activation: (request: OSSystemExtensionRequest, done: CheckedContinuation<Bool, Never>)?
    @ObservationIgnored private var deactivation: OSSystemExtensionRequest?
    @ObservationIgnored private var properties: OSSystemExtensionRequest?
    @ObservationIgnored private lazy var receiver = ReportReceiver { [weak self] reports in
        Task { @MainActor in self?.onReports(reports) }
    }

    override init() {
        status = Self.isIncluded ? .checking : .notIncluded
        super.init()
        guard Self.isIncluded else { return }
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.captureStatus = self?.proxyManager?.connection.status ?? .invalid }
        }
        Task { await load() }
    }

    /// Where things stood when the app last quit, without installing anything.
    private func load() async {
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: ExtensionConstants.identifier, queue: .main)
        request.delegate = self
        properties = request
        OSSystemExtensionManager.shared.submitRequest(request)
        let filter = NEFilterManager.shared()
        try? await filter.loadFromPreferences()
        isFilterOn = filter.isEnabled
        // As the system proxy's fourth safeguard does (architecture §2), a transparent
        // proxy an earlier run left on stops, whatever stopped that run. Capture is
        // always off when the app starts.
        if let manager = try? await NETransparentProxyManager.loadAllFromPreferences().first, ![.invalid, .disconnected].contains(manager.connection.status) {
            manager.connection.stopVPNTunnel()
            log.notice("stopped a transparent proxy an earlier run left on")
        }
        updateHeartbeat()
    }

    // MARK: Content filter

    func setFilter(_ on: Bool) async {
        error = nil
        if on, await !activate() { return }
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if on {
                let configuration = NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterDataProviderBundleIdentifier = ExtensionConstants.identifier
                manager.providerConfiguration = configuration
                manager.localizedDescription = "WiFiDetect"
                // After any firewall's filter: this one only watches.
                manager.grade = .inspector
            }
            manager.isEnabled = on
            // Turning it on asks the user the first time (“Filter Network Content”).
            try await manager.saveToPreferences()
        } catch {
            self.error = error.localizedDescription
        }
        isFilterOn = manager.isEnabled
        log.notice("content filter \(self.isFilterOn ? "on" : "off")")
        updateHeartbeat()
    }

    // MARK: Transparent proxy

    /// Starts capture, or updates which apps it covers while it runs.
    func startCapture(port: Int, apps: [String]) async {
        let running = capture.port != 0
        capture = CaptureSettings(port: port, apps: apps)
        renew()
        guard !running else { return }
        isStartingCapture = true
        defer { isStartingCapture = false }
        error = nil
        guard await activate() else {
            capture = CaptureSettings()
            return
        }
        do {
            let manager = try await NETransparentProxyManager.loadAllFromPreferences().first ?? NETransparentProxyManager()
            let configuration = NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = ExtensionConstants.identifier
            // Shown in System Settings › VPN; the proxy does listen there.
            configuration.serverAddress = "127.0.0.1"
            manager.protocolConfiguration = configuration
            manager.localizedDescription = "WiFiDetect"
            manager.isEnabled = true
            // The first save asks the user (“Add Proxy Configurations”).
            try await manager.saveToPreferences()
            // A configuration just saved won't start until it's loaded again.
            try await manager.loadFromPreferences()
            proxyManager = manager
            try manager.connection.startVPNTunnel()
            captureStatus = manager.connection.status
            log.notice("capture on: port \(port), \(apps.count) apps")
        } catch {
            self.error = error.localizedDescription
            capture = CaptureSettings()
        }
        updateHeartbeat()
        // At once rather than at the next beat: the extension starts up meanwhile.
        renew()
    }

    func stopCapture() async {
        guard capture.port != 0 else { return }
        capture = CaptureSettings()
        // Direct at once, even before the tunnel is down.
        renew()
        proxyManager?.connection.stopVPNTunnel()
        log.notice("capture off")
        updateHeartbeat()
    }

    // MARK: Installing

    /// Installs the extension, or replaces an older copy; true once it's running.
    /// While the user hasn't allowed it this waits, as long as it takes.
    private func activate() async -> Bool {
        guard Self.isIncluded, activation == nil else { return false }
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ExtensionConstants.identifier, queue: .main)
        request.delegate = self
        status = .installing
        return await withCheckedContinuation { done in
            activation = (request, done)
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func finishActivation(_ status: Status) {
        self.status = status
        activation?.done.resume(returning: status == .installed)
        activation = nil
        log.notice("extension: \(String(describing: status), privacy: .public)")
    }

    // MARK: Removing

    /// Takes the extension off the Mac, its configurations first. Moving the app to the
    /// Trash doesn't: macOS 26 kept the trashed app's extension installed and running
    /// (docs/README.md D14).
    func uninstall() async {
        guard Self.isIncluded, activation == nil, deactivation == nil else { return }
        error = nil
        status = .removing
        await stopCapture()
        do {
            let filter = NEFilterManager.shared()
            try await filter.loadFromPreferences()
            if filter.providerConfiguration != nil {
                try await filter.removeFromPreferences()
            }
            for manager in try await NETransparentProxyManager.loadAllFromPreferences() {
                try await manager.removeFromPreferences()
            }
        } catch {
            // The extension stays, so Remove can be tried again.
            self.error = error.localizedDescription
            status = .installed
            return
        }
        proxyManager = nil
        isFilterOn = false
        updateHeartbeat()
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: ExtensionConstants.identifier, queue: .main)
        request.delegate = self
        deactivation = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private nonisolated static func describe(_ error: Error) -> String {
        switch (error as? OSSystemExtensionError)?.code {
        case .unsupportedParentBundleLocation:
            String(localized: "Move WiFiDetect to the Applications folder and open it from there: macOS installs network extensions only from there.")
        case .requestCanceled, .requestSuperseded:
            String(localized: "Installing was cancelled.")
        case .forbiddenBySystemPolicy:
            String(localized: "This Mac's settings or its management profile don't allow the extension.")
        default:
            error.localizedDescription
        }
    }

    // MARK: Connection

    /// The extension serves its connection only while it runs, so the beat also brings
    /// the connection back after the extension restarts or is replaced.
    private func updateHeartbeat() {
        let wanted = isFilterOn || capture.port != 0
        if wanted, heartbeat == nil {
            heartbeat = Task { [weak self] in
                while !Task.isCancelled {
                    self?.renew()
                    try? await Task.sleep(for: .seconds(CaptureGate.renewal))
                }
            }
        } else if !wanted {
            heartbeat?.cancel()
            heartbeat = nil
            connection?.invalidate()
            connection = nil
        }
    }

    private func renew() {
        guard let settings = try? PropertyListEncoder().encode(capture) else { return }
        remote()?.renew(settings)
    }

    private func remote() -> ExtensionProtocol? {
        let connection = self.connection ?? makeConnection()
        self.connection = connection
        // remoteObjectProxy is always an NSXPC proxy for the declared interface.
        return connection.remoteObjectProxyWithErrorHandler { _ in } as? ExtensionProtocol
    }

    private func makeConnection() -> NSXPCConnection {
        // Privileged: the extension's service is in the system's namespace, where any
        // process could register a name, hence the requirement too.
        let connection = NSXPCConnection(machServiceName: ExtensionConstants.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: ExtensionProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: ExtensionClientProtocol.self)
        connection.exportedObject = receiver
        connection.setCodeSigningRequirement(ExtensionConstants.extensionRequirement)
        let id = ObjectIdentifier(connection)
        // Called on an XPC queue; without @Sendable it would inherit @MainActor and trap.
        connection.invalidationHandler = { @Sendable [weak self] in
            Task { @MainActor in
                if let self, self.connection.map(ObjectIdentifier.init) == id { self.connection = nil }
            }
        }
        connection.resume()
        return connection
    }
}

extension NetworkExtensionClient: OSSystemExtensionRequestDelegate {
    // All on the main queue, which the requests were made with.

    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        log.notice("replacing extension \(existing.bundleShortVersion, privacy: .public) (\(existing.bundleVersion, privacy: .public)) with \(ext.bundleShortVersion, privacy: .public) (\(ext.bundleVersion, privacy: .public))")
        MainActor.assumeIsolated { status = .updating }
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated { status = .needsApproval }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated {
            if request === activation?.request {
                finishActivation(result == .willCompleteAfterReboot ? .needsRestart : .installed)
            } else if request === deactivation {
                deactivation = nil
                status = result == .willCompleteAfterReboot ? .removalNeedsRestart : .notInstalled
                log.notice("extension: \(String(describing: self.status), privacy: .public)")
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let message = Self.describe(error)
        MainActor.assumeIsolated {
            if request === properties {
                status = .failed(message)
            } else if request === activation?.request {
                finishActivation(.failed(message))
            } else if request === deactivation {
                deactivation = nil
                self.error = message
                status = .installed
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, foundProperties found: [OSSystemExtensionProperties]) {
        let state: Status = if found.contains(where: { $0.isEnabled && !$0.isUninstalling }) {
            .installed
        } else if found.contains(where: \.isAwaitingUserApproval) {
            .needsApproval
        } else {
            .notInstalled
        }
        MainActor.assumeIsolated {
            // An activation started meanwhile knows better.
            if activation == nil { status = state }
        }
    }
}

/// Takes the filter's batches on its XPC queue and decodes them there.
private final class ReportReceiver: NSObject, ExtensionClientProtocol, Sendable {
    private let deliver: @Sendable ([FlowReport]) -> Void

    init(deliver: @escaping @Sendable ([FlowReport]) -> Void) {
        self.deliver = deliver
    }

    func didReport(_ batch: Data) {
        guard let reports = ReportBuffer.decode(batch), !reports.isEmpty else { return }
        deliver(reports)
    }
}
