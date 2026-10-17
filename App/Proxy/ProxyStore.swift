import AppKit
import NIOCore
import Observation

@MainActor @Observable
final class ProxyStore {
    enum Authority {
        case loading
        case none
        case untrusted(CertificateAuthority)
        case trusted(CertificateAuthority)
    }

    let helper: HelperClient
    let network: NetworkExtensionClient
    @ObservationIgnored let server: ProxyServer?

    /// Listening, with the system proxy pointed here.
    private(set) var isRunning = false
    private(set) var isChanging = false
    private(set) var error: String?
    /// The port the running proxy listens on.
    private(set) var port = 0
    /// Oldest first; a snapshot of the server's log, taken twice a second.
    private(set) var flows: [ProxyFlow] = []
    private(set) var authority = Authority.loading
    /// The hosts whose HTTPS is decrypted (F3.6), as the user wrote them.
    var decryptHosts: [String] {
        didSet {
            UserDefaults.standard.set(decryptHosts, forKey: SettingsKey.decryptHosts)
            applyPolicy()
        }
    }
    /// Map Local, in the order they're tried.
    var mapLocalRules: [MapLocalRule] {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(mapLocalRules), forKey: SettingsKey.mapLocal)
            applyPolicy()
        }
    }
    /// Map Remote, in the order they're tried.
    var mapRemoteRules: [MapRemoteRule] {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(mapRemoteRules), forKey: SettingsKey.mapRemote)
            applyPolicy()
        }
    }
    /// Breakpoints; every one that matches applies.
    var breakpointRules: [BreakpointRule] {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(breakpointRules), forKey: SettingsKey.breakpoints)
            applyPolicy()
        }
    }
    /// Scripts, in the order they're tried.
    var scriptRules: [ScriptRule] {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(scriptRules), forKey: SettingsKey.scripts)
            applyPolicy()
        }
    }
    /// Kept on or off as the user left it; the Requests page says while it's on.
    var throttle: ThrottleSettings {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(throttle), forKey: SettingsKey.throttle)
            applyPolicy()
        }
    }
    /// Apps that ignore the system proxy, captured by the network extension while the
    /// proxy runs.
    var capture: CaptureApps {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(capture), forKey: SettingsKey.captureApps)
            Task { await applyCapture() }
        }
    }
    /// Flows a breakpoint holds, waiting on the user.
    private(set) var pausedCount = 0

    @ObservationIgnored private var version = -1

    init(helper: HelperClient, network: NetworkExtensionClient) {
        self.helper = helper
        self.network = network
        capture = UserDefaults.standard.data(forKey: SettingsKey.captureApps).flatMap { try? JSONDecoder().decode(CaptureApps.self, from: $0) } ?? CaptureApps()
        decryptHosts = UserDefaults.standard.stringArray(forKey: SettingsKey.decryptHosts) ?? []
        mapLocalRules = UserDefaults.standard.data(forKey: SettingsKey.mapLocal).flatMap { try? JSONDecoder().decode([MapLocalRule].self, from: $0) } ?? []
        mapRemoteRules = UserDefaults.standard.data(forKey: SettingsKey.mapRemote).flatMap { try? JSONDecoder().decode([MapRemoteRule].self, from: $0) } ?? []
        breakpointRules = UserDefaults.standard.data(forKey: SettingsKey.breakpoints).flatMap { try? JSONDecoder().decode([BreakpointRule].self, from: $0) } ?? []
        scriptRules = UserDefaults.standard.data(forKey: SettingsKey.scripts).flatMap { try? JSONDecoder().decode([ScriptRule].self, from: $0) } ?? []
        throttle = UserDefaults.standard.data(forKey: SettingsKey.throttle).flatMap { try? JSONDecoder().decode(ThrottleSettings.self, from: $0) } ?? ThrottleSettings()
        do {
            server = try ProxyServer()
        } catch {
            server = nil
            self.error = String(localized: "The proxy couldn't load the system's root certificates: \(error.localizedDescription)")
        }
        helper.onInterruption.append { [weak self] in
            guard let self, isRunning else { return }
            isRunning = false
            Task {
                await self.network.stopCapture()
                // The message itself starts the helper again (launchd launches a Mach
                // service on demand), so this doesn't wait on launchd noticing the backup.
                do {
                    try await self.helper.restoreSystemProxy()
                    self.error = String(localized: "The helper stopped unexpectedly, so the proxy is off. Start it again.")
                } catch {
                    self.error = String(localized: "The helper stopped unexpectedly and couldn't put the proxy settings back: \(error.localizedDescription) Check System Settings › Network › Proxies.")
                }
                // Only now: until the settings are back, apps still send their traffic here.
                await self.server?.stop()
            }
        }
        Task {
            await restoreLeftover()
            await loadAuthority()
        }
        // Lives as long as the app, like the store.
        Task {
            while true {
                self.snapshot()
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
    }

    var trustedAuthority: CertificateAuthority? {
        if case .trusted(let authority) = authority { authority } else { nil }
    }

    func start() async {
        guard let server, !isRunning else { return }
        isChanging = true
        defer { isChanging = false }
        let port = UserDefaults.standard.object(forKey: SettingsKey.proxyPort) as? Int ?? ProxyStore.defaultPort
        do {
            let bound = try await server.start(port: port)
            do {
                try await helper.enableSystemProxy(port: bound, bypass: HostPatterns.appleServices + HostPatterns.encryptedDNS)
            } catch {
                await server.stop()
                throw error
            }
            self.port = bound
            isRunning = true
            error = nil
            await applyCapture()
        } catch let error as IOError where error.errnoCode == EADDRINUSE {
            self.error = String(localized: "Port \(port) is taken by another app. Choose another in Settings › Proxy.")
        } catch {
            self.error = error.localizedDescription
        }
    }

    func stop() async {
        guard isRunning else { return }
        isChanging = true
        defer { isChanging = false }
        // First, so captured apps go direct before anything else stops answering.
        await network.stopCapture()
        do {
            try await helper.restoreSystemProxy()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        // Open connections finish on their own; new ones go direct again.
        await server?.stop()
        isRunning = false
    }

    func clear() {
        server?.log.clear()
    }

    func resume(_ flow: Int, _ decision: BreakpointDecision) {
        server?.resume(flow, decision)
    }

    /// Creates the CA if there's none yet, then asks macOS to trust it, which shows the
    /// system's password dialog.
    func trustAuthority() async {
        isChanging = true
        defer { isChanging = false }
        let result = await Task.detached {
            Result { () throws -> (CertificateAuthority, Bool) in
                let authority = try CertificateStore.load() ?? CertificateStore.create()
                try CertificateStore.trust(authority)
                return (authority, authority.isTrusted())
            }
        }.value
        switch result {
        case .success(let (authority, trusted)):
            self.authority = trusted ? .trusted(authority) : .untrusted(authority)
            error = trusted ? nil : String(localized: "macOS still doesn't trust the certificate. Check it in Keychain Access.")
        case .failure(let error):
            self.error = error.localizedDescription
            await loadAuthority()
        }
        applyPolicy()
    }

    func removeAuthority() async {
        isChanging = true
        defer { isChanging = false }
        let result = await Task.detached { Result { try CertificateStore.remove() } }.value
        if case .failure(let error) = result {
            self.error = error.localizedDescription
        }
        await loadAuthority()
    }

    func decrypt(host: String) {
        guard !HostPatterns(decryptHosts).matches(host) else { return }
        decryptHosts.append(host)
    }

    // MARK: Private

    static let defaultPort = 9090

    /// The third of the three restore guarantees (architecture §2): whatever a previous
    /// run left, starting the app puts it back. The helper itself covers the other two.
    private func restoreLeftover() async {
        helper.refreshStatus()
        guard helper.status == .enabled else { return }
        try? await helper.restoreSystemProxy()
    }

    /// Capture runs while the proxy does, with the switch on and an app to capture.
    private func applyCapture() async {
        if isRunning, capture.isEnabled, !capture.apps.isEmpty {
            await network.startCapture(port: port, apps: capture.apps)
        } else {
            await network.stopCapture()
        }
    }

    private func loadAuthority() async {
        let result = await Task.detached {
            Result { try CertificateStore.load().map { ($0, $0.isTrusted()) } }
        }.value
        switch result {
        case .success(.some(let (authority, trusted))):
            self.authority = trusted ? .trusted(authority) : .untrusted(authority)
        case .success(.none):
            authority = .none
        case .failure(let error):
            authority = .none
            self.error = error.localizedDescription
        }
        applyPolicy()
    }

    private func applyPolicy() {
        let patterns = HostPatterns(decryptHosts)
        let authority = trustedAuthority
        let rules = mapLocalRules
        let remotes = mapRemoteRules
        let breakpoints = breakpointRules
        let scripts = scriptRules
        server?.policy.withLock { policy in
            policy.decrypt = patterns
            policy.authority = authority
            policy.mapLocalRules = rules
            policy.mapRemoteRules = remotes
            policy.breakpointRules = breakpoints
            policy.scriptRules = scripts
        }
        server?.throttle.set(throttle)
    }

    private func snapshot() {
        guard let server else { return }
        let current = server.log.state.withLock { state in
            state.version == version ? nil : (state.flows, state.version)
        }
        guard let (copy, latest) = current else { return }
        version = latest
        flows = copy.values.sorted { $0.id < $1.id }
        // A held request keeps an app waiting, so it's worth a bounce of the Dock icon
        // while WiFiDetect is in the background.
        let paused = flows.count { $0.paused != nil }
        if paused > pausedCount {
            NSApp.requestUserAttention(.informationalRequest)
        }
        pausedCount = paused
        NSApp.dockTile.badgeLabel = paused > 0 ? String(paused) : nil
    }
}
