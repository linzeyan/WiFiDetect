import ServiceManagement
import SwiftUI
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "helper")

enum SettingsKey {
    static let sampleRate = "sampleRate"
    static let thresholds = "signalThresholds"
    static let autoScan = "autoScan"
    static let autoScanInterval = "autoScanInterval"
    static let page = "page"
    static let proxyPort = "proxyPort"
    static let decryptHosts = "decryptHosts"
    static let mapLocal = "mapLocalRules"
    static let mapRemote = "mapRemoteRules"
    static let breakpoints = "breakpointRules"
    static let scripts = "scriptRules"
    static let throttle = "throttle"
    static let settingsTab = "settingsTab"
    static let shareWithPhone = "shareWithPhone"
    static let showInMenuBar = "showInMenuBar"
    static let favorites = "favoriteHosts"
    static let blacklist = "blacklist"
    static let alerts = "trafficAlerts"
    static let routerFlows = "routerFlows"
    static let routerFlowsPort = "routerFlowsPort"
    static let captureApps = "captureApps"
}

enum SettingsTab: String {
    case wifi, traffic, proxy, rules, helper
}

struct SettingsView: View {
    @AppStorage(SettingsKey.settingsTab) private var tab = SettingsTab.wifi

    var body: some View {
        TabView(selection: $tab) {
            Tab("Wi-Fi", systemImage: "wifi", value: .wifi) { WiFiSettingsView() }
            Tab("Traffic", systemImage: "chart.xyaxis.line", value: .traffic) { TrafficSettingsView() }
            Tab("Proxy", systemImage: "arrow.left.arrow.right", value: .proxy) { ProxySettingsView() }
            Tab("Rules", systemImage: "list.bullet.rectangle", value: .rules) { RulesSettingsView() }
            Tab("Helper", systemImage: "lock.shield", value: .helper) { HelperSettingsView() }
        }
        .frame(width: 520)
    }
}

private struct WiFiSettingsView: View {
    @Environment(CompanionServer.self) private var companion
    @Environment(WiFiMonitor.self) private var monitor
    @AppStorage(SettingsKey.sampleRate) private var sampleRate = 2
    @AppStorage(SettingsKey.showInMenuBar) private var showInMenuBar = true
    @AppStorage(SettingsKey.thresholds) private var thresholds = SignalThresholds()
    @State private var confirmsClear = false

    var body: some View {
        @Bindable var companion = companion
        Form {
            Picker("Sampling rate", selection: $sampleRate) {
                ForEach(WiFiMonitor.rates, id: \.self) { Text("\($0) Hz").tag($0) }
            }
            Toggle("Show in menu bar", isOn: $showInMenuBar)
            // No off switch: the readings say nothing about which network or where, and
            // Clear History covers wanting them gone.
            Section {
                Button("Clear History…") { confirmsClear = true }
                    .confirmationDialog("Clear the Wi-Fi history?", isPresented: $confirmsClear) {
                        Button("Clear History", role: .destructive) { monitor.clearHistory() }
                    } message: {
                        Text("All stored readings are deleted and the signal charts start over. This can't be undone.")
                    }
            } header: {
                Text("History")
            } footer: {
                Text("Readings from the last 7 days are kept on this Mac, in ~/Library/Application Support/WiFiDetect/Wi-Fi Readings, so the signal charts pick up where they left off. They hold signal, noise and the time, never the network's name. Traffic and requests aren't kept.")
            }
            Section {
                Toggle("Share readings with iPhone and iPad", isOn: $companion.isEnabled)
                if companion.isEnabled {
                    LabeledContent("Connected devices", value: "\(companion.clients.count)")
                }
                if let error = companion.error {
                    Text(error).foregroundStyle(Color.statusCritical).textSelection(.enabled)
                }
            } footer: {
                Text("The WiFiDetect app on an iPhone or iPad on the same network can then show this Mac's signal chart. So can anyone else on the network: signal, noise, channel and tx rate, never the network's name.")
            }
            // Each range stops one short of its neighbors, so the grades stay in order.
            Section {
                threshold("Excellent from", $thresholds.excellent, thresholds.good + 1, -20)
                threshold("Good from", $thresholds.good, thresholds.fair + 1, thresholds.excellent - 1)
                threshold("Fair from", $thresholds.fair, thresholds.poor + 1, thresholds.good - 1)
                threshold("Poor from", $thresholds.poor, -100, thresholds.fair - 1)
            } header: {
                Text("Signal grades")
            } footer: {
                Text("Weaker than Poor is Very poor. The Good line is also drawn on the chart as the VoIP and streaming minimum. Chipsets scale RSSI differently, so treat these as guidance.")
            }
            Section {
                threshold("Roaming line", $thresholds.roam, -100, -20)
            } footer: {
                Text("Where a Mac starts looking for a stronger access point.")
            }
            Section("Signal-to-noise ratio") {
                threshold("Voice grade from", $thresholds.snrVoice, thresholds.snrPoor + 1, 60, unit: "dB")
                threshold("Poor below", $thresholds.snrPoor, 0, thresholds.snrVoice - 1, unit: "dB")
            }
            Section {
                Button("Restore Defaults") { thresholds = SignalThresholds() }
                    .disabled(thresholds == SignalThresholds())
            }
        }
        .formStyle(.grouped)
        // Sized to its content it ran past a 1080 pt screen once History joined it, so it
        // scrolls at a fixed height like Traffic and Rules.
        .frame(height: 560)
    }

    private func threshold(_ label: LocalizedStringKey, _ value: Binding<Int>, _ low: Int, _ high: Int, unit: String = "dBm") -> some View {
        // max(): a hand-edited defaults value could invert the bounds, and an inverted
        // ClosedRange traps.
        Stepper(value: value, in: low ... max(low, high)) {
            LabeledContent(label) {
                Text(verbatim: "\(signed(value.wrappedValue)) \(unit)").monospacedDigit()
            }
        }
    }
}

/// The router flow collector, notifications, the blacklist and favorites. The two lists
/// grow, so this tab scrolls at a fixed height, like Rules, and the collector, which the
/// Router Flows page sends people here to turn on, comes first rather than below them.
private struct TrafficSettingsView: View {
    var body: some View {
        Form {
            AttributionSettings()
            RouterFlowSettings()
            NotificationSettings()
            BlacklistSettings()
            FavoriteSettings()
        }
        .formStyle(.grouped)
        .frame(height: 560)
    }
}

/// The network extension's content filter, which names each new connection's app
/// (architecture §3, Network extension).
private struct AttributionSettings: View {
    @Environment(NetworkExtensionClient.self) private var network
    @State private var isConfirmingRemoval = false

    var body: some View {
        let included = network.status != .notIncluded
        Section {
            Toggle("Name apps with a content filter", isOn: Binding { network.isFilterOn } set: { on in
                Task { await network.setFilter(on) }
            })
            .disabled(!included || network.status == .removing)
            if included {
                LabeledContent("Network extension", value: network.status.label)
                if network.status == .needsApproval {
                    Button("Open System Settings") { SMAppService.openSystemSettingsLoginItems() }
                }
                if network.status == .installed {
                    Button("Remove Network Extension…", role: .destructive) { isConfirmingRemoval = true }
                        .confirmationDialog("Remove WiFiDetect's network extension?", isPresented: $isConfirmingRemoval) {
                            Button("Remove", role: .destructive) { Task { await network.uninstall() } }
                        } message: {
                            Text("Connections are named from the socket table alone, apps that ignore the system proxy are no longer captured, and macOS uninstalls the extension. Do this before you move WiFiDetect to the Trash: the Trash alone leaves the extension installed. Turning either on again installs it again.")
                        }
                }
            }
            if let error = network.error {
                Text(error).foregroundStyle(Color.statusCritical).textSelection(.enabled)
            }
        } header: {
            Text("App attribution")
        } footer: {
            Text(included
                ? "Names the app behind each new connection, including those URLSession and other Network.framework code open, which the socket table can't see, and the app a system daemon such as nsurlsessiond works for. It never blocks anything: every connection is let through. If the extension stops, the connections it was watching are cut off; new ones go through without it. Connections that started before it was on keep the names they had."
                : "This build of WiFiDetect doesn't include its network extension, which comes with the Developer ID build; connections are named from the socket table alone.")
        }
    }
}

/// The port, the certificate that lets the proxy read HTTPS, and which hosts it reads.
private struct ProxySettingsView: View {
    @Environment(ProxyStore.self) private var proxy
    @AppStorage(SettingsKey.proxyPort) private var port = ProxyStore.defaultPort
    @State private var hosts = ""

    var body: some View {
        @Bindable var proxy = proxy
        Form {
            Section {
                TextField("Port", value: $port, format: .number.grouping(.never))
                    .onChange(of: port) { port = min(max(port, 1024), 65535) }
            } header: {
                Text("Proxy")
            } footer: {
                Text("Listens on 127.0.0.1 only. A new port takes effect the next time the proxy starts.")
            }
            CaptureAppsSettings()
            // Here rather than under Rules: it slows the proxy's whole link, not the
            // requests a pattern picks.
            Section {
                Toggle("Throttle", isOn: $proxy.throttle.isEnabled)
                Group {
                    Picker("Preset", selection: preset) {
                        ForEach(ThrottleSettings.presets, id: \.name) { Text($0.name).tag(Optional($0.name)) }
                        Text("Custom").tag(String?.none)
                    }
                    TextField("Download (kbit/s)", value: $proxy.throttle.downloadKbps, format: .number.grouping(.never))
                    TextField("Upload (kbit/s)", value: $proxy.throttle.uploadKbps, format: .number.grouping(.never))
                    TextField("Added latency (ms)", value: $proxy.throttle.latencyMs, format: .number.grouping(.never))
                }
                .disabled(!proxy.throttle.isEnabled)
            } header: {
                Text("Throttle")
            } footer: {
                Text("Slows everything through the proxy as a poor network would: downloads and uploads to these rates, shared by all connections, 0 for no limit; and every round trip by the latency, half each way. The presets are Chrome DevTools'. Packets aren't dropped, and Map Local answers come back at full speed.")
            }
            Section {
                LabeledContent("Status", value: certificateStatus)
                HStack {
                    switch proxy.authority {
                    case .loading:
                        EmptyView()
                    case .none:
                        Button("Create and Trust…") { Task { await proxy.trustAuthority() } }
                    case .untrusted:
                        Button("Trust…") { Task { await proxy.trustAuthority() } }
                        Button("Remove", role: .destructive) { Task { await proxy.removeAuthority() } }
                    case .trusted:
                        Button("Remove…", role: .destructive) { Task { await proxy.removeAuthority() } }
                    }
                }
                .disabled(proxy.isChanging)
            } header: {
                Text("Certificate")
            } footer: {
                Text("To read HTTPS, WiFiDetect makes a certificate authority of its own on this Mac and asks macOS to trust it. Its private key stays in your keychain and never leaves it. Remove it when you're done debugging.")
            }
            Section {
                // A fixed height, like the blacklist's: with only a minimum the window sized
                // itself to the whole form and ran past the screen, despite the frame below.
                TextEditor(text: $hosts)
                    .font(.body.monospaced())
                    .frame(height: 120)
                    .onChange(of: hosts) {
                        proxy.decryptHosts = hosts.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                    }
            } header: {
                Text("Decrypt HTTPS for")
            } footer: {
                Text("One host per line; *.example.com covers every subdomain. Other HTTPS passes through unread, and so does Apple's own traffic, which refuses to be decrypted.")
            }
        }
        .formStyle(.grouped)
        // Sized to its content it ran past a 1080 pt screen, cutting off the decrypt list,
        // and the app list above grows with every app added, so it scrolls at a fixed
        // height like Wi-Fi, Traffic and Rules.
        .frame(height: 560)
        .onAppear { hosts = proxy.decryptHosts.joined(separator: "\n") }
    }

    /// The preset the numbers match, if any; editing one turns the picker to Custom.
    private var preset: Binding<String?> {
        Binding {
            ThrottleSettings.presets.first { ($0.downloadKbps, $0.uploadKbps, $0.latencyMs) == (proxy.throttle.downloadKbps, proxy.throttle.uploadKbps, proxy.throttle.latencyMs) }?.name
        } set: { name in
            guard let preset = ThrottleSettings.presets.first(where: { $0.name == name }) else { return }
            var throttle = proxy.throttle
            (throttle.downloadKbps, throttle.uploadKbps, throttle.latencyMs) = (preset.downloadKbps, preset.uploadKbps, preset.latencyMs)
            proxy.throttle = throttle
        }
    }

    private var certificateStatus: String {
        switch proxy.authority {
        case .loading: String(localized: "Checking…")
        case .none: String(localized: "Not created")
        case .untrusted: String(localized: "Created, not trusted")
        case .trusted: String(localized: "Trusted")
        }
    }
}

/// Map Local, Map Remote, Breakpoints and Scripts. Their lists grow with every rule, so this
/// tab scrolls at a fixed height rather than sizing to its content and running off the screen.
private struct RulesSettingsView: View {
    var body: some View {
        Form {
            MapLocalSettings()
            MapRemoteSettings()
            BreakpointSettings()
            ScriptSettings()
        }
        .formStyle(.grouped)
        .frame(height: 480)
    }
}

/// Install state of the root helper. Results are also logged at notice level (info
/// isn't persisted), so `make logs` can check a run.
private struct HelperSettingsView: View {
    @Environment(HelperClient.self) private var helper
    @Environment(ProxyStore.self) private var proxy
    @State private var version: String?
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Status", value: statusText)
                LabeledContent("Version", value: version ?? "—")
                if let error {
                    Text(error).foregroundStyle(Color.statusCritical).textSelection(.enabled)
                }
                HStack {
                    if helper.status == .enabled {
                        Button("Uninstall") { Task { await unregister() } }
                    } else {
                        Button("Install") { register() }
                    }
                    Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                }
            } header: {
                Text("Capture helper")
            } footer: {
                Text("Runs as root, only to read packets for traffic monitoring and to point the system proxy at WiFiDetect. It starts when WiFiDetect connects to it and quits when WiFiDetect does, putting the proxy settings back.")
            }
        }
        .formStyle(.grouped)
        // A grouped form scrolls rather than asking for its height. This tab is short and
        // stays short, so it takes just the height it needs instead of the others' 560.
        .fixedSize(horizontal: false, vertical: true)
        .task(id: helper.status) {
            helper.refreshStatus()
            version = helper.status == .enabled ? try? await helper.version() : nil
        }
    }

    private var statusText: String {
        switch helper.status {
        case .notRegistered: String(localized: "Not installed")
        case .enabled: String(localized: "Installed")
        case .requiresApproval: String(localized: "Waiting for approval in Login Items")
        // Also what an installed-but-never-registered daemon reports, not only a
        // missing plist — `make build` already checks the plist is in the bundle.
        case .notFound: String(localized: "Not installed")
        @unknown default: String(localized: "Unknown (\(helper.status.rawValue))")
        }
    }

    private func register() {
        do {
            try helper.register()
            error = nil
        } catch {
            // Throws while approval is pending too; the status already says so.
            self.error = helper.status == .requiresApproval ? nil : error.localizedDescription
        }
        log.notice("helper register: \(statusText, privacy: .public)")
    }

    private func unregister() async {
        // Uninstalling stops the helper; after that nothing could put the proxy settings back.
        await proxy.stop()
        do {
            try await helper.unregister()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        log.notice("helper unregister: \(statusText, privacy: .public)")
    }
}
