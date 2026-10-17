import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

/// One row of the requests table, with the sortable values worked out once.
struct RequestRow: Identifiable {
    let flow: ProxyFlow
    var id: Int { flow.id }
    /// Path and query; empty for a tunnel, which has none to show.
    let path: String
    /// The app the network extension captured it from; empty for the rest.
    let app: String
    let status: String
    let statusOrder: Int
    let size: Int
    let duration: Double

    init(_ flow: ProxyFlow) {
        self.flow = flow
        let origin = flow.url.firstRange(of: "://").flatMap { flow.url[$0.upperBound...].firstIndex(of: "/") }
        path = flow.kind == .tunnel ? "" : origin.map { String(flow.url[$0...]) } ?? flow.url
        app = flow.app.map { URL(filePath: $0).deletingPathExtension().lastPathComponent } ?? ""
        if flow.paused != nil {
            status = String(localized: "Paused")
            statusOrder = -1
        } else if flow.error != nil {
            status = String(localized: "Failed")
            statusOrder = 1000
        } else if flow.kind == .tunnel {
            status = String(localized: "Tunnel")
            statusOrder = 999
        } else if let code = flow.status {
            status = String(code)
            statusOrder = code
        } else {
            status = "…"
            statusOrder = 0
        }
        size = flow.kind == .tunnel || flow.isWebSocket ? flow.bytesDown : flow.response.size
        duration = flow.finished.map { $0.timeIntervalSince(flow.started) } ?? -1
    }
}

struct RequestsView: View {
    @Environment(ProxyStore.self) private var proxy
    @State private var search = ""
    @State private var selection: ProxyFlow.ID?
    @State private var sortOrder = [KeyPathComparator(\RequestRow.flow.id)]
    @State private var showsInspector = true

    var body: some View {
        Group {
            if proxy.helper.status == .enabled {
                content
            } else {
                HelperSetupView(
                    title: "Install the Helper",
                    purpose: "Sending this Mac's web traffic through the proxy means changing its network settings, which macOS allows only as root. WiFiDetect installs a small helper that does that, and puts them back when WiFiDetect quits."
                )
            }
        }
        .task { proxy.helper.refreshStatus() }
        .navigationTitle("Requests")
    }

    private var content: some View {
        let all = proxy.flows.map(RequestRow.init)
        let rows = all.filter(matches).sorted(using: sortOrder)
        return VStack(spacing: 0) {
            ProxyBar().padding(12)
            Divider()
            Table(rows, selection: $selection, sortOrder: $sortOrder) {
                TableColumn("Time", value: \.flow.started) { (row: RequestRow) in Text(row.flow.started, format: .dateTime.hour().minute().second()) }
                    .width(min: 85, ideal: 95)
                TableColumn("Method", value: \.flow.method).width(min: 55, ideal: 70)
                TableColumn("App", value: \.app).width(min: 50, ideal: 90)
                TableColumn("Host", value: \.flow.host).width(min: 120, ideal: 200)
                TableColumn("Path", value: \.path) { (row: RequestRow) in Text(row.path).truncationMode(.middle) }
                    .width(min: 120, ideal: 320)
                TableColumn("Status", value: \.statusOrder) { (row: RequestRow) in StatusText(row: row) }
                    // Wide enough for an icon and "Paused" or "Failed": with the inspector
                    // open the table squeezes every column toward its minimum.
                    .width(min: 80, ideal: 85)
                TableColumn("Size", value: \.size) { (row: RequestRow) in Text(bytes(row.size)).monospacedDigit() }
                    .width(min: 60, ideal: 75)
                TableColumn("Duration", value: \.duration) { (row: RequestRow) in
                    Text(row.duration < 0 ? "" : Duration.seconds(row.duration).formatted(.units(allowed: [.seconds, .milliseconds], width: .narrow, maximumUnitCount: 1)))
                        .monospacedDigit()
                }
                .width(min: 60, ideal: 75)
            }
            .overlay {
                if all.isEmpty {
                    ContentUnavailableView {
                        Label(proxy.isRunning ? "Waiting for Requests" : "Proxy Off", systemImage: "arrow.left.arrow.right")
                    } description: {
                        Text(proxy.isRunning ? "Apps that use the system proxy show up here as they make requests." : "Start the proxy to send this Mac's web traffic through WiFiDetect.")
                    }
                } else if rows.isEmpty {
                    ContentUnavailableView.search(text: search)
                }
            }
        }
        .inspector(isPresented: $showsInspector) {
            FlowInspector(flow: proxy.flows.first { $0.id == selection })
                .inspectorColumnWidth(min: 320, ideal: 420, max: 800)
        }
        .onChange(of: proxy.flows.first { $0.paused != nil }?.id) { _, paused in
            // A held request keeps an app waiting, so it comes up by itself, unless the
            // one on show is held too and may be half edited.
            guard let paused, proxy.flows.first(where: { $0.id == selection })?.paused == nil else { return }
            selection = paused
            showsInspector = true
        }
        .searchable(text: $search, prompt: "URL, method or status")
        .toolbar { ProxyToolbar(showsInspector: $showsInspector) }
        .navigationSubtitle(rows.count == all.count ? "\(rows.count) requests" : "\(rows.count) of \(all.count) requests")
    }

    private func matches(_ row: RequestRow) -> Bool {
        search.isEmpty || [row.flow.url, row.flow.method, row.status].contains { $0.localizedStandardContains(search) }
    }
}

/// Failures carry an icon as well as the word, so the state never rests on color.
private struct StatusText: View {
    let row: RequestRow

    var body: some View {
        if row.flow.paused != nil {
            Label {
                Text(row.status)
            } icon: {
                Image(systemName: "pause.circle.fill").foregroundStyle(Color.statusWarning)
            }
            .help("Held at a breakpoint: send it on or abort it in the inspector.")
        } else if row.flow.error != nil {
            Label {
                Text(row.status)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
            }
            .help(row.flow.error ?? "")
        } else if row.flow.scriptFailed {
            // Ahead of the maps: the flow went through, but not as the script meant it to.
            Label {
                Text(row.status).monospacedDigit()
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusWarning)
            }
            .help(row.flow.scriptNotes.joined(separator: "\n"))
        } else if let file = row.flow.mapLocal {
            Label {
                Text(row.status).monospacedDigit()
            } icon: {
                Image(systemName: "doc")
            }
            .help("Map Local: \(URL(filePath: file).lastPathComponent)")
        } else if let url = row.flow.mapRemote {
            Label {
                Text(row.status).monospacedDigit()
            } icon: {
                Image(systemName: "arrow.turn.up.right")
            }
            .help("Map Remote: \(url)")
        } else if !row.flow.scriptNotes.isEmpty {
            Label {
                Text(row.status).monospacedDigit()
            } icon: {
                Image(systemName: "curlybraces")
            }
            .help(row.flow.scriptNotes.joined(separator: "\n"))
        } else {
            Text(row.status).monospacedDigit().foregroundStyle(row.flow.kind == .tunnel ? .secondary : .primary)
        }
    }
}

/// What the proxy is doing and what it can read.
struct ProxyBar: View {
    @Environment(ProxyStore.self) private var proxy
    @Environment(\.openSettings) private var openSettings
    @AppStorage(SettingsKey.settingsTab) private var settingsTab = SettingsTab.wifi

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if proxy.isRunning {
                Label("Listening on 127.0.0.1:\(String(proxy.port)); this Mac's apps send their web traffic here.", systemImage: "point.3.filled.connected.trianglepath.dotted")
            }
            if let error = proxy.error {
                Label {
                    Text(error).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            }
            if proxy.pausedCount > 0 {
                Label {
                    Text("^[\(proxy.pausedCount) request](inflect: true) waiting at a breakpoint for you to send on or abort in the inspector.")
                } icon: {
                    Image(systemName: "pause.circle.fill").foregroundStyle(Color.statusWarning)
                }
            }
            if proxy.isRunning, proxy.capture.isEnabled, !proxy.capture.apps.isEmpty {
                Label(captureSummary, systemImage: "app.connected.to.app.below.fill")
            }
            // Left on, a throttle passes for a slow server; this keeps it from being forgotten.
            if proxy.throttle.isEnabled {
                HStack(spacing: 8) {
                    Label {
                        Text("Throttled: \(Self.rate(proxy.throttle.downloadKbps)) down, \(Self.rate(proxy.throttle.uploadKbps)) up, \(proxy.throttle.latencyMs) ms added to each round trip.")
                    } icon: {
                        Image(systemName: "tortoise.fill").foregroundStyle(Color.statusWarning)
                    }
                    Button("Turn Off") { proxy.throttle.isEnabled = false }
                        .buttonStyle(.link)
                }
            }
            HStack(spacing: 8) {
                switch proxy.authority {
                case .loading:
                    EmptyView()
                case .trusted:
                    Label(decryptSummary, systemImage: "lock.open")
                case .none, .untrusted:
                    Label("HTTPS passes through unread until you trust WiFiDetect's certificate.", systemImage: "lock")
                }
                Button("Proxy Settings…") {
                    settingsTab = .proxy
                    openSettings()
                }
                .buttonStyle(.link)
            }
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var decryptSummary: String {
        let hosts = proxy.decryptHosts.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        return hosts.isEmpty ? String(localized: "Decrypting no HTTPS hosts yet.") : String(localized: "Decrypting HTTPS for \(hosts.formatted(.list(type: .and))).")
    }

    private static func rate(_ kbps: Int) -> String {
        kbps <= 0 ? String(localized: "no limit") : kbps < 1000 ? "\(kbps) kbit/s" : "\((Double(kbps) / 1000).formatted()) Mbit/s"
    }

    private var captureSummary: String {
        let names = proxy.capture.apps.map { URL(filePath: $0).deletingPathExtension().lastPathComponent }.formatted(.list(type: .and))
        let network = proxy.network
        guard network.capture.port != 0 else {
            return String(localized: "Not capturing \(names): \(network.error ?? network.status.label)")
        }
        return switch network.captureStatus {
        case .connected: proxy.capture.apps.count == 1
            ? String(localized: "Also capturing the HTTPS of \(names), which ignores the system proxy.")
            : String(localized: "Also capturing the HTTPS of \(names), which ignore the system proxy.")
        case .connecting, .reasserting: String(localized: "Starting to capture \(names)…")
        default: String(localized: "Capture of \(names) stopped. Turn it off and on again in Proxy Settings.")
        }
    }
}

extension NetworkExtensionClient.Status {
    var label: String {
        switch self {
        case .notIncluded: String(localized: "Not in this build")
        case .checking: String(localized: "Checking…")
        case .notInstalled: String(localized: "Not installed")
        case .installing: String(localized: "Installing…")
        case .updating: String(localized: "Updating to this version…")
        case .needsApproval: String(localized: "Waiting for you to allow it in System Settings › General › Login Items & Extensions › Network Extensions")
        case .needsRestart: String(localized: "Restart the Mac to finish installing it")
        case .installed: String(localized: "Installed")
        case .failed(let message): message
        }
    }
}

/// Settings › Proxy: apps whose HTTPS the network extension sends to the proxy though
/// they ignore the system proxy.
struct CaptureAppsSettings: View {
    @Environment(ProxyStore.self) private var proxy

    var body: some View {
        @Bindable var proxy = proxy
        let included = proxy.network.status != .notIncluded
        Section {
            Toggle("Capture apps that ignore the system proxy", isOn: $proxy.capture.isEnabled)
                .disabled(!included)
            ForEach(proxy.capture.apps, id: \.self) { path in
                HStack {
                    Label {
                        Text(FileManager.default.displayName(atPath: path))
                        Text((path as NSString).abbreviatingWithTildeInPath).truncationMode(.middle)
                    } icon: {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                    }
                    Spacer()
                    Button("Remove", systemImage: "minus.circle") {
                        proxy.capture.apps.removeAll { $0 == path }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
            HStack {
                Button("Add App…", action: chooseApp)
                if proxy.network.status == .needsApproval {
                    Button("Open System Settings") { SMAppService.openSystemSettingsLoginItems() }
                }
            }
            .disabled(!included)
            if included {
                LabeledContent("Network extension", value: proxy.network.status.label)
            }
            if let error = proxy.network.error {
                Text(error).foregroundStyle(Color.statusCritical).textSelection(.enabled)
            }
        } header: {
            Text("Apps that ignore the system proxy")
        } footer: {
            Text(included
                ? "While the proxy runs, these apps' HTTPS goes to it even if they don't use the system proxy, as curl --noproxy and many Go, Python and Java programs don't. Helpers inside an app come with it. Their QUIC is refused so they fall back to TCP; plain HTTP on port 80 isn't captured. If WiFiDetect quits or its proxy stops answering, they connect directly again. WiFiDetect itself is never captured."
                : "This build of WiFiDetect doesn't include its network extension, which comes with the Developer ID build; only apps that use the system proxy reach WiFiDetect.")
        }
    }

    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.prompt = String(localized: "Capture")
        panel.directoryURL = URL(filePath: "/Applications")
        // App bundles, and programs such as /usr/bin/curl or a Go binary.
        panel.allowedContentTypes = [.application, .unixExecutable]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // What the extension sees is the real path, not a symlink such as Homebrew's.
        let path = url.resolvingSymlinksInPath().path
        if !proxy.capture.apps.contains(path) {
            proxy.capture.apps.append(path)
        }
    }
}

struct ProxyToolbar: ToolbarContent {
    @Environment(ProxyStore.self) private var proxy
    @Binding var showsInspector: Bool

    var body: some ToolbarContent {
        ToolbarItemGroup {
            Button { exportHAR() } label: {
                Label("Export HAR…", systemImage: "square.and.arrow.up")
            }
            .disabled(!proxy.flows.contains { $0.kind != .tunnel })
            Button { proxy.clear() } label: {
                Label("Clear", systemImage: "trash")
            }
            .disabled(proxy.flows.isEmpty)
            if proxy.isRunning {
                Button { Task { await proxy.stop() } } label: {
                    Label("Stop Proxy", systemImage: "stop.fill")
                }
                .disabled(proxy.isChanging)
            } else {
                Button { Task { await proxy.start() } } label: {
                    Label("Start Proxy", systemImage: "play.fill")
                }
                .disabled(proxy.isChanging || proxy.server == nil)
            }
            Button { showsInspector.toggle() } label: {
                Label("Inspector", systemImage: "sidebar.right")
            }
        }
    }

    private func exportHAR() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "har", conformingTo: .json) ?? .json]
        let stamp = Date.ISO8601FormatStyle(timeSeparator: .omitted, timeZone: .current).year().month().day().time(includingFractionalSeconds: false)
        panel.nameFieldStringValue = "WiFiDetect \(Date.now.formatted(stamp)).har"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try HAR(proxy.flows).encoded().write(to: url, options: .atomic)
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

/// Settings › Rules: which requests are answered from a file on this Mac.
struct MapLocalSettings: View {
    @Environment(ProxyStore.self) private var proxy
    @State private var pattern = ""

    var body: some View {
        @Bindable var proxy = proxy
        Section {
            ForEach($proxy.mapLocalRules) { $rule in
                HStack {
                    Toggle(isOn: $rule.isEnabled) {
                        Text(rule.pattern).font(.body.monospaced())
                        Text((rule.path as NSString).abbreviatingWithTildeInPath).truncationMode(.middle)
                    }
                    Button("Remove", systemImage: "minus.circle") {
                        proxy.mapLocalRules.removeAll { $0.id == rule.id }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
            HStack {
                TextField("URL pattern", text: $pattern, prompt: Text("https://api.example.com/v1/users*"))
                Button("Map to File…", action: chooseFile)
                    .disabled(pattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        } header: {
            Text("Map Local")
        } footer: {
            Text("A request whose URL matches gets the file as its response, read fresh each time; the server never sees it. * matches anything, a pattern without http:// or https:// covers both, and the first match wins. Only requests WiFiDetect can read are mapped: plain HTTP, and HTTPS for the hosts listed in the Proxy tab. Other HTTPS passes through unread and is never mapped.")
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.prompt = String(localized: "Map")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        proxy.mapLocalRules.append(MapLocalRule(pattern: pattern.trimmingCharacters(in: .whitespaces), path: url.path))
        pattern = ""
    }
}

/// Settings › Rules: which requests go to another server than the one they asked for.
struct MapRemoteSettings: View {
    @Environment(ProxyStore.self) private var proxy
    @State private var pattern = ""
    @State private var destination = ""

    var body: some View {
        @Bindable var proxy = proxy
        let origin = RemoteOrigin(destination)
        Section {
            ForEach($proxy.mapRemoteRules) { $rule in
                HStack {
                    Toggle(isOn: $rule.isEnabled) {
                        Text(rule.pattern).font(.body.monospaced())
                        Text(rule.destination).font(.body.monospaced())
                    }
                    Button("Remove", systemImage: "minus.circle") {
                        proxy.mapRemoteRules.removeAll { $0.id == rule.id }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
            TextField("URL pattern", text: $pattern, prompt: Text("https://api.example.com/*"))
            HStack {
                TextField("Send to", text: $destination, prompt: Text("http://localhost:3000"))
                Button("Add Map Remote") {
                    guard let origin else { return }
                    proxy.mapRemoteRules.append(MapRemoteRule(pattern: pattern.trimmingCharacters(in: .whitespaces), destination: origin.url))
                    pattern = ""
                    destination = ""
                }
                .disabled(pattern.trimmingCharacters(in: .whitespaces).isEmpty || origin == nil)
            }
        } header: {
            Text("Map Remote")
        } footer: {
            Text("A request whose URL matches goes to this server instead, with the same path, query and body; its Host header names the new server. Give http:// or https://, a host and, if it isn't the usual one, a port. Patterns work as in Map Local, only for requests WiFiDetect can read, and the first match wins. A request Map Local answers isn't sent anywhere.")
        }
    }
}

/// Settings › Rules: which requests and responses wait for the user on their way.
struct BreakpointSettings: View {
    @Environment(ProxyStore.self) private var proxy
    @State private var pattern = ""

    var body: some View {
        @Bindable var proxy = proxy
        Section {
            ForEach($proxy.breakpointRules) { $rule in
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(rule.pattern).font(.body.monospaced())
                        HStack {
                            Toggle("Request", isOn: $rule.request)
                            Toggle("Response", isOn: $rule.response)
                        }
                        .toggleStyle(.checkbox)
                        .disabled(!rule.isEnabled)
                    }
                    Spacer()
                    Toggle("On", isOn: $rule.isEnabled).labelsHidden()
                    Button("Remove", systemImage: "minus.circle") {
                        proxy.breakpointRules.removeAll { $0.id == rule.id }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
            HStack {
                TextField("URL pattern", text: $pattern, prompt: Text("https://api.example.com/v1/*"))
                Button("Add Breakpoint") {
                    proxy.breakpointRules.append(BreakpointRule(pattern: pattern.trimmingCharacters(in: .whitespaces)))
                    pattern = ""
                }
                .disabled(pattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        } header: {
            Text("Breakpoints")
        } footer: {
            Text("A matching request waits before it goes to the server, and a matching response before it goes back to the app, for you to edit or abort in the Requests inspector. Patterns work as in Map Local, but every matching rule applies. The app waits too, and most give up after a minute.")
        }
    }
}

/// Settings › Rules: JavaScript that edits matching requests and responses on their way.
struct ScriptSettings: View {
    @Environment(ProxyStore.self) private var proxy
    @State private var pattern = ""
    /// The rule in the editor sheet; a new one joins the list only once it's saved.
    @State private var editing: ScriptRule?

    var body: some View {
        @Bindable var proxy = proxy
        Section {
            ForEach($proxy.scriptRules) { $rule in
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(rule.pattern).font(.body.monospaced())
                        HStack {
                            Toggle("Request", isOn: $rule.request)
                            Toggle("Response", isOn: $rule.response)
                        }
                        .toggleStyle(.checkbox)
                        .disabled(!rule.isEnabled)
                    }
                    Spacer()
                    Button("Edit…") { editing = rule }
                    Toggle("On", isOn: $rule.isEnabled).labelsHidden()
                    Button("Remove", systemImage: "minus.circle") {
                        proxy.scriptRules.removeAll { $0.id == rule.id }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
            HStack {
                TextField("URL pattern", text: $pattern, prompt: Text("https://api.example.com/v1/*"))
                Button("Add Script…") { editing = ScriptRule(pattern: pattern.trimmingCharacters(in: .whitespaces)) }
                    .disabled(pattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        } header: {
            Text("Scripts")
        } footer: {
            Text("A matching request or response is collected whole and handed to the script's onRequest(request) or onResponse(request, response). A request has method, path, headers and body; a response has status, headers and body. Headers are a list of [name, value] pairs, so repeated ones like Set-Cookie stay apart. The body is the text, decoded, or null when it isn't text; null sends it on as it came. Edit the object or return a new one; returning nothing sends on the one given, edits included. A script that throws or runs past 5 seconds leaves the message as it came, and the inspector says why. Scripts run before breakpoints, which then show the script's edit. Patterns work as in Map Local, and the first match runs. Scripts can't reach the network or files, and keep nothing between runs.")
        }
        .sheet(item: $editing) { rule in
            ScriptEditor(rule: rule) { source in
                if let index = proxy.scriptRules.firstIndex(where: { $0.id == rule.id }) {
                    proxy.scriptRules[index].source = source
                } else {
                    var rule = rule
                    rule.source = source
                    proxy.scriptRules.append(rule)
                    pattern = ""
                }
            }
        }
    }
}

/// A script's source, edited apart from its rule so a half-typed script never runs.
private struct ScriptEditor: View {
    let rule: ScriptRule
    let save: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var source: String

    init(rule: ScriptRule, save: @escaping (String) -> Void) {
        self.rule = rule
        self.save = save
        _source = State(initialValue: rule.source)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(rule.pattern).font(.headline.monospaced())
            CodeEditor(text: $source)
                .border(.separator)
            // Checked without running it: saved with an error, every match would fail.
            if let problem = ScriptRunner.syntaxError(in: source) {
                Label {
                    Text(problem)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                // ⌘S, not Return: Return is a new line in the editor.
                Button("Save") {
                    save(source)
                    dismiss()
                }
                .keyboardShortcut("s")
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .frame(width: 520, height: 440)
    }
}

// MARK: Inspector

struct FlowInspector: View {
    private enum Part: CaseIterable, Identifiable {
        case request, response, messages
        var id: Self { self }

        var label: String {
            switch self {
            case .request: String(localized: "Request")
            case .response: String(localized: "Response")
            case .messages: String(localized: "Messages")
            }
        }
    }

    let flow: ProxyFlow?
    @Environment(ProxyStore.self) private var proxy
    @State private var part = Part.response

    var body: some View {
        if let flow {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    summary(flow)
                    if let phase = flow.paused {
                        BreakpointEditor(flow: flow, phase: phase)
                            // Starts over from what's held, for each flow and each phase.
                            .id("\(flow.id)-\(phase)")
                    } else if flow.kind == .tunnel {
                        tunnelNote(flow)
                    } else {
                        // The choice carries over between flows; Messages falls back to
                        // the response on one that isn't a WebSocket.
                        let parts = flow.isWebSocket ? Part.allCases : [.request, .response]
                        let shown = parts.contains(part) ? part : .response
                        Picker("Message", selection: Binding { shown } set: { part = $0 }) {
                            ForEach(parts) { Text($0.label).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        if shown == .messages {
                            WebSocketMessagesView(flow: flow)
                                .id(flow.id)
                        } else {
                            MessageView(message: shown == .request ? flow.request : flow.response)
                                // A new flow starts on its own format choice.
                                .id("\(flow.id)-\(shown)")
                        }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("No Request Selected", systemImage: "arrow.left.arrow.right")
        }
    }

    private func summary(_ flow: ProxyFlow) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(flow.url).font(.body.monospaced()).textSelection(.enabled)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                if let status = flow.status {
                    row("Status", "\(status) \(flow.reason)")
                }
                if let app = flow.app {
                    row("App", (app as NSString).abbreviatingWithTildeInPath)
                }
                if flow.kind != .tunnel {
                    // A server that answers in another version than the app spoke is why
                    // gRPC fails through the proxy, so it's spelled out.
                    let server = flow.serverVersion.flatMap { $0 == flow.version ? nil : $0 }
                    row("Protocol", server.map { String(localized: "\(flow.version) from the app, \($0) to the server") } ?? flow.version)
                }
                if let file = flow.mapLocal {
                    row("Map Local", (file as NSString).abbreviatingWithTildeInPath)
                }
                if let url = flow.mapRemote {
                    row("Map Remote", url)
                }
                if !flow.scriptNotes.isEmpty {
                    row("Script", flow.scriptNotes.joined(separator: "\n"))
                }
                if !flow.breakpointNotes.isEmpty {
                    row("Breakpoint", flow.breakpointNotes.joined(separator: "\n"))
                }
                row("Started", flow.started.formatted(.dateTime.hour().minute().second().secondFraction(.fractional(3))))
                if let finished = flow.finished {
                    row("Duration", Duration.seconds(finished.timeIntervalSince(flow.started)).formatted(.units(allowed: [.seconds, .milliseconds], width: .abbreviated, maximumUnitCount: 2)))
                }
                if flow.isWebSocket {
                    row("Messages", (flow.messages.count + flow.droppedMessages).formatted())
                }
                if flow.kind == .tunnel || flow.isWebSocket {
                    row("Sent", bytes(flow.bytesUp))
                    row("Received", bytes(flow.bytesDown))
                } else {
                    row("Request body", bytes(flow.request.size))
                    row("Response body", bytes(flow.response.size))
                }
            }
            if let error = flow.error {
                Label {
                    Text(error).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            }
        }
    }

    private func row(_ label: LocalizedStringKey, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).monospacedDigit().textSelection(.enabled)
        }
    }

    @ViewBuilder
    private func tunnelNote(_ flow: ProxyFlow) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Passed through encrypted: only the host and the byte counts are known.")
                .foregroundStyle(.secondary)
            if HostPatterns(HostPatterns.appleServices).matches(flow.host) {
                Text("Apple's services refuse to be decrypted, so WiFiDetect never tries.")
                    .foregroundStyle(.secondary)
            } else if !HostPatterns(proxy.decryptHosts).matches(flow.host) {
                Button("Decrypt \(flow.host)") { proxy.decrypt(host: flow.host) }
                if proxy.trustedAuthority == nil {
                    Text("Decrypting also needs WiFiDetect's certificate trusted, in Proxy Settings.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// What a breakpoint holds, to edit, with the buttons that send it on or abort it.
private struct BreakpointEditor: View {
    let flow: ProxyFlow
    let phase: BreakpointPhase
    @Environment(ProxyStore.self) private var proxy
    @State private var method: String
    @State private var path: String
    @State private var status: String
    @State private var headers: String
    @State private var text: String
    /// The body as text, decoded; nil when it isn't text, which then goes on as it came.
    private let original: String?

    init(flow: ProxyFlow, phase: BreakpointPhase) {
        self.flow = flow
        self.phase = phase
        let message = phase == .request ? flow.request : flow.response
        original = message.decodedBody.flatMap { String(data: $0, encoding: .utf8) }
        _method = State(initialValue: flow.method)
        _path = State(initialValue: RequestRow(flow).path)
        _status = State(initialValue: flow.status.map(String.init) ?? "")
        _headers = State(initialValue: message.headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n"))
        _text = State(initialValue: original ?? "")
    }

    var body: some View {
        let edit = self.edit
        VStack(alignment: .leading, spacing: 12) {
            Label {
                Text(phase == .request ? "Held before it goes to the server" : "Held before it goes back to the app")
            } icon: {
                Image(systemName: "pause.circle.fill").foregroundStyle(Color.statusWarning)
            }
            .font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 8, verticalSpacing: 6) {
                if phase == .request {
                    field("Method", $method)
                    field("Path", $path)
                } else {
                    field("Status", $status)
                }
            }
            Text("Headers, one per line").font(.caption).foregroundStyle(.secondary)
            editor($headers, height: 120)
            Text("Body").font(.caption).foregroundStyle(.secondary)
            if original == nil {
                let size = phase == .request ? flow.request.size : flow.response.size
                Text(size == 0 ? "No body." : "\(bytes(size)) that aren't text; they go on as they came.").foregroundStyle(.secondary)
            } else {
                editor($text, height: 200)
                if (phase == .request ? flow.request : flow.response).header("content-encoding") != nil {
                    Text("Shown decoded. Edited, it goes on unencoded.").font(.caption).foregroundStyle(.secondary)
                }
            }
            if case .failure(let problem) = edit {
                Label {
                    Text(problem.description)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            }
            HStack {
                Button("Abort", role: .destructive) { proxy.resume(flow.id, .abort) }
                    .help("Answer the app with a 502 instead.")
                Spacer()
                Button("Continue") {
                    if case .success(let message) = edit { proxy.resume(flow.id, .proceed(message)) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled((try? edit.get()) == nil)
            }
        }
    }

    private func field(_ label: LocalizedStringKey, _ value: Binding<String>) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            TextField(label, text: value).labelsHidden().font(.body.monospaced())
        }
    }

    private func editor(_ value: Binding<String>, height: CGFloat) -> some View {
        CodeEditor(text: value)
            .frame(height: height)
            .border(.separator)
    }

    /// The message to send on, or what's wrong with it.
    private var edit: Result<EditedMessage, ProxyFailure> {
        var message = EditedMessage()
        if phase == .request {
            guard !method.isEmpty, !method.contains(where: \.isWhitespace) else { return .failure(ProxyFailure(String(localized: "The method can't be empty or have spaces."))) }
            guard path.hasPrefix("/"), !path.contains(where: \.isWhitespace) else { return .failure(ProxyFailure(String(localized: "The path starts with / and has no spaces."))) }
            message.method = method
            message.path = path
        } else {
            guard let code = Int(status), (100 ... 599).contains(code) else { return .failure(ProxyFailure(String(localized: "The status is a number from 100 to 599."))) }
            message.status = code
        }
        guard let headers = EditedMessage.headers(from: headers) else {
            return .failure(ProxyFailure(String(localized: "Each header line is a name, a colon, then the value.")))
        }
        message.headers = headers
        // Untouched, the body goes on as it came, encoding and all.
        message.body = original != nil && text != original ? Data(text.utf8) : nil
        return .success(message)
    }
}

/// Plain text for JSON and headers. macOS's substitutions turn typed quotes curly,
/// which breaks JSON, and SwiftUI's TextEditor has no way to switch them off.
private struct CodeEditor: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let view = scroll.documentView as! NSTextView
        view.isRichText = false
        view.allowsUndo = true
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticSpellingCorrectionEnabled = false
        view.font = .monospacedSystemFont(ofSize: NSFont.preferredFont(forTextStyle: .callout).pointSize, weight: .regular)
        view.string = text
        view.delegate = context.coordinator
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let view = scroll.documentView as! NSTextView
        if view.string != text {
            view.string = text
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSTextViewDelegate {
        let text: Binding<String>
        init(text: Binding<String>) { self.text = text }

        func textDidChange(_ notification: Notification) {
            text.wrappedValue = (notification.object as! NSTextView).string
        }
    }
}

/// Headers, then the body in the chosen format.
private struct MessageView: View {
    private enum Format: CaseIterable, Identifiable {
        case text, json, hex
        var id: Self { self }

        var label: String {
            switch self {
            case .text: String(localized: "Text")
            case .json: "JSON"
            case .hex: String(localized: "Hex")
            }
        }
    }

    /// SwiftUI text layout slows to a crawl past this much; the HAR export has the rest.
    private static let shownLimit = 256 << 10

    let message: HTTPMessage
    @State private var format = Format.text

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if message.headers.isEmpty {
                Text("No headers yet.").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 8, verticalSpacing: 2) {
                    ForEach(Array(message.headers.enumerated()), id: \.offset) { _, header in
                        GridRow {
                            Text(header.name).foregroundStyle(.secondary)
                            Text(header.value).textSelection(.enabled)
                        }
                    }
                }
                .font(.callout.monospaced())
            }
            Divider()
            let body = message.decodedBody
            if message.size == 0 {
                Text("No body.").foregroundStyle(.secondary)
            } else {
                Picker("Format", selection: $format) {
                    ForEach(Format.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                if message.truncated {
                    Text("Only the first 10 MB of \(bytes(message.size)) were kept.").font(.caption).foregroundStyle(.secondary)
                }
                if body == nil {
                    Text("Couldn't undo the \(message.header("content-encoding") ?? "") encoding; showing the bytes as sent.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(rendered(body ?? message.body))
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func rendered(_ data: Data) -> String {
        let shown = data.prefix(Self.shownLimit)
        let note = data.count > shown.count ? "\n" + String(localized: "… \(bytes(data.count - shown.count)) more") : ""
        switch format {
        case .text:
            return (String(data: shown, encoding: .utf8) ?? String(decoding: shown, as: UTF8.self)) + note
        case .json:
            guard let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
                  let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .withoutEscapingSlashes, .fragmentsAllowed]) else {
                return String(localized: "Not valid JSON.")
            }
            let prettyShown = pretty.prefix(Self.shownLimit)
            return String(decoding: prettyShown, as: UTF8.self) + (pretty.count > prettyShown.count ? "\n…" : "")
        case .hex:
            let bytes = [UInt8](shown.prefix(16 << 10))
            return stride(from: 0, to: bytes.count, by: 16).map { start in
                let line = bytes[start ..< min(start + 16, bytes.count)]
                let hex = line.map { String(format: "%02x", $0) }.joined(separator: " ")
                let ascii = String(line.map { (0x20 ... 0x7e).contains($0) ? Character(UnicodeScalar($0)) : "." })
                return String(format: "%08x  ", start) + hex.padding(toLength: 48, withPad: " ", startingAt: 0) + " " + ascii
            }.joined(separator: "\n") + (data.count > bytes.count ? "\n…" : "")
        }
    }
}

/// A WebSocket's messages, oldest first, each a few lines until opened.
private struct WebSocketMessagesView: View {
    let flow: ProxyFlow
    /// By position in the whole conversation, so dropping the oldest doesn't shift them.
    @State private var opened: Set<Int> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if flow.droppedMessages > 0 {
                Text("The oldest \(flow.droppedMessages.formatted()) messages weren't kept.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if flow.messages.isEmpty {
                Text("No messages yet.").foregroundStyle(.secondary)
            }
            LazyVStack(alignment: .leading, spacing: 10) {
                ForEach(flow.messages.indices, id: \.self) { index in
                    row(flow.messages[index], number: flow.droppedMessages + index)
                }
            }
        }
    }

    private func row(_ message: WebSocketMessage, number: Int) -> some View {
        let isOpen = opened.contains(number)
        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Button {
                    if isOpen { opened.remove(number) } else { opened.insert(number) }
                } label: {
                    Image(systemName: isOpen ? "chevron.down" : "chevron.right")
                        .frame(width: 12)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(isOpen ? "Show less" : "Show all")
                Label(message.fromClient ? "Sent" : "Received", systemImage: message.fromClient ? "arrow.up" : "arrow.down")
                Text(message.kind)
                // Up here, where it shows while the payload is cut to three lines.
                Text(message.size > message.payload.count ? String(localized: "\(bytes(message.size)), \(bytes(message.payload.count)) kept") : bytes(message.size))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(message.time.formatted(.dateTime.hour().minute().second().secondFraction(.fractional(3))))
                    .foregroundStyle(.secondary)
            }
            .lineLimit(1)
            .monospacedDigit()
            Text(Self.payload(message, whole: isOpen))
                .font(.callout.monospaced())
                .lineLimit(isOpen ? nil : 3)
                .textSelection(.enabled)
                .padding(.leading, 18)
        }
    }

    private static func payload(_ message: WebSocketMessage, whole: Bool) -> String {
        let data = message.payload
        switch message.opcode {
        case 1:
            return String(decoding: data, as: UTF8.self)
        case 8:
            // RFC 6455 §5.5.1: a two-byte status code, then a UTF-8 reason.
            let code = [UInt8](data.prefix(2))
            guard code.count == 2 else { return String(localized: "No status code.") }
            let reason = String(decoding: data.dropFirst(2), as: UTF8.self)
            return "\(Int(code[0]) << 8 | Int(code[1]))" + (reason.isEmpty ? "" : " \(reason)")
        default:
            guard !data.isEmpty else { return String(localized: "Empty.") }
            // Hex is three characters a byte; a whole 64 KB message would stall text layout.
            let shown = data.prefix(whole ? 4 << 10 : 48)
            return shown.map { String(format: "%02x", $0) }.joined(separator: " ") + (data.count > shown.count ? " …" : "")
        }
    }
}
