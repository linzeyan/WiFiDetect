import SwiftUI

@main
struct WiFiDetectApp: App {
    @State private var monitor: WiFiMonitor
    // Shares readings whether or not a window is open; Settings turns it on.
    @State private var companion: CompanionServer
    // App-wide: capture keeps running across page switches, and Settings shares the
    // helper connection.
    @State private var traffic: TrafficStore
    // App-wide too: requests keep arriving whichever page is showing, and Settings
    // manages the same certificate and host list.
    @State private var proxy: ProxyStore
    // App-wide like capture: its notifications come with every window closed.
    @State private var watchlist: Watchlist
    // App-wide like capture: routers keep exporting with the window closed.
    @State private var routerFlows = RouterFlowStore()
    // Feeds capture's attribution and the proxy's capture; Settings turns both on.
    @State private var network: NetworkExtensionClient
    @AppStorage(SettingsKey.sampleRate) private var sampleRate = 2
    @AppStorage(SettingsKey.showInMenuBar) private var showInMenuBar = true
    @NSApplicationDelegateAdaptor private var appDelegate: AppDelegate

    init() {
        // `make test` launches the app as the tests' host; its readings go to a scratch
        // folder, not into the history of whoever runs the tests.
        let hostsTests = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
        let monitor = WiFiMonitor(store: hostsTests ? SampleStore(directory: .temporaryDirectory.appending(path: "WiFiDetect-test-host")) : SampleStore())
        _monitor = State(initialValue: monitor)
        _companion = State(initialValue: CompanionServer(monitor: monitor))
        let traffic = TrafficStore()
        _traffic = State(initialValue: traffic)
        let network = NetworkExtensionClient()
        network.onReports = { [weak traffic] in traffic?.attribute($0) }
        _network = State(initialValue: network)
        _proxy = State(initialValue: ProxyStore(helper: traffic.helper, network: network))
        _watchlist = State(initialValue: Watchlist(traffic: traffic))
        // Polling starts with the app, not with a window: the menu bar readout and the
        // iPhone's feed need it when the window was never opened, and history keeps
        // filling while the window is closed.
        monitor.start(hz: sampleRate)
        Task { await monitor.restore() }
    }

    var body: some Scene {
        // One window: a second copy of the same live readings adds nothing.
        Window("WiFiDetect", id: "main") {
            ContentView()
                .environment(monitor)
                .environment(traffic)
                .environment(proxy)
                .environment(watchlist)
                .environment(routerFlows)
        }
        .defaultSize(width: 1280, height: 860)
        // A scene's onChange, not a view's: it fires with no window open. start(hz:)
        // re-times the one timer rather than adding another.
        .onChange(of: sampleRate) { monitor.start(hz: sampleRate) }
        .commands {
            CommandGroup(replacing: .appInfo) { AboutCommand() }
            CommandGroup(after: .newItem) { OpenCaptureCommand(traffic: traffic) }
        }
        MenuBarExtra(isInserted: $showInMenuBar) {
            MenuBarPanel()
                .environment(monitor)
        } label: {
            // Its own view, so only the label redraws at the sampling rate, not every scene.
            MenuBarLabel()
                .environment(monitor)
        }
        .menuBarExtraStyle(.window)
        Settings {
            SettingsView()
                .environment(monitor)
                .environment(traffic.helper)
                .environment(proxy)
                .environment(companion)
                .environment(watchlist)
                .environment(routerFlows)
                .environment(network)
        }
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    /// An app whose window is a `Window` scene quits when it closes, taking the menu bar
    /// readout, the iPhone feed, capture and the proxy with it. They outlive the window;
    /// the Dock icon or the menu bar reopens it, and Quit ends the app.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

private enum Page: String {
    case signal, nearby, traffic, connections, routerFlows, requests
}

/// WiFiDetect › About WiFiDetect: the standard panel, with the notices the Apache License
/// asks the app to carry (NOTICE.md) as its credits.
private struct AboutCommand: View {
    var body: some View {
        Button("About WiFiDetect") {
            NSApp.orderFrontStandardAboutPanel(options: [.credits: noticeCredits()])
        }
    }

    /// NOTICE.md a line at a time: headings bold, each package's own notice in a monospaced
    /// face so its layout holds, and links that open.
    private func noticeCredits() -> NSAttributedString {
        guard let url = Bundle.main.url(forResource: "NOTICE", withExtension: "md"),
              let markdown = try? String(contentsOf: url, encoding: .utf8) else { return NSAttributedString() }
        let size = NSFont.smallSystemFontSize
        let body: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: size), .foregroundColor: NSColor.labelColor]
        let heading = body.merging([.font: NSFont.boldSystemFont(ofSize: size)]) { $1 }
        let quoted = body.merging([.font: NSFont.monospacedSystemFont(ofSize: size - 2, weight: .regular), .foregroundColor: NSColor.secondaryLabelColor]) { $1 }
        let credits = NSMutableAttributedString()
        var inQuote = false
        var paragraph: [String] = []
        func endParagraph() {
            guard !paragraph.isEmpty else { return }
            credits.append(NSAttributedString(string: paragraph.joined(separator: " ") + "\n", attributes: quoted))
            paragraph = []
        }
        for line in markdown.components(separatedBy: "\n") {
            if line.hasPrefix("```") {
                endParagraph()
                inQuote.toggle()
            } else if inQuote {
                // The notices are broken for 80 columns and the panel is far narrower, so a
                // paragraph's lines are joined for the panel to wrap. Indented lines, their
                // lists, keep their breaks; deeper indents only centered a title.
                let indent = line.prefix(while: \.isWhitespace).count
                if line.isEmpty || indent > 0 || line.allSatisfy({ $0 == "-" || $0 == "=" }) {
                    endParagraph()
                    let kept = indent > 4 ? String(line.dropFirst(indent)) : line
                    credits.append(NSAttributedString(string: kept + "\n", attributes: quoted))
                } else {
                    paragraph.append(line)
                }
            } else if line.hasPrefix("# ") {
                // "NOTICE": the panel's title already says whose it is.
            } else if line.hasPrefix("## ") {
                credits.append(NSAttributedString(string: String(line.dropFirst(3)) + "\n", attributes: heading))
            } else {
                let text = line.hasPrefix("- ") ? "• " + line.dropFirst(2) : line
                let parsed = (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(text)
                let inline = NSMutableAttributedString(parsed)
                inline.addAttributes(body, range: NSRange(location: 0, length: inline.length))
                credits.append(inline)
                credits.append(NSAttributedString(string: "\n", attributes: body))
            }
        }
        return credits
    }
}

/// File › Open Capture… (⌘O), from any page: the file shows on the Overview unless a
/// traffic page is already up.
private struct OpenCaptureCommand: View {
    let traffic: TrafficStore
    @AppStorage(SettingsKey.page) private var page = Page.signal
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Open Capture…") {
            guard let url = chooseCaptureFile() else { return }
            if page != .traffic, page != .connections {
                page = .traffic
            }
            openWindow(id: "main")
            Task { await traffic.open(url) }
        }
        .keyboardShortcut("o")
        // Opening a file stops the capture, and would end the recording with it.
        .disabled(traffic.isRecording)
    }
}

private struct ContentView: View {
    // Reopens on the page last used.
    @AppStorage(SettingsKey.page) private var page = Page.signal
    // Owned here so scan results survive switching pages.
    @State private var scanner = NetworkScanner()

    var body: some View {
        NavigationSplitView {
            List(selection: Binding<Page?> { page } set: { page = $0 ?? page }) {
                Section("Wi-Fi") {
                    Label("Signal", systemImage: "waveform.path.ecg").tag(Page.signal)
                    Label("Nearby Networks", systemImage: "wifi").tag(Page.nearby)
                }
                Section("Traffic") {
                    Label("Overview", systemImage: "chart.xyaxis.line").tag(Page.traffic)
                    Label("Connections", systemImage: "point.3.connected.trianglepath.dotted").tag(Page.connections)
                    Label("Router Flows", systemImage: "wifi.router").tag(Page.routerFlows)
                }
                Section("HTTP") {
                    Label("Requests", systemImage: "arrow.left.arrow.right").tag(Page.requests)
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            switch page {
            case .nearby: NearbyView(scanner: scanner)
            case .signal: SignalView()
            case .traffic: TrafficOverview()
            case .connections: ConnectionsView()
            case .routerFlows: RouterFlowsView()
            case .requests: RequestsView()
            }
        }
        // Sidebar + the signal page's figures row + the inspector, measured: at 1120 the
        // split view squeezes the sidebar and clips the inspector's values.
        .frame(minWidth: 1200, minHeight: 720)
    }
}
