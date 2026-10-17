import AppKit
import SwiftUI

/// Settings › Traffic: which events notify. Turning the first one on is what asks macOS
/// for permission, and a refusal shows here with the way to undo it.
struct NotificationSettings: View {
    @Environment(Watchlist.self) private var watchlist

    var body: some View {
        @Bindable var watchlist = watchlist
        Section {
            Toggle("Traffic stays above a limit", isOn: $watchlist.alerts.traffic)
            if watchlist.alerts.traffic {
                Picker("Measure", selection: $watchlist.alerts.trafficDirection) {
                    ForEach(TrafficDirection.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                LabeledContent("Limit") {
                    HStack {
                        TextField("Limit", value: $watchlist.alerts.trafficLimit, format: .number)
                            .labelsHidden()
                            .multilineTextAlignment(.trailing)
                            .frame(width: 70)
                            // Zero or less would put every second over the limit.
                            .onChange(of: watchlist.alerts.trafficLimit) { watchlist.alerts.trafficLimit = max(watchlist.alerts.trafficLimit, 0.01) }
                        Text("MB/s")
                    }
                }
            }
            Toggle("A blacklisted address has a new connection", isOn: $watchlist.alerts.blacklist)
            Toggle("A favorite host has a new connection", isOn: $watchlist.alerts.favorites)
            if watchlist.alerts.isAnyOn, watchlist.authorization == .denied {
                Label {
                    Text("macOS is set not to show WiFiDetect's notifications. Allow them in System Settings › Notifications › WiFiDetect.")
                } icon: {
                    Image(systemName: "bell.slash.fill").foregroundStyle(Color.statusWarning)
                }
                Button("Open Notification Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(Bundle.main.bundleIdentifier ?? "")")!)
                }
            }
        } header: {
            Text("Notify me when")
        } footer: {
            Text("Checked every second while capture runs, with or without the WiFiDetect window open. Traffic counts as above the limit after \(ThresholdAlarm.seconds) seconds in a row. The limit, each blacklist entry and each favorite notify at most once a minute.")
        }
        .task { await watchlist.refreshAuthorization() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await watchlist.refreshAuthorization() }
        }
    }
}

/// Settings › Traffic: the user's own blacklist, typed, pasted or imported.
struct BlacklistSettings: View {
    @Environment(Watchlist.self) private var watchlist

    var body: some View {
        @Bindable var watchlist = watchlist
        let blacklist = watchlist.blacklist
        Section {
            TextEditor(text: $watchlist.blacklistText)
                .font(.body.monospaced())
                .frame(height: 120)
            if !blacklist.invalid.isEmpty {
                Label {
                    Text(invalidLines(blacklist.invalid)).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusWarning)
                }
            }
            HStack {
                Text(blacklist.entries.count == 1 ? "1 entry" : "\(blacklist.entries.count) entries")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Import from File…", action: importFile)
            }
        } header: {
            Text("Blacklist")
        } footer: {
            Text("One IPv4 or IPv6 address or CIDR range per line, such as 203.0.113.7 or 203.0.113.0/24; text after # or ; is a comment. Connections whose remote address matches are marked Blacklisted in Connections. WiFiDetect doesn't download lists: import one you trust.")
        }
    }

    private func invalidLines(_ invalid: [(line: Int, text: String)]) -> String {
        let shown = invalid.prefix(5).map { String(localized: "Line \($0.line): \($0.text)") }
        let more = invalid.count > 5 ? [String(localized: "…and \(invalid.count - 5) more")] : []
        return ([String(localized: "Not an address or range, so nothing matches:")] + shown + more).joined(separator: "\n")
    }

    private func importFile() {
        let panel = NSOpenPanel()
        panel.prompt = String(localized: "Import")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            // Added after what's there rather than replacing it, so an import can't lose
            // entries typed by hand.
            let current = watchlist.blacklistText
            watchlist.blacklistText = current + (current.last?.isNewline ?? true ? "" : "\n") + text
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

/// Settings › Traffic: the starred hosts. Stars are added in Connections; this is where
/// one whose connections have all left the table can be taken off.
struct FavoriteSettings: View {
    @Environment(Watchlist.self) private var watchlist

    var body: some View {
        Section {
            if watchlist.favorites.hosts.isEmpty {
                Text("No favorites yet.").foregroundStyle(.secondary)
            }
            ForEach(watchlist.favorites.hosts.sorted(), id: \.self) { host in
                HStack {
                    Text(host)
                    Spacer()
                    Button("Remove", systemImage: "minus.circle") {
                        watchlist.favorites.hosts.remove(host)
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                }
            }
        } header: {
            Text("Favorites")
        } footer: {
            Text("Star a connection in Connections to add its host: its domain, or its address when it has none.")
        }
    }
}
