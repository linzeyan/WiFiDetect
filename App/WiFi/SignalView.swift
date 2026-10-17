import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct SignalView: View {
    @Environment(WiFiMonitor.self) private var monitor
    @AppStorage(SettingsKey.thresholds) private var thresholds = SignalThresholds()
    @State private var window = TimeWindow.oneMinute
    @State private var showsDetails = true
    @State private var isExporting = false

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            SignalHeader(sample: monitor.latest, txRate: monitor.link?.txRate, unavailable: monitor.unavailableReason, thresholds: thresholds)
            Picker("Time window", selection: $window) {
                ForEach(TimeWindow.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            SignalCharts(history: monitor.history, end: monitor.latest?.date ?? .now, window: window, thresholds: thresholds)
        }
        .padding(20)
        .navigationTitle("Signal")
        .toolbar {
            Button { exportCSV() } label: {
                Label("Export CSV…", systemImage: "square.and.arrow.up")
            }
            .help("Every reading in the time window shown")
            .disabled(monitor.history.samples.isEmpty || isExporting)
            Button {
                showsDetails.toggle()
            } label: {
                Label("Connection Details", systemImage: "info.circle")
            }
        }
        .inspector(isPresented: $showsDetails) {
            ConnectionDetails()
                .inspectorColumnWidth(min: 260, ideal: 280)
        }
    }

    private func exportCSV() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        // Named like the PCAP and HAR exports, in local time.
        let stamp = Date.ISO8601FormatStyle(timeSeparator: .omitted, timeZone: .current).year().month().day().time(includingFractionalSeconds: false)
        panel.nameFieldStringValue = "WiFiDetect \(Date.now.formatted(stamp)).csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        isExporting = true
        Task {
            defer { isExporting = false }
            do {
                try await monitor.exportCSV(window: window.rawValue, to: url)
            } catch {
                NSAlert(error: error).runModal()
            }
        }
    }
}

struct ConnectionDetails: View {
    @Environment(WiFiMonitor.self) private var monitor

    var body: some View {
        // Without an association CoreWLAN still answers, with stale or zero values.
        let link = monitor.latest?.rssi == nil ? nil : monitor.link
        Form {
            Section("Network") {
                LabeledContent("Name") { located(link?.ssid) }
                LabeledContent("BSSID") { located(link?.bssid) }
                LabeledContent("Country") { located(link?.countryCode) }
                if !monitor.isLocationAuthorized {
                    LocationAccessPrompt()
                }
            }
            Section("Radio") {
                LabeledContent("Channel", value: link?.channel?.label ?? "—")
                LabeledContent("PHY mode", value: link?.phyMode.label ?? "—")
                LabeledContent("Security", value: link?.security.label ?? "—")
                LabeledContent("Tx rate", value: link.map { "\(Int($0.txRate)) Mbps" } ?? "—")
                LabeledContent("Tx power", value: link.map { "\($0.txPower) mW" } ?? "—")
                LabeledContent("Interface", value: monitor.link?.interfaceName ?? "—")
            }
        }
        .formStyle(.grouped)
    }

    /// What macOS withholds without Location reads "Hidden", not "—", so it isn't
    /// mistaken for a value the network doesn't have.
    private func located(_ value: String?) -> Text {
        if let value {
            Text(value)
        } else if monitor.isLocationAuthorized || monitor.latest?.rssi == nil {
            Text("—")
        } else {
            Text("Hidden").foregroundStyle(.secondary)
        }
    }
}

/// Progressive authorization (spec F1.5): nothing asks for Location until the user
/// wants a network name. Once denied, macOS won't prompt again, so the retry is a
/// trip to System Settings.
struct LocationAccessPrompt: View {
    @Environment(WiFiMonitor.self) private var monitor

    var body: some View {
        if monitor.locationStatus == .notDetermined {
            VStack(alignment: .leading, spacing: 6) {
                Button("Show Network Names") { monitor.requestLocation() }
                Text("macOS shows network names and BSSIDs only to apps with location access. WiFiDetect doesn't use where you are.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else if !monitor.isLocationAuthorized {
            VStack(alignment: .leading, spacing: 6) {
                Text("Location access is off for WiFiDetect, so macOS hides network names and BSSIDs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Open Location Settings…") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices")!)
                }
            }
        }
    }
}
