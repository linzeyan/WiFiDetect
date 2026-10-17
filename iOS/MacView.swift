import SwiftUI
import UIKit

/// The Mac's Wi-Fi, as its own signal page shows it (spec F4.1).
struct MacView: View {
    @Environment(MacClient.self) private var mac
    @Environment(\.openURL) private var openURL
    @AppStorage("searchesForMacs") private var searchesForMacs = false
    @State private var window = TimeWindow.oneMinute
    // ponytail: the Mac's own thresholds aren't sent; send them if users tune them often.
    private let thresholds = SignalThresholds()

    var body: some View {
        @Bindable var mac = mac
        NavigationStack {
            content
                .navigationTitle(mac.selected ?? "Mac")
                .toolbar {
                    if mac.macs.count > 1 {
                        Picker("Mac", selection: $mac.selected) {
                            ForEach(mac.macs, id: \.self) { Text($0).tag(Optional($0)) }
                        }
                        .pickerStyle(.menu)
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        if !mac.history.samples.isEmpty {
            readings
        } else {
            switch mac.status {
            case .idle:
                ContentUnavailableView {
                    Label("See Your Mac's Wi-Fi", systemImage: "laptopcomputer.and.iphone")
                } description: {
                    Text("Shows the signal chart of a Mac running WiFiDetect on this network. iOS will ask to let WiFiDetect find devices on your local network.")
                } actions: {
                    Button("Look for Macs") { searchesForMacs = true }
                        .buttonStyle(.borderedProminent)
                }
            case .denied:
                ContentUnavailableView {
                    Label("Local Network Access Is Off", systemImage: "wifi.exclamationmark")
                } description: {
                    Text("WiFiDetect needs it to find your Mac.")
                } actions: {
                    Button("Open Settings") { openURL(URL(string: UIApplication.openSettingsURLString)!) }
                }
            case .failed(let message):
                ContentUnavailableView("Couldn't Connect", systemImage: "exclamationmark.triangle", description: Text(message))
            case .searching, .connecting, .connected:
                ContentUnavailableView {
                    Label {
                        Text(mac.status == .searching ? "Looking for Macs" : "Connecting")
                    } icon: {
                        ProgressView()
                    }
                } description: {
                    Text("On the Mac, open WiFiDetect › Settings › Wi-Fi and turn on Share readings with iPhone and iPad. Both need to be on the same network.")
                }
            }
        }
    }

    private var readings: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                if mac.status != .connected {
                    Label("Reconnecting…", systemImage: "arrow.triangle.2.circlepath")
                        .foregroundStyle(.secondary)
                }
                SignalHeader(sample: mac.history.samples.last, txRate: mac.link?.txRate, unavailable: unavailable, thresholds: thresholds)
                Picker("Time window", selection: $window) {
                    // The Mac sends its last hour, not its stored week.
                    ForEach(TimeWindow.allCases.filter { $0 <= .oneHour }) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                SignalCharts(history: mac.history, end: mac.history.samples.last?.date ?? .now, window: window, thresholds: thresholds)
                if let channel = mac.link?.channel {
                    LabeledContent("Channel", value: channel)
                }
            }
            .padding()
        }
    }

    private var unavailable: String {
        guard let link = mac.link else { return String(localized: "No Wi-Fi interface") }
        return link.isPoweredOn ? String(localized: "Not connected") : String(localized: "Wi-Fi is off")
    }
}
