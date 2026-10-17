import Charts
import CoreWLAN
import SwiftUI

struct NearbyView: View {
    let scanner: NetworkScanner
    @Environment(WiFiMonitor.self) private var monitor
    @AppStorage(SettingsKey.thresholds) private var thresholds = SignalThresholds()
    @AppStorage(SettingsKey.autoScan) private var autoScan = false
    @AppStorage(SettingsKey.autoScanInterval) private var autoScanInterval = 30
    @State private var band: CWChannelBand?
    @State private var sortOrder = [KeyPathComparator(\NearbyNetwork.rssi, order: .reverse)]
    @State private var hoveredChannel: Double?

    private static let bands: [CWChannelBand] = [.band2GHz, .band5GHz, .band6GHz]
    private static let floor = -100.0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Picker("Band", selection: Binding { currentBand } set: { band = $0 }) {
                        ForEach(Self.bands, id: \.self) { band in
                            Text("\(band.label) (\(networks(in: band).count))").tag(band)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    Spacer()
                    if networks(in: currentBand).contains(where: isCurrent) {
                        legend
                    }
                }
                channelChart
            }
            .padding(20)
            if !monitor.isLocationAuthorized {
                LocationAccessPrompt()
                    .padding(.horizontal, 20)
                    .padding(.bottom, 12)
            }
            table
        }
        .navigationTitle("Nearby Networks")
        .navigationSubtitle(subtitle)
        .toolbar {
            Toggle(isOn: $autoScan) {
                Label("Auto-Scan", systemImage: "timer")
            }
            .help("Scan again on an interval while this page is open")
            Picker("Interval", selection: $autoScanInterval) {
                ForEach([10, 30, 60], id: \.self) { Text("Every \($0) s").tag($0) }
            }
            .disabled(!autoScan)
            Button {
                Task { await scanner.scan() }
            } label: {
                Label("Scan", systemImage: "arrow.clockwise")
            }
            .disabled(scanner.isScanning)
        }
        // Scans once on first visit; auto-scan runs only while this page is visible.
        // Off by default: a scan takes the radio off-channel for a few seconds, which
        // the user's own connection feels.
        .task(id: autoScan ? autoScanInterval : nil) {
            if scanner.lastScan == nil {
                await scanner.scan()
            }
            guard autoScan else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(autoScanInterval))
                guard !Task.isCancelled else { return }
                await scanner.scan()
            }
        }
    }

    private var currentBand: CWChannelBand {
        if let band { return band }
        let connected = monitor.link?.channel?.band ?? .band5GHz
        return Self.bands.contains(connected) ? connected : .band5GHz
    }

    private func networks(in band: CWChannelBand) -> [NearbyNetwork] {
        scanner.networks.filter { $0.channel?.band == band }
    }

    private func isCurrent(_ network: NearbyNetwork) -> Bool {
        network.bssid != nil && network.bssid == monitor.link?.bssid
    }

    private var subtitle: String {
        if scanner.isScanning { return String(localized: "Scanning…") }
        guard let lastScan = scanner.lastScan else { return "" }
        return String(localized: "\(scanner.networks.count) networks · scanned \(lastScan.formatted(date: .omitted, time: .standard))")
    }

    // MARK: Channel chart

    /// Each network is drawn across the spectrum its channel occupies, as a trapezoid
    /// up to its RSSI. Every wash is 10% opaque, so where channels overlap the fill
    /// darkens: congestion shows without a separate encoding. Networks aren't
    /// colored individually (a crowded band has dozens); hovering names them.
    private var channelChart: some View {
        let band = currentBand
        let shown = networks(in: band)
        let hovered = hoveredChannel.map { Self.snap($0, band) }
        return Chart {
            ForEach(shown) { network in
                let span = network.channel!.span
                let rssi = Double(network.rssi)
                let color = isCurrent(network) ? Color.rssi : Color.gray
                let outline = [(span.lowerBound, Self.floor), (span.lowerBound + 1, rssi), (span.upperBound - 1, rssi), (span.upperBound, Self.floor)]
                ForEach(outline.indices, id: \.self) { i in
                    AreaMark(
                        x: .value("Channel", outline[i].0),
                        yStart: .value("Floor", Self.floor),
                        yEnd: .value("RSSI", outline[i].1),
                        series: .value("Network", network.id)
                    )
                    .foregroundStyle(color.opacity(0.1))
                    LineMark(x: .value("Channel", outline[i].0), y: .value("RSSI", outline[i].1), series: .value("Network", network.id))
                        .foregroundStyle(color)
                        .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                }
            }
            if let hovered {
                RuleMark(x: .value("Channel", hovered))
                    .foregroundStyle(Color.cursor)
                    .lineStyle(StrokeStyle(lineWidth: 1))
                    .annotation(position: .top, spacing: 0, overflowResolution: .init(x: .fit(to: .chart), y: .fit(to: .plot))) {
                        channelTooltip(hovered, shown.filter { $0.channel!.span.contains(hovered) })
                    }
            }
        }
        .chartXScale(domain: Self.domain(band))
        .chartYScale(domain: Self.floor ... -20)
        .chartXAxis {
            AxisMarks(values: Self.ticks(band)) { value in
                AxisGridLine(stroke: .hairline)
                // Centered under its gridline: a channel number names that exact point.
                AxisValueLabel(anchor: .top) {
                    if let channel = value.as(Double.self) { Text("\(Int(channel))") }
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                AxisGridLine(stroke: .hairline)
                AxisValueLabel {
                    if let v = value.as(Double.self) { Text(signed(Int(v))) }
                }
            }
        }
        .chartXSelection(value: $hoveredChannel)
        .frame(height: 220)
    }

    private var legend: some View {
        HStack(spacing: 16) {
            legendKey(.rssi, "Your network")
            legendKey(.gray, "Other networks")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    private func legendKey(_ color: Color, _ label: LocalizedStringKey) -> some View {
        HStack(spacing: 6) {
            Capsule().fill(color).frame(width: 12, height: 3)
            Text(label)
        }
    }

    private func channelTooltip(_ channel: Double, _ networks: [NearbyNetwork]) -> some View {
        let strongest = networks.sorted { $0.rssi > $1.rssi }
        return VStack(alignment: .leading, spacing: 4) {
            Text("Channel \(Int(channel))").foregroundStyle(.secondary)
            if strongest.isEmpty {
                Text("No networks").foregroundStyle(.secondary)
            }
            ForEach(strongest.prefix(8)) { network in
                HStack {
                    Text(network.ssid ?? String(localized: "Hidden")).foregroundStyle(network.ssid == nil ? .secondary : .primary)
                    Spacer(minLength: 12)
                    Text(dBm(network.rssi)).monospacedDigit()
                }
            }
            if strongest.count > 8 {
                Text("\(strongest.count - 8) more").foregroundStyle(.secondary)
            }
        }
        .font(.caption)
        .frame(maxWidth: 220)
        .padding(8)
        .background(.regularMaterial, in: .rect(cornerRadius: 6))
    }

    /// The nearest real 20 MHz channel to a pointer position.
    private static func snap(_ x: Double, _ band: CWChannelBand) -> Double {
        if band == .band2GHz { return min(max(x.rounded(), 1), 14) }
        let base = band == .band6GHz ? 1.0 : (x >= 147 ? 149 : 36)
        return base + ((x - base) / 4).rounded() * 4
    }

    private static func domain(_ band: CWChannelBand) -> ClosedRange<Double> {
        switch band {
        case .band2GHz: -1.5 ... 16.5
        case .band6GHz: -3 ... 237
        default: 30 ... 181
        }
    }

    private static func ticks(_ band: CWChannelBand) -> [Double] {
        switch band {
        case .band2GHz: Array(1 ... 14).map(Double.init)
        case .band6GHz: stride(from: 1.0, through: 225, by: 32).map { $0 }
        default: [36, 52, 64, 100, 116, 132, 149, 165, 177]
        }
    }

    // MARK: Table

    private var table: some View {
        Table(scanner.networks.sorted(using: sortOrder), sortOrder: $sortOrder) {
            TableColumn("Network", value: \.ssidKey) { network in
                HStack(spacing: 4) {
                    Text(network.ssid ?? String(localized: "Hidden")).foregroundStyle(network.ssid == nil ? .secondary : .primary)
                    if isCurrent(network) {
                        Image(systemName: "checkmark").foregroundStyle(.secondary).help("Connected")
                    }
                }
            }
            .width(min: 110, ideal: 160)
            TableColumn("Signal", value: \.rssi) { network in
                let grade = thresholds.grade(rssi: network.rssi)
                Label {
                    Text(dBm(network.rssi)).monospacedDigit()
                } icon: {
                    Image(systemName: "wifi", variableValue: grade.bars).foregroundStyle(grade.color)
                }
                .help(grade.label)
            }
            .width(min: 90, ideal: 95)
            TableColumn("Channel", value: \.channelKey) { Text($0.channel.map { "\($0.number)" } ?? "—").monospacedDigit() }
                .width(min: 50, ideal: 55)
            TableColumn("Band", value: \.bandKey) { Text($0.channel?.band.label ?? "—") }
                .width(min: 55, ideal: 60)
            TableColumn("Width", value: \.widthKey) { Text($0.channel?.widthMHz.map { "\($0) MHz" } ?? "—") }
                .width(min: 55, ideal: 60)
            TableColumn("Security", value: \.securityKey) { Text($0.security.label) }
                .width(min: 120, ideal: 170)
            TableColumn("PHY", value: \.phyKey) { Text($0.phyMode.label) }
                .width(min: 120, ideal: 140)
            TableColumn("BSSID", value: \.bssidKey) { Text($0.bssid ?? "—").monospaced() }
                .width(min: 130, ideal: 145)
        }
        .overlay {
            if scanner.networks.isEmpty {
                if let error = scanner.error {
                    ContentUnavailableView("Scan Failed", systemImage: "exclamationmark.triangle", description: Text(error))
                } else if scanner.isScanning {
                    ProgressView("Scanning…")
                } else if scanner.lastScan != nil {
                    ContentUnavailableView("No Networks Found", systemImage: "wifi.slash")
                }
            }
        }
    }
}
