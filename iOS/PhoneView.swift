import Charts
import SwiftUI
import UIKit

/// This iPhone's or iPad's own Wi-Fi (spec F4.2, F4.3). Nothing here is dBm or "signal
/// strength": iOS doesn't give apps either.
struct PhoneView: View {
    @Environment(PhoneMonitor.self) private var phone
    @Environment(\.openURL) private var openURL

    /// The page's tab symbol: its name fits either device, the picture can be the right one.
    static var symbol: String {
        UIDevice.current.userInterfaceIdiom == .pad ? "ipad" : "iphone"
    }

    var body: some View {
        NavigationStack {
            Group {
                if phone.isOnWiFi {
                    List {
                        wifi
                        roundTrip
                    }
                } else {
                    ContentUnavailableView("Not on Wi-Fi", systemImage: "wifi.slash", description: Text("Join a Wi-Fi network to measure it."))
                }
            }
            .navigationTitle("This Device")
        }
        .onAppear { phone.isActive = true }
        .onDisappear { phone.isActive = false }
    }

    // MARK: Wi-Fi

    private var wifi: some View {
        Section {
            LabeledContent("Network") { networkName }
            LabeledContent("Link quality") { rating }
            LabeledContent("Router", value: phone.router.map { "\($0)" } ?? "—")
        } header: {
            Text("Wi-Fi")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("iOS doesn't let apps read Wi-Fi signal strength. Link quality is the system's own rating of this connection.")
                if !isLocationAuthorized {
                    Text("iOS shows the network's name only to apps with location access. WiFiDetect doesn't use where you are.")
                }
            }
        }
    }

    private var isLocationAuthorized: Bool {
        phone.locationStatus == .authorizedWhenInUse || phone.locationStatus == .authorizedAlways
    }

    @ViewBuilder
    private var networkName: some View {
        if let ssid = phone.ssid {
            Text(ssid)
        } else if phone.locationStatus == .notDetermined {
            Button("Show Name") { phone.requestLocation() }
        } else if !isLocationAuthorized {
            Button("Allow in Settings") { openURL(URL(string: UIApplication.openSettingsURLString)!) }
        } else {
            Text("—")
        }
    }

    @ViewBuilder
    private var rating: some View {
        switch phone.rating {
        case .unsupported: Text("Needs iOS 26").foregroundStyle(.secondary)
        case .unknown: Text("Unknown").foregroundStyle(.secondary)
        case .minimal: ratingLabel("Minimal", "exclamationmark.triangle.fill", .statusCritical)
        case .moderate: ratingLabel("Moderate", "exclamationmark.circle.fill", .statusWarning)
        case .good: ratingLabel("Good", "checkmark.circle.fill", .statusGood)
        }
    }

    /// Not a Label: a List gives a row with a Label in it the Label's own row layout,
    /// which on iOS 26 made this row three times as tall, with its separator under "Good".
    private func ratingLabel(_ text: LocalizedStringKey, _ icon: String, _ color: Color) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon).foregroundStyle(color)
            Text(text)
        }
    }

    // MARK: Round trip

    private var roundTrip: some View {
        Section {
            pingFigures("Router", phone.routerPings, color: .router)
            pingFigures("Internet (\(PhoneMonitor.internetHost))", phone.internetPings, color: .internet)
            pingChart
        } header: {
            Text("Round trip, last minute")
        } footer: {
            Text("Timed once a second over Wi-Fi. Jitter is how much back-to-back round trips differ, which is what calls and games feel.")
        }
    }

    private func pingFigures(_ title: LocalizedStringKey, _ stats: PingStats, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(title)
            } icon: {
                Capsule().fill(color).frame(width: 12, height: 3)
            }
            HStack(alignment: .top) {
                figure("Median", stats.median.map(milliseconds))
                figure("Jitter", stats.jitter.map(milliseconds))
                figure("Loss", stats.loss.map { $0.formatted(.percent.precision(.fractionLength(0))) })
            }
        }
    }

    private func figure(_ label: LocalizedStringKey, _ value: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value ?? "—").font(.title3.weight(.semibold)).monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var pingChart: some View {
        // The legend shows these, and the color scale is keyed by them.
        let router = String(localized: "Router"), internet = String(localized: "Internet")
        let points = pingPoints(phone.routerPings, router) + pingPoints(phone.internetPings, internet)
        let end = Date.now
        let domain = end.addingTimeInterval(-60) ... end
        return Chart(points) { point in
            LineMark(x: .value("Time", point.date), y: .value("Round trip", point.rtt), series: .value("Line", "\(point.series) \(point.segment)"))
                .foregroundStyle(by: .value("Host", point.series))
                .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
        }
        .chartForegroundStyleScale([router: Color.router, internet: Color.internet])
        .chartLegend(position: .top, alignment: .leading)
        .chartXScale(domain: domain)
        .chartXAxis { timeAxis(domain, labels: .dateTime.hour().minute().second(), quarters: true) }
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                AxisGridLine(stroke: .hairline)
                AxisValueLabel { if let v = value.as(Double.self) { Text("\(Int(v)) ms") } }
            }
        }
        .frame(height: 160)
        .padding(.vertical, 8)
    }

    private struct PingPoint: Identifiable {
        let series: String
        /// A lost ping breaks the line instead of being bridged.
        let segment: Int
        let date: Date
        let rtt: Double

        var id: String { "\(series) \(date.timeIntervalSinceReferenceDate)" }
    }

    private func pingPoints(_ stats: PingStats, _ series: String) -> [PingPoint] {
        var segment = 0
        return stats.results.compactMap { result in
            guard let rtt = result.rtt else {
                segment += 1
                return nil
            }
            return PingPoint(series: series, segment: segment, date: result.date, rtt: rtt)
        }
    }
}
