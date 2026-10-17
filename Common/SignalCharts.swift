import Charts
import SwiftUI

enum TimeWindow: Double, CaseIterable, Identifiable {
    case oneMinute = 60, fiveMinutes = 300, thirtyMinutes = 1800, oneHour = 3600
    case oneDay = 86400, sevenDays = 604_800

    var id: Self { self }

    var label: String {
        switch self {
        case .oneMinute: String(localized: "1 min")
        case .fiveMinutes: String(localized: "5 min")
        case .thirtyMinutes: String(localized: "30 min")
        case .oneHour: String(localized: "1 hour")
        case .oneDay: String(localized: "24 hours")
        case .sevenDays: String(localized: "7 days")
        }
    }

    /// The long windows plot a summary per bucket of this many seconds (SampleHistory),
    /// about 500 points each. Whole minutes, so the chart can say what a point is.
    var bucket: TimeInterval? {
        switch self {
        case .oneDay: 180
        case .sevenDays: 1200
        default: nil
        }
    }

    var axisFormat: Date.FormatStyle {
        switch self {
        case .oneMinute, .fiveMinutes: .dateTime.hour().minute().second()
        case .thirtyMinutes, .oneHour, .oneDay: .dateTime.hour().minute()
        case .sevenDays: .dateTime.month().day()
        }
    }

    /// Break a line where samples are further apart than this: the Mac slept, or the
    /// app stopped polling. Downsampled buckets are window/600 apart, hence the scaling;
    /// the long windows' are a little wider, and this still spans more than two.
    var maxGap: TimeInterval {
        max(5, 3 * rawValue / 600)
    }
}

extension TimeWindow: Comparable {
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

/// Time marks for a chart spanning `domain`, on whole quarter minutes when `quarters`:
/// .automatic and .stride both count from wherever the domain starts, which at one
/// minute is :33, :48, :03, moving every second. Otherwise .automatic's round times.
/// The marks slide with the data, so the newest nears the right edge; a label with no
/// room there is left out, its gridline kept, rather than cut to "11:…" (.greedy).
@AxisContentBuilder
func timeAxis(_ domain: ClosedRange<Date>, labels: Date.FormatStyle?, quarters: Bool) -> some AxisContent {
    if quarters {
        let first = (domain.lowerBound.timeIntervalSince1970 / 15).rounded(.up) * 15
        let marks = stride(from: first, through: domain.upperBound.timeIntervalSince1970, by: 15).map(Date.init(timeIntervalSince1970:))
        AxisMarks(values: marks) { _ in
            AxisGridLine(stroke: .hairline)
            if let labels { AxisValueLabel(format: labels, collisionResolution: .greedy) }
        }
    } else {
        AxisMarks(values: .automatic(desiredCount: 6)) { _ in
            AxisGridLine(stroke: .hairline)
            if let labels { AxisValueLabel(format: labels, collisionResolution: .greedy) }
        }
    }
}

private enum Series: String {
    case rssi, noise, snr

    /// The legend's and the tooltip's. The color scale is keyed by it too, so every
    /// mark names its series with this and not the raw value.
    var name: String {
        switch self {
        case .rssi: String(localized: "RSSI")
        case .noise: String(localized: "Noise")
        case .snr: String(localized: "SNR")
        }
    }

    var color: Color {
        switch self {
        case .rssi: .rssi
        case .noise: .noise
        case .snr: .snr
        }
    }
}

private struct ChartPoint: Hashable {
    let series: Series
    /// A line breaks between segments, so it never bridges a time nothing was measured.
    let segment: Int
    let date: Date
    let value: Double
}

/// A long window's band from the bucket's lowest to its highest reading.
private struct BandPoint: Hashable {
    let series: Series
    let segment: Int
    let date: Date
    let range: ClosedRange<Double>
}

/// The latest reading in figures. Shared by the Mac's signal page and the iPhone's view
/// of it, which is why it takes values rather than the Mac's monitor.
struct SignalHeader: View {
    let sample: WiFiSample?
    /// Mbps
    let txRate: Double?
    /// Takes the grade's place when there is no reading, saying why. Localized.
    let unavailable: String
    let thresholds: SignalThresholds

    var body: some View {
        // An iPhone is too narrow for one row.
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 20) {
                signal
                Spacer()
                tiles
            }
            VStack(alignment: .leading, spacing: 16) {
                signal
                tiles
            }
        }
    }

    private var signal: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Signal").foregroundStyle(.secondary)
            Text(sample?.rssi.map(dBm) ?? "—")
                .font(.system(size: 48, weight: .semibold))
            if let rssi = sample?.rssi {
                SignalGradeLabel(grade: thresholds.grade(rssi: rssi))
            } else {
                Label(unavailable, systemImage: "wifi.slash").foregroundStyle(.secondary)
            }
        }
    }

    private var tiles: some View {
        HStack(alignment: .top, spacing: 20) {
            tile("Noise", sample?.noise.map(dBm))
            tile("SNR", sample?.snr.map { "\($0) dB" }, badge: sample?.snr.flatMap { snrBadge(thresholds.grade(snr: $0)) })
            tile("Tx rate", sample?.rssi == nil ? nil : txRate.map { "\(Int($0)) Mbps" })
        }
    }

    /// A fixed minimum width, so a value changing width at the sampling rate doesn't
    /// nudge its neighbors.
    private func tile(_ label: LocalizedStringKey, _ value: String?, badge: (text: LocalizedStringKey, icon: String, color: Color)? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).foregroundStyle(.secondary)
            Text(value ?? "—").font(.title2.weight(.semibold))
            if let badge {
                Label {
                    Text(badge.text)
                } icon: {
                    Image(systemName: badge.icon).foregroundStyle(badge.color)
                }
                .font(.callout)
            }
        }
        .frame(minWidth: 100, alignment: .leading)
    }

    private func snrBadge(_ grade: SNRGrade?) -> (text: LocalizedStringKey, icon: String, color: Color)? {
        switch grade {
        case .voice: ("Voice grade", "checkmark.circle.fill", .statusGood)
        case .poor: ("Poor", "exclamationmark.triangle.fill", .statusCritical)
        case nil: nil
        }
    }
}

/// Signal and noise over time, and SNR on a time axis shared with it.
struct SignalCharts: View {
    let history: SampleHistory
    /// The newest reading's time: "now" on the chart.
    let end: Date
    let window: TimeWindow
    let thresholds: SignalThresholds
    @State private var selectedDate: Date?

    var body: some View {
        let plot = history.plot(window: window.rawValue, end: end)
        // Headroom after "now" for the end-of-line value labels.
        let xDomain = end.addingTimeInterval(-window.rawValue) ... end.addingTimeInterval(window.rawValue * 0.08)
        let selected = selectedDate.flatMap { date in
            plot.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }
        }
        VStack(alignment: .leading, spacing: 24) {
            signalChart(plot, xDomain: xDomain, selected: selected)
            snrChart(plot, xDomain: xDomain, selected: selected)
        }
    }

    private func signalChart(_ plot: [PlotSample], xDomain: ClosedRange<Date>, selected: PlotSample?) -> some View {
        let points = chartPoints(plot, .rssi, \.rssi) + chartPoints(plot, .noise, \.noise)
        let bands = bandPoints(plot, .rssi, \.rssiRange) + bandPoints(plot, .noise, \.noiseRange)
        let values = points.map(\.value) + bands.flatMap { [$0.range.lowerBound, $0.range.upperBound] }
        let yDomain = min(-100, (values.min() ?? -100) - 5) ... max(-20, (values.max() ?? -20) + 5)
        return VStack(alignment: .leading, spacing: 8) {
            // Beside the title, not above the charts: switching windows doesn't move them.
            HStack(alignment: .firstTextBaseline) {
                Text("Signal and noise (dBm)").font(.headline)
                Spacer()
                if let bucket = window.bucket {
                    Text("\(Int(bucket / 60))-minute averages, shaded from lowest to highest reading")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            Chart {
                ranges(bands)
                lines(points)
                referenceLine(thresholds.good, "\(dBm(thresholds.good)) · VoIP and streaming")
                referenceLine(thresholds.roam, "\(dBm(thresholds.roam)) · Mac starts roaming")
                endLabels(points)
                if let selected {
                    selectionRule(selected)
                        .annotation(position: .top, spacing: 0, overflowResolution: .init(x: .fit(to: .chart), y: .fit(to: .plot))) {
                            tooltip(selected)
                        }
                }
            }
            .chartForegroundStyleScale([Series.rssi.name: Series.rssi.color, Series.noise.name: Series.noise.color])
            // Leading: the hover tooltip floats over the top edge, and most hovering
            // happens at the right, over the newest readings.
            .chartLegend(position: .top, alignment: .leading)
            .chartXScale(domain: xDomain)
            .chartYScale(domain: yDomain)
            // The SNR chart right below carries the time labels. The same marks as it, or
            // at 24 hours and 7 days the gridlines of the two don't line up.
            .chartXAxis { timeAxis(xDomain, labels: nil, quarters: window == .oneMinute) }
            .chartYAxis { valueAxis { signed(Int($0)) } }
            .chartXSelection(value: $selectedDate)
            .frame(minHeight: 220)
        }
    }

    private func snrChart(_ plot: [PlotSample], xDomain: ClosedRange<Date>, selected: PlotSample?) -> some View {
        let points = chartPoints(plot, .snr, \.snr)
        let bands = bandPoints(plot, .snr, \.snrRange)
        let top = max(60, ((points.map(\.value) + bands.map(\.range.upperBound)).max() ?? 0) + 5)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Signal-to-noise ratio (dB)").font(.headline)
            Chart {
                ranges(bands)
                lines(points)
                referenceLine(thresholds.snrVoice, "\(thresholds.snrVoice) dB · Voice")
                referenceLine(thresholds.snrPoor, "\(thresholds.snrPoor) dB · Poor")
                endLabels(points)
                if let selected {
                    selectionRule(selected)
                }
            }
            .chartForegroundStyleScale([Series.snr.name: Series.snr.color])
            .chartLegend(.hidden)
            .chartXScale(domain: xDomain)
            .chartYScale(domain: 0 ... top)
            .chartXAxis { timeAxis(xDomain, labels: window.axisFormat, quarters: window == .oneMinute) }
            .chartYAxis { valueAxis { "\(Int($0))" } }
            .chartXSelection(value: $selectedDate)
            .frame(height: 140)
        }
    }

    private func chartPoints(_ plot: [PlotSample], _ series: Series, _ value: KeyPath<PlotSample, Double?>) -> [ChartPoint] {
        plot.runs(value, maxGap: window.maxGap).map { ChartPoint(series: series, segment: $0.run, date: $0.date, value: $0.value) }
    }

    private func bandPoints(_ plot: [PlotSample], _ series: Series, _ range: KeyPath<PlotSample, ClosedRange<Double>?>) -> [BandPoint] {
        plot.runs(range, maxGap: window.maxGap).map { BandPoint(series: series, segment: $0.run, date: $0.date, range: $0.value) }
    }

    /// Under the lines, in the same color, faint enough that the line stays the reading.
    @ChartContentBuilder
    private func ranges(_ bands: [BandPoint]) -> some ChartContent {
        ForEach(bands, id: \.self) { band in
            AreaMark(
                x: .value("Time", band.date),
                yStart: .value("Lowest", band.range.lowerBound),
                yEnd: .value("Highest", band.range.upperBound),
                series: .value("Band", "\(band.series.rawValue) \(band.segment)")
            )
            .foregroundStyle(by: .value("Series", band.series.name))
            .opacity(0.25)
        }
    }

    @ChartContentBuilder
    private func lines(_ points: [ChartPoint]) -> some ChartContent {
        ForEach(points, id: \.self) { point in
            LineMark(
                x: .value("Time", point.date),
                y: .value("Value", point.value),
                series: .value("Line", "\(point.series.rawValue) \(point.segment)")
            )
            .foregroundStyle(by: .value("Series", point.series.name))
            .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
        }
    }

    /// Only a line that reaches "now" gets a label; an older endpoint would show a
    /// stale value as if it were current.
    @ChartContentBuilder
    private func endLabels(_ points: [ChartPoint]) -> some ChartContent {
        ForEach(points.filter { $0.date == end }, id: \.self) { point in
            PointMark(x: .value("Time", point.date), y: .value("Value", point.value))
                .symbol {
                    // The surface ring keeps the dot legible where it sits on its line.
                    Circle().fill(point.series.color).frame(width: 8, height: 8)
                        .padding(2).background(Circle().fill(.background))
                }
                .annotation(position: .trailing, alignment: .leading, spacing: 4) {
                    Text(signed(Int(point.value.rounded())))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
        }
    }

    private func referenceLine(_ value: Int, _ label: LocalizedStringKey) -> some ChartContent {
        RuleMark(y: .value("Reference", Double(value)))
            .foregroundStyle(Color.reference)
            .lineStyle(StrokeStyle(lineWidth: 1))
            .annotation(position: .top, alignment: .leading, spacing: 2) {
                // The surface behind the text keeps it legible where a reading near the
                // threshold runs through it; the line hides for the label's width.
                Text(label).font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 3)
                    .background(.background, in: .rect(cornerRadius: 3))
                    // Clear of the axis labels, which can sit at the same height.
                    .padding(.leading, 3)
            }
    }

    private func selectionRule(_ sample: PlotSample) -> some ChartContent {
        RuleMark(x: .value("Time", sample.date))
            .foregroundStyle(Color.cursor)
            .lineStyle(StrokeStyle(lineWidth: 1))
    }

    /// Fixed label width: both charts share the time axis, so their plot areas must
    /// line up even though "−100" and "60" differ in width.
    private func valueAxis(_ format: @escaping (Double) -> String) -> some AxisContent {
        AxisMarks(position: .leading) { value in
            AxisGridLine(stroke: .hairline)
            AxisValueLabel {
                if let v = value.as(Double.self) {
                    Text(format(v)).frame(width: 32, alignment: .trailing)
                }
            }
        }
    }

    private func tooltip(_ sample: PlotSample) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            // A long window spans days.
            Text(sample.date, format: window.bucket == nil ? .dateTime.hour().minute().second() : .dateTime.month().day().hour().minute())
                .foregroundStyle(.secondary)
            tooltipRow(.rssi, sample.rssi.map { dBm(Int($0.rounded())) }, sample.rssiRange)
            tooltipRow(.noise, sample.noise.map { dBm(Int($0.rounded())) }, sample.noiseRange)
            tooltipRow(.snr, sample.snr.map { "\(Int($0.rounded())) dB" }, sample.snrRange)
        }
        .font(.caption)
        .padding(8)
        .background(.regularMaterial, in: .rect(cornerRadius: 6))
    }

    private func tooltipRow(_ series: Series, _ value: String?, _ range: ClosedRange<Double>?) -> some View {
        HStack(spacing: 6) {
            Capsule().fill(series.color).frame(width: 10, height: 3)
            Text(series.name).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value ?? "—").monospacedDigit()
            if let range {
                Text("\(signed(Int(range.lowerBound))) to \(signed(Int(range.upperBound)))")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
        }
    }
}
