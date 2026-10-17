import AppKit
import Charts
import SwiftUI

/// The signal at a glance with the main window closed, like Sniffnet's thumbnail mode.
/// A bare number: menu bar space is tight, and the panel spells out the unit.
struct MenuBarLabel: View {
    @Environment(WiFiMonitor.self) private var monitor

    var body: some View {
        if let rssi = monitor.latest?.rssi {
            HStack(spacing: 4) {
                Image(systemName: "wifi")
                // Monospaced, so the menu bar items beside it don't shift at the sampling rate.
                Text(signed(rssi)).monospacedDigit().accessibilityLabel(dBm(rssi))
            }
        } else {
            Image(systemName: "wifi.slash")
        }
    }
}

struct MenuBarPanel: View {
    @Environment(WiFiMonitor.self) private var monitor
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    @AppStorage(SettingsKey.thresholds) private var thresholds = SignalThresholds()

    var body: some View {
        let sample = monitor.latest
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(sample?.rssi.map(dBm) ?? "—").font(.title.weight(.semibold))
                Spacer()
                if let rssi = sample?.rssi {
                    SignalGradeLabel(grade: thresholds.grade(rssi: rssi))
                } else {
                    Label(monitor.unavailableReason, systemImage: "wifi.slash").foregroundStyle(.secondary)
                }
            }
            HStack(spacing: 20) {
                figure("Noise", sample?.noise.map(dBm))
                figure("SNR", sample?.snr.map { "\($0) dB" })
            }
            MiniSignalChart(history: monitor.history, end: sample?.date ?? .now, voip: thresholds.good)
            Divider()
            Button("Open WiFiDetect") {
                // The panel stays up over the window it opened otherwise.
                dismiss()
                openWindow(id: "main")
                // Clicking a menu bar item doesn't activate the app, so the window would
                // otherwise open behind the frontmost app.
                NSApp.activate()
            }
        }
        .padding()
        .frame(width: 300)
    }

    private func figure(_ label: LocalizedStringKey, _ value: String?) -> some View {
        HStack(spacing: 6) {
            Text(label).foregroundStyle(.secondary)
            Text(value ?? "—").monospacedDigit()
        }
    }
}

/// The signal page's RSSI and noise lines, shrunk: same colors and VoIP line, no time
/// axis, no hover.
private struct MiniSignalChart: View {
    let history: SampleHistory
    let end: Date
    /// dBm
    let voip: Int

    var body: some View {
        let window = TimeWindow.fiveMinutes
        let plot = history.plot(window: window.rawValue, end: end)
        // The legend shows these, and the color scale is keyed by them.
        let rssi = String(localized: "RSSI"), noise = String(localized: "Noise"), reference = String(localized: "VoIP and streaming")
        let points = line(rssi, plot, \.rssi, window) + line(noise, plot, \.noise, window)
        let values = points.map(\.value)
        VStack(alignment: .leading, spacing: 4) {
            Text("Last 5 minutes").font(.caption).foregroundStyle(.secondary)
            Chart {
                ForEach(points, id: \.self) { point in
                    LineMark(
                        x: .value("Time", point.date),
                        y: .value("dBm", point.value),
                        series: .value("Line", "\(point.series) \(point.run)")
                    )
                    .foregroundStyle(by: .value("Series", point.series))
                    .lineStyle(StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
                }
                // Named in the legend, not on the line: readings near the threshold would
                // run through a label, and the translucent panel has no surface color
                // to back one with, as the signal page does.
                RuleMark(y: .value("Reference", Double(voip)))
                    .foregroundStyle(by: .value("Series", reference))
                    .lineStyle(StrokeStyle(lineWidth: 1))
            }
            .chartForegroundStyleScale([rssi: Color.rssi, noise: Color.noise, reference: Color.reference])
            .chartXScale(domain: end.addingTimeInterval(-window.rawValue) ... end)
            .chartYScale(domain: min(-100, (values.min() ?? -100) - 5) ... max(-20, (values.max() ?? -20) + 5))
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                    AxisGridLine(stroke: .hairline)
                    AxisValueLabel {
                        if let v = value.as(Double.self) { Text(signed(Int(v))) }
                    }
                }
            }
            .frame(height: 110)
        }
    }

    private func line(_ series: String, _ plot: [PlotSample], _ value: KeyPath<PlotSample, Double?>, _ window: TimeWindow) -> [MiniChartPoint] {
        plot.runs(value, maxGap: window.maxGap).map { MiniChartPoint(series: series, run: $0.run, date: $0.date, value: $0.value) }
    }
}

private struct MiniChartPoint: Hashable {
    let series: String
    /// A line breaks between runs, so it never bridges a time nothing was measured.
    let run: Int
    let date: Date
    let value: Double
}
