import CoreWLAN
import Foundation
import Testing
@testable import WiFiDetect

struct SignalGradeTests {
    /// The spec states each grade as "this value or stronger", so a boundary value
    /// belongs to the better grade; one dB weaker drops a grade.
    @Test(arguments: [
        (-60, SignalGrade.excellent), (-61, .good),
        (-67, .good), (-68, .fair),
        (-70, .fair), (-71, .poor),
        (-80, .poor), (-81, .veryPoor),
    ])
    func rssiBoundaries(rssi: Int, expected: SignalGrade) {
        #expect(SignalThresholds().grade(rssi: rssi) == expected)
    }

    @Test(arguments: [(25, SNRGrade?.some(.voice)), (24, nil), (15, nil), (14, .poor)])
    func snrBoundaries(snr: Int, expected: SNRGrade?) {
        #expect(SignalThresholds().grade(snr: snr) == expected)
    }

    /// Settings persist through @AppStorage as a string; a value that doesn't parse
    /// must fall back to the defaults rather than load half a set.
    @Test func thresholdsRoundTripThroughStorage() {
        let custom = SignalThresholds(excellent: -55, good: -65, fair: -72, poor: -85, roam: -78, snrVoice: 30, snrPoor: 10)
        #expect(SignalThresholds(rawValue: custom.rawValue) == custom)
        #expect(SignalThresholds(rawValue: "-55,-65,-72") == nil)
    }
}

struct WiFiSampleTests {
    /// CoreWLAN reports 0 for "no reading". Taken at face value it would plot a 0 dBm
    /// spike and an SNR of rssi − 0.
    @Test func zeroMeansNoReading() {
        #expect(WiFiSample(date: .now, rssi: -50, noise: 0).snr == nil)
        #expect(WiFiSample(date: .now, rssi: 0, noise: -90).rssi == nil)
        #expect(WiFiSample(date: .now, rssi: -50, noise: -90).snr == 40)
    }
}

struct SampleHistoryTests {
    @Test func dropsOldestBeyondCapacity() {
        var history = SampleHistory(capacity: 3)
        for second in 1 ... 5 {
            history.append(sample(at: Double(second), rssi: -second))
        }
        #expect(history.samples.map(\.rssi) == [-3, -4, -5])
    }

    /// The one-hour window holds more samples than a chart can redraw at 2 Hz, so it
    /// is averaged down; but averaging must not paper over a disconnect.
    @Test func plotDownsamplesButKeepsGaps() throws {
        var history = SampleHistory(capacity: 10_000)
        // 20 minutes at 2 Hz, disconnected for the 11th minute.
        for tick in 0 ..< 2400 {
            let t = Double(tick) / 2
            history.append(sample(at: t, rssi: (600 ..< 660).contains(t) ? 0 : -50))
        }
        let end = try #require(history.samples.last).date
        let plot = history.plot(window: 1200, end: end, maxPoints: 100)
        #expect(plot.count == 100)
        #expect(plot.filter { $0.rssi == nil }.count == 5)
        #expect(plot.compactMap(\.rssi).allSatisfy { $0 == -50 })
    }

    /// A week is drawn as 20-minute points. Averaged alone, one reading at −90 dBm would
    /// barely move its point, and a drop like that is what someone looking at a week is
    /// after; so each point keeps its weakest and strongest reading.
    @Test func longWindowKeepsADropAndASpike() throws {
        let week = TimeWindow.sevenDays
        var history = SampleHistory(capacity: 100, summaries: [(week.rawValue, try #require(week.bucket))])
        // Two hours at 2 Hz, −50 dBm but for one reading at −90 and one at −30.
        for tick in 0 ..< 14_400 {
            history.append(sample(at: Double(tick) / 2, rssi: tick == 5000 ? -90 : tick == 9000 ? -30 : -50))
        }
        let plot = history.plot(window: week.rawValue, end: try #require(history.samples.last).date)
        let ranges = plot.compactMap(\.rssiRange)
        #expect(ranges.map(\.lowerBound).min() == -90)
        #expect(ranges.map(\.upperBound).max() == -30)
        // The line itself stays the typical reading.
        #expect(plot.compactMap(\.rssi).allSatisfy { abs($0 + 50) < 0.1 })
    }

    /// The long windows' points are minutes apart, but a disconnect, or hours with the
    /// app not running, must still break the line: joined up, it would claim a signal
    /// nobody measured.
    @Test func longWindowKeepsGapsAsGaps() throws {
        let day = TimeWindow.oneDay
        var history = SampleHistory(capacity: 100, summaries: [(day.rawValue, try #require(day.bucket))])
        var t = 0.0
        func readings(for seconds: Double, rssi: Int) {
            for _ in 0 ..< Int(seconds * 2) {
                history.append(sample(at: t, rssi: rssi))
                t += 0.5
            }
        }
        readings(for: 3600, rssi: -50)
        readings(for: 1800, rssi: 0) // disconnected
        readings(for: 3600, rssi: -50)
        t += 3 * 3600 // quit
        readings(for: 3600, rssi: -50)
        let plot = history.plot(window: day.rawValue, end: try #require(history.samples.last).date)
        #expect(Set(plot.runs(\.rssi, maxGap: day.maxGap).map(\.run)).count == 3)
    }

    private func sample(at seconds: Double, rssi: Int) -> WiFiSample {
        WiFiSample(date: Date(timeIntervalSinceReferenceDate: seconds), rssi: rssi, noise: -90)
    }
}

/// Every signal chart (the signal page, the menu bar, the iPhone) draws a line per run.
struct PlotRunsTests {
    /// A disconnect between two readings must show as a gap. Joined up, the line would
    /// claim a signal was measured while there was none.
    @Test func disconnectBreaksTheLine() {
        let runs = [plot(0, -60), plot(1, nil), plot(2, -62)].runs(\.rssi, maxGap: 5).map(\.run)
        #expect(runs.count == 2)
        #expect(runs[0] != runs[1])
    }

    /// Readings either side of a sleep are minutes apart with nothing nil in between;
    /// only the time gap shows the line must break there. Readings at the sampling rate
    /// must still join up.
    @Test func pauseInPollingBreaksTheLine() {
        let runs = [plot(0, -60), plot(1, -61), plot(7, -62)].runs(\.rssi, maxGap: 5).map(\.run)
        #expect(runs[0] == runs[1])
        #expect(runs[1] != runs[2])
    }

    private func plot(_ seconds: Double, _ rssi: Double?) -> PlotSample {
        PlotSample(date: Date(timeIntervalSinceReferenceDate: seconds), rssi: rssi, noise: -90)
    }
}

struct SignalCSVTests {
    /// Fixed offsets, so the expected text doesn't depend on this Mac's zone or DST.
    private let taipei = TimeZone(secondsFromGMT: 8 * 3600)!
    /// 2026-10-15 07:05:37.250 in Taipei.
    private let start = try! Date("2026-10-14T23:05:37Z", strategy: .iso8601).addingTimeInterval(0.25)

    /// Numbers names its columns from the first row, and the units live only there.
    @Test func headerThenOneRowPerSample() {
        let csv = [WiFiSample(date: start, rssi: -52, noise: -91)].csv(timeZone: taipei)
        #expect(csv == "time,rssi_dbm,noise_dbm,snr_db\n2026-10-15T07:05:37.250+08:00,-52,-91,39\n")
    }

    /// A 0 would chart as the strongest signal possible and drag an average up; an
    /// empty cell is a gap the spreadsheet skips.
    @Test func disconnectedIsEmptyCellsNotZero() {
        let csv = [WiFiSample(date: start, rssi: 0, noise: 0)].csv(timeZone: taipei)
        #expect(rows(csv) == ["2026-10-15T07:05:37.250+08:00,,,"])
    }

    /// SNR against a missing noise floor would just be the RSSI, a number that looks
    /// plausible and is wrong.
    @Test func snrOnlyWhenBothReadingsExist() {
        let csv = [
            WiFiSample(date: start, rssi: -50, noise: 0),
            WiFiSample(date: start, rssi: 0, noise: -90),
        ].csv(timeZone: taipei)
        #expect(rows(csv) == ["2026-10-15T07:05:37.250+08:00,-50,,", "2026-10-15T07:05:37.250+08:00,,-90,"])
    }

    /// Local wall-clock time is what the user remembers, and the offset keeps it
    /// unambiguous across zones; at 4 Hz, whole seconds would collapse four samples.
    @Test func timeIsLocalWithOffsetAndMilliseconds() {
        let samples = [WiFiSample(date: start, rssi: -50, noise: -90), WiFiSample(date: start.addingTimeInterval(0.25), rssi: -50, noise: -90)]
        #expect(times(samples.csv(timeZone: taipei)) == ["2026-10-15T07:05:37.250+08:00", "2026-10-15T07:05:37.500+08:00"])
        let pacific = TimeZone(secondsFromGMT: -7 * 3600)!
        #expect(times(samples.csv(timeZone: pacific)) == ["2026-10-14T16:05:37.250-07:00", "2026-10-14T16:05:37.500-07:00"])
    }

    /// A spreadsheet reads down in time; the export must keep the history's order.
    @Test func rowsAreOldestFirst() {
        let samples = (0 ..< 3).map { WiFiSample(date: start.addingTimeInterval(Double($0)), rssi: -50, noise: -90) }
        #expect(times(samples.csv(timeZone: taipei)) == ["2026-10-15T07:05:37.250+08:00", "2026-10-15T07:05:38.250+08:00", "2026-10-15T07:05:39.250+08:00"])
    }

    /// Data rows, without the header and the trailing newline.
    private func rows(_ csv: String) -> [String] {
        Array(csv.split(separator: "\n").dropFirst().map(String.init))
    }

    private func times(_ csv: String) -> [String] {
        rows(csv).map { String($0.prefix { $0 != "," }) }
    }
}

struct ChannelSpanTests {
    /// CoreWLAN reports only the primary channel. Drawing a wide channel around the
    /// primary instead of its real block would hide exactly the overlap the channel
    /// chart exists to show. One unit is 5 MHz.
    @Test(arguments: [
        (CWChannelBand.band2GHz, 6, CWChannelWidth.width20MHz, 4.0 ... 8.0),
        (.band5GHz, 36, .width80MHz, 34 ... 50),   // block 36–48
        (.band5GHz, 44, .width80MHz, 34 ... 50),   // same block, different primary
        (.band5GHz, 100, .width160MHz, 98 ... 130), // block 100–128
        (.band5GHz, 157, .width80MHz, 147 ... 163), // UNII-3 blocks start at 149
        (.band5GHz, 165, .width20MHz, 163 ... 167),
        (.band6GHz, 37, .width160MHz, 31 ... 63),   // block 33–61, center 47
    ])
    func span(band: CWChannelBand, number: Int, width: CWChannelWidth, expected: ClosedRange<Double>) {
        #expect(WiFiChannel(number: number, band: band, width: width).span == expected)
    }
}
