import Foundation
import Testing
@testable import WiFiDetect

/// A store in a folder of its own, so tests never touch the real history.
func temporaryStore() -> SampleStore {
    SampleStore(directory: FileManager.default.temporaryDirectory.appending(path: "WiFiDetect-\(UUID().uuidString)"))
}

struct SampleStoreTests {
    /// Yesterday at noon UTC: mid-day, so readings a few seconds apart share a file
    /// whenever the test runs.
    private let noon = Date(timeIntervalSinceReferenceDate: ((Date.now.timeIntervalSinceReferenceDate / 86400).rounded(.down) - 0.5) * 86400)

    /// After a relaunch the charts and the CSV show what was measured: to the
    /// millisecond, and a missing reading still missing rather than 0 dBm.
    @Test func roundTripKeepsEveryReading() async {
        let store = temporaryStore()
        let samples = [
            WiFiSample(date: noon, rssi: -52, noise: -91),
            WiFiSample(date: noon.addingTimeInterval(0.25), rssi: 0, noise: -90),
            WiFiSample(date: noon.addingTimeInterval(0.5), rssi: -127, noise: 0),
        ]
        store.append(samples)
        let read = await store.readings(from: .distantPast, through: .now)
        #expect(read.map(\.date) == samples.map(\.date))
        #expect(read.map(\.rssi) == [-52, nil, -127])
        #expect(read.map(\.noise) == [-91, -90, nil])
    }

    /// Kept for 7 days, as the user chose: older readings go, from the disk too, and
    /// everything newer stays.
    @Test func dropsReadingsOlderThanSevenDays() async {
        let store = temporaryStore()
        let ages: [TimeInterval] = [8 * 86400, 7 * 86400 + 60, 7 * 86400 - 60, 3600]
        let dates = ages.map { Date.now.addingTimeInterval(-$0) }
        store.append(dates.map { WiFiSample(date: $0, rssi: -50, noise: -90) })
        let kept = await store.readings(from: .distantPast, through: .now)
        #expect(kept.map(\.date) == Array(dates.suffix(2)))
        #expect(!FileManager.default.fileExists(atPath: store.file(for: dates[0]).path))
    }

    /// A crash mid-write can cut the last record short. The whole ones before it must
    /// still load, and the next write must not land out of step with them, or every
    /// reading after it would decode as garbage.
    @Test func cutShortFileKeepsItsRecordsAndTakesNewOnes() async throws {
        let store = temporaryStore()
        store.append((0 ..< 3).map { WiFiSample(date: noon.addingTimeInterval(Double($0)), rssi: -50 - $0, noise: -90) })
        _ = await store.readings(from: .distantPast, through: .now)
        let handle = try FileHandle(forWritingTo: store.file(for: noon))
        // Two 10-byte records and half of the third.
        try handle.truncate(atOffset: 25)
        try handle.close()

        store.append([WiFiSample(date: noon.addingTimeInterval(10), rssi: -60, noise: -90)])
        let read = await store.readings(from: .distantPast, through: .now)
        #expect(read.map(\.rssi) == [-50, -51, -60])
    }

    /// A damaged or unreadable file costs its own day, never the other days, and never
    /// a crash.
    @Test func damagedFileLosesOnlyItsDay() async throws {
        let store = temporaryStore()
        let days = [noon.addingTimeInterval(-2 * 86400), noon.addingTimeInterval(-86400), noon]
        store.append(days.map { WiFiSample(date: $0, rssi: -50, noise: -90) })
        _ = await store.readings(from: .distantPast, through: .now)
        try Data(repeating: 0xA5, count: 1000).write(to: store.file(for: days[0]))
        try FileManager.default.removeItem(at: store.file(for: days[1]))
        try FileManager.default.createDirectory(at: store.file(for: days[1]), withIntermediateDirectories: false)

        let read = await store.readings(from: .distantPast, through: .now)
        #expect(read.map(\.date) == [noon])
    }
}

@MainActor
struct WiFiHistoryTests {
    /// After a relaunch the charts show the stored readings and then the new ones, with
    /// the time the app wasn't running as a gap, not a line drawn across it.
    @Test func relaunchShowsStoredThenNewWithAGap() async throws {
        let store = temporaryStore()
        let earlier = Date.now.addingTimeInterval(-7200)
        store.append((0 ..< 10).map { WiFiSample(date: earlier.addingTimeInterval(Double($0) / 2), rssi: -50, noise: -90) })
        let monitor = WiFiMonitor(store: store)
        // Taken while the store was loading.
        monitor.publish(WiFiSample(date: .now, rssi: -60, noise: -90), nil)
        await monitor.restore()

        #expect(monitor.history.samples.map(\.rssi) == Array(repeating: -50, count: 10) + [-60])
        let end = try #require(monitor.latest).date
        for window in [TimeWindow.oneDay, .sevenDays] {
            let plot = monitor.history.plot(window: window.rawValue, end: end)
            #expect(Set(plot.runs(\.rssi, maxGap: window.maxGap).map(\.run)).count == 2, "\(window.label)")
        }
    }

    /// Readings reach the disk every few seconds, not at the sampling rate, and a crash
    /// loses at most the last few seconds.
    @Test func readingsReachTheDiskInBatches() async {
        let store = temporaryStore()
        let monitor = WiFiMonitor(store: store)
        let start = Date.now.addingTimeInterval(-60)
        for tick in 0 ..< 12 {
            monitor.publish(WiFiSample(date: start.addingTimeInterval(Double(tick) / 2), rssi: -50, noise: -90), nil)
        }
        // The batch's five seconds and the reading that closed it; the last waits.
        #expect(await store.readings(from: .distantPast, through: .now).count == 11)
    }

    /// Clear History empties the charts and the disk, and a reading taken just before
    /// isn't written after it.
    @Test func clearHistoryEmptiesTheChartsAndTheDisk() async {
        let store = temporaryStore()
        store.append([WiFiSample(date: .now.addingTimeInterval(-3600), rssi: -50, noise: -90)])
        let monitor = WiFiMonitor(store: store)
        await monitor.restore()
        monitor.publish(WiFiSample(date: .now, rssi: -55, noise: -90), nil)

        monitor.clearHistory()
        #expect(monitor.history.samples.isEmpty)
        #expect(monitor.history.plot(window: TimeWindow.sevenDays.rawValue, end: .now).isEmpty)
        let later = Date.now.addingTimeInterval(1)
        monitor.publish(WiFiSample(date: later, rssi: -60, noise: -90), nil)
        monitor.publish(WiFiSample(date: later.addingTimeInterval(5), rssi: -61, noise: -90), nil)
        #expect(await store.readings(from: .distantPast, through: later.addingTimeInterval(10)).map(\.rssi) == [-60, -61])
    }

    /// The export covers the window on screen at full resolution, from the disk: the
    /// charts summarize a long window, the CSV mustn't. Readings not yet written are in.
    @Test func csvCoversTheWindowAtFullResolution() async throws {
        let store = temporaryStore()
        let now = Date.now
        // One reading two days ago, then a minute at 2 Hz an hour ago.
        store.append([WiFiSample(date: now.addingTimeInterval(-2 * 86400), rssi: -70, noise: -90)]
            + (0 ..< 120).map { WiFiSample(date: now.addingTimeInterval(-3600 + Double($0) / 2), rssi: -50, noise: -90) })
        let monitor = WiFiMonitor(store: store)
        await monitor.restore()
        monitor.publish(WiFiSample(date: now, rssi: -55, noise: -90), nil)

        let url = FileManager.default.temporaryDirectory.appending(path: "\(UUID().uuidString).csv")
        try await monitor.exportCSV(window: TimeWindow.oneDay.rawValue, to: url)
        let rows = try String(contentsOf: url, encoding: .utf8).split(separator: "\n").dropFirst()
        #expect(rows.count == 121)
        #expect(rows.last?.hasSuffix(",-55,-90,35") == true)
    }
}
