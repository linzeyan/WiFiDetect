import Foundation
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "history")

/// The last seven days of Wi-Fi readings on disk, so the signal page picks up where it
/// left off after a relaunch. Readings only (time, RSSI, noise): no network name, no
/// BSSID. Traffic and proxy data aren't kept.
///
/// One append-only file per UTC day of fixed 10-byte records, rather than SQLite:
/// pruning is deleting a file; a crash mid-write can only cut the last record short,
/// which a read skips and the next write trims; and a damaged file costs that day, never
/// the others. UTC, so a time zone change can't put a reading in another day's file.
/// 10 bytes at 2 Hz is about 12 MB a week, 24 MB at 4 Hz.
final class SampleStore: Sendable {
    static let retention: TimeInterval = 7 * 86400
    static let defaultDirectory = URL.applicationSupportDirectory.appending(path: "WiFiDetect/Wi-Fi Readings")
    /// Seconds since 2001 (Float64), RSSI and noise (Int8, 0 for none, as CoreWLAN says).
    private static let recordSize = 10
    /// 2026-10-16.bin: names sort by date, which reads and pruning rely on.
    private static let dayName = Date.ISO8601FormatStyle(timeZone: .gmt).year().month().day()

    let directory: URL
    /// Serial: a read sees every write queued before it.
    private let queue = DispatchQueue(label: "com.zeyanlin.wifidetect.history", qos: .utility)

    init(directory: URL = defaultDirectory) {
        self.directory = directory
        queue.async { [self] in prune() }
    }

    /// Returns at once; the write happens on the store's queue.
    func append(_ samples: [WiFiSample]) {
        queue.async { [self] in
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                var startedADay = false
                for (url, group) in Dictionary(grouping: samples, by: { file(for: $0.date) }) {
                    startedADay = try write(group, to: url) || startedADay
                }
                // A new file means a new day, which is when the oldest file falls out.
                if startedADay { prune() }
            } catch {
                log.error("write failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Every reading from `start` through `end` that is still kept, oldest first.
    func readings(from start: Date, through end: Date) async -> [WiFiSample] {
        await withCheckedContinuation { continuation in
            queue.async { [self] in continuation.resume(returning: read(from: start, through: end)) }
        }
    }

    func clear() {
        queue.async { [self] in
            do {
                try FileManager.default.removeItem(at: directory)
            } catch CocoaError.fileNoSuchFile {
                // Nothing stored yet.
            } catch {
                log.error("clear failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Not private so tests can damage one.
    func file(for date: Date) -> URL {
        directory.appending(path: date.formatted(Self.dayName) + ".bin")
    }

    /// Whether the file is new.
    private func write(_ samples: [WiFiSample], to url: URL) throws -> Bool {
        let created = !FileManager.default.fileExists(atPath: url.path)
        if created {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        let end = try handle.seekToEnd()
        // Left by a crash mid-write; appending after it would misalign every record
        // that follows.
        let partial = end % UInt64(Self.recordSize)
        if partial != 0 {
            try handle.truncate(atOffset: end - partial)
        }
        var data = Data(capacity: samples.count * Self.recordSize)
        for sample in samples {
            withUnsafeBytes(of: sample.date.timeIntervalSinceReferenceDate.bitPattern.littleEndian) { data.append(contentsOf: $0) }
            data.append(UInt8(bitPattern: Int8(clamping: sample.rssi ?? 0)))
            data.append(UInt8(bitPattern: Int8(clamping: sample.noise ?? 0)))
        }
        try handle.write(contentsOf: data)
        return created
    }

    private func read(from start: Date, through end: Date) -> [WiFiSample] {
        let start = max(start, Date.now.addingTimeInterval(-Self.retention))
        let first = file(for: start).lastPathComponent
        let last = file(for: end).lastPathComponent
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        var samples: [WiFiSample] = []
        for name in names.sorted() where name.hasSuffix(".bin") && name >= first && name <= last {
            // A file that can't be read costs its own day.
            guard let data = try? Data(contentsOf: directory.appending(path: name), options: .mappedIfSafe) else { continue }
            data.withUnsafeBytes { bytes in
                // A partial record at the end, cut short by a crash, is left out.
                for offset in stride(from: 0, through: bytes.count - Self.recordSize, by: Self.recordSize) {
                    let time = Double(bitPattern: UInt64(littleEndian: bytes.loadUnaligned(fromByteOffset: offset, as: UInt64.self)))
                    let date = Date(timeIntervalSinceReferenceDate: time)
                    // Also what drops a damaged record: garbage bytes make a time far
                    // outside the week, or NaN, which fails both.
                    guard date >= start, date <= end else { continue }
                    samples.append(WiFiSample(date: date, rssi: Int(Int8(bitPattern: bytes[offset + 8])), noise: Int(Int8(bitPattern: bytes[offset + 9]))))
                }
            }
        }
        return samples
    }

    /// Deletes the files of days that ended before the retention began. The day it
    /// begins in stays, and reads leave out its older readings.
    private func prune() {
        let oldest = file(for: Date.now.addingTimeInterval(-Self.retention)).lastPathComponent
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return }
        for name in names where name.hasSuffix(".bin") && name < oldest {
            do {
                try FileManager.default.removeItem(at: directory.appending(path: name))
            } catch {
                log.error("prune failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}
