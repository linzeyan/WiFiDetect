import Foundation

/// One poll of the current link. CoreWLAN reports 0 for "no reading" (not associated,
/// Wi-Fi off, or a failed read), so 0 becomes nil here instead of being plotted as
/// the strongest signal possible.
struct WiFiSample: Codable, Sendable {
    let date: Date
    /// dBm
    let rssi: Int?
    /// dBm
    let noise: Int?

    init(date: Date, rssi: Int, noise: Int) {
        self.date = date
        self.rssi = rssi == 0 ? nil : rssi
        self.noise = noise == 0 ? nil : noise
    }

    /// dB. Only the current link has one: scan results almost never carry noise.
    var snr: Int? {
        guard let rssi, let noise else { return nil }
        return rssi - noise
    }
}

/// The newest `capacity` readings, which the short windows plot and an iPhone gets on
/// connect, plus a running summary for each long window. A week at 2 Hz is 1.2 million
/// readings: too many to hold as samples, and to re-bucket at every redraw. The readings
/// themselves stay on disk, for the CSV.
struct SampleHistory {
    let capacity: Int
    private(set) var samples: [WiFiSample]
    private(set) var summaries: [SampleSummary]

    /// `summaries`: each long window, in seconds, and the seconds each of its points covers.
    /// `samples`: oldest first, all of them summarized, the newest `capacity` kept.
    init(capacity: Int, summaries: [(window: TimeInterval, bucket: TimeInterval)] = [], samples: [WiFiSample] = []) {
        self.capacity = capacity
        // Not append(): past capacity it shifts the array once per sample.
        self.samples = Array(samples.suffix(capacity))
        self.summaries = summaries.map { SampleSummary(window: $0.window, bucket: $0.bucket) }
        for sample in samples {
            for i in self.summaries.indices { self.summaries[i].append(sample) }
        }
    }

    mutating func append(_ sample: WiFiSample) {
        samples.append(sample)
        // ponytail: shifts the whole array once full; at 14,400 samples and 4 Hz that
        // is noise. Swap in a ring buffer only if capacity grows by orders of magnitude.
        if samples.count > capacity {
            samples.removeFirst(samples.count - capacity)
        }
        for i in summaries.indices { summaries[i].append(sample) }
    }

    /// The samples in `[end - window, end]`, averaged into fixed time buckets when
    /// there are more than `maxPoints`, so a one-hour window still redraws at the
    /// sampling rate without hanging the main thread. Buckets are aligned to absolute
    /// time so they don't shift, and the line doesn't shimmer, as the window slides.
    /// A bucket with no reading stays nil, so a disconnect still shows as a gap.
    /// A long window comes from its summary instead, with each bucket's extremes.
    func plot(window: TimeInterval, end: Date, maxPoints: Int = 600) -> [PlotSample] {
        let start = end.addingTimeInterval(-window)
        if let summary = summaries.first(where: { $0.window == window }) {
            return summary.buckets.drop { $0.date < start }.map(\.plot)
        }
        let visible = samples.drop { $0.date < start }
        guard visible.count > maxPoints else {
            return visible.map { PlotSample(date: $0.date, rssi: $0.rssi.map(Double.init), noise: $0.noise.map(Double.init)) }
        }
        let bucket = window / Double(maxPoints)
        let buckets = Dictionary(grouping: visible) { ($0.date.timeIntervalSinceReferenceDate / bucket).rounded(.down) }
        return buckets.keys.sorted().map { key in
            let group = buckets[key]!
            return PlotSample(date: group.last!.date, rssi: mean(group.compactMap(\.rssi)), noise: mean(group.compactMap(\.noise)))
        }
    }

    private func mean(_ values: [Int]) -> Double? {
        values.isEmpty ? nil : Double(values.reduce(0, +)) / Double(values.count)
    }
}

/// A long window's readings, `bucket` seconds to a point, updated as they arrive.
struct SampleSummary {
    let window: TimeInterval
    let bucket: TimeInterval
    private(set) var buckets: [Bucket] = []

    struct Bucket {
        let key: Double
        /// The newest reading's, as for the short windows: the last point is "now".
        var date: Date
        var rssi = ReadingStats(), noise = ReadingStats(), snr = ReadingStats()

        var plot: PlotSample {
            PlotSample(date: date, rssi: rssi.mean, noise: noise.mean, rssiRange: rssi.range, noiseRange: noise.range, snrRange: snr.range)
        }
    }

    mutating func append(_ sample: WiFiSample) {
        // Aligned to absolute time, like the short windows' buckets.
        let key = (sample.date.timeIntervalSinceReferenceDate / bucket).rounded(.down)
        if buckets.last?.key != key {
            buckets.append(Bucket(key: key, date: sample.date))
            // One more than the window holds: the oldest is cut by the window's start.
            if Double(buckets.count) > window / bucket + 1 { buckets.removeFirst() }
        }
        buckets[buckets.count - 1].date = sample.date
        buckets[buckets.count - 1].rssi.add(sample.rssi)
        buckets[buckets.count - 1].noise.add(sample.noise)
        buckets[buckets.count - 1].snr.add(sample.snr)
    }
}

/// One series in a bucket. The mean draws the line and the extremes a band around it:
/// averaged alone, a ten-second drop in a 20-minute bucket would barely move the line,
/// and that drop is what someone looking at a week is after.
struct ReadingStats {
    private var low = Int.max, high = Int.min, total = 0, count = 0

    mutating func add(_ value: Int?) {
        guard let value else { return }
        low = min(low, value)
        high = max(high, value)
        total += value
        count += 1
    }

    /// nil when the bucket has no reading, so a disconnect stays a gap.
    var mean: Double? { count == 0 ? nil : Double(total) / Double(count) }
    var range: ClosedRange<Double>? { count == 0 ? nil : Double(low) ... Double(high) }
}

struct PlotSample {
    let date: Date
    let rssi: Double?
    let noise: Double?
    /// A long window's point: its bucket's lowest and highest readings. nil in the
    /// short windows, which plot readings or a few seconds' average.
    var rssiRange: ClosedRange<Double>? = nil
    var noiseRange: ClosedRange<Double>? = nil
    var snrRange: ClosedRange<Double>? = nil

    var snr: Double? {
        guard let rssi, let noise else { return nil }
        return rssi - noise
    }
}

extension [PlotSample] {
    /// One series' readings, numbered by unbroken run. Charts draw each run as a line of
    /// its own, so a disconnect, or readings further apart than `maxGap` (the Mac slept,
    /// polling stopped), shows as a gap rather than a line through time nothing was
    /// measured.
    func runs<Value>(_ value: KeyPath<PlotSample, Value?>, maxGap: TimeInterval) -> [(run: Int, date: Date, value: Value)] {
        var points: [(run: Int, date: Date, value: Value)] = []
        var run = 0
        var previous: Date?
        for sample in self {
            guard let v = sample[keyPath: value] else {
                previous = nil
                continue
            }
            if previous.map({ sample.date.timeIntervalSince($0) > maxGap }) ?? true {
                run += 1
            }
            points.append((run, sample.date, v))
            previous = sample.date
        }
        return points
    }
}

enum SignalGrade {
    case excellent, good, fair, poor, veryPoor
}

enum SNRGrade {
    case voice, poor
}

/// Guidance, not spec: chipsets scale RSSI differently (wifi-signal-apis.md Q12), so
/// every boundary is adjustable in Settings.
struct SignalThresholds: Equatable {
    var excellent = -60
    /// Also drawn on the chart as the VoIP and streaming minimum.
    var good = -67
    var fair = -70
    var poor = -80
    /// Drawn on the chart: where a Mac starts looking for an access point to roam to.
    var roam = -75
    var snrVoice = 25
    var snrPoor = 15

    /// Each boundary belongs to the better grade ("good is −67 dBm or stronger").
    func grade(rssi: Int) -> SignalGrade {
        switch rssi {
        case excellent...: .excellent
        case good...: .good
        case fair...: .fair
        case poor...: .poor
        default: .veryPoor
        }
    }

    /// nil in between: the spec labels only the two ends.
    func grade(snr: Int) -> SNRGrade? {
        snr >= snrVoice ? .voice : snr < snrPoor ? .poor : nil
    }
}

/// One comma-separated string, so a single @AppStorage key holds the whole set. A
/// value that doesn't parse (say, from a build with other fields) reads as nil, and
/// @AppStorage falls back to the defaults.
extension SignalThresholds: RawRepresentable {
    init?(rawValue: String) {
        let values = rawValue.split(separator: ",").compactMap { Int($0) }
        guard values.count == 7 else { return nil }
        (excellent, good, fair, poor, roam, snrVoice, snrPoor) = (values[0], values[1], values[2], values[3], values[4], values[5], values[6])
    }

    var rawValue: String {
        [excellent, good, fair, poor, roam, snrVoice, snrPoor].map(String.init).joined(separator: ",")
    }
}
