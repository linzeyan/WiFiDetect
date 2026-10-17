import CoreLocation
import CoreWLAN
import Observation
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "history")

/// The current link as of the last poll. SSID, BSSID and country stay nil without
/// Location authorization (macOS 14+); everything else needs none.
struct WiFiLink: Equatable, Sendable {
    var interfaceName: String?
    var isPoweredOn: Bool
    var ssid: String?
    var bssid: String?
    var countryCode: String?
    /// Mbps
    var txRate: Double
    /// mW
    var txPower: Int
    var channel: WiFiChannel?
    var phyMode: CWPHYMode
    var security: CWSecurity
}

@MainActor @Observable
final class WiFiMonitor {
    /// Hz (spec F1.1).
    static let rates = 1...4
    /// Seconds of readings written to disk at a time: a crash loses at most this much.
    static let batch: TimeInterval = 5
    nonisolated private static let summaries = TimeWindow.allCases.compactMap { window in
        window.bucket.map { (window: window.rawValue, bucket: $0) }
    }

    /// One hour at the fastest rate, and the long windows' summaries. An iPhone gets the
    /// hour on connect, as before there was a stored week: a week would be tens of MB,
    /// past the line it accepts (Companion.maxLine).
    private(set) var history = SampleHistory(capacity: 3600 * WiFiMonitor.rates.upperBound, summaries: WiFiMonitor.summaries)
    /// nil when the Mac has no Wi-Fi interface.
    private(set) var link: WiFiLink?
    private(set) var locationStatus: CLAuthorizationStatus
    /// Each new sample, after `link` is updated: the iPhone companion's feed.
    @ObservationIgnored var onSample: ((WiFiSample) -> Void)?
    private let locationManager = CLLocationManager()
    private var timer: DispatchSourceTimer?
    @ObservationIgnored private let store: SampleStore
    /// Readings not yet handed to the store.
    @ObservationIgnored private var pending: [WiFiSample] = []
    /// Bumped by a clear, so a restore that was already reading doesn't bring it back.
    @ObservationIgnored private var clears = 0

    init(store: SampleStore) {
        self.store = store
        locationStatus = locationManager.authorizationStatus
    }

    var latest: WiFiSample? { history.samples.last }

    /// macOS has a single authorized state; a when-in-use request lands here too.
    var isLocationAuthorized: Bool {
        locationStatus == .authorizedAlways
    }

    /// Starts polling, or re-times it when already running.
    func start(hz: Int) {
        let hz = min(max(hz, Self.rates.lowerBound), Self.rates.upperBound)
        (timer ?? makeTimer()).schedule(deadline: .now(), repeating: .milliseconds(1000 / hz))
    }

    private func makeTimer() -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        // Polled, not event-driven: linkQualityDidChange is never delivered (FB22464790).
        // @Sendable matters: an unannotated closure written in this @MainActor method
        // inherits main-actor isolation, and Swift 6 traps when the timer then runs it
        // on the utility queue.
        timer.setEventHandler { @Sendable [weak self] in
            let reading = Self.read()
            Task { @MainActor in self?.publish(reading.sample, reading.link) }
        }
        timer.resume()
        self.timer = timer
        return timer
    }

    /// Each call is a synchronous round trip to airportd, so this runs off main.
    nonisolated private static func read() -> (sample: WiFiSample, link: WiFiLink?) {
        guard let iface = CWWiFiClient.shared().interface() else {
            return (WiFiSample(date: .now, rssi: 0, noise: 0), nil)
        }
        let sample = WiFiSample(date: .now, rssi: iface.rssiValue(), noise: iface.noiseMeasurement())
        let link = WiFiLink(
            interfaceName: iface.interfaceName,
            isPoweredOn: iface.powerOn(),
            ssid: iface.ssid(),
            bssid: iface.bssid(),
            countryCode: iface.countryCode(),
            txRate: iface.transmitRate(),
            txPower: iface.transmitPower(),
            channel: iface.wlanChannel().map(WiFiChannel.init),
            phyMode: iface.activePHYMode(),
            security: iface.security()
        )
        return (sample, link)
    }

    func requestLocation() {
        locationManager.requestWhenInUseAuthorization()
    }

    /// Not private so tests can feed readings without a Wi-Fi interface.
    func publish(_ sample: WiFiSample, _ newLink: WiFiLink?) {
        history.append(sample)
        pending.append(sample)
        if sample.date.timeIntervalSince(pending[0].date) >= Self.batch { flush() }
        // Observation notifies on every assignment, equal or not; skip the no-ops so
        // views that read only these don't redraw at the sampling rate.
        if newLink != link { link = newLink }
        let status = locationManager.authorizationStatus
        if status != locationStatus { locationStatus = status }
        onSample?(sample)
    }

    private func flush() {
        guard !pending.isEmpty else { return }
        store.append(pending)
        pending = []
    }

    /// Brings back the stored week. The reading and summarizing happen off the main
    /// thread, so the first reading doesn't wait for them (Phase 1: within a second of
    /// launch); readings taken meanwhile go after the stored ones.
    func restore() async {
        let clears = clears
        let started = ContinuousClock.now
        let stored = await store.readings(from: .distantPast, through: .now)
        let capacity = history.capacity
        var restored = await Task.detached(priority: .utility) {
            SampleHistory(capacity: capacity, summaries: Self.summaries, samples: stored)
        }.value
        guard clears == self.clears else { return }
        let last = restored.samples.last?.date ?? .distantPast
        for sample in history.samples where sample.date > last {
            restored.append(sample)
        }
        history = restored
        log.notice("restored \(stored.count, privacy: .public) readings in \((ContinuousClock.now - started).formatted(.units(allowed: [.milliseconds])), privacy: .public)")
    }

    /// Settings › Wi-Fi: the charts start over, and the files go.
    func clearHistory() {
        clears += 1
        pending = []
        history = SampleHistory(capacity: history.capacity, summaries: Self.summaries)
        store.clear()
    }

    /// Every reading in the window, from disk: in memory, past the first hour there are
    /// only summaries. Off the main thread, as a week is about 50 MB of text.
    func exportCSV(window: TimeInterval, to url: URL) async throws {
        // Queued ahead of the read, so the export runs to the latest reading.
        flush()
        let end = latest?.date ?? .now
        let samples = await store.readings(from: end.addingTimeInterval(-window), through: end)
        try await Task.detached(priority: .userInitiated) {
            try samples.csv().write(to: url, atomically: true, encoding: .utf8)
        }.value
    }

    /// Why there's no reading, shown in place of the grade.
    var unavailableReason: String {
        guard let link else {
            return latest == nil ? String(localized: "Reading…") : String(localized: "No Wi-Fi interface")
        }
        return link.isPoweredOn ? String(localized: "Not connected") : String(localized: "Wi-Fi is off")
    }
}
