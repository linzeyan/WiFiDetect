#if DEBUG
import Foundation

/// Made-up readings for App Store screenshots, on with `-demo YES`: a simulator has no
/// router, no Wi-Fi to rate and no Mac sharing its readings. Fixed curves rather than
/// random ones, so every run takes the same pictures.
enum Demo {
    static let isOn = UserDefaults.standard.bool(forKey: "demo")

    static let link = SharedLink(isPoweredOn: true, txRate: 1201, channel: "149 · 5 GHz, 80 MHz")

    /// The Mac's last hour at 2 Hz: a slow drift, a little flutter, and one fade 20
    /// minutes ago, the kind of thing the chart is for.
    static func macHistory(until end: Date) -> [WiFiSample] {
        (0 ..< 7200).map { i in
            let t = Double(i) / 2
            let fade = 14 * exp(-pow((t - 2400) / 40, 2))
            let rssi = -54 + 3 * sin(t / 95) + 1.5 * sin(t / 6) - fade
            let noise = -93 + sin(t / 37)
            return WiFiSample(date: end.addingTimeInterval(t - 3599.5), rssi: Int(rssi.rounded()), noise: Int(noise.rounded()))
        }
    }

    /// A minute of pings, one a second, around `median` ms.
    static func pings(until end: Date, median: Double, spread: Double) -> PingStats {
        var stats = PingStats()
        for i in 0 ..< PingStats.capacity {
            let t = Double(i)
            let rtt = median + spread * (sin(t * 1.3) + 0.6 * sin(t * 0.37))
            stats.append(PingResult(date: end.addingTimeInterval(t - 59), rtt: max(1, rtt)))
        }
        return stats
    }
}
#endif
