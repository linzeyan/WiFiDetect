import Foundation

/// The Mac shares its Wi-Fi readings with the iPhone companion over the local network
/// (spec F4.1): it advertises this Bonjour type, and the iPhone connects and listens.
/// The protocol is one JSON object per line, Mac to iPhone only.
enum Companion {
    static let serviceType = "_wifidetect._tcp"
    /// An hour of history at 4 Hz is under 1 MB of JSON. A longer line isn't one of
    /// ours, and buffering it waiting for a newline would grow without bound.
    static let maxLine = 4 << 20
}

/// The first message on a connection carries the whole history, so the iPhone's chart
/// starts full; every later one carries the newest sample.
struct CompanionMessage: Codable {
    var samples: [WiFiSample]
    /// nil when the Mac has no Wi-Fi interface.
    var link: SharedLink?

    /// Newline-terminated. JSONEncoder escapes newlines inside strings, so the only
    /// raw one is the terminator.
    func line() throws -> Data {
        try JSONEncoder().encode(self) + [0x0A]
    }
}

/// The Mac's link, minus what would identify the network: no SSID, no BSSID. Anyone on
/// the network can read these.
struct SharedLink: Codable, Equatable {
    var isPoweredOn: Bool
    /// Mbps
    var txRate: Double
    /// "36 · 5 GHz, 80 MHz"
    var channel: String?
}

/// Cuts a TCP byte stream into lines: a message can arrive in pieces, or several in
/// one read.
struct LineBuffer {
    struct LineTooLong: LocalizedError {
        var errorDescription: String? { String(localized: "The Mac sent more than expected.") }
    }

    private var pending = Data()

    /// The lines completed by `data`, without their newlines.
    mutating func append(_ data: Data) throws -> [Data] {
        pending.append(data)
        var lines: [Data] = []
        while let newline = pending.firstIndex(of: 0x0A) {
            lines.append(pending[pending.startIndex ..< newline])
            pending.removeSubrange(pending.startIndex ... newline)
        }
        if pending.count > Companion.maxLine { throw LineTooLong() }
        return lines
    }
}
