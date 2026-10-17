import CoreWLAN
import Observation

struct NearbyNetwork: Identifiable, Sendable {
    /// Position in the scan, strongest first. Without Location authorization there is
    /// no BSSID, and one SSID can sit on several channels, so nothing else is unique.
    let id: Int
    let ssid: String?
    let bssid: String?
    /// dBm
    let rssi: Int
    let channel: WiFiChannel?
    let security: CWSecurity
    let phyMode: CWPHYMode

    // Table sorts through KeyPathComparator, which needs non-optional Comparable keys.
    var ssidKey: String { ssid ?? "" }
    var bssidKey: String { bssid ?? "" }
    var channelKey: Int { channel?.number ?? 0 }
    var bandKey: Int { channel?.band.rawValue ?? 0 }
    var widthKey: Int { channel?.widthMHz ?? 0 }
    var securityKey: String { security.label }
    var phyKey: Int { phyMode.rawValue }
}

@MainActor @Observable
final class NetworkScanner {
    private(set) var networks: [NearbyNetwork] = []
    private(set) var isScanning = false
    private(set) var lastScan: Date?
    private(set) var error: String?

    func scan() async {
        guard !isScanning else { return }
        isScanning = true
        defer { isScanning = false }
        do {
            networks = try await Task.detached(priority: .utility) { try Self.scanBlocking() }.value
            lastScan = .now
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Blocks for the whole scan, about 6 s (wifi-signal-apis.md Q6).
    nonisolated private static func scanBlocking() throws -> [NearbyNetwork] {
        guard let iface = CWWiFiClient.shared().interface() else { return [] }
        return try iface.scanForNetworks(withSSID: nil, includeHidden: true)
            .sorted { $0.rssiValue > $1.rssiValue }
            .enumerated()
            .map { index, network in
                NearbyNetwork(
                    id: index,
                    ssid: network.ssid,
                    bssid: network.bssid,
                    rssi: network.rssiValue,
                    channel: network.wlanChannel.map(WiFiChannel.init),
                    security: CWSecurity.strongestFirst.first(where: network.supportsSecurity) ?? .unknown,
                    phyMode: CWPHYMode.newestFirst.first(where: network.supportsPHYMode) ?? .modeNone
                )
            }
    }
}
