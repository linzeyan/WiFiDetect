import CoreWLAN
import Foundation

struct WiFiChannel: Hashable, Sendable {
    let number: Int
    let band: CWChannelBand
    let width: CWChannelWidth

    init(number: Int, band: CWChannelBand, width: CWChannelWidth) {
        self.number = number
        self.band = band
        self.width = width
    }

    init(_ channel: CWChannel) {
        self.init(number: channel.channelNumber, band: channel.channelBand, width: channel.channelWidth)
    }

    var widthMHz: Int? {
        switch width {
        case .width20MHz: 20
        case .width40MHz: 40
        case .width80MHz: 80
        case .width160MHz: 160
        default: nil
        }
    }

    /// The spectrum the channel occupies, in channel-number units (one unit is 5 MHz),
    /// for the channel chart. CoreWLAN reports the primary 20 MHz channel; a wider
    /// channel is the aligned block of 20 MHz channels that contains it.
    var span: ClosedRange<Double> {
        let blocks = (widthMHz ?? 20) / 20
        let center: Int
        if band == .band2GHz {
            // ponytail: CoreWLAN doesn't say whether a 2.4 GHz 40 MHz channel bonds up
            // or down; assume up from 1–7 and down above, the usual HT40+/HT40- split.
            center = blocks == 1 ? number : (number <= 7 ? number + 2 : number - 2)
        } else {
            // 5 GHz blocks are aligned from 36, and from 149 in UNII-3; 6 GHz from 1.
            let base = band == .band6GHz ? 1 : (number >= 149 ? 149 : 36)
            center = base + (number - base) / 4 / blocks * blocks * 4 + (blocks - 1) * 2
        }
        let half = Double(2 * blocks)
        return Double(center) - half ... Double(center) + half
    }
}

extension CWChannelBand {
    var label: String {
        switch self {
        case .band2GHz: "2.4 GHz"
        case .band5GHz: "5 GHz"
        case .band6GHz: "6 GHz"
        default: String(localized: "Unknown band")
        }
    }
}

extension WiFiChannel {
    var label: String {
        "\(number) · \(band.label)" + (widthMHz.map { ", \($0) MHz" } ?? "")
    }
}

extension CWPHYMode {
    /// Newest first: a scan result reports every mode it supports; the list shows the newest.
    static let newestFirst: [CWPHYMode] = [.mode11be, .mode11ax, .mode11ac, .mode11n, .mode11g, .mode11a, .mode11b]

    var label: String {
        switch self {
        case .mode11a: "802.11a"
        case .mode11b: "802.11b"
        case .mode11g: "802.11g"
        case .mode11n: "802.11n (Wi-Fi 4)"
        case .mode11ac: "802.11ac (Wi-Fi 5)"
        case .mode11ax: "802.11ax (Wi-Fi 6)"
        case .mode11be: "802.11be (Wi-Fi 7)"
        default: "—"
        }
    }
}

extension CWSecurity {
    /// Strongest first: a scan result reports every type it supports; the list shows the strongest.
    static let strongestFirst: [CWSecurity] = [
        .wpa3Enterprise, .wpa3Personal, .wpa3Transition, .wpa2Enterprise, .wpa2Personal,
        .enterprise, .personal, .wpaEnterpriseMixed, .wpaPersonalMixed, .wpaEnterprise, .wpaPersonal,
        .OWE, .oweTransition, .dynamicWEP, .WEP, CWSecurity.none,
    ]

    var label: String {
        switch self {
        case CWSecurity.none: String(localized: "Open")
        case .WEP: "WEP"
        case .dynamicWEP: String(localized: "Dynamic WEP")
        case .wpaPersonal: String(localized: "WPA Personal")
        case .wpaPersonalMixed: String(localized: "WPA/WPA2 Personal")
        case .wpa2Personal: String(localized: "WPA2 Personal")
        case .personal: String(localized: "Personal")
        case .wpaEnterprise: String(localized: "WPA Enterprise")
        case .wpaEnterpriseMixed: String(localized: "WPA/WPA2 Enterprise")
        case .wpa2Enterprise: String(localized: "WPA2 Enterprise")
        case .enterprise: String(localized: "Enterprise")
        case .wpa3Personal: String(localized: "WPA3 Personal")
        case .wpa3Enterprise: String(localized: "WPA3 Enterprise")
        case .wpa3Transition: String(localized: "WPA2/WPA3 Personal")
        case .OWE: String(localized: "Enhanced Open")
        case .oweTransition: String(localized: "Enhanced Open (transition)")
        default: String(localized: "Unknown")
        }
    }
}

extension [WiFiSample] {
    /// Every reading, in order, for Numbers or a report: the charts plot averages,
    /// which aren't readings. A missing reading is an empty cell, not 0, which a
    /// spreadsheet would average in as the strongest signal possible.
    func csv(timeZone: TimeZone = .current) -> String {
        // The wall-clock time the user remembers, with the offset that keeps it
        // unambiguous; milliseconds because samples come up to 4 a second.
        let time = Date.ISO8601FormatStyle(timeZone: timeZone).year().month().day().time(includingFractionalSeconds: true).timeZone(separator: .colon)
        let rows = map { sample in
            ([sample.date.formatted(time)] + [sample.rssi, sample.noise, sample.snr].map { $0.map(String.init) ?? "" }).joined(separator: ",")
        }
        return (["time,rssi_dbm,noise_dbm,snr_db"] + rows).joined(separator: "\n") + "\n"
    }
}
