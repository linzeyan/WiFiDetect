import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Series colors are slots 1–3 of the dataviz reference palette, run through its
/// validator against this app's real surfaces (#ffffff light; #1e1e1e dark on the Mac,
/// #000000 on the iPhone). System orange and teal fail the dark-mode lightness band;
/// these pass in both modes. A series keeps its color on every chart. Light-mode SNR
/// green is under 3:1 on white, which is why the SNR line always carries a value label.
extension Color {
    static let rssi = Color(light: 0x2a78d6, dark: 0x3987e5)
    static let noise = Color(light: 0xeb6834, dark: 0xd95926)
    static let snr = Color(light: 0x1baf7a, dark: 0x199e70)
    // The traffic chart's pair: slots 1–2 again, a different chart from RSSI and noise.
    static let inbound = rssi
    static let outbound = noise
    // The iPhone's round-trip chart: slots 1–2 once more, on a chart of its own.
    static let router = rssi
    static let internet = noise

    // Status colors: the same in both modes, never used for a series, and always
    // paired with an icon and a label.
    static let statusGood = Color(light: 0x0ca30c, dark: 0x0ca30c)
    static let statusWarning = Color(light: 0xfab219, dark: 0xfab219)
    static let statusSerious = Color(light: 0xec835a, dark: 0xec835a)
    static let statusCritical = Color(light: 0xd03b3b, dark: 0xd03b3b)

    // Chart chrome stays gray. A bare `.secondary` inside a chart resolves against the
    // chart's default foreground, the accent color, and draws blue reference lines
    // beside the blue RSSI line.
    #if os(macOS)
    static let reference = Color(nsColor: .secondaryLabelColor)
    static let cursor = Color(nsColor: .tertiaryLabelColor)

    private init(light: UInt32, dark: UInt32) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let (r, g, b) = Self.components(appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light)
            return NSColor(srgbRed: r, green: g, blue: b, alpha: 1)
        })
    }
    #else
    static let reference = Color(uiColor: .secondaryLabel)
    static let cursor = Color(uiColor: .tertiaryLabel)

    private init(light: UInt32, dark: UInt32) {
        self.init(uiColor: UIColor { traits in
            let (r, g, b) = Self.components(traits.userInterfaceStyle == .dark ? dark : light)
            return UIColor(red: r, green: g, blue: b, alpha: 1)
        })
    }
    #endif

    private static func components(_ hex: UInt32) -> (CGFloat, CGFloat, CGFloat) {
        (CGFloat(hex >> 16 & 0xff) / 255, CGFloat(hex >> 8 & 0xff) / 255, CGFloat(hex & 0xff) / 255)
    }
}

extension StrokeStyle {
    /// Gridlines: solid and recessive. The default time-axis gridline is dashed.
    static let hairline = StrokeStyle(lineWidth: 0.5)
}

/// "−67 dBm" with a true minus sign; a hyphen reads as a dash at display sizes.
func dBm(_ value: Int) -> String {
    "\(signed(value)) dBm"
}

func signed(_ value: Int) -> String {
    value < 0 ? "\u{2212}\(-value)" : "\(value)"
}

/// Round trips on the local network are often a few ms, where a tenth matters.
func milliseconds(_ value: Double) -> String {
    "\(value.formatted(.number.precision(.fractionLength(value < 10 ? 1 : 0)))) ms"
}

extension SignalGrade {
    var label: String {
        switch self {
        case .excellent: String(localized: "Excellent")
        case .good: String(localized: "Good")
        case .fair: String(localized: "Fair")
        case .poor: String(localized: "Poor")
        case .veryPoor: String(localized: "Very poor")
        }
    }

    var color: Color {
        switch self {
        case .excellent, .good: .statusGood
        case .fair: .statusWarning
        case .poor: .statusSerious
        case .veryPoor: .statusCritical
        }
    }

    /// How much of the wifi symbol is lit.
    var bars: Double {
        switch self {
        case .excellent: 1
        case .good: 0.75
        case .fair: 0.5
        case .poor: 0.25
        case .veryPoor: 0
        }
    }
}

struct SignalGradeLabel: View {
    let grade: SignalGrade

    var body: some View {
        Label {
            Text(grade.label)
        } icon: {
            Image(systemName: "wifi", variableValue: grade.bars).foregroundStyle(grade.color)
        }
    }
}
