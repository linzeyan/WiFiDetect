import Foundation
import Network
import NetworkExtension
import Security

/// The network extension (architecture §3, Network extension): one system extension holding a content
/// filter, which names the app behind each new connection, and a transparent proxy,
/// which hands the HTTPS of apps the user picked to the app's proxy. Only the
/// Developer ID build carries it (`make dist`); a development build runs without.
enum ExtensionConstants {
    static let identifier = "com.zeyanlin.wifidetect.extension"
    /// Network Extension wants the Mach service under an app group the extension holds;
    /// on macOS a team-prefixed group needs no registration. The Info.plist and the
    /// entitlements spell the same names with $(TeamIdentifierPrefix).
    static let machServiceName = "\(HelperConstants.teamID).\(identifier)"
    /// What the app demands of the extension. The extension demands
    /// `HelperConstants.appRequirement` of the app, as the helper does.
    static let extensionRequirement = HelperConstants.requirement(identifier: identifier)
    /// Inside the app bundle; only the Developer ID build has it.
    static let bundlePath = "Contents/Library/SystemExtensions/\(identifier).systemextension"
}

/// Served by the extension, called by the app.
@objc protocol ExtensionProtocol {
    /// A property-list encoded `CaptureSettings`, sent every `CaptureGate.renewal`
    /// seconds while the app wants the filter's reports or capture. The connection
    /// that renews is the one the reports go to.
    func renew(_ settings: Data)
}

/// Served by the app, called by the extension.
@objc protocol ExtensionClientProtocol {
    /// A property-list encoded `[FlowReport]`.
    func didReport(_ batch: Data)
}

struct CaptureSettings: Codable, Equatable, Sendable {
    /// The proxy's port; 0 captures nothing.
    var port = 0
    /// Paths of the apps (bundles) and programs whose HTTPS goes to the proxy.
    var apps: [String] = []
}

/// Which new flows the transparent proxy takes, and where they go. Every doubt sends a
/// flow direct: an app the proxy can't serve must still reach the network.
struct CaptureGate: Sendable {
    /// How often the app renews, and how long a renewal holds: five missed in a row
    /// mean the app is hung, and a hung app's proxy answers nothing.
    static let renewal: TimeInterval = 2
    static let lease: TimeInterval = 10
    /// How long new flows go direct after the proxy refused one or didn't answer.
    static let backoff: TimeInterval = 30
    /// Never captured, whatever the list says. The proxy's own connections to servers
    /// come from the app, and capturing them would send them back into the proxy.
    static let exempt: Set = [HelperConstants.appIdentifier, HelperConstants.machServiceName, ExtensionConstants.identifier]

    private(set) var settings = CaptureSettings()
    private var renewed = Date.distantPast
    private var failed = Date.distantPast

    mutating func renew(_ settings: CaptureSettings, at now: Date) {
        self.settings = settings
        renewed = now
    }

    /// The app's connection is gone: it quit, crashed or was killed.
    mutating func disconnect() {
        settings = CaptureSettings()
    }

    mutating func proxyFailed(at now: Date) {
        failed = now
    }

    enum Decision: Equatable, Sendable {
        case direct
        case proxy(port: Int)
        /// QUIC, refused so the app falls back to TCP, which the proxy can take.
        case refuse
    }

    /// `path` is only asked for once everything cheaper has passed: it's a code-signing
    /// lookup, and every new HTTPS connection on the Mac comes through here.
    func decide(identifier: String?, remote: Network.NWEndpoint.Host?, udp: Bool, at now: Date, path: () -> String?) -> Decision {
        guard settings.port != 0, !settings.apps.isEmpty,
              now.timeIntervalSince(renewed) < Self.lease, now.timeIntervalSince(failed) >= Self.backoff,
              !(identifier.map(Self.exempt.contains) ?? false), !Self.isLocal(remote),
              let path = path(), settings.apps.contains(where: { Self.covers($0, path) })
        else { return .direct }
        return udp ? .refuse : .proxy(port: settings.port)
    }

    /// An app bundle covers its helpers, which live inside it and make most of a
    /// browser's connections; a program covers only itself.
    static func covers(_ app: String, _ path: String) -> Bool {
        let app = app.hasSuffix("/") ? String(app.dropLast()) : app
        return !app.isEmpty && (path == app || path.hasPrefix(app + "/"))
    }

    /// The network rules leave these out already; this holds if a rule is ever wrong.
    static func isLocal(_ host: Network.NWEndpoint.Host?) -> Bool {
        switch host {
        case .ipv4(let address): address.isLoopback || address.isLinkLocal
        case .ipv6(let address): address.isLoopback || address.isLinkLocal
        default: false
        }
    }
}

/// What the transparent proxy is shown: HTTPS over TCP for the proxy, and over UDP so
/// QUIC can be refused, to any address. A wildcard address leaves out loopback by
/// itself; link-local goes too, since printers, AirPlay and captive portals there have
/// no business in the proxy.
// ponytail: port 443 only. Plain HTTP on 80 would reach the proxy as a tunnel it
// doesn't read; send it origin-form requests instead if HTTP debugging needs it.
enum ProxyRules {
    static var settings: NETransparentProxyNetworkSettings {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = ["0.0.0.0", "::"].flatMap { any in
            [
                NENetworkRule(destinationNetworkEndpoint: .hostPort(host: .init(any), port: 443), prefix: 0, protocol: .TCP),
                NENetworkRule(destinationNetworkEndpoint: .hostPort(host: .init(any), port: 443), prefix: 0, protocol: .UDP),
            ]
        }
        settings.excludedNetworkRules = [("169.254.0.0", 16), ("fe80::", 10)].map { network, prefix in
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: .init(network), port: 0), prefix: prefix, protocol: .any)
        }
        return settings
    }
}

/// A new connection as the content filter saw it. The app matches it to captured
/// traffic by protocol and local port, as it does libproc's socket table.
struct FlowReport: Codable, Equatable, Sendable {
    struct Process: Codable, Equatable, Sendable {
        var pid: Int32
        /// The app bundle, or the program when it has none; empty when its code
        /// couldn't be looked up.
        var path: String
        var identifier: String?
    }

    var time: Date
    var proto: UInt8
    var local: IPAddress?
    var localPort: UInt16
    var remote: IPAddress?
    var remotePort: UInt16
    /// The name the app connected by, when it used one (Network.framework, URLSession).
    var remoteHostname: String?
    /// Who the connection is for.
    var app: Process
    /// Who opened it, when that's a system daemon working for `app`.
    var via: Process?

    /// Address and port of an endpoint as Network Extension hands it over; nil while
    /// the socket has no port yet, when nothing could match it.
    static func parse(_ endpoint: Network.NWEndpoint?) -> (address: IPAddress?, port: UInt16)? {
        guard case .hostPort(let host, let port)? = endpoint, port.rawValue != 0 else { return nil }
        return (IPAddress(host: host), port.rawValue)
    }
}

extension IPAddress {
    init?(host: Network.NWEndpoint.Host) {
        switch host {
        case .ipv4(let address): self = address.rawValue.withUnsafeBytes { IPAddress(v4Bytes: $0) }
        case .ipv6(let address): self = address.rawValue.withUnsafeBytes { IPAddress(v6Bytes: $0) }
        default: return nil
        }
    }
}

/// The filter's reports waiting for the next send, every quarter second as the
/// helper batches packets. Bounded: the extension runs as root on every connection
/// the Mac makes, and an app that stops reading mustn't make it grow. The newest are
/// kept, their connections being the likeliest still open.
struct ReportBuffer: Sendable {
    static let limit = 4096
    private var reports: [FlowReport] = []

    var isEmpty: Bool { reports.isEmpty }

    mutating func append(_ report: FlowReport) {
        reports.append(report)
        if reports.count > Self.limit {
            reports.removeFirst(reports.count - Self.limit)
        }
    }

    /// Empties the buffer into one batch; nil when there's nothing to send.
    mutating func drain() -> Data? {
        guard !reports.isEmpty else { return nil }
        defer { reports.removeAll(keepingCapacity: true) }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try? encoder.encode(reports)
    }

    static func decode(_ batch: Data) -> [FlowReport]? {
        try? PropertyListDecoder().decode([FlowReport].self, from: batch)
    }
}

/// Who's behind an audit token, from the kernel's code-signing records: the lookup
/// XPC peer checks use, which the extension's sandbox allows.
enum ProcessIdentity {
    static func lookup(_ token: Data) -> FlowReport.Process? {
        guard token.count == MemoryLayout<audit_token_t>.size else { return nil }
        let pid = audit_token_to_pid(token.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        var code: SecCode?
        var staticCode: SecStaticCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode
        else { return FlowReport.Process(pid: pid, path: "") }
        var url: CFURL?
        var info: CFDictionary?
        SecCodeCopyPath(staticCode, [], &url)
        SecCodeCopySigningInformation(staticCode, [], &info)
        return FlowReport.Process(pid: pid, path: (url as URL?)?.path ?? "", identifier: (info as? [String: Any])?[kSecCodeInfoIdentifier as String] as? String)
    }
}

/// How the transparent proxy hands a connection to the app's proxy: the CONNECT any
/// proxy client sends, so the proxy needs nothing new, with a header naming the app.
/// The proxy reads it, and it goes no further: a CONNECT's headers end at the proxy.
enum ConnectPreface {
    static let appHeader = "X-WiFiDetect-App"

    /// The host to ask for: the name the app connected by, else the one in its
    /// ClientHello, else the address. A name with anything but hostname characters
    /// is passed over, since it goes into a request line.
    static func host(remoteHostname: String?, hello: Data, address: Network.NWEndpoint.Host) -> String? {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        for name in [remoteHostname, TLS.serverName(in: hello)] {
            if let name, !name.isEmpty, name.count <= 253, name.allSatisfy(allowed.contains) {
                return name
            }
        }
        return IPAddress(host: address)?.description
    }

    static func request(host: String, port: UInt16, app: String) -> Data {
        let authority = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        let app = app.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        return Data("CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n\(appHeader): \(app)\r\n\r\n".utf8)
    }

    enum Reply: Equatable {
        case incomplete
        /// With whatever the server sent after it, which belongs to the app.
        case established(rest: Data)
        case refused(String)
    }

    /// The proxy's answer, from what's been read of it so far.
    static func reply(_ bytes: Data) -> Reply {
        guard let end = bytes.firstRange(of: Data("\r\n\r\n".utf8)) else {
            return bytes.count > 8192 ? .refused("The proxy's answer is too long.") : .incomplete
        }
        let status = String(decoding: bytes[..<end.lowerBound], as: UTF8.self).prefix { $0 != "\r" }
        let parts = status.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), parts[1] == "200" else { return .refused(String(status)) }
        return .established(rest: Data(bytes[end.upperBound...]))
    }
}
