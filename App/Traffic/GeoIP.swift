import Foundation

/// A value from a MaxMind DB data section.
indirect enum MMDBValue {
    case map([String: MMDBValue])
    case array([MMDBValue])
    case string(String)
    case uint(UInt64)
    case int(Int32)
    case double(Double)
    case bool(Bool)
    case bytes(Data)

    subscript(key: String) -> MMDBValue? {
        if case .map(let map) = self { map[key] } else { nil }
    }

    var string: String? {
        if case .string(let value) = self { value } else { nil }
    }

    var uint: UInt64? {
        if case .uint(let value) = self { value } else { nil }
    }
}

/// Just enough of the MaxMind DB format (maxmind.github.io/MaxMind-DB) to look an
/// address up in the DB-IP Lite files: a binary search tree over the address bits,
/// then one record from the data section. A reader package would be a dependency,
/// and C, for a hundred lines.
struct MaxMindDB: Sendable {
    private let bytes: Data
    private let nodeCount: Int
    private let recordSize: Int
    private let dataStart: Int
    private let ipv4Root: Int

    init?(url: URL) {
        guard let bytes = try? Data(contentsOf: url, options: .alwaysMapped) else { return nil }
        let marker = Data([0xab, 0xcd, 0xef] + Array("MaxMind.com".utf8))
        guard let found = bytes.range(of: marker, options: .backwards) else { return nil }
        self.bytes = bytes
        var offset = found.upperBound
        guard let metadata = Self.decode(bytes, at: &offset, base: found.upperBound),
              let nodes = metadata["node_count"]?.uint, let size = metadata["record_size"]?.uint,
              [24, 28, 32].contains(size) else { return nil }
        nodeCount = Int(nodes)
        recordSize = Int(size)
        dataStart = nodeCount * recordSize / 4 + 16
        guard dataStart <= bytes.count else { return nil }
        // IPv4 addresses live under ::/96 in an IPv6 tree: 96 left turns from the root.
        var node = 0
        if metadata["ip_version"]?.uint == 6 {
            for _ in 0 ..< 96 where node < nodeCount {
                node = Self.record(bytes, node: node, right: false, size: recordSize)
            }
        }
        ipv4Root = node
    }

    func lookup(_ address: IPAddress) -> MMDBValue? {
        var node: Int
        switch address {
        case .v4(let value):
            node = ipv4Root
            for bit in 0 ..< 32 where node < nodeCount {
                node = Self.record(bytes, node: node, right: value >> (31 - bit) & 1 == 1, size: recordSize)
            }
        case .v6(let high, let low):
            node = 0
            for bit in 0 ..< 128 where node < nodeCount {
                let half = bit < 64 ? high : low
                node = Self.record(bytes, node: node, right: half >> (63 - bit % 64) & 1 == 1, size: recordSize)
            }
        }
        // Equal to the node count means "no data"; above it points into the data section.
        guard node > nodeCount else { return nil }
        var offset = dataStart + node - nodeCount - 16
        return Self.decode(bytes, at: &offset, base: dataStart)
    }

    private static func record(_ bytes: Data, node: Int, right: Bool, size: Int) -> Int {
        let start = bytes.startIndex + node * size / 4
        func byte(_ index: Int) -> Int { Int(bytes[start + index]) }
        switch (size, right) {
        case (24, false): return byte(0) << 16 | byte(1) << 8 | byte(2)
        case (24, true): return byte(3) << 16 | byte(4) << 8 | byte(5)
        case (28, false): return (byte(3) & 0xf0) << 20 | byte(0) << 16 | byte(1) << 8 | byte(2)
        case (28, true): return (byte(3) & 0x0f) << 24 | byte(4) << 16 | byte(5) << 8 | byte(6)
        case (_, false): return byte(0) << 24 | byte(1) << 16 | byte(2) << 8 | byte(3)
        case (_, true): return byte(4) << 24 | byte(5) << 16 | byte(6) << 8 | byte(7)
        }
    }

    /// `base` is where pointers count from: the data section, or the metadata.
    private static func decode(_ bytes: Data, at offset: inout Int, base: Int, depth: Int = 0) -> MMDBValue? {
        func next(_ count: Int) -> Data? {
            guard offset >= 0, offset + count <= bytes.count else { return nil }
            defer { offset += count }
            return bytes[bytes.startIndex + offset ..< bytes.startIndex + offset + count]
        }
        func number(_ data: Data) -> Int { data.reduce(0) { $0 << 8 | Int($1) } }

        guard depth < 32, let control = next(1)?.first else { return nil }
        var type = Int(control >> 5)
        if type == 1 {
            let small = Int(control >> 3 & 0x3)
            let high = Int(control & 0x7)
            guard let tail = next(small + 1) else { return nil }
            let pointer = switch small {
            case 0: high << 8 | number(tail)
            case 1: (high << 16 | number(tail)) + 2048
            case 2: (high << 24 | number(tail)) + 526_336
            default: number(tail)
            }
            var target = base + pointer
            return decode(bytes, at: &target, base: base, depth: depth + 1)
        }
        if type == 0 {
            guard let extended = next(1)?.first else { return nil }
            type = 7 + Int(extended)
        }
        var size = Int(control & 0x1f)
        switch size {
        case 29: size = 29 + (next(1).map(number) ?? 0)
        case 30: size = 285 + (next(2).map(number) ?? 0)
        case 31: size = 65_821 + (next(3).map(number) ?? 0)
        default: break
        }
        switch type {
        case 2: return next(size).map { .string(String(decoding: $0, as: UTF8.self)) }
        case 3: return next(size).map { .double(Double(bitPattern: UInt64(number($0)))) }
        case 4: return next(size).map { .bytes($0) }
        case 5, 6, 9: return next(size).map { .uint(UInt64(number($0))) }
        case 10: return next(size).map { .uint(UInt64(truncatingIfNeeded: number($0.suffix(8)))) }
        case 8: return next(size).map { .int(Int32(truncatingIfNeeded: number($0))) }
        case 14: return .bool(size != 0)
        case 15: return next(size).map { .double(Double(Float(bitPattern: UInt32(number($0))))) }
        case 7:
            var map: [String: MMDBValue] = [:]
            for _ in 0 ..< size {
                guard let key = decode(bytes, at: &offset, base: base, depth: depth + 1)?.string,
                      let value = decode(bytes, at: &offset, base: base, depth: depth + 1) else { return nil }
                map[key] = value
            }
            return .map(map)
        case 11:
            var array: [MMDBValue] = []
            for _ in 0 ..< size {
                guard let value = decode(bytes, at: &offset, base: base, depth: depth + 1) else { return nil }
                array.append(value)
            }
            return .array(array)
        default:
            return nil
        }
    }
}

struct GeoInfo: Sendable {
    var countryCode: String?
    var country: String?
    var asn: UInt64?
    var organization: String?

    /// "🇯🇵 Japan": the flag from the two regional-indicator letters.
    var countryLabel: String? {
        guard let country else { return nil }
        let flag = countryCode.map { code in
            String(String.UnicodeScalarView(code.uppercased().unicodeScalars.compactMap { Unicode.Scalar(0x1f1a5 + $0.value) }))
        }
        return flag.map { "\($0) \(country)" } ?? country
    }

    var networkLabel: String? {
        switch (organization, asn) {
        case let (organization?, asn?): "\(organization) (AS\(asn))"
        case let (nil, asn?): "AS\(asn)"
        default: nil
        }
    }
}

/// DB-IP Lite country and ASN databases (CC BY 4.0), bundled by `make geoip`. Missing
/// files leave the columns empty rather than failing.
struct GeoIP: Sendable {
    static let shared = GeoIP()

    private let countries = Bundle.main.url(forResource: "dbip-country-lite", withExtension: "mmdb").flatMap(MaxMindDB.init)
    private let networks = Bundle.main.url(forResource: "dbip-asn-lite", withExtension: "mmdb").flatMap(MaxMindDB.init)

    /// Country names come from macOS, in the interface's language: the database has no
    /// Traditional Chinese, and the interface may be English on a Mac in any locale.
    private static let names = Locale(identifier: Bundle.main.preferredLocalizations.first ?? "en")

    var isAvailable: Bool { countries != nil && networks != nil }

    func lookup(_ address: IPAddress) -> GeoInfo {
        let country = countries?.lookup(address)?["country"]
        let network = networks?.lookup(address)
        let code = country?["iso_code"]?.string
        return GeoInfo(
            countryCode: code,
            country: code.flatMap(Self.names.localizedString(forRegionCode:)) ?? country?["names"]?["en"]?.string,
            asn: network?["autonomous_system_number"]?.uint,
            organization: network?["autonomous_system_organization"]?.string
        )
    }
}
