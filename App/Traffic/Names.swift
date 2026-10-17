import Darwin
import Foundation

/// Reads address records out of captured DNS and mDNS responses. The bytes come off
/// the wire from anyone, so every read is bounds-checked and a malformed message
/// yields whatever parsed before the problem.
enum DNS {
    /// Each A and AAAA record, paired with the name that was asked for: through a
    /// CNAME chain that's still the name the program used, which is what a person
    /// recognizes. mDNS announcements ask nothing, so they pair with the record's own
    /// name.
    static func addresses(in message: Data) -> [(IPAddress, String)] {
        let bytes = [UInt8](message)
        guard bytes.count >= 12, bytes[2] & 0x80 != 0 else { return [] } // responses only
        var offset = 12
        var asked: String?
        for _ in 0 ..< u16(bytes, 4) {
            guard let (name, end) = name(bytes, at: offset) else { return [] }
            asked = asked ?? name
            offset = end + 4
        }
        var found: [(IPAddress, String)] = []
        for _ in 0 ..< u16(bytes, 6) {
            guard let (owner, end) = name(bytes, at: offset), end + 10 <= bytes.count else { break }
            let type = u16(bytes, end)
            let start = end + 10
            let length = u16(bytes, end + 8)
            guard start + length <= bytes.count else { break }
            bytes[start ..< start + length].withUnsafeBytes { data in
                switch (type, length) {
                case (1, 4): found.append((IPAddress(v4Bytes: data), asked ?? owner))
                case (28, 16): found.append((IPAddress(v6Bytes: data), asked ?? owner))
                default: break
                }
            }
            offset = start + length
        }
        return found
    }

    /// The name at `start` and where the record continues after it. Compression
    /// pointers are followed a bounded number of times, so a pointer loop can't spin.
    static func name(_ bytes: [UInt8], at start: Int) -> (String, Int)? {
        var labels: [String] = []
        var offset = start
        var resume: Int?
        var jumps = 0
        while offset < bytes.count {
            let length = Int(bytes[offset])
            if length == 0 {
                return (labels.joined(separator: "."), resume ?? offset + 1)
            }
            if length & 0xc0 == 0xc0 {
                guard offset + 1 < bytes.count, jumps < 16 else { return nil }
                resume = resume ?? offset + 2
                offset = (length & 0x3f) << 8 | Int(bytes[offset + 1])
                jumps += 1
            } else {
                guard length < 64, offset + 1 + length <= bytes.count, labels.count < 128 else { return nil }
                labels.append(String(decoding: bytes[offset + 1 ... offset + length], as: UTF8.self))
                offset += 1 + length
            }
        }
        return nil
    }

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> Int {
        offset + 1 < bytes.count ? Int(bytes[offset]) << 8 | Int(bytes[offset + 1]) : 0
    }
}

/// Where an address lives, from the IANA special-purpose registries: what F2.10 calls
/// local versus internet traffic.
enum AddressScope {
    case loopback, linkLocal, privateNetwork, multicast, broadcast, reserved, internet

    var label: String {
        switch self {
        case .loopback: String(localized: "This Mac")
        case .linkLocal: String(localized: "Link-local")
        case .privateNetwork: String(localized: "Private network")
        case .multicast: String(localized: "Multicast")
        case .broadcast: String(localized: "Broadcast")
        case .reserved: String(localized: "Reserved")
        case .internet: String(localized: "Internet")
        }
    }
}

extension IPAddress {
    var scope: AddressScope {
        switch self {
        case .v4(let a):
            func within(_ prefix: UInt32, _ bits: UInt32) -> Bool { a >> (32 - bits) == prefix >> (32 - bits) }
            if a == 0xffff_ffff { return .broadcast }
            if within(0x7f00_0000, 8) { return .loopback }
            if within(0xa9fe_0000, 16) { return .linkLocal }
            // 100.64/10 is carrier-grade NAT, and VPNs such as Tailscale use it.
            if within(0x0a00_0000, 8) || within(0xac10_0000, 12) || within(0xc0a8_0000, 16) || within(0x6440_0000, 10) {
                return .privateNetwork
            }
            if within(0xe000_0000, 4) { return .multicast }
            if within(0, 8) || within(0xc000_0000, 24) || within(0xc000_0200, 24) || within(0xc612_0000, 15)
                || within(0xc633_6400, 24) || within(0xcb00_7100, 24) || within(0xf000_0000, 4) {
                return .reserved
            }
            return .internet
        case .v6(let high, let low):
            func within(_ prefix: UInt64, _ bits: UInt64) -> Bool { high >> (64 - bits) == prefix >> (64 - bits) }
            if high == 0 && low == 1 { return .loopback }
            if within(0xfe80 << 48, 10) { return .linkLocal }
            if within(0xfc00 << 48, 7) { return .privateNetwork }
            if within(0xff00 << 48, 8) { return .multicast }
            // Global unicast is 2000::/3, minus the documentation prefix.
            if within(0x2000 << 48, 3) && !within(0x2001_0db8 << 32, 32) { return .internet }
            return .reserved
        }
    }

    /// The PTR name, or nil. Blocks for as long as the resolver takes, which can be
    /// seconds: call it off the main thread.
    func reverseName() -> String? {
        var storage = sockaddr_storage()
        let length: Int
        switch self {
        case .v4(let value):
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr = in_addr(s_addr: value.bigEndian)
            withUnsafeMutableBytes(of: &storage) { $0.storeBytes(of: address, as: sockaddr_in.self) }
            length = MemoryLayout<sockaddr_in>.size
        case .v6(let high, let low):
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            withUnsafeMutableBytes(of: &address.sin6_addr) { $0.storeBytes(of: (high.bigEndian, low.bigEndian), as: (UInt64, UInt64).self) }
            withUnsafeMutableBytes(of: &storage) { $0.storeBytes(of: address, as: sockaddr_in6.self) }
            length = MemoryLayout<sockaddr_in6>.size
        }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t(length), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        return status == 0 ? host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) } : nil
    }
}

/// The service a connection uses, from /etc/services. The lower port is tried first:
/// it's almost always the server's, while the other end's ephemeral port can happen
/// to collide with some registered name.
@MainActor
func serviceName(_ key: FlowKey) -> String? {
    guard key.proto == PacketParser.tcp || key.proto == PacketParser.udp else { return nil }
    let ports = [key.localPort, key.remotePort].sorted()
    return ports.lazy.compactMap { lookupService(port: $0, proto: key.proto) }.first
}

// getservbyport answers from a static buffer and rereads /etc/services each call:
// main actor only, and cached.
@MainActor private var services: [Int: String?] = [:]

@MainActor private func lookupService(port: UInt16, proto: UInt8) -> String? {
    guard port != 0 else { return nil }
    let key = Int(proto) << 16 | Int(port)
    if let cached = services[key] {
        return cached
    }
    let name = getservbyport(Int32(port.bigEndian), proto == PacketParser.tcp ? "tcp" : "udp").map { String(cString: $0.pointee.s_name) }
    services[key] = name
    return name
}
