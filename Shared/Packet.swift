import Darwin
import Foundation

enum IPAddress: Hashable, Sendable, Codable {
    /// The four bytes in network order: 192.168.0.1 is 0xC0A80001.
    case v4(UInt32)
    /// The sixteen bytes in network order, as two big-endian halves.
    case v6(UInt64, UInt64)

    init?(_ text: String) {
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            self = .v4(UInt32(bigEndian: v4.s_addr))
        } else if inet_pton(AF_INET6, text, &v6) == 1 {
            self = withUnsafeBytes(of: &v6) { Self(v6Bytes: $0) }
        } else {
            return nil
        }
    }

    init(v4Bytes bytes: UnsafeRawBufferPointer) {
        self = .v4(bytes.loadUnaligned(as: UInt32.self).bigEndian)
    }

    init(v6Bytes bytes: UnsafeRawBufferPointer) {
        self = .v6(bytes.loadUnaligned(as: UInt64.self).bigEndian, bytes.loadUnaligned(fromByteOffset: 8, as: UInt64.self).bigEndian)
    }

    var isV4: Bool {
        if case .v4 = self { true } else { false }
    }
}

extension IPAddress: CustomStringConvertible {
    var description: String {
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch self {
        case .v4(let value):
            var address = in_addr(s_addr: value.bigEndian)
            inet_ntop(AF_INET, &address, &text, socklen_t(text.count))
        case .v6(let high, let low):
            var bytes = (high.bigEndian, low.bigEndian)
            withUnsafeBytes(of: &bytes) { raw in
                _ = inet_ntop(AF_INET6, raw.baseAddress, &text, socklen_t(text.count))
            }
        }
        return text.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }
}

/// One captured frame, reduced to what traffic monitoring needs. The helper parses
/// only fixed-layout L2–L4 headers; DNS payloads are passed through for the app to
/// parse, so the variable-length, pointer-chasing parsing never runs as root.
struct PacketSummary: Codable, Equatable, Sendable {
    /// Seconds since 1970, from the capture timestamp.
    var time: Double
    /// Bytes on the wire, not the captured (snapped) length.
    var length: Int
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6); 0 for a non-IP frame.
    var proto: UInt8 = 0
    var source: IPAddress?
    var destination: IPAddress?
    var sourcePort: UInt16 = 0
    var destinationPort: UInt16 = 0
    /// SYN and ACK (`PacketParser.syn`, `.ack`), which time the TCP handshake. The
    /// other bits are masked off, so an ECN-capable SYN-ACK still reads as SYN-ACK.
    var tcpFlags: UInt8 = 0
    /// UDP payload of a DNS or mDNS packet.
    var dns: Data?
    /// TCP payload that opens with a TLS ClientHello: its server name is often the
    /// only name a connection has once DNS travels encrypted.
    var clientHello: Data?
    /// UDP payload that opens with a QUIC client Initial, which carries the same
    /// ClientHello under encryption the app can undo.
    var quicInitial: Data?
}

/// A batch sent from the helper to the app, with the capture's running statistics.
struct CaptureBatch: Codable, Sendable {
    /// The id the app gave `startCapture`, so it can tell which capture (and so
    /// which PCAP file) a batch belongs to without relying on reply ordering.
    var capture: Int
    var packets: [PacketSummary]
    /// pcap_stats since the capture started: frames the kernel dropped because the
    /// buffer was full.
    var dropped: Int
    /// Set on the last batch of a capture that ended on its own, e.g. its interface
    /// went away.
    var error: String?
}

enum PacketParser {
    static let tcp: UInt8 = 6
    static let udp: UInt8 = 17
    static let syn: UInt8 = 0x02
    static let ack: UInt8 = 0x10
    static let dnsPorts: Set<UInt16> = [53, 5353]

    /// Never fails: a frame that is truncated or not IP still counts toward totals,
    /// so the packet count matches what a PCAP of the same capture holds.
    static func parse(_ frame: UnsafeRawBufferPointer, wireLength: Int, time: Double, linkType: Int32) -> PacketSummary {
        var summary = PacketSummary(time: time, length: wireLength)
        guard let (isV6, offset) = network(frame, linkType: linkType) else { return summary }
        if isV6 {
            parseV6(frame, at: offset, into: &summary)
        } else {
            parseV4(frame, at: offset, into: &summary)
        }
        return summary
    }

    /// Where the IP header starts, and whether it is IPv6.
    private static func network(_ frame: UnsafeRawBufferPointer, linkType: Int32) -> (Bool, Int)? {
        switch linkType {
        case DLT_EN10MB:
            var offset = 12
            var etherType = u16(frame, offset)
            // One 802.1Q tag; stacked tags are rare enough on a Mac's own link.
            if etherType == 0x8100 {
                offset += 4
                etherType = u16(frame, offset)
            }
            switch etherType {
            case 0x0800: return (false, offset + 2)
            case 0x86DD: return (true, offset + 2)
            default: return nil
            }
        case DLT_NULL, DLT_LOOP:
            // A 4-byte address family (lo0, utun). Host order for NULL, network for LOOP.
            guard frame.count >= 4 else { return nil }
            let raw = frame.loadUnaligned(as: UInt32.self)
            let family = linkType == DLT_LOOP ? UInt32(bigEndian: raw) : raw
            switch Int32(family) {
            case AF_INET: return (false, 4)
            case AF_INET6, 24, 28, 30: return (true, 4) // AF_INET6 differs across BSDs
            default: return nil
            }
        case DLT_RAW:
            guard let first = frame.first else { return nil }
            return (first >> 4 == 6, 0)
        default:
            return nil
        }
    }

    private static func parseV4(_ frame: UnsafeRawBufferPointer, at offset: Int, into summary: inout PacketSummary) {
        guard frame.count >= offset + 20 else { return }
        let headerLength = Int(frame[offset] & 0x0f) * 4
        summary.proto = frame[offset + 9]
        summary.source = IPAddress(v4Bytes: UnsafeRawBufferPointer(rebasing: frame[(offset + 12)...]))
        summary.destination = IPAddress(v4Bytes: UnsafeRawBufferPointer(rebasing: frame[(offset + 16)...]))
        // Only the first fragment carries the transport header.
        let fragmentOffset = u16(frame, offset + 6) & 0x1fff
        guard headerLength >= 20, fragmentOffset == 0 else { return }
        parseTransport(frame, at: offset + headerLength, into: &summary)
    }

    private static func parseV6(_ frame: UnsafeRawBufferPointer, at offset: Int, into summary: inout PacketSummary) {
        guard frame.count >= offset + 40 else { return }
        summary.source = IPAddress(v6Bytes: UnsafeRawBufferPointer(rebasing: frame[(offset + 8)...]))
        summary.destination = IPAddress(v6Bytes: UnsafeRawBufferPointer(rebasing: frame[(offset + 24)...]))
        var next = frame[offset + 6]
        var position = offset + 40
        // Hop-by-hop, routing, destination options and fragment headers; anything else
        // is the transport (or something we don't parse).
        while [0, 43, 44, 60].contains(next), frame.count >= position + 8 {
            if next == 44, u16(frame, position + 2) & 0xfff8 != 0 {
                summary.proto = frame[position]
                return // a later fragment: no transport header
            }
            let length = next == 44 ? 8 : (Int(frame[position + 1]) + 1) * 8
            next = frame[position]
            position += length
        }
        summary.proto = next
        parseTransport(frame, at: position, into: &summary)
    }

    private static func parseTransport(_ frame: UnsafeRawBufferPointer, at offset: Int, into summary: inout PacketSummary) {
        guard summary.proto == tcp || summary.proto == udp, frame.count >= offset + 4 else { return }
        summary.sourcePort = u16(frame, offset)
        summary.destinationPort = u16(frame, offset + 2)
        let isDNS = dnsPorts.contains(summary.sourcePort) || dnsPorts.contains(summary.destinationPort)
        if summary.proto == udp, isDNS, frame.count > offset + 8 {
            summary.dns = Data(frame[(offset + 8)...])
        }
        // Handshake record (0x16), TLS major version 3, ClientHello (1): a check on
        // three fixed bytes, so nothing variable-length is parsed here.
        // ponytail: only the segment that opens the ClientHello is passed on, so one
        // too big for a segment (Chrome's post-quantum key share) loses a server name
        // that falls in the next. Reassembly would need per-connection state here in
        // the root helper and sequence numbers in the summary; add it if such
        // connections show up without names.
        if summary.proto == tcp, frame.count > offset + 13 {
            summary.tcpFlags = frame[offset + 13] & (syn | ack)
            let payload = offset + Int(frame[offset + 12] >> 4) * 4
            if frame.count > payload + 5, frame[payload] == 0x16, frame[payload + 1] == 3, frame[payload + 5] == 1 {
                summary.clientHello = Data(frame[payload...])
            }
        }
        // A QUIC client's Initial: long header with the fixed bit, then a version and
        // its Initial type bits (0b00 in version 1, 0b01 in version 2, RFC 9369).
        // Again fixed bytes only; the app decrypts it.
        if summary.proto == udp, summary.destinationPort == 443, frame.count > offset + 12 {
            let type = frame[offset + 8] & 0xf0
            let version = UInt32(u16(frame, offset + 9)) << 16 | UInt32(u16(frame, offset + 11))
            if (type == 0xc0 && version == 1) || (type == 0xd0 && version == 0x6b33_43cf) {
                summary.quicInitial = Data(frame[(offset + 8)...])
            }
        }
    }

    private static func u16(_ frame: UnsafeRawBufferPointer, _ offset: Int) -> UInt16 {
        guard frame.count >= offset + 2 else { return 0 }
        return UInt16(frame[offset]) << 8 | UInt16(frame[offset + 1])
    }
}
