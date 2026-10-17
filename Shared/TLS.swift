import Foundation

/// Shared with the network extension, whose transparent proxy asks the app's proxy for
/// the host a ClientHello names. The bytes come from local apps, and every read here
/// is bounds-checked.
enum TLS {
    /// The server name (SNI) a ClientHello asks for. With Encrypted Client Hello this
    /// is the provider's public name rather than the site's, which is still what the
    /// wire says. A ClientHello cut short (the helper passes on only its first TCP
    /// segment) yields nil when the extension falls past the cut.
    static func serverName(in hello: Data) -> String? {
        let bytes = [UInt8](hello)
        func u16(_ offset: Int) -> Int { offset + 1 < bytes.count ? Int(bytes[offset]) << 8 | Int(bytes[offset + 1]) : 0 }
        // Record header (5), handshake header (4), version (2), random (32).
        var offset = 43
        guard bytes.count > offset, bytes[0] == 0x16, bytes[5] == 1 else { return nil }
        offset += 1 + Int(bytes[offset]) // session id
        offset += 2 + u16(offset) // cipher suites
        guard offset < bytes.count else { return nil }
        offset += 1 + Int(bytes[offset]) // compression methods
        let end = min(bytes.count, offset + 2 + u16(offset))
        offset += 2
        while offset + 4 <= end {
            let type = u16(offset)
            let length = u16(offset + 2)
            offset += 4
            if type == 0 {
                // List length (2), name type (1; 0 = host name), name length (2), name.
                let length = u16(offset + 3)
                guard offset + 5 + length <= bytes.count, length > 0, bytes[offset + 2] == 0 else { return nil }
                return String(decoding: bytes[offset + 5 ..< offset + 5 + length], as: UTF8.self)
            }
            offset += length
        }
        return nil
    }

    /// Whether `bytes`, the start of a connection, hold the whole first TLS record, so
    /// the server name in it can be read; also true when they can't be the start of a
    /// handshake, as there's then no name to wait for. An app writes its ClientHello in
    /// one go, but nothing promises it arrives in one read.
    static func hasWholeRecord(_ bytes: Data) -> Bool {
        let header = [UInt8](bytes.prefix(5))
        guard header.first == 0x16 else { return !header.isEmpty }
        guard header.count == 5 else { return false }
        return bytes.count >= 5 + (Int(header[3]) << 8 | Int(header[4]))
    }
}
