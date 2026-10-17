import CommonCrypto
import CryptoKit
import Foundation

/// Reads a QUIC client's Initial packets. They are encrypted, but with keys anyone can
/// derive from the packet itself (RFC 9001 §5.2): the protection keeps middleboxes
/// from tampering, not from reading, so the ClientHello inside is as readable as over
/// TCP. The bytes come off the wire from anyone, so every read is bounds-checked.
enum QUIC {
    struct Keys: Equatable {
        let key: [UInt8]
        let iv: [UInt8]
        let hp: [UInt8]
    }

    /// Initial protection per version: RFC 9001 for version 1; RFC 9369 for version 2,
    /// which changes the salt, the labels and the Initial type bits so middleboxes
    /// can't ossify on version 1. A new version needs an entry here and its fixed
    /// bytes in `PacketParser`.
    private static let versions: [UInt32: (salt: [UInt8], labels: String, initialType: UInt8)] = [
        1: ([0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a], "quic", 0),
        0x6b33_43cf: ([0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9], "quicv2", 1),
    ]

    /// The client's Initial keys, from the destination connection ID of its first
    /// Initial.
    static func clientKeys(version: UInt32, connectionID: [UInt8]) -> Keys? {
        guard let protection = versions[version] else { return nil }
        let initial = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: connectionID), salt: protection.salt)
        let client = expandLabel(initial, "client in", 32)
        func derive(_ label: String, _ length: Int) -> [UInt8] {
            expandLabel(client, "\(protection.labels) \(label)", length).withUnsafeBytes { Array($0) }
        }
        return Keys(key: derive("key", 16), iv: derive("iv", 12), hp: derive("hp", 16))
    }

    /// TLS 1.3's HKDF-Expand-Label (RFC 8446 §7.1), with an empty context.
    private static func expandLabel(_ secret: some ContiguousBytes, _ label: String, _ length: Int) -> SymmetricKey {
        let label = Array("tls13 \(label)".utf8)
        let info = [UInt8(length >> 8), UInt8(length & 0xff), UInt8(label.count)] + label + [0]
        return HKDF<SHA256>.expand(pseudoRandomKey: secret, info: info, outputByteCount: length)
    }

    /// Header protection's mask: AES-128-ECB over a 16-byte sample of the ciphertext
    /// (RFC 9001 §5.4.3). CryptoKit has no single-block AES.
    static func mask(hp: [UInt8], sample: ArraySlice<UInt8>) -> [UInt8]? {
        var mask = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = hp.withUnsafeBytes { key in
            sample.withUnsafeBytes { input in
                mask.withUnsafeMutableBytes { output in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            key.baseAddress, key.count, nil, input.baseAddress, input.count, output.baseAddress, output.count, &moved)
                }
            }
        }
        return status == kCCSuccess ? mask : nil
    }

    /// The frames of the datagram's first packet if it is a client Initial that
    /// authenticates. Keys come from the packet's own destination connection ID:
    /// right for everything the client sends before the server answers, which is
    /// where the ClientHello goes. Later Initials, sent to the server's connection ID
    /// under the same keys, don't open and are skipped; coalesced packets after the
    /// first are ignored.
    static func initialPayload(_ datagram: [UInt8]) -> [UInt8]? {
        guard datagram.count > 6 else { return nil }
        let version = datagram[1 ..< 5].reduce(0) { $0 << 8 | UInt32($1) }
        guard datagram[0] & 0xc0 == 0xc0, let protection = versions[version], datagram[0] >> 4 & 0x03 == protection.initialType else { return nil }
        // A client's first destination connection ID is 8 to 20 bytes (RFC 9000 §7.2).
        let idLength = Int(datagram[5])
        guard (8 ... 20).contains(idLength), 6 + idLength < datagram.count else { return nil }
        let connectionID = Array(datagram[6 ..< 6 + idLength])
        var offset = 6 + idLength
        offset += 1 + Int(datagram[offset]) // source connection ID
        guard let tokenLength = varint(datagram, &offset), tokenLength <= datagram.count - offset else { return nil }
        offset += tokenLength
        // The sample sits 4 bytes past the packet number's start, whatever its length.
        guard let length = varint(datagram, &offset), length >= 20, length <= datagram.count - offset,
              let keys = clientKeys(version: version, connectionID: connectionID),
              let mask = mask(hp: keys.hp, sample: datagram[offset + 4 ..< offset + 20]) else { return nil }
        var header = Array(datagram[..<offset])
        header[0] ^= mask[0] & 0x0f
        // A client's Initials are its first packets, numbered from 0 with nothing
        // acknowledged yet, so the encoded packet number is the whole one.
        var number: UInt64 = 0
        for index in 0 ..< Int(header[0] & 0x03) + 1 {
            let byte = datagram[offset + index] ^ mask[1 + index]
            header.append(byte)
            number = number << 8 | UInt64(byte)
        }
        var nonce = keys.iv
        for index in 0 ..< 8 {
            nonce[11 - index] ^= UInt8(truncatingIfNeeded: number >> (8 * index))
        }
        let end = offset + length
        guard let box = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: datagram[header.count ..< end - 16], tag: datagram[end - 16 ..< end]),
              let frames = try? AES.GCM.open(box, using: SymmetricKey(data: keys.key), authenticating: header) else { return nil }
        return Array(frames)
    }

    /// Each CRYPTO frame's offset in the handshake stream, and its bytes.
    static func cryptoFrames(in frames: [UInt8]) -> [(offset: Int, data: ArraySlice<UInt8>)] {
        var found: [(offset: Int, data: ArraySlice<UInt8>)] = []
        var position = 0
        while position < frames.count {
            switch frames[position] {
            case 0x00, 0x01: // PADDING, PING: Chrome scatters both between CRYPTO frames
                position += 1
            case 0x06:
                position += 1
                guard let offset = varint(frames, &position), let length = varint(frames, &position),
                      length <= frames.count - position else { return found }
                found.append((offset, frames[position ..< position + length]))
                position += length
            default:
                // ACK and CONNECTION_CLOSE, the other frames an Initial holds, come
                // once the server has answered: the ClientHello has gone out by then.
                return found
            }
        }
        return found
    }

    /// A variable-length integer (RFC 9000 §16): the top two bits give its length.
    private static func varint(_ bytes: [UInt8], _ offset: inout Int) -> Int? {
        guard offset < bytes.count else { return nil }
        let length = 1 << (bytes[offset] >> 6)
        guard length <= bytes.count - offset else { return nil }
        let value = bytes[offset + 1 ..< offset + length].reduce(Int(bytes[offset] & 0x3f)) { $0 << 8 | Int($1) }
        offset += length
        return value
    }
}

/// One QUIC connection's ClientHello, put together by offset from the CRYPTO frames
/// of its client Initials: with a post-quantum key share it outgrows one packet, and
/// Chrome splits and reorders its CRYPTO frames on purpose.
struct QUICHello: Sendable {
    // ponytail: gives up after 8 Initials, or at a frame reaching past 16 KB. A
    // ClientHello takes two or three Initials even with a post-quantum key share; the
    // limits cap what a flow holds and how often it decrypts. Raise them if a client
    // needs more.
    static let packetLimit = 8
    static let byteLimit = 16_384

    private var packets = 0
    private var bytes: [UInt8] = []
    private var received = IndexSet()

    /// Takes a datagram the helper passed on as a client Initial. Returns the server
    /// name once the pieces so far hold it; after that, and after the limit, nothing.
    mutating func add(_ datagram: Data) -> String? {
        guard packets < Self.packetLimit else { return nil }
        packets += 1
        for frame in QUIC.initialPayload([UInt8](datagram)).map(QUIC.cryptoFrames) ?? [] {
            let end = frame.offset + frame.data.count
            // The offset is the sender's to claim; a buffer sized to it could be
            // terabytes. No ClientHello comes near this, so whatever sent it isn't one.
            guard end <= Self.byteLimit else {
                packets = Self.packetLimit
                break
            }
            if bytes.count < end {
                bytes += repeatElement(0, count: end - bytes.count)
            }
            bytes.replaceSubrange(frame.offset ..< end, with: frame.data)
            received.insert(integersIn: frame.offset ..< end)
        }
        guard let start = received.rangeView.first, start.lowerBound == 0 else { return nil }
        // QUIC carries the handshake messages bare; the TLS parser expects them in a
        // record, as TCP sends them.
        let name = TLS.serverName(in: Data([0x16, 3, 1, 0, 0] + bytes[..<start.upperBound]))
        if name != nil || packets == Self.packetLimit {
            packets = Self.packetLimit
            bytes = []
            received = IndexSet()
        }
        return name
    }
}
