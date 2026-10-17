import CryptoKit
import Foundation
import Testing
@testable import WiFiDetect

/// Hex as the RFCs print it, spaces and line breaks included.
private func hex(_ text: String) -> [UInt8] {
    let digits = Array(text.filter(\.isHexDigit))
    return stride(from: 0, to: digits.count, by: 2).map { UInt8(String(digits[$0 ... $0 + 1]), radix: 16)! }
}

private func varint(_ value: Int) -> [UInt8] {
    if value < 1 << 14 {
        return [0x40 | UInt8(value >> 8), UInt8(value & 0xff)]
    }
    var bytes = (0 ..< 8).reversed().map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    bytes[0] |= 0xc0
    return bytes
}

private func crypto(_ offset: Int, _ data: ArraySlice<UInt8>) -> [UInt8] {
    [0x06] + varint(offset) + varint(data.count) + data
}

/// A version 1 client Initial, protected the way a client does it (RFC 9001 §5), so a
/// test can split a ClientHello across packets however it likes.
private func initial(_ frames: [UInt8], number: Int, numberLength: Int) -> [UInt8] {
    let connectionID: [UInt8] = [0x5a, 0x17, 0x01, 0x9e, 0x2b, 0xc4, 0x70, 0x33]
    let keys = QUIC.clientKeys(version: 1, connectionID: connectionID)!
    // Padded the way a client fills its Initial datagram to 1200 bytes.
    let payload = frames + [UInt8](repeating: 0, count: max(0, 1150 - frames.count))
    let numberBytes = (0 ..< numberLength).reversed().map { UInt8(truncatingIfNeeded: number >> (8 * $0)) }
    // No source connection ID, no token.
    let header = [0xc0 | UInt8(numberLength - 1), 0, 0, 0, 1, UInt8(connectionID.count)] + connectionID
        + [0, 0] + varint(numberLength + payload.count + 16) + numberBytes
    var nonce = keys.iv
    for index in 0 ..< 8 {
        nonce[11 - index] ^= UInt8(truncatingIfNeeded: number >> (8 * index))
    }
    let sealed = try! AES.GCM.seal(payload, using: SymmetricKey(data: keys.key), nonce: AES.GCM.Nonce(data: nonce), authenticating: header)
    var packet = header + sealed.ciphertext + sealed.tag
    let start = header.count - numberLength
    let mask = QUIC.mask(hp: keys.hp, sample: packet[start + 4 ..< start + 20])!
    packet[0] ^= mask[0] & 0x0f
    for index in 0 ..< numberLength {
        packet[start + index] ^= mask[1 + index]
    }
    return packet
}

struct QUICTests {
    /// RFC 9001 Appendix A.2, the client Initial implementations check themselves
    /// against. Its ClientHello asks for example.com.
    static let version1Initial = hex("""
        c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
        d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
        1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
        8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
        30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
        457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
        4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
        4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
        485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
        059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
        7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
        9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
        be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
        68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
        c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
        f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
        291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
        25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
        14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
        ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
        e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
        c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
        203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
        cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
        fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
        a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
        90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
        162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
        40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
        6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
        8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
        be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
        54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
        760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
        f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
        056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
        7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
        e221af44860018ab0856972e194cd934
        """)

    /// RFC 9369 Appendix A.2: the same ClientHello under version 2's salt and labels.
    static let version2Initial = hex("""
        d76b3343cf088394c8f03e5157080000 449ea0c95e82ffe67b6abcdb4298b485
        dd04de806071bf03dceebfa162e75d6c 96058bdbfb127cdfcbf903388e99ad04
        9f9a3dd4425ae4d0992cfff18ecf0fdb 5a842d09747052f17ac2053d21f57c5d
        250f2c4f0e0202b70785b7946e992e58 a59ac52dea6774d4f03b55545243cf1a
        12834e3f249a78d395e0d18f4d766004 f1a2674802a747eaa901c3f10cda5500
        cb9122faa9f1df66c392079a1b40f0de 1c6054196a11cbea40afb6ef5253cd68
        18f6625efce3b6def6ba7e4b37a40f77 32e093daa7d52190935b8da58976ff33
        12ae50b187c1433c0f028edcc4c2838b 6a9bfc226ca4b4530e7a4ccee1bfa2a3
        d396ae5a3fb512384b2fdd851f784a65 e03f2c4fbe11a53c7777c023462239dd
        6f7521a3f6c7d5dd3ec9b3f233773d4b 46d23cc375eb198c63301c21801f6520
        bcfb7966fc49b393f0061d974a2706df 8c4a9449f11d7f3d2dcbb90c6b877045
        636e7c0c0fe4eb0f697545460c806910 d2c355f1d253bc9d2452aaa549e27a1f
        ac7cf4ed77f322e8fa894b6a83810a34 b361901751a6f5eb65a0326e07de7c12
        16ccce2d0193f958bb3850a833f7ae43 2b65bc5a53975c155aa4bcb4f7b2c4e5
        4df16efaf6ddea94e2c50b4cd1dfe060 17e0e9d02900cffe1935e0491d77ffb4
        fdf85290fdd893d577b1131a610ef6a5 c32b2ee0293617a37cbb08b847741c3b
        8017c25ca9052ca1079d8b78aebd4787 6d330a30f6a8c6d61dd1ab5589329de7
        14d19d61370f8149748c72f132f0fc99 f34d766c6938597040d8f9e2bb522ff9
        9c63a344d6a2ae8aa8e51b7b90a4a806 105fcbca31506c446151adfeceb51b91
        abfe43960977c87471cf9ad4074d30e1 0d6a7f03c63bd5d4317f68ff325ba3bd
        80bf4dc8b52a0ba031758022eb025cdd 770b44d6d6cf0670f4e990b22347a7db
        848265e3e5eb72dfe8299ad7481a4083 22cac55786e52f633b2fb6b614eaed18
        d703dd84045a274ae8bfa73379661388 d6991fe39b0d93debb41700b41f90a15
        c4d526250235ddcd6776fc77bc97e7a4 17ebcb31600d01e57f32162a8560cacc
        7e27a096d37a1a86952ec71bd89a3e9a 30a2a26162984d7740f81193e8238e61
        f6b5b984d4d3dfa033c1bb7e4f0037fe bf406d91c0dccf32acf423cfa1e70710
        10d3f270121b493ce85054ef58bada42 310138fe081adb04e2bd901f2f13458b
        3d6758158197107c14ebb193230cd115 7380aa79cae1374a7c1e5bbcb80ee23e
        06ebfde206bfb0fcbc0edc4ebec30966 1bdd908d532eb0c6adc38b7ca7331dce
        8dfce39ab71e7c32d318d136b6100671 a1ae6a6600e3899f31f0eed19e3417d1
        34b90c9058f8632c798d4490da498730 7cba922d61c39805d072b589bd52fdf1
        e86215c2d54e6670e07383a27bbffb5a ddf47d66aa85a0c6f9f32e59d85a44dd
        5d3b22dc2be80919b490437ae4f36a0a e55edf1d0b5cb4e9a3ecabee93dfc6e3
        8d209d0fa6536d27a5d6fbb17641cde2 7525d61093f1b28072d111b2b4ae5f89
        d5974ee12e5cf7d5da4d6a31123041f3 3e61407e76cffcdcfd7e19ba58cf4b53
        6f4c4938ae79324dc402894b44faf8af bab35282ab659d13c93f70412e85cb19
        9a37ddec600545473cfb5a05e08d0b20 9973b2172b4d21fb69745a262ccde96b
        a18b2faa745b6fe189cf772a9f84cbfc
        """)

    private static let hello = Array(TLSServerNameTests.clientHello("video.example").dropFirst(5))

    /// The keys both appendices print. A wrong salt or label shows here, before it
    /// shows as QUIC connections that never get a name.
    @Test func derivesRFCKeys() {
        let connectionID = hex("8394c8f03e515708")
        #expect(QUIC.clientKeys(version: 1, connectionID: connectionID) == QUIC.Keys(
            key: hex("1f369613dd76d5467730efcbe3b1a22d"), iv: hex("fa044b2f42a3fd3b46fb255c"), hp: hex("9f50449e04a0e810283a1e9933adedd2")))
        #expect(QUIC.clientKeys(version: 0x6b33_43cf, connectionID: connectionID) == QUIC.Keys(
            key: hex("8b1a0bc121284290a29e0971b5cd045d"), iv: hex("91f73e2351d8fa91660e909f"), hp: hex("45b95e15235d6f45a6b19cbcb0294ba9")))
    }

    /// The whole path on the RFCs' own packets, in both versions browsers speak: header
    /// protection off, payload authenticated, CRYPTO frame found, server name read.
    @Test func readsServerNameFromRFCInitials() {
        var version1 = QUICHello()
        #expect(version1.add(Data(Self.version1Initial)) == "example.com")
        var version2 = QUICHello()
        #expect(version2.add(Data(Self.version2Initial)) == "example.com")
    }

    /// Wire bytes come from anyone: a packet that doesn't authenticate or is cut short
    /// yields nothing, not a name read from garbage, and doesn't trap.
    @Test func tamperedOrTruncatedYieldsNothing() {
        var tampered = Self.version1Initial
        tampered[600] ^= 1
        #expect(QUIC.initialPayload(tampered) == nil)
        #expect(QUIC.initialPayload(Array(Self.version1Initial.prefix(600))) == nil)
        #expect(QUIC.initialPayload(Array(Self.version1Initial.prefix(20))) == nil)
    }

    /// Split across two Initials with the CRYPTO frames out of order and PING and
    /// PADDING between them, as Chrome sends a ClientHello: the name comes once the
    /// pieces join up from offset 0, whatever order they came in.
    @Test func joinsCryptoFramesByOffset() {
        let hello = Self.hello
        let first = initial([0x01] + crypto(90, hello[90...]) + [0, 0, 0] + crypto(0, hello[..<40]), number: 0, numberLength: 1)
        let second = initial(crypto(40, hello[40 ..< 90]) + [0x01], number: 1, numberLength: 2)
        var assembly = QUICHello()
        #expect(assembly.add(Data(first)) == nil)
        #expect(assembly.add(Data(second)) == "video.example")
    }

    /// A flow that keeps sending what looks like an Initial costs bounded work: past
    /// the limit, even a whole ClientHello is ignored.
    @Test func givesUpAfterPacketLimit() {
        var assembly = QUICHello()
        for number in 0 ..< QUICHello.packetLimit {
            // Never the opening byte, so never a name.
            #expect(assembly.add(Data(initial(crypto(1, Self.hello[1...]), number: number, numberLength: 1))) == nil)
        }
        #expect(assembly.add(Data(initial(crypto(0, Self.hello[...]), number: QUICHello.packetLimit, numberLength: 1))) == nil)
    }

    /// The offset is the sender's to claim, and a buffer sized to it could run to
    /// terabytes. A frame reaching past the limit ends the attempt: none of it is kept,
    /// nor anything after.
    @Test func givesUpAtFramePastByteLimit() {
        var assembly = QUICHello()
        let frames = crypto(QUICHello.byteLimit, [1, 2, 3]) + crypto(0, Self.hello[...])
        #expect(assembly.add(Data(initial(frames, number: 0, numberLength: 1))) == nil)
        #expect(assembly.add(Data(initial(crypto(0, Self.hello[...]), number: 1, numberLength: 1))) == nil)
    }

    /// F2.8: a QUIC connection's own server name names its row, as a TCP connection's
    /// ClientHello does.
    @Test func initialNamesItsFlow() {
        let mac = IPAddress("192.168.1.10")!
        var packet = PacketSummary(time: 1, length: 1242, proto: PacketParser.udp, source: mac, destination: IPAddress("93.184.216.34")!, sourcePort: 52000, destinationPort: 443)
        packet.quicInitial = Data(Self.version1Initial)
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [packet], dropped: 0))
        #expect(aggregator.flows.values.first?.serverName == "example.com")
    }
}
