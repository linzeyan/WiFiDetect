import Darwin
import Foundation
import Testing
@testable import WiFiDetect

// MARK: Fixture builders

private func be16(_ value: Int) -> [UInt8] { [UInt8(value >> 8 & 0xff), UInt8(value & 0xff)] }

private func ethernet(_ etherType: Int, _ payload: [UInt8]) -> [UInt8] {
    [UInt8](repeating: 0xaa, count: 12) + be16(etherType) + payload
}

private func ipv4(_ proto: UInt8, _ source: [UInt8], _ destination: [UInt8], fragment: Int = 0, _ payload: [UInt8]) -> [UInt8] {
    [0x45, 0] + be16(20 + payload.count) + [0, 0] + be16(fragment) + [64, proto, 0, 0] + source + destination + payload
}

private func ipv6(_ next: UInt8, _ source: [UInt8], _ destination: [UInt8], _ payload: [UInt8]) -> [UInt8] {
    [0x60, 0, 0, 0] + be16(payload.count) + [next, 64] + source + destination + payload
}

private func udp(_ source: Int, _ destination: Int, _ payload: [UInt8] = []) -> [UInt8] {
    be16(source) + be16(destination) + be16(8 + payload.count) + [0, 0] + payload
}

private func tcp(_ source: Int, _ destination: Int) -> [UInt8] {
    be16(source) + be16(destination) + [UInt8](repeating: 0, count: 8) + [0x50, 0x18] + [0, 0, 0, 0, 0, 0]
}

private let mac = IPAddress("192.168.1.10")!
private let server = IPAddress("93.184.216.34")!
private let mac6 = IPAddress("2001:db8::10")!
private let resolver6 = IPAddress("2001:db8::53")!

private func bytes(_ address: IPAddress) -> [UInt8] {
    switch address {
    case .v4(let value): be16(Int(value >> 16)) + be16(Int(value & 0xffff))
    case .v6(let high, let low): withUnsafeBytes(of: (high.bigEndian, low.bigEndian)) { Array($0) }
    }
}

private func parse(_ frame: [UInt8], linkType: Int32 = DLT_EN10MB, wireLength: Int? = nil) -> PacketSummary {
    frame.withUnsafeBytes { PacketParser.parse($0, wireLength: wireLength ?? frame.count, time: 1, linkType: linkType) }
}

// MARK: Parser

struct PacketParserTests {
    @Test func ipv4TCP() {
        let summary = parse(ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), tcp(52000, 443))))
        #expect(summary.proto == 6)
        #expect(summary.source == mac)
        #expect(summary.destination == server)
        #expect(summary.sourcePort == 52000)
        #expect(summary.destinationPort == 443)
        #expect(summary.dns == nil)
    }

    /// The app times TCP handshakes from these flags. ECN bits ride along on a
    /// SYN-ACK and must not make it read as something else.
    @Test func tcpFlagsKeepOnlySYNAndACK() {
        var synAck = tcp(443, 52000)
        synAck[13] = 0x52 // SYN, ACK, ECE
        #expect(parse(ethernet(0x0800, ipv4(6, bytes(server), bytes(mac), synAck))).tcpFlags == PacketParser.syn | PacketParser.ack)
        #expect(parse(ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), tcp(52000, 443)))).tcpFlags == PacketParser.ack)
    }

    /// DNS answers name the hosts in the connection table, so the payload has to
    /// survive the trip to the app, where it's parsed outside the root helper.
    @Test func ipv6DNSKeepsPayload() {
        let query: [UInt8] = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        let summary = parse(ethernet(0x86DD, ipv6(17, bytes(resolver6), bytes(mac6), udp(53, 61000, query))))
        #expect(summary.proto == 17)
        #expect(summary.source == resolver6)
        #expect(summary.sourcePort == 53)
        #expect(summary.dns == Data(query))
    }

    /// Hop-by-hop options sit between the IPv6 header and UDP; skipping them is what
    /// finds the ports.
    @Test func ipv6ExtensionHeader() {
        let hopByHop: [UInt8] = [17, 0, 0, 0, 0, 0, 0, 0]
        let summary = parse(ethernet(0x86DD, ipv6(0, bytes(mac6), bytes(resolver6), hopByHop + udp(5353, 5353))))
        #expect(summary.proto == 17)
        #expect(summary.destinationPort == 5353)
    }

    /// A truncated or non-IP frame still counts its wire length, so the app's totals
    /// and packet count match the PCAP of the same capture.
    @Test func truncatedAndNonIPStillCount() {
        let truncated = Array(ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), tcp(1, 2)))[..<24])
        let cut = parse(truncated, wireLength: 1500)
        #expect(cut.length == 1500)
        #expect(cut.source == nil)

        let arp = parse(ethernet(0x0806, [UInt8](repeating: 0, count: 28)))
        #expect(arp.proto == 0)
        #expect(arp.source == nil)
        #expect(arp.length == 42)
    }

    /// Only a datagram's first fragment carries ports; reading a later one's payload
    /// as ports would invent connections.
    @Test func laterFragmentHasNoPorts() {
        let summary = parse(ethernet(0x0800, ipv4(17, bytes(server), bytes(mac), fragment: 185, udp(53, 61000))))
        #expect(summary.source == server)
        #expect(summary.sourcePort == 0)
        #expect(summary.dns == nil)
    }

    /// lo0 and utun frames start with a 4-byte host-order address family, not Ethernet.
    @Test func loopbackLinkType() {
        let frame = withUnsafeBytes(of: UInt32(AF_INET)) { Array($0) } + ipv4(17, bytes(mac), bytes(mac), udp(5000, 6000))
        let summary = parse(frame, linkType: DLT_NULL)
        #expect(summary.source == mac)
        #expect(summary.destinationPort == 6000)
    }

    @Test func addressText() {
        #expect(IPAddress("2001:db8::10")?.description == "2001:db8::10")
        #expect(mac.description == "192.168.1.10")
        #expect(IPAddress("not an address") == nil)
    }
}

// MARK: Aggregator

struct FlowAggregatorTests {
    private func packet(_ time: Double, from source: IPAddress?, _ sourcePort: UInt16, to destination: IPAddress?, _ destinationPort: UInt16, length: Int) -> PacketSummary {
        PacketSummary(time: time, length: length, proto: 6, source: source, destination: destination, sourcePort: sourcePort, destinationPort: destinationPort)
    }

    /// A request and its response are one connection, with the bytes split by
    /// direction relative to this Mac. Getting this backwards swaps every In and Out.
    @Test func bothDirectionsLandOnOneFlow() {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [
            packet(100.2, from: mac, 52000, to: server, 443, length: 100),
            packet(100.5, from: server, 443, to: mac, 52000, length: 1500),
            packet(101.1, from: server, 443, to: mac, 52000, length: 1500),
        ], dropped: 0))

        #expect(aggregator.flows.count == 1)
        let flow = aggregator.flows.values.first!
        #expect(flow.key.local == mac && flow.key.remote == server && flow.key.remotePort == 443)
        #expect(flow.counts == TrafficCounts(bytesIn: 3000, bytesOut: 100, packetsIn: 2, packetsOut: 1))
        #expect(flow.firstSeen == Date(timeIntervalSince1970: 100.2))
        #expect(flow.lastSeen == Date(timeIntervalSince1970: 101.1))
        #expect(aggregator.seconds[100] == TrafficCounts(bytesIn: 1500, bytesOut: 100, packetsIn: 1, packetsOut: 1))
        #expect(aggregator.seconds[101] == TrafficCounts(bytesIn: 1500, packetsIn: 1))
    }

    /// The recording's packet count is what gets held up against `tcpdump -r`, so it
    /// counts every frame of that capture and nothing from the others.
    @Test func countsPacketsPerCapture() {
        var aggregator = FlowAggregator()
        aggregator.ingest(CaptureBatch(capture: 1, packets: [packet(1, from: nil, 0, to: nil, 0, length: 60)], dropped: 0))
        aggregator.ingest(CaptureBatch(capture: 2, packets: Array(repeating: packet(2, from: server, 1, to: mac, 2, length: 60), count: 3), dropped: 4))
        aggregator.ingest(CaptureBatch(capture: 2, packets: [packet(3, from: server, 1, to: mac, 2, length: 60)], dropped: 5))

        #expect(aggregator.packets == [1: 1, 2: 4])
        #expect(aggregator.dropped[2] == 5)
        // The non-IP frame counts toward totals but has no connection to show.
        #expect(aggregator.totals.packetsIn == 5)
        #expect(aggregator.flows.count == 1)
    }

    /// Quiet seconds are zero throughput, not missing data; before the first captured
    /// second nothing was measured, so nothing is plotted. Buckets stay put as the
    /// window slides, so the line doesn't shimmer.
    @Test func ratesZeroFillAndAlign() {
        let seconds: [Int: TrafficCounts] = [1000: TrafficCounts(bytesIn: 600), 1004: TrafficCounts(bytesIn: 300)]
        let perSecond = seconds.rates(window: 10, end: 1005)
        #expect(perSecond.map(\.counts.bytesIn) == [600, 0, 0, 0, 300, 0])

        let bucketed = seconds.rates(window: 3600, end: 1005)
        #expect(bucketed.map(\.counts.bytesIn) == [600, 300])
        #expect(bucketed.allSatisfy { $0.span == 6 && Int($0.date.timeIntervalSince1970) % 6 == 0 })
        #expect([Int: TrafficCounts]().rates(window: 60, end: 1005).isEmpty)
    }

    /// A capture left running for days must hold only recent connections, or its
    /// memory grows without bound. 601 seconds of silence is past the 10 minutes the
    /// Connections page promises; 100 seconds is not.
    @Test func evictsIdleFlowsOnly() {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [
            packet(1000, from: mac, 52000, to: server, 443, length: 100),
            packet(1501, from: mac, 52001, to: server, 443, length: 100),
        ], dropped: 0))
        aggregator.prune(before: 0, now: Date(timeIntervalSince1970: 1601))
        #expect(aggregator.flows.keys.map(\.localPort) == [52001])
    }

    /// The Overview's Received, Sent and Packets tiles and its chart count everything
    /// captured; a row leaving the table must not take its bytes with it.
    @Test func evictionKeepsTotals() {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [
            packet(1000, from: mac, 52000, to: server, 443, length: 100),
            packet(1000.5, from: server, 443, to: mac, 52000, length: 1500),
        ], dropped: 0))
        let totals = aggregator.totals
        let seconds = aggregator.seconds
        aggregator.prune(before: 0, now: Date(timeIntervalSince1970: 2000))
        #expect(aggregator.flows.isEmpty)
        #expect(aggregator.totals == totals)
        #expect(aggregator.seconds == seconds)
    }

    /// The top lists sit under totals that cover the whole capture. A connection
    /// leaving the table must not take its bytes out of them, or a finished download
    /// would vanish from Hosts while the Received tile still counts it.
    @Test func topListsKeepEvictedBytes() {
        let other = IPAddress("198.51.100.7")!
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [
            packet(1000, from: server, 443, to: mac, 52000, length: 1500),
            packet(1500, from: mac, 52001, to: server, 443, length: 100),
            packet(1500, from: mac, 52002, to: other, 443, length: 900),
        ], dropped: 0))
        let evicted = aggregator.prune(before: 0, now: Date(timeIntervalSince1970: 1700))
        #expect(evicted.map(\.key.localPort) == [52000])

        var totals = TopTotals()
        let host = { (flow: Flow) in flow.key.remote.description }
        // A list that can't name a flow, as Programs can't before its lookup, skips it.
        totals.retire(evicted) { flow, grouping in grouping == .program ? nil : host(flow) }
        let live = Array(aggregator.flows.values)
        let top = totals.top(.host, live: live, name: host)
        #expect(top.map(\.name) == [server.description, other.description])
        #expect(top.map(\.bytes) == [1600, 900])
        #expect(totals.top(.program, live: [], name: host).isEmpty)
    }

    /// Idle counts from the last packet, not the first: a connection that's been open
    /// for half an hour but sent something 599 seconds ago keeps its row.
    @Test func recentPacketKeepsOldFlow() {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: [
            packet(1000, from: mac, 52000, to: server, 443, length: 100),
            packet(2001, from: server, 443, to: mac, 52000, length: 1500),
        ], dropped: 0))
        aggregator.prune(before: 0, now: Date(timeIntervalSince1970: 2600))
        #expect(aggregator.flows.count == 1)
    }
}

// MARK: Names

struct DNSTests {
    private func encode(_ name: String) -> [UInt8] {
        name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
    }

    private func record(_ owner: [UInt8], type: Int, _ data: [UInt8]) -> [UInt8] {
        owner + be16(type) + be16(1) + [0, 0, 0x0e, 0x10] + be16(data.count) + data
    }

    /// speed.cloudflare.com → CNAME → A, with compression pointers, as resolvers send
    /// it. The address must be named for what curl asked for, not the CDN's alias.
    private var cnameResponse: [UInt8] {
        let header: [UInt8] = [0x12, 0x34, 0x81, 0x80] + be16(1) + be16(2) + be16(0) + be16(0)
        let question = encode("speed.cloudflare.com") + be16(1) + be16(1)
        let alias = record([0xc0, 0x0c], type: 5, encode("cdn.example"))
        // The alias's own name starts after its 12-byte fixed part: header + question + 2 + 10.
        let aliasName = 12 + question.count + 12
        return header + question + alias + record([0xc0, UInt8(aliasName)], type: 1, [162, 159, 140, 220])
    }

    @Test func namesAddressForTheQueriedName() {
        let found = DNS.addresses(in: Data(cnameResponse))
        #expect(found.map(\.0) == [IPAddress("162.159.140.220")!])
        #expect(found.map(\.1) == ["speed.cloudflare.com"])
    }

    /// mDNS announcements carry no question; the record's own name is all there is.
    @Test func mDNSAnnouncementUsesOwnerName() {
        let header: [UInt8] = [0, 0, 0x84, 0] + be16(0) + be16(1) + be16(0) + be16(0)
        let message = header + record(encode("Studio.local"), type: 28, bytes(mac6))
        #expect(DNS.addresses(in: Data(message)).map(\.1) == ["Studio.local"])
    }

    /// Wire bytes come from anyone: a pointer loop, a cut-off message or a query must
    /// come back empty-handed, not hang or trap.
    @Test func hostileMessagesYieldNothing() {
        let header: [UInt8] = [0, 0, 0x81, 0x80] + be16(1) + be16(1) + be16(0) + be16(0)
        #expect(DNS.addresses(in: Data(header + [0xc0, 0x0c] + be16(1) + be16(1))).isEmpty)
        #expect(DNS.addresses(in: Data(cnameResponse.dropLast(3))).isEmpty)
        var query = cnameResponse
        query[2] = 0x01
        #expect(DNS.addresses(in: Data(query)).isEmpty)
    }
}

struct AddressScopeTests {
    /// F2.10: which traffic stays on this network and which leaves it.
    @Test(arguments: [
        ("192.168.11.100", AddressScope.privateNetwork), ("10.1.2.3", .privateNetwork), ("172.31.0.1", .privateNetwork),
        ("172.32.0.1", .internet), ("100.100.1.1", .privateNetwork), ("127.0.0.1", .loopback),
        ("169.254.1.1", .linkLocal), ("224.0.0.251", .multicast), ("255.255.255.255", .broadcast),
        ("192.0.2.1", .reserved), ("8.8.8.8", .internet), ("::1", .loopback), ("fe80::1", .linkLocal),
        ("fd12::1", .privateNetwork), ("ff02::fb", .multicast), ("2001:db8::1", .reserved), ("2606:4700::1", .internet),
    ])
    func scope(address: String, expected: AddressScope) {
        #expect(IPAddress(address)?.scope == expected)
    }
}

struct GeoIPTests {
    /// Reads the bundled DB-IP files through the hand-written MMDB reader, IPv4 and
    /// IPv6 alike. A missing database fails here instead of quietly blanking the
    /// Location column.
    @Test func looksUpWellKnownNetworks() {
        #expect(GeoIP.shared.isAvailable)
        let google = GeoIP.shared.lookup(IPAddress("8.8.8.8")!)
        #expect(google.asn == 15169)
        #expect(google.countryCode == "US")
        #expect(google.countryLabel == "🇺🇸 United States")
        let cloudflare = GeoIP.shared.lookup(IPAddress("2606:4700:4700::1111")!)
        #expect(cloudflare.asn == 13335)
        #expect(GeoIP.shared.lookup(IPAddress("192.168.1.1")!).asn == nil)
    }
}

struct TLSServerNameTests {
    /// A ClientHello as curl sends it: an extension before server_name, so the walk
    /// over the extension list is what finds it.
    static func clientHello(_ host: String) -> [UInt8] {
        let name = Array(host.utf8)
        let sni = be16(0) + be16(name.count + 5) + be16(name.count + 3) + [0] + be16(name.count) + name
        let extensions = be16(0x000b) + be16(2) + [1, 0] + sni
        let body: [UInt8] = [3, 3] + [UInt8](repeating: 7, count: 32) + [32] + [UInt8](repeating: 9, count: 32)
            + be16(4) + [0x13, 0x01, 0x13, 0x02] + [1, 0] + be16(extensions.count) + extensions
        let handshake = [1, 0] + be16(body.count) + body
        return [0x16, 3, 1] + be16(handshake.count) + handshake
    }

    @Test func readsServerName() {
        #expect(TLS.serverName(in: Data(Self.clientHello("speed.cloudflare.com"))) == "speed.cloudflare.com")
    }

    /// Cut short by the snapshot length, or not a ClientHello at all: no name, no trap.
    @Test func truncatedOrOtherRecordsYieldNothing() {
        let hello = Self.clientHello("speed.cloudflare.com")
        #expect(TLS.serverName(in: Data(hello.prefix(hello.count - 4))) == nil)
        #expect(TLS.serverName(in: Data(hello.prefix(60))) == nil)
        var serverHello = hello
        serverHello[5] = 2
        #expect(TLS.serverName(in: Data(serverHello)) == nil)
    }

    /// From UDP the helper hands over a QUIC client Initial, the one packet a server
    /// name can be read from: not the Handshake, 0-RTT or Retry packets that share the
    /// long header, not short headers, not other ports.
    @Test func parserPassesOnlyQUICInitials() {
        let padding = [UInt8](repeating: 0, count: 32)
        func initial(_ port: Int, _ header: [UInt8]) -> Data? {
            parse(ethernet(0x0800, ipv4(17, bytes(mac), bytes(server), udp(52000, port, header + padding)))).quicInitial
        }
        let version1: [UInt8] = [0xc3, 0, 0, 0, 1]
        #expect(initial(443, version1) == Data(version1 + padding))
        #expect(initial(443, [0xd3, 0x6b, 0x33, 0x43, 0xcf]) != nil)
        #expect(initial(443, [0xe3, 0, 0, 0, 1]) == nil) // version 1 Handshake
        #expect(initial(443, [0xd3, 0, 0, 0, 1]) == nil) // version 1 0-RTT
        #expect(initial(443, [0xc3, 0x6b, 0x33, 0x43, 0xcf]) == nil) // version 2 Retry
        #expect(initial(443, [0x43, 0, 0, 0, 1]) == nil) // short header
        #expect(initial(8443, version1) == nil)
    }

    /// The helper hands over a ClientHello and nothing else from a TCP stream.
    @Test func parserPassesOnlyClientHellos() {
        let hello = parse(ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), tcp(52000, 443) + Self.clientHello("example.com"))))
        #expect(hello.clientHello.map { TLS.serverName(in: $0) } == "example.com")
        let data = parse(ethernet(0x0800, ipv4(6, bytes(server), bytes(mac), tcp(443, 52000) + [0x17, 3, 3, 0, 32] + [UInt8](repeating: 1, count: 32))))
        #expect(data.clientHello == nil)
    }
}

// MARK: Capture files

private func le32(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.littleEndian) { Array($0) } }

/// A pcap file as tcpdump writes one: little-endian, microsecond timestamps.
private func pcap(_ packets: [(time: Double, frame: [UInt8])], linkType: UInt32 = 1) -> [UInt8] {
    packets.reduce(le32(0xa1b2_c3d4) + [2, 0, 4, 0] + le32(0) + le32(0) + le32(65535) + le32(linkType)) { file, packet in
        let seconds = UInt32(packet.time)
        let micros = UInt32(((packet.time - Double(seconds)) * 1_000_000).rounded())
        return file + le32(seconds) + le32(micros) + le32(UInt32(packet.frame.count)) + le32(UInt32(packet.frame.count)) + packet.frame
    }
}

/// The same packets as pcapng: a section header, one Ethernet interface, then an
/// enhanced packet block each.
private func pcapng(_ packets: [(time: Double, frame: [UInt8])]) -> [UInt8] {
    func block(_ type: UInt32, _ body: [UInt8]) -> [UInt8] {
        let padded = body + [UInt8](repeating: 0, count: (4 - body.count % 4) % 4)
        return le32(type) + le32(UInt32(12 + padded.count)) + padded + le32(UInt32(12 + padded.count))
    }
    let header = block(0x0a0d_0d0a, le32(0x1a2b_3c4d) + [1, 0, 0, 0] + [UInt8](repeating: 0xff, count: 8)) + block(1, [1, 0, 0, 0] + le32(65535))
    return packets.reduce(header) { file, packet in
        let micros = UInt64((packet.time * 1_000_000).rounded())
        let count = le32(UInt32(packet.frame.count))
        return file + block(6, le32(0) + le32(UInt32(micros >> 32)) + le32(UInt32(truncatingIfNeeded: micros)) + count + count + packet.frame)
    }
}

private func temporaryFile(_ bytes: [UInt8], _ pathExtension: String = "pcap") throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).\(pathExtension)")
    try Data(bytes).write(to: url)
    return url
}

/// Captured on a machine that isn't this Mac, eleven days into 1970: a download from
/// `server`, a request to another host, a neighbor's mDNS announcement and an ARP.
private let capturedElsewhere: [(time: Double, frame: [UInt8])] = [
    (1_000_000.25, ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), tcp(52000, 443)))),
    (1_000_000.5, ethernet(0x0800, ipv4(6, bytes(server), bytes(mac), tcp(443, 52000) + [UInt8](repeating: 0, count: 1000)))),
    (1_000_090, ethernet(0x0800, ipv4(6, bytes(mac), bytes(IPAddress("198.51.100.7")!), tcp(52001, 80)))),
    (1_000_100, ethernet(0x0800, ipv4(17, bytes(IPAddress("192.168.1.20")!), bytes(IPAddress("224.0.0.251")!), udp(5353, 5353)))),
    (1_000_100.5, ethernet(0x0806, [UInt8](repeating: 0, count: 28))),
]

struct CaptureFileTests {
    private func read(_ bytes: [UInt8], _ pathExtension: String = "pcap") throws -> (file: FlowAggregator, failure: CaptureFileError?) {
        let url = try temporaryFile(bytes, pathExtension)
        defer { try? FileManager.default.removeItem(at: url) }
        let reader = CaptureFileReader()
        var failure: CaptureFileError?
        do throws(CaptureFileError) {
            try reader.read(url, flowLimit: 100) { _ in }
        } catch {
            failure = error
        }
        return (reader.sink.state.withLock { $0 }, failure)
    }

    /// A file shows when its packets happened and which way they went for the machine
    /// that captured it, which needn't be this Mac: times come from the file, and the
    /// machine from its conversations. A neighbor's multicast is heard, not sent.
    @Test func readsPacketTimesAndDirections() throws {
        let (file, failure) = try read(pcap(capturedElsewhere))
        #expect(failure == nil)
        #expect(file.localAddresses == [mac])
        #expect(file.totals.packetsIn + file.totals.packetsOut == 5)
        #expect(file.totals.packetsOut == 2)
        #expect(file.seconds.keys.sorted() == [1_000_000, 1_000_090, 1_000_100])
        #expect(file.flows.count == 3)
        let download = try #require(file.flows.values.first { $0.key.remote == server })
        #expect(download.key.local == mac && download.key.localPort == 52000)
        #expect(download.counts.packetsOut == 1 && download.counts.packetsIn == 1)
        #expect(download.firstSeen == Date(timeIntervalSince1970: 1_000_000.25))
        #expect(download.lastSeen == Date(timeIntervalSince1970: 1_000_000.5))
    }

    /// The Open panel offers pcapng as well, the format Wireshark writes by default:
    /// the same packets read the same either way.
    @Test func readsPcapngLikePcap() throws {
        let classic = try read(pcap(capturedElsewhere)).file
        let (next, failure) = try read(pcapng(capturedElsewhere), "pcapng")
        #expect(failure == nil)
        #expect(next.totals == classic.totals)
        #expect(next.seconds == classic.seconds)
        #expect(Set(next.flows.keys) == Set(classic.flows.keys))
    }

    /// A recording copied while still being written ends mid-packet. What comes before
    /// the cut must still show, and the cut be said rather than passed off as the end.
    @Test func keepsPacketsBeforeACut() throws {
        let (file, failure) = try read(Array(pcap(capturedElsewhere).dropLast(20)))
        #expect(failure != nil)
        #expect(file.totals.packetsIn + file.totals.packetsOut == 4)
    }

    /// Linux's `tcpdump -i any` writes cooked frames, which the parser doesn't read: the
    /// packets still count, and the page says why no connections show rather than
    /// looking empty.
    @Test func saysWhenFramesCantBeRead() throws {
        let (file, failure) = try read(pcap(capturedElsewhere, linkType: 113))
        #expect(failure?.message.contains("Linux cooked") == true)
        #expect(file.totals.packetsIn == 5)
        #expect(file.flows.isEmpty)
    }

    /// A file's connections get what live ones get from the same packets: the TCP
    /// handshake's round trip, timed by the file's timestamps, and the server name in a
    /// QUIC Initial, which only decrypts whole.
    @Test func timesHandshakesAndNamesQUIC() throws {
        var syn = tcp(52000, 443)
        syn[13] = PacketParser.syn
        var synAck = tcp(443, 52000)
        synAck[13] = PacketParser.syn | PacketParser.ack
        let (file, failure) = try read(pcap([
            (1_000_000, ethernet(0x0800, ipv4(6, bytes(mac), bytes(server), syn))),
            (1_000_000.025, ethernet(0x0800, ipv4(6, bytes(server), bytes(mac), synAck))),
            (1_000_001, ethernet(0x0800, ipv4(17, bytes(mac), bytes(server), udp(52001, 443, QUICTests.version1Initial)))),
        ]))
        #expect(failure == nil)
        let rtt = try #require(file.flows.values.first { $0.key.proto == PacketParser.tcp }?.rtt)
        #expect(abs(rtt - 0.025) < 0.000_01)
        #expect(file.flows.values.first { $0.key.proto == PacketParser.udp }?.serverName == "example.com")
    }

    /// The capturing machine is whichever addresses every conversation goes through:
    /// both of its IPv4 addresses, though a server talks to the two of them, and for an
    /// IPv6 address that only ever talked to one server, the private end of the pair
    /// rather than the internet one.
    @Test func hostIsWhatEveryConversationGoesThrough() {
        let second = IPAddress("192.168.1.11")!
        let private6 = IPAddress("fd12::10")!
        let resolver = IPAddress("1.1.1.1")!
        let conversations: Set<Conversation> = [
            Conversation(mac, server), Conversation(mac, resolver), Conversation(mac, IPAddress("8.8.8.8")!),
            Conversation(second, resolver), Conversation(second, IPAddress("9.9.9.9")!),
            Conversation(IPAddress("2606:4700::1111")!, private6),
        ]
        #expect(CaptureFileReader.hosts(of: conversations) == [mac, second, private6])
    }

    /// A file keeps its connections however old, up to a limit; past it the ones idle
    /// longest go, and the totals above the table still count them.
    @Test func capKeepsTheMostRecentlyActive() {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 0, packets: [1000, 3000, 2000].enumerated().map { index, time in
            PacketSummary(time: time, length: 100, proto: 6, source: mac, destination: server, sourcePort: UInt16(index + 1), destinationPort: 443)
        }, dropped: 0))
        let totals = aggregator.totals
        let evicted = aggregator.prune(keepingLatest: 2)
        #expect(evicted.map(\.key.localPort) == [1])
        #expect(Set(aggregator.flows.keys.map(\.localPort)) == [2, 3])
        #expect(aggregator.totals == totals)
    }
}

@MainActor
struct OpenFileTests {
    /// Days-old packets against today's clock: pruned as live capture is, a file would
    /// lose its whole history (over an hour old) and every connection (idle for days).
    /// Shown, it keeps both, and its chart ends where it does. Back to Live, none of it
    /// stays behind.
    @Test(.timeLimit(.minutes(1)))
    func fileKeepsItsHistoryAndConnections() async throws {
        let url = try temporaryFile(pcap(capturedElsewhere))
        defer { try? FileManager.default.removeItem(at: url) }
        let traffic = TrafficStore()
        await traffic.open(url)
        while traffic.file?.progress != nil {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(traffic.file?.error == nil)
        #expect(traffic.flows.count == 3)
        #expect(traffic.seconds.keys.sorted() == [1_000_000, 1_000_090, 1_000_100])
        #expect(traffic.now == 1_000_100)
        #expect(traffic.file?.span == 1_000_000 ... 1_000_100)
        #expect(traffic.file?.packets == 5)
        #expect(traffic.file?.hosts == [mac])

        await traffic.backToLive()
        #expect(traffic.file == nil)
        #expect(traffic.flows.isEmpty && traffic.seconds.isEmpty)
    }
}
