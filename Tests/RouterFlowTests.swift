import Darwin
import Foundation
import NIOCore
import Testing
@testable import WiFiDetect

// MARK: Fixture builders

private func be16(_ value: Int) -> [UInt8] { [UInt8(value >> 8 & 0xff), UInt8(value & 0xff)] }
private func be32(_ value: Int) -> [UInt8] { be16(value >> 16 & 0xffff) + be16(value & 0xffff) }
private func be64(_ value: Int) -> [UInt8] { be32(value >> 32 & 0xffff_ffff) + be32(value & 0xffff_ffff) }

private func flowSet(_ id: Int, _ body: [UInt8]) -> [UInt8] { be16(id) + be16(4 + body.count) + body }

/// Version 9, record count, uptime, export time, sequence, source id.
private func netFlowV9(uptime: Int, exported: Int, sourceID: Int = 0, _ sets: [UInt8]...) -> [UInt8] {
    be16(9) + be16(0) + be32(uptime) + be32(exported) + be32(1) + be32(sourceID) + sets.joined()
}

/// Version 10, message length, export time, sequence, observation domain.
private func ipfix(domain: Int = 1, exported: Int = 1_760_000_000, _ sets: [UInt8]...) -> [UInt8] {
    let body = Array(sets.joined())
    return be16(10) + be16(16 + body.count) + be32(exported) + be32(1) + be32(domain) + body
}

/// A template record: id, field count, then each field's id and length.
private func template(_ id: Int, _ fields: [(Int, Int)]) -> [UInt8] {
    be16(id) + be16(fields.count) + fields.flatMap { be16($0.0) + be16($0.1) }
}

private let router = IPAddress("192.168.1.1")!
private let laptop = IPAddress("192.168.1.20")!
private let server = IPAddress("93.184.216.34")!

private func bytes(_ address: IPAddress) -> [UInt8] {
    switch address {
    case .v4(let value): be32(Int(value))
    case .v6(let high, let low): be64(Int(truncatingIfNeeded: high)) + be64(Int(truncatingIfNeeded: low))
    }
}

/// Source, destination, protocol, then the counters: the layout most tests use.
private let addressesAndCounts = template(256, [(8, 4), (12, 4), (4, 1), (1, 4), (2, 4)])

private func addressesAndCounts(_ source: IPAddress, _ destination: IPAddress, bytes count: Int, packets: Int) -> [UInt8] {
    bytes(source) + bytes(destination) + [6] + be32(count) + be32(packets)
}

private func parse(_ datagram: [UInt8], from exporter: IPAddress = router, _ templates: inout FlowTemplates) -> ExportMessage? {
    FlowExport.parse(datagram, from: exporter, templates: &templates)
}

// MARK: Parser

struct FlowExportTests {
    /// Consumer and older routers speak NetFlow v9: a layout, then values. Both records
    /// must come out as the flows they describe, the padding after them as none, and
    /// their times pinned to the wall clock through the header's uptime, even when the
    /// uptime counter has wrapped since the flow started.
    @Test func readsNetFlowV9() throws {
        let layout = template(256, [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (22, 4), (21, 4)])
        let first = bytes(laptop) + bytes(server) + be16(52000) + be16(443) + [6] + be32(1500) + be32(3) + be32(40_000) + be32(90_000)
        let wrapped = bytes(laptop) + bytes(IPAddress("1.1.1.1")!) + be16(53000) + be16(53) + [17] + be32(80) + be32(1) + be32(4_294_960_000) + be32(100_000)
        let exported = 1_760_000_000
        var templates = FlowTemplates()
        let message = try #require(parse(netFlowV9(uptime: 100_000, exported: exported, flowSet(0, layout), flowSet(256, first + wrapped + [0, 0])), &templates))

        #expect(message.version == 9)
        try #require(message.flows.count == 2)
        let flow = message.flows[0]
        #expect(flow.source == laptop && flow.destination == server)
        #expect(flow.sourcePort == 52000 && flow.destinationPort == 443 && flow.proto == 6)
        #expect(flow.bytes == 1500 && flow.packets == 3)
        #expect(flow.start == Date(timeIntervalSince1970: Double(exported) - 60))
        #expect(flow.end == Date(timeIntervalSince1970: Double(exported) - 10))
        // 7,296 ms before the counter wrapped, plus the 100,000 since.
        #expect(message.flows[1].start == Date(timeIntervalSince1970: Double(exported * 1000 - 107_296) / 1000))
    }

    /// IPFIX strings, an interface name here, take as many bytes as they need, a short
    /// one with a single length byte and a long one with 255 and two more. Misreading
    /// either shifts every field after it.
    @Test func readsIPFIXVariableLengthFields() throws {
        let layout = template(300, [(8, 4), (82, 0xffff), (12, 4), (7, 2), (11, 2), (1, 8), (152, 8), (153, 8)])
        func record(_ name: [UInt8], port: Int) -> [UInt8] {
            bytes(laptop) + name + bytes(server) + be16(port) + be16(443) + be64(4096) + be64(1_760_000_000_250) + be64(1_760_000_001_500)
        }
        let long = [UInt8](repeating: 0x61, count: 300)
        var templates = FlowTemplates()
        let message = try #require(parse(ipfix(flowSet(2, layout), flowSet(300, record([4] + Array("en0x".utf8), port: 52000) + record([255] + be16(300) + long, port: 52001))), &templates))

        #expect(message.flows.map(\.sourcePort) == [52000, 52001])
        #expect(message.flows.allSatisfy { $0.destination == server && $0.destinationPort == 443 && $0.bytes == 4096 })
        #expect(message.flows[1].start == Date(timeIntervalSince1970: 1_760_000_000.25))
        #expect(message.flows[1].end == Date(timeIntervalSince1970: 1_760_000_001.5))
    }

    /// A vendor's own element can reuse a standard element's number: this one is 1,
    /// octetDeltaCount's, under enterprise 29305. It must be skipped by its length, its
    /// enterprise number in the template skipped too (read as a field, it would garble
    /// the fields after it), and never read as a byte count.
    @Test func skipsEnterpriseElements() throws {
        let layout = be16(256) + be16(4) + be16(8) + be16(4) + be16(1) + be16(4) + be16(0x8001) + be16(8) + be32(29305) + be16(12) + be16(4)
        var templates = FlowTemplates()
        let message = try #require(parse(ipfix(flowSet(2, layout), flowSet(256, bytes(laptop) + be32(1234) + be64(999_999) + bytes(server))), &templates))
        #expect(message.flows.map(\.bytes) == [1234])
        #expect(message.flows.first?.destination == server)
    }

    /// Template ids are each exporter's own, numbered per observation domain: the same
    /// id from another domain or another router is another layout, and must not be read
    /// with this one.
    @Test func templatesBelongToTheirExporterAndDomain() throws {
        var templates = FlowTemplates()
        let v6Layout = template(256, [(27, 16), (28, 16)])
        _ = parse(ipfix(domain: 1, flowSet(2, addressesAndCounts)), &templates)
        _ = parse(ipfix(domain: 2, flowSet(2, v6Layout)), &templates)

        let data = flowSet(256, addressesAndCounts(laptop, server, bytes: 100, packets: 1))
        let message = try #require(parse(ipfix(domain: 1, data), &templates))
        #expect(message.flows.map(\.destination) == [server])
        #expect(parse(ipfix(domain: 1, data), from: IPAddress("10.0.0.1")!, &templates)?.unreadSets == 1)
    }

    /// Withdrawn, a template reads nothing more, so a router that renumbers its layouts
    /// can't have new values read with an old one; id 2 with no fields withdraws them all.
    @Test func withdrawnTemplatesReadNothing() throws {
        var templates = FlowTemplates()
        let data = flowSet(256, addressesAndCounts(laptop, server, bytes: 100, packets: 1))
        #expect(parse(ipfix(flowSet(2, addressesAndCounts), data), &templates)?.flows.count == 1)
        #expect(parse(ipfix(flowSet(2, be16(256) + be16(0)), data), &templates)?.unreadSets == 1)

        let second = template(257, [(8, 4), (12, 4)])
        _ = parse(ipfix(flowSet(2, addressesAndCounts + second)), &templates)
        let both = parse(ipfix(flowSet(2, be16(2) + be16(0)), data, flowSet(257, bytes(laptop) + bytes(server))), &templates)
        #expect(both?.unreadSets == 2)
        #expect(both?.flows.isEmpty == true)
    }

    /// Anything that reaches the port gets parsed: a message cut short, a set longer
    /// than its message, a template with no room for its fields, or not NetFlow at all
    /// must come back with what it validly held, not trap or loop.
    @Test func hostileMessagesYieldWhatTheyValidlyHold() {
        var templates = FlowTemplates()
        let good = ipfix(flowSet(2, addressesAndCounts), flowSet(256, addressesAndCounts(laptop, server, bytes: 1, packets: 1)))
        #expect(parse(Array(good.dropLast(3)), &templates)?.flows.isEmpty == true)
        #expect(parse(good, &templates)?.flows.count == 1)
        #expect(parse(ipfix(be16(256) + be16(400) + [1, 2, 3]), &templates)?.flows.isEmpty == true)
        #expect(parse(ipfix(flowSet(2, be16(258) + be16(1000))), &templates)?.flows.isEmpty == true)
        #expect(parse(ipfix(flowSet(256, [])), &templates)?.flows.isEmpty == true)
        // A set claiming no length would otherwise be read again and again, forever.
        #expect(parse(ipfix(be16(256) + be16(0)), &templates)?.flows.isEmpty == true)
        // So would records of nothing but empty fields.
        _ = parse(ipfix(flowSet(2, template(259, [(1, 0)]))), &templates)
        #expect(parse(ipfix(flowSet(259, [1, 2, 3, 4])), &templates)?.flows.isEmpty == true)
        #expect(parse([0, 9, 0, 1], &templates) == nil)
        #expect(parse([0, 5] + [UInt8](repeating: 0, count: 30), &templates) == nil)
        #expect(parse([0, 10, 0, 3] + [UInt8](repeating: 0, count: 12), &templates) == nil)
    }
}

// MARK: Table

struct RouterFlowTableTests {
    private let now = Date(timeIntervalSince1970: 1_760_000_000)

    /// Data that comes before its template is dropped and counted against the router,
    /// so the page can say why its table is still empty; once the template has come,
    /// the same data reads.
    @Test func dataBeforeItsTemplateIsCounted() {
        var table = RouterFlowTable()
        let data = flowSet(256, addressesAndCounts(laptop, server, bytes: 100, packets: 1))
        table.receive(ipfix(data), from: router, at: now)
        #expect(table.flows.isEmpty)
        #expect(table.exporters[router]?.unreadSets == 1)
        #expect(table.exporters[router]?.version == FlowExport.ipfix)

        table.receive(ipfix(flowSet(2, addressesAndCounts), data), from: router, at: now)
        #expect(table.flows.count == 1)
        #expect(table.exporters[router]?.records == 1)
    }

    /// A router reports a long flow once per active timeout, each record with the bytes
    /// since the last: one row per router and 5-tuple holds their sum. The same
    /// conversation reported by a second router is that router's row.
    @Test func recordsAddUpPerExporterAndTuple() throws {
        var table = RouterFlowTable()
        let message = ipfix(flowSet(2, addressesAndCounts), flowSet(256, addressesAndCounts(laptop, server, bytes: 100, packets: 1)))
        table.receive(message, from: router, at: now)
        table.receive(message, from: router, at: now.addingTimeInterval(60))
        table.receive(message, from: IPAddress("192.168.1.2")!, at: now)

        #expect(table.flows.count == 2)
        let flow = try #require(table.flows.values.first { $0.key.exporter == router })
        #expect(flow.bytes == 200 && flow.packets == 2)
        #expect(flow.updated == now.addingTimeInterval(60))
    }

    /// A router without NTP says it's 1970. Idleness goes by when records arrive here:
    /// by the router's clock every flow would be decades idle on arrival.
    @Test func idleIsMeasuredOnThisMacsClock() {
        var table = RouterFlowTable()
        let layout = template(256, [(8, 4), (12, 4), (150, 4), (151, 4)])
        table.receive(ipfix(exported: 1000, flowSet(2, layout), flowSet(256, bytes(laptop) + bytes(server) + be32(900) + be32(950))), from: router, at: now)
        table.prune(now: now.addingTimeInterval(599))
        #expect(table.flows.count == 1)
        #expect(table.flows.values.first?.lastSeen == Date(timeIntervalSince1970: 950))
        table.prune(now: now.addingTimeInterval(601))
        #expect(table.flows.isEmpty)
    }

    /// Anyone who reaches the port can send records for made-up flows: the table stays
    /// near its limit, giving up the flows updated longest ago.
    @Test func floodStaysWithinTheLimit() {
        var table = RouterFlowTable()
        let layout = template(256, [(8, 4), (12, 4)])
        var next = 0
        func message(_ count: Int) -> [UInt8] {
            defer { next += count }
            return ipfix(flowSet(2, layout), flowSet(256, (next ..< next + count).flatMap { bytes(.v4(0x0a00_0000 + UInt32($0))) + bytes(server) }))
        }
        table.receive(message(4000), from: router, at: now)
        table.receive(message(4000), from: router, at: now.addingTimeInterval(1))
        table.receive(message(2001), from: router, at: now.addingTimeInterval(2))
        #expect(table.flows.count == RouterFlowTable.flowLimit + 1 - RouterFlowTable.flowLimit / 10)
        #expect(table.flows.values.count { $0.updated == now } == 3000)
    }
}

// MARK: Collector

struct FlowCollectorTests {
    /// The socket is dual-stack, so an IPv4 router's datagrams arrive from ::ffff:a.b.c.d;
    /// listed that way, it would look like a second, IPv6 router.
    @Test func unmapsIPv4Senders() throws {
        #expect(IPAddress(try SocketAddress(ipAddress: "::ffff:192.168.1.1", port: 4739)) == router)
        #expect(IPAddress(try SocketAddress(ipAddress: "2001:db8::1", port: 4739)) == IPAddress("2001:db8::1"))
    }

    /// End to end over loopback: a datagram bigger than NIO reads by default (2 KB),
    /// as an exporter filling its path MTU or more sends them, arrives whole and lands in
    /// the table under its sender.
    @Test(.timeLimit(.minutes(1)))
    func collectsWholeDatagrams() async throws {
        let collector = FlowCollector()
        let port = try await collector.start(host: "127.0.0.1", port: 0)
        defer { Task { await collector.stop() } }
        let records = (0 ..< 200).flatMap { addressesAndCounts(.v4(0x0a00_0000 + UInt32($0)), server, bytes: 100, packets: 1) }
        let datagram = ipfix(flowSet(2, addressesAndCounts), flowSet(256, records))
        #expect(datagram.count > 2048)
        send(datagram, to: port)
        for _ in 0 ..< 100 where collector.table.withLock({ $0.flows.isEmpty }) {
            try await Task.sleep(for: .milliseconds(20))
        }
        let table = collector.table.withLock { $0 }
        #expect(table.flows.count == 200)
        #expect(table.exporters.keys.map(\.description) == ["127.0.0.1"])
    }

    private func send(_ datagram: [UInt8], to port: Int) {
        let socket = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(socket) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(socket, datagram, datagram.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
}
