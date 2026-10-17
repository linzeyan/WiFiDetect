import Foundation
import NIOCore
import NIOPosix
import Observation
import Synchronization

// MARK: Parsing

/// One flow record from a router's NetFlow v9 (RFC 3954) or IPFIX (RFC 7011) export,
/// cut down to what the Router Flows page shows.
struct ExportedFlow: Equatable, Sendable {
    var proto: UInt8 = 0
    var source: IPAddress?
    var destination: IPAddress?
    var sourcePort: UInt16 = 0
    var destinationPort: UInt16 = 0
    var bytes = 0
    var packets = 0
    /// By the exporter's clock; nil when its template carries no times.
    var start: Date?
    var end: Date?
}

/// The record layouts exporters have announced. Both protocols send a layout now and
/// then and only values in between, so a data set means nothing until its template
/// has come.
struct FlowTemplates {
    /// Template ids are the exporter's own, numbered per source id (v9) or observation
    /// domain (IPFIX), as both RFCs scope them.
    struct Key: Hashable {
        var exporter: IPAddress
        var version: UInt16
        var domain: UInt32
        var id: UInt16
    }

    struct Field: Equatable {
        var id: UInt16
        /// 0xFFFF: variable, given in each record (IPFIX).
        var length: Int
        /// An IPFIX vendor's own element: its id means something to that vendor only,
        /// so it's skipped by length.
        var enterprise: Bool
    }

    // ponytail: capped rather than aged out. Anyone who reaches the port can announce
    // templates, and 1,024 of up to 256 fields bounds what that costs; a big router with
    // more (one per interface and domain) needs expiry at its template refresh interval.
    static let limit = 1024
    static let fieldLimit = 256

    private(set) var layouts: [Key: [Field]] = [:]

    subscript(key: Key) -> [Field]? {
        layouts[key]
    }

    mutating func add(_ fields: [Field], for key: Key) {
        guard fields.count <= Self.fieldLimit, layouts[key] != nil || layouts.count < Self.limit else { return }
        layouts[key] = fields
    }

    mutating func withdraw(_ key: Key) {
        layouts[key] = nil
    }

    /// Every template of the key's exporter and domain.
    mutating func withdrawAll(like key: Key) {
        layouts = layouts.filter { $0.key.exporter != key.exporter || $0.key.version != key.version || $0.key.domain != key.domain }
    }
}

/// What one export message held.
struct ExportMessage: Equatable {
    var version: UInt16
    var flows: [ExportedFlow] = []
    /// Data sets whose template hadn't come, or had been withdrawn: dropped and counted
    /// rather than held. A router repeats its templates every few minutes, and records
    /// held that long would show up late anyway.
    var unreadSets = 0
}

enum FlowExport {
    static let netFlowV9: UInt16 = 9
    static let ipfix: UInt16 = 10

    /// Nil unless the datagram is NetFlow v9 or IPFIX. The bytes come from anyone who
    /// can reach the port, so every read is bounds-checked, and a malformed set ends the
    /// message, keeping what came before it.
    static func parse(_ bytes: [UInt8], from exporter: IPAddress, templates: inout FlowTemplates) -> ExportMessage? {
        guard bytes.count >= 4 else { return nil }
        let version = UInt16(number(bytes[0 ..< 2]))
        let clock: Clock
        let domain: Int
        let sets: Range<Int>
        switch version {
        case netFlowV9:
            // Version, record count, uptime (ms), export time (s), sequence, source id.
            guard bytes.count >= 20 else { return nil }
            clock = Clock(exported: number(bytes[8 ..< 12]), uptime: number(bytes[4 ..< 8]))
            domain = number(bytes[16 ..< 20])
            sets = 20 ..< bytes.count
        case ipfix:
            // Version, message length, export time (s), sequence, observation domain.
            guard bytes.count >= 16, number(bytes[2 ..< 4]) >= 16 else { return nil }
            clock = Clock(exported: number(bytes[4 ..< 8]), uptime: nil)
            domain = number(bytes[12 ..< 16])
            sets = 16 ..< min(bytes.count, number(bytes[2 ..< 4]))
        default:
            return nil
        }
        var key = FlowTemplates.Key(exporter: exporter, version: version, domain: UInt32(domain), id: 0)
        var message = ExportMessage(version: version)
        var offset = sets.lowerBound
        while offset + 4 <= sets.upperBound {
            let id = number(bytes[offset ..< offset + 2])
            let length = number(bytes[offset + 2 ..< offset + 4])
            guard length >= 4, offset + length <= sets.upperBound else { break }
            let set = offset + 4 ..< offset + length
            if id == (version == ipfix ? 2 : 0) {
                readTemplates(bytes, set, key, ipfix: version == ipfix, into: &templates)
            } else if id >= 256 {
                key.id = UInt16(id)
                if let fields = templates[key] {
                    message.flows += records(bytes, set, fields, clock)
                } else {
                    message.unreadSets += 1
                }
            }
            // Options templates (v9's set 1, IPFIX's 3) describe the exporter, not
            // flows; the other ids are reserved.
            offset += length
        }
        return message
    }

    private static func readTemplates(_ bytes: [UInt8], _ set: Range<Int>, _ key: FlowTemplates.Key, ipfix: Bool, into templates: inout FlowTemplates) {
        var key = key
        var offset = set.lowerBound
        // Template id, field count, the fields; anything under 4 bytes left is padding.
        while offset + 4 <= set.upperBound {
            key.id = UInt16(number(bytes[offset ..< offset + 2]))
            let count = number(bytes[offset + 2 ..< offset + 4])
            offset += 4
            // No fields withdraws the template, and id 2 all of them (RFC 7011 §8.1).
            guard count > 0 else {
                if key.id == 2 {
                    templates.withdrawAll(like: key)
                } else {
                    templates.withdraw(key)
                }
                continue
            }
            var fields: [FlowTemplates.Field] = []
            for _ in 0 ..< count {
                guard offset + 4 <= set.upperBound else { return }
                let id = number(bytes[offset ..< offset + 2])
                // IPFIX's top bit marks an enterprise element; its enterprise number follows.
                let enterprise = ipfix && id & 0x8000 != 0
                fields.append(FlowTemplates.Field(id: UInt16(enterprise ? id & 0x7fff : id), length: number(bytes[offset + 2 ..< offset + 4]), enterprise: enterprise))
                offset += enterprise ? 8 : 4
            }
            guard offset <= set.upperBound else { return }
            if key.id >= 256 {
                templates.add(fields, for: key)
            }
        }
    }

    private static func records(_ bytes: [UInt8], _ set: Range<Int>, _ fields: [FlowTemplates.Field], _ clock: Clock) -> [ExportedFlow] {
        // The shortest a record can be; whatever's left shorter is the set's padding.
        let shortest = fields.reduce(0) { $0 + ($1.length == 0xffff ? 1 : $1.length) }
        guard shortest > 0 else { return [] }
        var flows: [ExportedFlow] = []
        var offset = set.lowerBound
        while set.upperBound - offset >= shortest {
            var flow = ExportedFlow()
            var times = Times()
            for field in fields {
                var length = field.length
                if length == 0xffff {
                    // One length byte, or 255 and two more (RFC 7011 §7).
                    guard offset < set.upperBound else { return flows }
                    length = Int(bytes[offset])
                    offset += 1
                    if length == 255 {
                        guard offset + 2 <= set.upperBound else { return flows }
                        length = number(bytes[offset ..< offset + 2])
                        offset += 2
                    }
                }
                guard offset + length <= set.upperBound else { return flows }
                if !field.enterprise {
                    read(field.id, bytes[offset ..< offset + length], into: &flow, &times)
                }
                offset += length
            }
            flow.start = clock.date(times.start, uptime: times.startUptime, systemInit: times.systemInit)
            flow.end = clock.date(times.end, uptime: times.endUptime, systemInit: times.systemInit)
            flows.append(flow)
        }
        return flows
    }

    /// Information elements by IANA number, which NetFlow v9's field types share for
    /// these. Counters and ports may come in fewer bytes than their type
    /// (reduced-size encoding, RFC 7011 §6.2); addresses only at their full size.
    private static func read(_ id: UInt16, _ value: ArraySlice<UInt8>, into flow: inout ExportedFlow, _ times: inout Times) {
        let small = value.count <= 8
        switch id {
        case 1 where small: flow.bytes = number(value) // octetDeltaCount, IN_BYTES
        case 2 where small: flow.packets = number(value) // packetDeltaCount, IN_PKTS
        case 4 where small: flow.proto = UInt8(truncatingIfNeeded: number(value))
        case 7 where small: flow.sourcePort = UInt16(truncatingIfNeeded: number(value))
        case 11 where small: flow.destinationPort = UInt16(truncatingIfNeeded: number(value))
        case 8 where value.count == 4: flow.source = value.withUnsafeBytes { IPAddress(v4Bytes: $0) }
        case 12 where value.count == 4: flow.destination = value.withUnsafeBytes { IPAddress(v4Bytes: $0) }
        case 27 where value.count == 16: flow.source = value.withUnsafeBytes { IPAddress(v6Bytes: $0) }
        case 28 where value.count == 16: flow.destination = value.withUnsafeBytes { IPAddress(v6Bytes: $0) }
        case 22 where small: times.startUptime = number(value) // flowStartSysUpTime, FIRST_SWITCHED
        case 21 where small: times.endUptime = number(value) // flowEndSysUpTime, LAST_SWITCHED
        // Milliseconds win over seconds, whichever comes first in the record.
        case 150 where small: times.start = times.start ?? number(value) * 1000 // flowStartSeconds
        case 151 where small: times.end = times.end ?? number(value) * 1000 // flowEndSeconds
        case 152 where small: times.start = number(value) // flowStartMilliseconds
        case 153 where small: times.end = number(value) // flowEndMilliseconds
        case 160 where small: times.systemInit = number(value) // systemInitTimeMilliseconds
        default: break
        }
    }

    /// Big-endian, up to 8 bytes.
    private static func number(_ bytes: ArraySlice<UInt8>) -> Int {
        bytes.reduce(0) { $0 << 8 | Int($1) }
    }

    /// A record's times, in milliseconds: since 1970, or since the exporter booted.
    private struct Times {
        var start: Int?
        var end: Int?
        var startUptime: Int?
        var endUptime: Int?
        var systemInit: Int?
    }

    /// The message header's clock. NetFlow v9 gives flow times in milliseconds of the
    /// exporter's uptime, which its header pins to the wall clock; IPFIX can do the same
    /// against systemInitTimeMilliseconds, if the record carries it (exporters mostly
    /// send it in options records, which aren't read).
    private struct Clock {
        /// Seconds since 1970.
        let exported: Int
        /// Milliseconds since the exporter booted, at `exported` (NetFlow v9).
        let uptime: Int?

        func date(_ milliseconds: Int?, uptime value: Int?, systemInit: Int?) -> Date? {
            if let milliseconds {
                return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
            }
            guard let value else { return nil }
            if let systemInit {
                return Date(timeIntervalSince1970: Double(systemInit + value) / 1000)
            }
            guard let uptime else { return nil }
            // The uptime counter is 32 bits and wraps every 49.7 days; the age doesn't.
            let age = (uptime - value) & 0xffff_ffff
            return Date(timeIntervalSince1970: Double(exported * 1000 - age) / 1000)
        }
    }
}

// MARK: Aggregation

struct RouterFlowKey: Hashable, Sendable {
    var exporter: IPAddress
    var proto: UInt8
    var source: IPAddress
    var sourcePort: UInt16
    var destination: IPAddress
    var destinationPort: UInt16
}

/// One exporter's records for a 5-tuple, added up: a router reports a long flow once
/// per active timeout (a minute to half an hour), each record with the bytes since the
/// last.
struct RouterFlow: Identifiable, Sendable {
    let key: RouterFlowKey
    var bytes = 0
    var packets = 0
    /// By the exporter's clock, or this Mac's when its records carry no times.
    var firstSeen: Date
    var lastSeen: Date
    /// When a record for it last came, by this Mac's clock. Idleness is measured on
    /// this: a router's own clock can be anything, years off on one without NTP.
    var updated: Date

    var id: RouterFlowKey { key }
}

struct Exporter: Identifiable, Sendable {
    let address: IPAddress
    var version: UInt16
    var lastHeard: Date
    var records = 0
    var unreadSets = 0

    var id: IPAddress { address }
}

/// The Router Flows table. Pure state, so it can be fed fixtures in tests; the collector
/// keeps one behind a lock and the store snapshots it.
struct RouterFlowTable {
    /// As many as a capture file keeps. Anyone who reaches the port can send records, so
    /// every part of the table has a bound.
    static let flowLimit = 10_000
    static let exporterLimit = 64

    private(set) var flows: [RouterFlowKey: RouterFlow] = [:]
    private(set) var exporters: [IPAddress: Exporter] = [:]
    /// Bumped on every change, so a snapshot can skip copying when nothing arrived.
    private(set) var version = 0
    private var templates = FlowTemplates()

    mutating func receive(_ datagram: [UInt8], from address: IPAddress, at now: Date) {
        guard exporters[address] != nil || exporters.count < Self.exporterLimit,
              let message = FlowExport.parse(datagram, from: address, templates: &templates) else { return }
        var exporter = exporters[address] ?? Exporter(address: address, version: message.version, lastHeard: now)
        exporter.version = message.version
        exporter.lastHeard = now
        exporter.records += message.flows.count
        exporter.unreadSets += message.unreadSets
        exporters[address] = exporter
        for record in message.flows {
            // A record without addresses (an L2 or MPLS template) has no row to go in.
            guard let source = record.source, let destination = record.destination else { continue }
            let key = RouterFlowKey(exporter: address, proto: record.proto, source: source, sourcePort: record.sourcePort, destination: destination, destinationPort: record.destinationPort)
            let start = record.start ?? record.end ?? now
            let end = record.end ?? record.start ?? now
            var flow = flows[key] ?? RouterFlow(key: key, firstSeen: start, lastSeen: end, updated: now)
            flow.bytes += record.bytes
            flow.packets += record.packets
            flow.firstSeen = min(flow.firstSeen, start)
            flow.lastSeen = max(flow.lastSeen, end)
            flow.updated = now
            flows[key] = flow
        }
        // A tenth at a time, so the sort doesn't run for every new flow past the limit.
        if flows.count > Self.flowLimit {
            for flow in flows.values.sorted(by: { $0.updated < $1.updated }).prefix(Self.flowLimit / 10) {
                flows[flow.key] = nil
            }
        }
        version += 1
    }

    /// Drops flows no record has updated for `FlowAggregator.idleLimit`, as the
    /// Connections table drops idle connections.
    mutating func prune(now: Date) {
        let kept = flows.filter { now.timeIntervalSince($0.value.updated) <= FlowAggregator.idleLimit }
        if kept.count != flows.count {
            flows = kept
            version += 1
        }
    }
}

// MARK: Collector

extension IPAddress {
    /// A datagram's sender. The collector's socket is dual-stack, so IPv4 senders arrive
    /// as ::ffff:a.b.c.d; they're IPv4 exporters, and show as such.
    init?(_ address: SocketAddress) {
        guard let text = address.ipAddress, let parsed = IPAddress(text) else { return nil }
        if case .v6(0, let low) = parsed, low >> 32 == 0xffff {
            self = .v4(UInt32(truncatingIfNeeded: low))
        } else {
            self = parsed
        }
    }
}

/// Listens for export datagrams over UDP, which needs no root, and folds them in on
/// NIO's event loop: the main thread never parses one.
final class FlowCollector: Sendable {
    let table = Mutex(RouterFlowTable())
    private let channel = Mutex<Channel?>(nil)

    /// Returns the port bound: port 0 picks a free one.
    func start(host: String, port: Int) async throws -> Int {
        let channel = try await DatagramBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            // NIO reads datagrams into 2 KB by default and cuts the rest off; an IPFIX
            // message may be up to 64 KB, sent fragmented.
            .channelOption(.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 65_536))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ExportReceiver(collector: self))
                }
            }
            .bind(host: host, port: port)
            .get()
        self.channel.withLock { $0 = channel }
        return channel.localAddress?.port ?? port
    }

    func stop() async {
        let channel = channel.withLock { channel in
            defer { channel = nil }
            return channel
        }
        try? await channel?.close()
    }
}

private final class ExportReceiver: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let collector: FlowCollector

    init(collector: FlowCollector) {
        self.collector = collector
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        guard let exporter = IPAddress(envelope.remoteAddress) else { return }
        let bytes = Array(envelope.data.readableBytesView)
        collector.table.withLock { $0.receive(bytes, from: exporter, at: .now) }
    }
}

// MARK: Store

/// The Router Flows page's data, and the collector Settings › Traffic turns on. Off by
/// default: it listens on every interface, to whoever sends. App-wide, so collecting
/// goes on with the window closed, like capture.
@MainActor @Observable
final class RouterFlowStore {
    static let defaultPort = 4739

    var isEnabled: Bool {
        didSet {
            UserDefaults.standard.set(isEnabled, forKey: SettingsKey.routerFlows)
            restart()
        }
    }
    /// Settings keeps it within 1024–65535.
    var port: Int {
        didSet {
            guard port != oldValue else { return }
            UserDefaults.standard.set(port, forKey: SettingsKey.routerFlowsPort)
            if isEnabled {
                restart()
            }
        }
    }
    /// The port bound while listening.
    private(set) var listening: Int?
    private(set) var error: String?
    private(set) var flows: [RouterFlow] = []
    private(set) var exporters: [Exporter] = []

    @ObservationIgnored let collector = FlowCollector()
    @ObservationIgnored private var restarting: Task<Void, Never>?
    @ObservationIgnored private var version = -1

    init() {
        isEnabled = UserDefaults.standard.bool(forKey: SettingsKey.routerFlows)
        port = UserDefaults.standard.object(forKey: SettingsKey.routerFlowsPort) as? Int ?? Self.defaultPort
        if isEnabled {
            restart()
        }
        // Lives as long as the app, like the store.
        Task {
            while true {
                self.snapshot()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// One after another: switched off and on quickly, the new listener mustn't try the
    /// port while the old one still holds it.
    private func restart() {
        restarting = Task { [previous = restarting] in
            await previous?.value
            await collector.stop()
            listening = nil
            error = nil
            guard isEnabled else { return }
            do {
                // "::" is every interface, IPv4 too: NIO opens IPv6 sockets dual-stack.
                listening = try await collector.start(host: "::", port: port)
            } catch let error as IOError where error.errnoCode == EADDRINUSE {
                self.error = String(localized: "Port \(port) is taken by another app. Choose another.")
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func snapshot() {
        let now = Date.now
        let copy = collector.table.withLock { table -> (flows: [RouterFlow], exporters: [Exporter], version: Int)? in
            table.prune(now: now)
            return table.version == version ? nil : (Array(table.flows.values), Array(table.exporters.values), table.version)
        }
        guard let copy else { return }
        version = copy.version
        flows = copy.flows
        exporters = copy.exporters.sorted { $0.address < $1.address }
    }
}
