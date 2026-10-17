import Foundation

struct TrafficCounts: Equatable, Sendable {
    var bytesIn = 0
    var bytesOut = 0
    var packetsIn = 0
    var packetsOut = 0

    mutating func add(_ length: Int, outbound: Bool) {
        if outbound {
            bytesOut += length
            packetsOut += 1
        } else {
            bytesIn += length
            packetsIn += 1
        }
    }

    static func + (a: Self, b: Self) -> Self {
        Self(bytesIn: a.bytesIn + b.bytesIn, bytesOut: a.bytesOut + b.bytesOut, packetsIn: a.packetsIn + b.packetsIn, packetsOut: a.packetsOut + b.packetsOut)
    }
}

/// A conversation as seen from this Mac: an outbound packet's source and an inbound
/// packet's destination are both `local`, so both halves land on one row.
struct FlowKey: Hashable, Sendable {
    var proto: UInt8
    var local: IPAddress
    var localPort: UInt16
    var remote: IPAddress
    var remotePort: UInt16
}

struct Flow: Identifiable, Sendable {
    let key: FlowKey
    var firstSeen: Date
    var lastSeen: Date
    var counts = TrafficCounts()
    /// From the connection's TLS ClientHello, over TCP or in QUIC's Initial packets.
    /// Per connection, so it stays right where one address serves many sites, as CDN
    /// addresses do.
    var serverName: String?
    /// The TCP handshake's round trip, timed at this Mac's interface: its SYN to the
    /// SYN-ACK when this Mac opened the connection, its SYN-ACK to the final ACK when
    /// the other end did. Nil when the capture missed the handshake.
    var rtt: TimeInterval?
    /// This Mac's last handshake packet while unanswered, and the flags of the reply
    /// that completes the round trip.
    var unanswered: (sent: Date, reply: UInt8)?
    var quicHello = QUICHello()

    var id: FlowKey { key }
}

/// Folds packet summaries into flows and per-second totals. Pure state, so it can be
/// fed fixtures in tests; the app keeps one behind a lock and snapshots it.
struct FlowAggregator {
    /// This Mac's addresses. A packet from one of them is outbound; everything else,
    /// including broadcast and multicast from other hosts, is inbound.
    var localAddresses: Set<IPAddress> = []
    private(set) var flows: [FlowKey: Flow] = [:]
    /// Totals per whole second since 1970. Non-IP frames count here but have no flow.
    private(set) var seconds: [Int: TrafficCounts] = [:]
    private(set) var totals = TrafficCounts()
    /// Packets per capture id: a recording's count, to hold up against its file.
    private(set) var packets: [Int: Int] = [:]
    /// The latest pcap_stats drop count of each capture.
    private(set) var dropped: [Int: Int] = [:]
    /// Why a capture ended on its own.
    private(set) var failures: [Int: String] = [:]
    /// Address → the name a program looked up to reach it, from captured DNS answers.
    private(set) var names: [IPAddress: String] = [:]
    /// Bumped on every change, so a snapshot can skip copying when nothing arrived.
    private(set) var version = 0

    mutating func ingest(_ batch: CaptureBatch) {
        packets[batch.capture, default: 0] += batch.packets.count
        dropped[batch.capture] = batch.dropped
        failures[batch.capture] = batch.error
        for packet in batch.packets {
            add(packet)
        }
        version += 1
    }

    private mutating func add(_ packet: PacketSummary) {
        if let dns = packet.dns {
            for (address, name) in DNS.addresses(in: dns) {
                names[address] = name
            }
        }
        let outbound = packet.source.map(localAddresses.contains) ?? false
        seconds[Int(packet.time), default: TrafficCounts()].add(packet.length, outbound: outbound)
        totals.add(packet.length, outbound: outbound)
        guard let source = packet.source, let destination = packet.destination else { return }
        let key = outbound
            ? FlowKey(proto: packet.proto, local: source, localPort: packet.sourcePort, remote: destination, remotePort: packet.destinationPort)
            : FlowKey(proto: packet.proto, local: destination, localPort: packet.destinationPort, remote: source, remotePort: packet.sourcePort)
        let date = Date(timeIntervalSince1970: packet.time)
        flows[key, default: Flow(key: key, firstSeen: date, lastSeen: date)].record(packet.length, outbound: outbound, at: date, tcpFlags: packet.tcpFlags)
        if let hello = packet.clientHello, let name = TLS.serverName(in: hello) {
            flows[key]?.serverName = name
        }
        if let initial = packet.quicInitial, let name = flows[key]?.quicHello.add(initial) {
            flows[key]?.serverName = name
        }
    }

    /// How long a flow goes without a packet before it's dropped, so a capture left
    /// running for days holds only recent connections. Fixed rather than a setting;
    /// the Connections page states it in words, so change both together.
    static let idleLimit: TimeInterval = 600

    /// Drops history before `second` and flows idle at `now`, and returns those flows.
    /// An evicted flow's bytes stay in totals and history; a later packet on the same
    /// ports starts a new flow.
    @discardableResult
    mutating func prune(before second: Int, now: Date) -> [Flow] {
        seconds = seconds.filter { $0.key >= second }
        let evicted = flows.values.filter { now.timeIntervalSince($0.lastSeen) > Self.idleLimit }
        for flow in evicted {
            flows[flow.key] = nil
        }
        return evicted
    }

    /// A capture file's flows aren't idle-pruned: its clock stopped when it was written,
    /// so against today's every one of them is idle. It keeps up to `limit` instead; past
    /// that, the ones idle longest go, their bytes staying in totals as above.
    @discardableResult
    mutating func prune(keepingLatest limit: Int) -> [Flow] {
        guard flows.count > limit else { return [] }
        let evicted = flows.values.sorted { $0.lastSeen < $1.lastSeen }.prefix(flows.count - limit)
        for flow in evicted {
            flows[flow.key] = nil
        }
        return Array(evicted)
    }
}

/// What the Overview's top lists group a flow under.
enum Grouping: CaseIterable {
    case host, service, program, country
}

/// The Overview's top lists over the whole capture, like the totals above them: flows
/// in the table count as they stand, evicted ones as they were when they left.
struct TopTotals {
    private var retired: [Grouping: [String: Int]] = [:]

    /// `name` nil leaves the flow out of that list.
    // ponytail: names are fixed at eviction, so a PTR answer arriving later doesn't
    // move an address's bytes to its name; and the tallies grow with distinct names,
    // like the DNS and GeoIP caches.
    mutating func retire(_ flows: [Flow], name: (Flow, Grouping) -> String?) {
        for grouping in Grouping.allCases {
            Self.add(flows, by: { name($0, grouping) }, to: &retired[grouping, default: [:]])
        }
    }

    func top(_ grouping: Grouping, live flows: [Flow], count: Int = 5, name: (Flow) -> String?) -> [(name: String, bytes: Int)] {
        var totals = retired[grouping] ?? [:]
        Self.add(flows, by: name, to: &totals)
        return totals.sorted { $0.value > $1.value }.prefix(count).map { ($0.key, $0.value) }
    }

    private static func add(_ flows: [Flow], by name: (Flow) -> String?, to totals: inout [String: Int]) {
        for flow in flows {
            if let name = name(flow) {
                totals[name, default: 0] += flow.counts.bytesIn + flow.counts.bytesOut
            }
        }
    }
}

private extension Flow {
    mutating func record(_ length: Int, outbound: Bool, at date: Date, tcpFlags: UInt8) {
        counts.add(length, outbound: outbound)
        lastSeen = max(lastSeen, date)
        if outbound, tcpFlags & PacketParser.syn != 0 {
            // A retransmission restarts the clock: the reply most likely answers the
            // latest one, the earlier lost, and timing from the first would add the
            // retransmission timeout (a second or more) to the round trip. When it was
            // the reply that came late, past that timeout, the figure comes out short;
            // Karn's rule would leave such connections without a figure instead.
            let opened = tcpFlags & PacketParser.ack == 0
            unanswered = (date, opened ? PacketParser.syn | PacketParser.ack : PacketParser.ack)
        } else if !outbound, let unanswered, tcpFlags == unanswered.reply {
            rtt = date.timeIntervalSince(unanswered.sent)
            self.unanswered = nil
        }
    }
}

/// For sorting tables: IPv4 before IPv6, then numerically.
extension IPAddress: Comparable {
    static func < (a: Self, b: Self) -> Bool {
        switch (a, b) {
        case let (.v4(x), .v4(y)): x < y
        case let (.v6(x1, x2), .v6(y1, y2)): (x1, x2) < (y1, y2)
        case (.v4, .v6): true
        case (.v6, .v4): false
        }
    }
}

/// Throughput in one plotted bucket, per second.
struct TrafficRate: Sendable {
    let date: Date
    let counts: TrafficCounts
    /// Seconds the bucket spans; counts divided by this are per-second rates.
    let span: Int
}

extension Dictionary where Key == Int, Value == TrafficCounts {
    /// Zero-filled, so a quiet second plots as zero rather than a gap, but only from
    /// the first second captured: before that nothing was measured. Buckets sit on
    /// absolute time, so they don't shift as the window slides.
    func rates(window: Int, end: Int, maxPoints: Int = 600) -> [TrafficRate] {
        guard let first = keys.min() else { return [] }
        let span = Swift.max(1, window / maxPoints)
        let last = end / span * span
        return stride(from: Swift.max(last - window + span, first / span * span), through: last, by: span).map { start in
            let counts = (start ..< start + span).reduce(TrafficCounts()) { $0 + (self[$1] ?? TrafficCounts()) }
            return TrafficRate(date: Date(timeIntervalSince1970: TimeInterval(start)), counts: counts, span: span)
        }
    }
}
