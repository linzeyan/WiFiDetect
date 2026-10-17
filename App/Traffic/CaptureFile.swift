import Foundation
import Synchronization

struct CaptureFileError: Error {
    let message: String
}

/// Two addresses that exchanged packets, whichever way.
struct Conversation: Hashable {
    let low: IPAddress
    let high: IPAddress

    init(_ a: IPAddress, _ b: IPAddress) {
        (low, high) = a < b ? (a, b) : (b, a)
    }
}

/// Reads a capture file into the traffic pages through the same parser and aggregator
/// as live capture, so a file shows what capturing its packets would have shown.
/// libpcap tells pcap from pcapng by itself, and reading a file needs no root.
final class CaptureFileReader: Sendable {
    /// An aggregator of its own, so nothing the helper still sends can land in a file.
    let sink = TrafficSink()
    private let cancelled = Atomic(false)

    // ponytail: the first pass stops collecting past this many conversations, which is
    // plenty to find the capturing machine and bounds the pass's memory. Raise it if
    // files whose host only shows up late come out with In and Out swapped.
    private static let conversationLimit = 100_000

    func cancel() {
        cancelled.store(true, ordering: .relaxed)
    }

    /// Reads the whole file into `sink`, twice: the first pass finds the machine it was
    /// captured on, which In and Out are relative to, and the second counts. Blocks until
    /// done or cancelled, so call it off the main thread. Throws when libpcap can't open
    /// the file or gives up partway, as on a recording cut off mid-packet (what came
    /// before stays counted), and when no frame is of a kind the parser reads.
    func read(_ url: URL, flowLimit: Int, progress: (Double) -> Void) throws(CaptureFileError) {
        var conversations: Set<Conversation> = []
        // The second pass meets any error again, after counting what comes before it.
        _ = try? each(url, progress: { progress($0 / 2) }) { packet in
            guard let source = packet.source, let destination = packet.destination, source.isUnicast, destination.isUnicast,
                  conversations.count < Self.conversationLimit else { return }
            conversations.insert(Conversation(source, destination))
        }
        let hosts = Self.hosts(of: conversations)
        sink.state.withLock { $0.localAddresses = hosts }
        var batch: [PacketSummary] = []
        // The last batch counts even when the file breaks off right after it.
        defer { sink.state.withLock { $0.ingest(CaptureBatch(capture: 0, packets: batch, dropped: 0)) } }
        let linkType = try each(url, progress: { progress(0.5 + $0 / 2) }) { packet in
            batch.append(packet)
            guard batch.count == 4096 else { return }
            sink.state.withLock { $0.ingest(CaptureBatch(capture: 0, packets: batch, dropped: 0)) }
            batch.removeAll(keepingCapacity: true)
            // The store caps the table at its once-a-second snapshot; read at full speed,
            // a scan's file would run past the cap by a million connections in between.
            while !cancelled.load(ordering: .relaxed), sink.state.withLock({ $0.flows.count }) > 2 * flowLimit {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        // The link types `PacketParser` reads; any other still counts every frame.
        guard [DLT_EN10MB, DLT_NULL, DLT_LOOP, DLT_RAW].contains(linkType) else {
            let name = pcap_datalink_val_to_description(linkType).map { String(cString: $0) } ?? String(localized: "link type \(linkType)")
            throw CaptureFileError(message: String(localized: "Its frames are \(name), which WiFiDetect doesn't read: only packet counts and sizes show, no connections."))
        }
    }

    /// Calls `body` with each packet, parsed as the helper parses live ones, and returns
    /// the file's link type.
    private func each(_ url: URL, progress: (Double) -> Void, _ body: (PacketSummary) -> Void) throws(CaptureFileError) -> Int32 {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let handle = pcap_open_offline(url.path, &errbuf) else {
            throw CaptureFileError(message: errbuf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
        }
        defer { pcap_close(handle) }
        let linkType = pcap_datalink(handle)
        let size = Double((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<u_char>?
        var count = 0
        var reported = 0.0
        while !cancelled.load(ordering: .relaxed) {
            switch pcap_next_ex(handle, &header, &data) {
            case 1:
                guard let header, let data else { continue }
                let frame = UnsafeRawBufferPointer(start: data, count: Int(header.pointee.caplen))
                let time = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1_000_000
                body(PacketParser.parse(frame, wireLength: Int(header.pointee.len), time: time, linkType: linkType))
                count += 1
                // In steps of a percent: each one redraws the page.
                if count % 4096 == 0, size > 0, Double(ftell(pcap_file(handle))) / size - reported >= 0.01 {
                    reported = Double(ftell(pcap_file(handle))) / size
                    progress(min(1, reported))
                }
            case PCAP_ERROR_BREAK:
                return linkType
            default:
                throw CaptureFileError(message: String(cString: pcap_geterr(handle)))
            }
        }
        return linkType
    }

    /// The machine a file was captured on. Every conversation in such a file has it at
    /// one end, so its addresses are the fewest that take part in all of them: taken
    /// busiest first, each one still talking to an address not yet taken. Of two that
    /// only ever talk to each other either could be the machine; a private one wins over
    /// one on the internet, as a Mac at home sits behind its router.
    static func hosts(of conversations: Set<Conversation>) -> Set<IPAddress> {
        var peers: [IPAddress: [IPAddress]] = [:]
        for conversation in conversations {
            peers[conversation.low, default: []].append(conversation.high)
            if conversation.high != conversation.low {
                peers[conversation.high, default: []].append(conversation.low)
            }
        }
        func rank(_ address: IPAddress) -> (Int, Int) {
            (peers[address]!.count, address.scope == .internet ? 0 : 1)
        }
        var hosts: Set<IPAddress> = []
        // The address itself last, so a file always comes out the same.
        for address in peers.keys.sorted(by: { rank($0) != rank($1) ? rank($0) > rank($1) : $0 < $1 })
        where peers[address]!.contains(where: { !hosts.contains($0) }) {
            hosts.insert(address)
        }
        return hosts
    }
}

private extension IPAddress {
    /// Group addresses are no one's end of a conversation: everyone on the link hears
    /// them, the capturing machine included.
    var isUnicast: Bool {
        scope != .multicast && scope != .broadcast
    }
}
