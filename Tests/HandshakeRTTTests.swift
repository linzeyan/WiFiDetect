import Foundation
import Testing
@testable import WiFiDetect

struct HandshakeRTTTests {
    private let mac = IPAddress("192.168.1.10")!
    private let remote = IPAddress("93.184.216.34")!
    private let syn = PacketParser.syn
    private let ack = PacketParser.ack

    private func segment(_ time: Double, from source: IPAddress, _ sourcePort: UInt16, to destination: IPAddress, _ destinationPort: UInt16, _ flags: UInt8) -> PacketSummary {
        PacketSummary(time: time, length: 60, proto: PacketParser.tcp, source: source, destination: destination, sourcePort: sourcePort, destinationPort: destinationPort, tcpFlags: flags)
    }

    private func rtt(_ packets: [PacketSummary]) -> TimeInterval? {
        var aggregator = FlowAggregator()
        aggregator.localAddresses = [mac]
        aggregator.ingest(CaptureBatch(capture: 1, packets: packets, dropped: 0))
        return aggregator.flows.values.first?.rtt
    }

    /// Opened by this Mac: its SYN to the SYN-ACK. The first SYN went unanswered and
    /// was sent again a second later; timing from it would show that second, not the
    /// network. A duplicate SYN-ACK afterwards (this Mac's ACK lost) doesn't retime it.
    @Test func timesOutboundHandshakeFromLatestSYN() throws {
        let measured = try #require(rtt([
            segment(100, from: mac, 52000, to: remote, 443, syn),
            segment(101, from: mac, 52000, to: remote, 443, syn),
            segment(101.025, from: remote, 443, to: mac, 52000, syn | ack),
            segment(101.026, from: mac, 52000, to: remote, 443, ack),
            segment(101.3, from: remote, 443, to: mac, 52000, syn | ack),
        ]))
        #expect(abs(measured - 0.025) < 1e-6)
    }

    /// Opened by the other end, an ssh session into this Mac say: this Mac's SYN-ACK
    /// to the final ACK is the round trip. The remote's SYN starts nothing; until this
    /// Mac answers, the time is this Mac's own.
    @Test func timesInboundHandshakeFromSYNACK() throws {
        let measured = try #require(rtt([
            segment(200, from: remote, 52000, to: mac, 22, syn),
            segment(200.0001, from: mac, 22, to: remote, 52000, syn | ack),
            segment(200.0041, from: remote, 52000, to: mac, 22, ack),
        ]))
        #expect(abs(measured - 0.004) < 1e-6)
    }

    /// A connection already open when the capture started, or caught after its SYN,
    /// has no handshake to time; a figure from some other pair of packets would be
    /// made up.
    @Test func noRTTWithoutHandshake() {
        #expect(rtt([
            segment(300, from: remote, 443, to: mac, 52000, syn | ack),
            segment(300.001, from: mac, 52000, to: remote, 443, ack),
            segment(300.02, from: mac, 52000, to: remote, 443, ack),
            segment(300.05, from: remote, 443, to: mac, 52000, ack),
        ]) == nil)
    }
}
