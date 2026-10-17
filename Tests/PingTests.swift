import Darwin
import Foundation
import Testing

struct ICMPEchoTests {
    /// A receiver checks a packet by summing it, checksum included; anything but zero
    /// and the router drops the request silently, which would read as 100% loss.
    @Test func requestChecksumVerifies() {
        let packet = ICMPEcho.request(identifier: 0x1234, sequence: 0x0001)
        #expect(Array(packet.prefix(8)) == [8, 0, 0xe5, 0xca, 0x12, 0x34, 0x00, 0x01])
        #expect(ICMPEcho.checksum(packet) == 0)
    }

    /// Darwin hands a datagram ICMP socket the reply with its IPv4 header still on, and
    /// every ICMP socket sees every reply; only ours, by identifier, may count.
    @Test func readsOnlyOurReplies() {
        let ipHeader: [UInt8] = [0x45] + Array(repeating: 0, count: 19)
        let reply: [UInt8] = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x07]
        #expect(ICMPEcho.replySequence(Data(ipHeader + reply), identifier: 0x1234) == 7)
        #expect(ICMPEcho.replySequence(Data(reply), identifier: 0x1234) == 7)
        #expect(ICMPEcho.replySequence(Data(ipHeader + reply), identifier: 0x4321) == nil)
        // Our own request echoed back isn't a reply.
        #expect(ICMPEcho.replySequence(Data(ipHeader + [8] + reply.dropFirst()), identifier: 0x1234) == nil)
    }
}

struct PingStatsTests {
    private func stats(_ rtts: [Double?]) -> PingStats {
        var stats = PingStats()
        for (i, rtt) in rtts.enumerated() {
            stats.append(PingResult(date: Date(timeIntervalSinceReferenceDate: Double(i)), rtt: rtt))
        }
        return stats
    }

    /// A lost ping is a gap, not a jump from 20 ms to 30 ms: counting it would make a
    /// lossy but steady link look jittery.
    @Test func jitterSkipsLostPings() throws {
        let s = stats([10, 20, nil, 30, 32])
        #expect(try #require(s.jitter) == 6) // (10 + 2) / 2
        #expect(s.loss == 0.2)
        #expect(s.median == 25)
    }

    @Test func keepsTheLastMinute() {
        let s = stats(Array(repeating: 5, count: 90))
        #expect(s.results.count == PingStats.capacity)
        #expect(s.results.first?.date == Date(timeIntervalSinceReferenceDate: 30))
    }
}

struct PingerTests {
    /// The real socket path, end to end: the unprivileged ICMP socket opens, the
    /// request goes out, and the reply is recognized as ours.
    @Test(.timeLimit(.minutes(1)))
    func pingsLoopback() async throws {
        let (results, continuation) = AsyncStream.makeStream(of: PingResult.self)
        let pinger = Pinger(address: in_addr(s_addr: inet_addr("127.0.0.1"))) { continuation.yield($0) }
        pinger.start()
        defer { pinger.stop() }
        var iterator = results.makeAsyncIterator()
        let first = await iterator.next()
        #expect(try #require(first?.rtt) < 100)
    }
}
