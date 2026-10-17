import CoreWLAN
import Foundation
import Network
import Testing
@testable import WiFiDetect

struct LineBufferTests {
    /// TCP doesn't keep message boundaries: one read can end mid-message or hold two.
    @Test func reassemblesLinesAcrossReads() throws {
        var buffer = LineBuffer()
        #expect(try buffer.append(Data("{\"a\":".utf8)).isEmpty)
        let lines = try buffer.append(Data("1}\n{\"b\":2}\n{\"c\"".utf8))
        #expect(lines.map { String(decoding: $0, as: UTF8.self) } == ["{\"a\":1}", "{\"b\":2}"])
        #expect(try buffer.append(Data(":3}\n".utf8)).map { String(decoding: $0, as: UTF8.self) } == ["{\"c\":3}"])
    }

    /// Anything on the network can advertise the service; a peer that never sends a
    /// newline must not make the iPhone buffer forever.
    @Test func rejectsARunawayLine() {
        var buffer = LineBuffer()
        #expect(throws: LineBuffer.LineTooLong.self) {
            try buffer.append(Data(count: Companion.maxLine + 1))
        }
    }
}

@MainActor
struct CompanionServerTests {
    private let link = WiFiLink(
        interfaceName: "en0", isPoweredOn: true, ssid: "Home Network", bssid: "aa:bb:cc:dd:ee:ff", countryCode: "TW",
        txRate: 866, txPower: 20, channel: WiFiChannel(number: 36, band: .band5GHz, width: .width80MHz),
        phyMode: .mode11ax, security: .wpa3Personal
    )

    /// A phone that connects mid-session sees the history so far, not an empty chart,
    /// then keeps up sample by sample.
    @Test(.timeLimit(.minutes(1)))
    func newClientGetsHistoryThenEachSample() async throws {
        let monitor = WiFiMonitor(store: temporaryStore())
        let server = CompanionServer(monitor: monitor)
        defer { server.stop() }
        for rssi in [-51, -52, -53] {
            monitor.publish(WiFiSample(date: .now, rssi: rssi, noise: -90), link)
        }
        let client = LineReader(port: try await server.start(advertise: false))
        defer { client.close() }

        let first = try await client.next()
        #expect(first.samples.map(\.rssi) == [-51, -52, -53])
        #expect(first.link == SharedLink(isPoweredOn: true, txRate: 866, channel: "36 · 5 GHz, 80 MHz"))

        monitor.publish(WiFiSample(date: .now, rssi: -60, noise: -90), link)
        let second = try await client.next()
        #expect(second.samples.map(\.rssi) == [-60])
        // The readings are readable by anyone on the network; the network's identity isn't.
        #expect(!String(decoding: try second.line(), as: UTF8.self).contains("Home Network"))
        #expect(!String(decoding: try second.line(), as: UTF8.self).contains("aa:bb"))
    }

    /// With days stored, a phone that connects still gets the last hour at 4 Hz, as
    /// before readings were kept: a week would be tens of MB of JSON, past the longest
    /// line the iPhone accepts.
    @Test(.timeLimit(.minutes(1)))
    func newClientGetsAnHourNotTheStoredDays() async throws {
        let store = temporaryStore()
        let now = Date.now
        // Two hours at 4 Hz.
        store.append((0 ..< 28_800).map { WiFiSample(date: now.addingTimeInterval(Double($0 - 28_800) / 4), rssi: -50, noise: -90) })
        let monitor = WiFiMonitor(store: store)
        await monitor.restore()
        let server = CompanionServer(monitor: monitor)
        defer { server.stop() }
        let client = LineReader(port: try await server.start(advertise: false))
        defer { client.close() }

        let first = try await client.next()
        #expect(first.samples.count == 14_400)
        #expect(first.samples.last?.date == monitor.latest?.date)
        #expect(try first.line().count < Companion.maxLine)
    }

    /// Settings shows how many iPhones are connected; one that leaves must drop off
    /// even while no sample is being sent.
    @Test(.timeLimit(.minutes(1)))
    func noticesADisconnect() async throws {
        let monitor = WiFiMonitor(store: temporaryStore())
        let server = CompanionServer(monitor: monitor)
        defer { server.stop() }
        let client = LineReader(port: try await server.start(advertise: false))
        _ = try await client.next()
        #expect(server.clients.count == 1)

        client.close()
        for _ in 0 ..< 100 where !server.clients.isEmpty {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(server.clients.isEmpty)
    }
}

/// The iPhone side's framing, over a plain loopback connection.
@MainActor
private final class LineReader {
    private let connection: NWConnection
    private var buffer = LineBuffer()
    private var lines: [Data] = []

    init(port: NWEndpoint.Port) {
        connection = NWConnection(host: .ipv4(.loopback), port: port, using: .tcp)
        connection.start(queue: .main)
    }

    func next() async throws -> CompanionMessage {
        while lines.isEmpty {
            let data: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, _, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else if let data {
                        continuation.resume(returning: data)
                    } else {
                        continuation.resume(throwing: URLError(.networkConnectionLost))
                    }
                }
            }
            lines += try buffer.append(data)
        }
        return try JSONDecoder().decode(CompanionMessage.self, from: lines.removeFirst())
    }

    func close() {
        connection.cancel()
    }
}
