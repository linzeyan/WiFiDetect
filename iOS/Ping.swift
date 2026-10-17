import Darwin
import Foundation

/// ICMP echo (RFC 792) through an unprivileged datagram socket, the kind iOS and macOS
/// let any app open (Apple's SimplePing sample and macOS's own `ping` do the same). The
/// app builds the header and checksum; replies arrive with their IPv4 header in front.
enum ICMPEcho {
    static func request(identifier: UInt16, sequence: UInt16) -> Data {
        var packet = Data([8, 0, 0, 0, UInt8(identifier >> 8), UInt8(identifier & 0xff), UInt8(sequence >> 8), UInt8(sequence & 0xff)])
        packet.append(Data(count: 8))
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8)
        packet[3] = UInt8(sum & 0xff)
        return packet
    }

    /// The sequence number, if `packet` is an echo reply carrying `identifier`. Every
    /// ICMP socket on the device can see every reply, so the identifier is what tells
    /// ours apart.
    static func replySequence(_ packet: Data, identifier: UInt16) -> UInt16? {
        var bytes = [UInt8](packet)
        // An IPv4 header starts with version 4 in the top nibble; an echo reply starts
        // with type 0.
        if let first = bytes.first, first >> 4 == 4 {
            let headerLength = Int(first & 0x0f) * 4
            guard bytes.count >= headerLength else { return nil }
            bytes.removeFirst(headerLength)
        }
        guard bytes.count >= 8, bytes[0] == 0, bytes[1] == 0,
              UInt16(bytes[4]) << 8 | UInt16(bytes[5]) == identifier else { return nil }
        return UInt16(bytes[6]) << 8 | UInt16(bytes[7])
    }

    /// RFC 1071: the ones' complement of the ones' complement sum of 16-bit words.
    static func checksum(_ data: Data) -> UInt16 {
        let bytes = [UInt8](data)
        var sum: UInt32 = 0
        for i in stride(from: 0, to: bytes.count, by: 2) {
            sum += UInt32(bytes[i]) << 8 | (i + 1 < bytes.count ? UInt32(bytes[i + 1]) : 0)
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~UInt16(sum)
    }
}

struct PingResult: Identifiable {
    let date: Date
    /// ms; nil when no reply came within a second.
    let rtt: Double?

    var id: Date { date }
}

/// The last minute of pings to one host.
struct PingStats {
    static let capacity = 60
    private(set) var results: [PingResult] = []

    mutating func append(_ result: PingResult) {
        results.append(result)
        if results.count > Self.capacity {
            results.removeFirst(results.count - Self.capacity)
        }
    }

    var latest: PingResult? { results.last }

    /// ms. The median, not the mean: one slow reply shouldn't move the typical figure.
    var median: Double? {
        let rtts = results.compactMap(\.rtt).sorted()
        guard !rtts.isEmpty else { return nil }
        let middle = rtts.count / 2
        return rtts.count.isMultiple(of: 2) ? (rtts[middle - 1] + rtts[middle]) / 2 : rtts[middle]
    }

    /// ms: the mean change between back-to-back replies, which is what a call or a game
    /// feels. A lost ping breaks the pair rather than counting as a jump.
    var jitter: Double? {
        let changes = zip(results, results.dropFirst()).compactMap { a, b in
            a.rtt.flatMap { a in b.rtt.map { abs($0 - a) } }
        }
        return changes.isEmpty ? nil : changes.reduce(0, +) / Double(changes.count)
    }

    /// 0–1
    var loss: Double? {
        results.isEmpty ? nil : Double(results.count(where: { $0.rtt == nil })) / Double(results.count)
    }
}

/// Pings one IPv4 host once a second, on its own queue, so a host that never answers
/// holds up nothing but itself.
final class Pinger: @unchecked Sendable {
    // Everything below is touched only on `queue`.
    private let queue = DispatchQueue(label: "com.zeyanlin.wifidetect.ping", qos: .utility)
    private let address: in_addr
    private let interface: UInt32?
    private let onResult: @Sendable (PingResult) -> Void
    private let identifier = UInt16.random(in: .min ... .max)
    private var sequence: UInt16 = 0
    private var socket: Int32 = -1
    private var timer: DispatchSourceTimer?

    /// `interface` pins the pings to one interface (an index), so they measure that link
    /// even when another one carries the default route.
    init(address: in_addr, interface: UInt32? = nil, onResult: @escaping @Sendable (PingResult) -> Void) {
        self.address = address
        self.interface = interface
        self.onResult = onResult
    }

    func start() {
        queue.async { [self] in
            socket = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            guard socket >= 0 else { return }
            if var interface {
                setsockopt(socket, IPPROTO_IP, IP_BOUND_IF, &interface, socklen_t(MemoryLayout<UInt32>.size))
            }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            // A ping that waits its full second delays the next tick; the timer
            // coalesces rather than queueing them up.
            timer.schedule(deadline: .now(), repeating: .seconds(1))
            timer.setEventHandler { [weak self] in self?.ping() }
            timer.resume()
            self.timer = timer
        }
    }

    func stop() {
        queue.async { [self] in
            timer?.cancel()
            timer = nil
            if socket >= 0 { close(socket) }
            socket = -1
        }
    }

    private func ping() {
        sequence &+= 1
        let date = Date.now
        let start = ContinuousClock.now
        let deadline = start + .seconds(1)
        let packet = ICMPEcho.request(identifier: identifier, sequence: sequence)
        var target = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size), sin_family: sa_family_t(AF_INET), sin_port: 0, sin_addr: address, sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        let sent = packet.withUnsafeBytes { bytes in
            withUnsafePointer(to: &target) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(socket, bytes.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        var buffer = [UInt8](repeating: 0, count: 1500)
        while sent == packet.count {
            let remaining = deadline - ContinuousClock.now
            guard remaining > .zero else { break }
            var poller = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
            guard poll(&poller, 1, Int32(max(1, remaining / .milliseconds(1)))) > 0 else { continue }
            var from = sockaddr_in()
            var fromLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let count = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(socket, &buffer, buffer.count, 0, $0, &fromLength) }
            }
            if count > 0, from.sin_addr.s_addr == address.s_addr,
               ICMPEcho.replySequence(Data(buffer[..<count]), identifier: identifier) == sequence {
                let elapsed = ContinuousClock.now - start
                onResult(PingResult(date: date, rtt: Double(elapsed.components.seconds) * 1000 + Double(elapsed.components.attoseconds) / 1e15))
                return
            }
        }
        onResult(PingResult(date: date, rtt: nil))
    }
}
