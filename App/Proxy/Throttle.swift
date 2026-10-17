import NIOCore
import Synchronization

/// How poor a network to make the proxy's traffic cross, as the user set it.
struct ThrottleSettings: Codable, Equatable, Sendable {
    var isEnabled = false
    /// kbit/s of 1000 bits; 0 is no limit.
    var downloadKbps = 1440
    var uploadKbps = 675
    /// Added to every round trip, half on the way out and half on the way back.
    var latencyMs = 150

    /// Chrome DevTools' presets (front_end/core/sdk/NetworkManager.ts in
    /// github.com/ChromeDevTools/devtools-frontend), so a page loads about as slowly here as
    /// it does under DevTools: the bandwidth DevTools applies, and the round trip it targets.
    /// DevTools multiplies that round trip because it adds it only once per request; here
    /// every round trip pays it, as on a real link.
    static let presets: [(name: String, downloadKbps: Int, uploadKbps: Int, latencyMs: Int)] = [
        ("Slow 3G", 400, 400, 400),
        ("Slow 4G", 1440, 675, 150),
        ("Fast 4G", 8100, 1350, 60),
    ]
}

/// The slow link the proxy pretends its traffic crosses: a lane each way, shared by every
/// connection, as a poor network is shared by everything on it.
final class Throttle: Sendable {
    enum Direction: Int, Sendable {
        /// From the apps to the servers, read on the client's connection.
        case up
        /// From the servers to the apps, read on each upstream connection.
        case down
    }

    private struct State {
        var settings = ThrottleSettings()
        /// When each lane has carried everything handed to it so far.
        var busyUntil = [NIODeadline.uptimeNanoseconds(0), .uptimeNanoseconds(0)]
    }

    private let state = Mutex(State())

    func set(_ settings: ThrottleSettings) {
        state.withLock { $0.settings = settings }
    }

    /// When the `count` bytes just read would have come in over the link: once the lane has
    /// carried what was ahead of them and them, plus half the latency. In pieces a tenth of
    /// a second long, so a slow link trickles rather than lurches. `limit` is how much a
    /// connection may hold before it stops reading: what the link has in flight in that
    /// half latency, and a quarter second more. Nil when throttling is off.
    func schedule(_ count: Int, _ direction: Direction) -> (pieces: [(count: Int, due: NIODeadline)], limit: Int)? {
        state.withLock { state in
            let settings = state.settings
            guard settings.isEnabled else { return nil }
            let now = NIODeadline.now()
            let oneWay = TimeAmount.nanoseconds(Int64(max(settings.latencyMs, 0)) * 500_000)
            // Bytes a second.
            let rate = max(direction == .up ? settings.uploadKbps : settings.downloadKbps, 0) * 125
            guard rate > 0 else { return ([(count, now + oneWay)], 1 << 20) }
            var end = max(now, state.busyUntil[direction.rawValue])
            var pieces: [(count: Int, due: NIODeadline)] = []
            var left = count
            while left > 0 {
                let piece = min(left, max(rate / 10, 1))
                end = end + .nanoseconds(Int64(piece) * 1_000_000_000 / Int64(rate))
                pieces.append((piece, end + oneWay))
                left -= piece
            }
            state.busyUntil[direction.rawValue] = end
            return (pieces, Int(Double(rate) * (Double(oneWay.nanoseconds) / 1e9 + 0.25)))
        }
    }
}

/// First in a pipeline, makes what its channel reads arrive as if over the throttled link:
/// each read waits until the link would have delivered it. A connection stops reading while
/// it holds more than the link would have in flight, so a fast sender is slowed by TCP
/// itself and a large download never piles up here. Writes pass untouched: the handler on
/// the other connection paced them as its reads.
final class ThrottleHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let throttle: Throttle
    private let direction: Throttle.Direction
    /// Oldest first; nil is the peer's end of input, which waits its turn behind the bytes.
    private var held = CircularBuffer<(due: NIODeadline, bytes: ByteBuffer?)>()
    private var heldBytes = 0
    private var limit = Int.max
    private var readPending = false
    private var timer: Scheduled<Void>?

    init(_ throttle: Throttle, _ direction: Throttle.Direction) {
        self.throttle = throttle
        self.direction = direction
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // The peer's EOF then comes as an event that can wait behind the bytes before it;
        // as a close it would drop them.
        try? context.channel.syncOptions?.setOption(.allowRemoteHalfClosure, value: true)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var bytes = unwrapInboundIn(data)
        guard let (pieces, limit) = throttle.schedule(bytes.readableBytes, direction) else {
            if let last = held.last {
                // Just turned off: what's held still goes first.
                heldBytes += bytes.readableBytes
                held.append((last.due, bytes))
            } else {
                context.fireChannelRead(data)
            }
            return
        }
        self.limit = limit
        heldBytes += bytes.readableBytes
        for piece in pieces {
            held.append((piece.due, bytes.readSlice(length: piece.count)!))
        }
        schedule(context)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        // Held bytes get their own read-complete as they're let through.
        if held.isEmpty {
            context.fireChannelReadComplete()
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard case .inputClosed = event as? ChannelEvent else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        // Nothing here wants a half-closed connection: it closes, as without the option,
        // only once the bytes before the EOF are through.
        if let last = held.last {
            held.append((last.due, nil))
        } else {
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        // Gone with the connection, as a dropped link's bytes are.
        timer?.cancel()
        timer = nil
        held.removeAll()
        heldBytes = 0
        context.fireChannelInactive()
    }

    func read(context: ChannelHandlerContext) {
        if heldBytes > limit {
            readPending = true
        } else {
            context.read()
        }
    }

    private func release(_ context: ChannelHandlerContext) {
        timer = nil
        let now = NIODeadline.now()
        var released = false
        while let first = held.first, first.due <= now {
            held.removeFirst()
            guard let bytes = first.bytes else {
                context.close(promise: nil)
                return
            }
            heldBytes -= bytes.readableBytes
            released = true
            context.fireChannelRead(wrapInboundOut(bytes))
        }
        if released {
            context.fireChannelReadComplete()
        }
        if readPending, heldBytes <= limit {
            readPending = false
            context.read()
        }
        schedule(context)
    }

    private func schedule(_ context: ChannelHandlerContext) {
        guard timer == nil, let first = held.first else { return }
        timer = context.eventLoop.assumeIsolated().scheduleTask(deadline: first.due) { [self] in
            release(context)
        }
    }
}
