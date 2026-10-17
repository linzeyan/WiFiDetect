import Foundation
import NIOCore

/// One WebSocket message, put back together from its frames.
struct WebSocketMessage: Sendable {
    let fromClient: Bool
    /// When its last frame arrived.
    var time = Date.now
    /// RFC 6455 §5.2: 1 text, 2 binary, 8 close, 9 ping, 10 pong.
    let opcode: UInt8
    /// Unmasked, up to `WebSocketParser.payloadLimit`.
    var payload = Data()
    /// Every payload byte, kept or not.
    var size = 0

    var kind: String {
        switch opcode {
        case 1: String(localized: "Text")
        case 2: String(localized: "Binary")
        case 8: String(localized: "Close")
        case 9: "Ping"
        case 10: "Pong"
        default: "Opcode \(opcode)"
        }
    }

    fileprivate mutating func append(_ bytes: [UInt8]) {
        size += bytes.count
        payload.append(contentsOf: bytes.prefix(max(WebSocketParser.payloadLimit - payload.count, 0)))
    }
}

/// Reads one direction of a WebSocket as its bytes go by. NIO's frame decoder works only
/// as a pipeline stage that holds each frame whole; here the relay forwards the bytes as
/// they came, so a frame this can't follow costs the inspector a message, never the
/// connection, and a large frame is counted rather than held.
struct WebSocketParser {
    /// Kept of each message: any chat or JSON message whole, while a stream of binary
    /// frames can't fill the memory.
    static let payloadLimit = 64 << 10

    let fromClient: Bool
    private var header: [UInt8] = []
    private var frame: Frame?
    /// A text or binary message, which may span frames.
    private var data: WebSocketMessage?
    /// Ping, pong or close: one frame, which may arrive between another message's frames.
    private var control: WebSocketMessage?

    private struct Frame {
        let opcode: UInt8
        let fin: Bool
        let mask: [UInt8]?
        var remaining: Int
        /// Payload bytes read so far: the mask repeats every four.
        var offset = 0

        var isControl: Bool { opcode >= 8 }
    }

    init(fromClient: Bool) {
        self.fromClient = fromClient
    }

    /// The messages these bytes complete, in the order they completed.
    mutating func read(_ buffer: ByteBuffer) -> [WebSocketMessage] {
        var bytes = buffer.readableBytesView
        var messages: [WebSocketMessage] = []
        while true {
            if frame == nil {
                while header.count < Self.headerLength(header), let byte = bytes.first {
                    header.append(byte)
                    bytes = bytes.dropFirst()
                }
                guard header.count == Self.headerLength(header) else { return messages }
                start(Self.frame(header))
                header = []
            }
            guard var current = frame else { return messages }
            var chunk = [UInt8](bytes.prefix(current.remaining))
            bytes = bytes.dropFirst(chunk.count)
            if let mask = current.mask {
                for i in chunk.indices {
                    chunk[i] ^= mask[(current.offset + i) % 4]
                }
            }
            current.offset += chunk.count
            current.remaining -= chunk.count
            if current.isControl {
                control?.append(chunk)
            } else {
                data?.append(chunk)
            }
            guard current.remaining == 0 else {
                frame = current
                return messages
            }
            frame = nil
            if current.isControl, var message = control {
                message.time = .now
                messages.append(message)
                control = nil
            } else if !current.isControl, current.fin, var message = data {
                message.time = .now
                messages.append(message)
                data = nil
            }
            if bytes.isEmpty { return messages }
        }
    }

    private mutating func start(_ frame: Frame) {
        self.frame = frame
        if frame.isControl {
            control = WebSocketMessage(fromClient: fromClient, opcode: frame.opcode)
        } else if frame.opcode != 0 || data == nil {
            // A continuation with nothing to continue is kept as what it says it is.
            data = WebSocketMessage(fromClient: fromClient, opcode: frame.opcode)
        }
    }

    /// Two bytes; then two or eight more of length when the 7-bit length says so; then a
    /// four-byte mask if the frame is masked, as every client frame is.
    private static func headerLength(_ header: [UInt8]) -> Int {
        guard header.count >= 2 else { return 2 }
        let length = header[1] & 0x7f
        return 2 + (length == 126 ? 2 : length == 127 ? 8 : 0) + (header[1] & 0x80 != 0 ? 4 : 0)
    }

    private static func frame(_ header: [UInt8]) -> Frame {
        let short = header[1] & 0x7f
        let extra = short == 126 ? 2 : short == 127 ? 8 : 0
        let length = extra == 0 ? UInt64(short) : header[2 ..< 2 + extra].reduce(0) { $0 << 8 | UInt64($1) }
        let masked = header[1] & 0x80 != 0
        return Frame(opcode: header[0] & 0x0f, fin: header[0] & 0x80 != 0, mask: masked ? Array(header.suffix(4)) : nil, remaining: Int(clamping: length))
    }
}
