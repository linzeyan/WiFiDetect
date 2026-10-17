import Compression
import Foundation

extension HTTPMessage {
    /// The body before its Content-Encoding, which is what a person wants to read:
    /// browsers ask for gzip or Brotli, so most bodies arrive compressed. Nil when the
    /// encoding is one this can't undo or the body was cut short mid-stream.
    var decodedBody: Data? {
        guard let encoding = header("content-encoding")?.trimmingCharacters(in: .whitespaces).lowercased(),
              !encoding.isEmpty, encoding != "identity" else { return body }
        switch encoding {
        case "gzip", "x-gzip": return Self.gzipPayload(body).flatMap { Self.inflate($0, .zlib) }
        // Meant to be zlib-wrapped (RFC 9110 §8.4.1.2), but some servers send raw DEFLATE.
        case "deflate": return Self.inflate(body.first == 0x78 ? body.dropFirst(2) : body, .zlib)
        case "br": return Self.inflate(body, .brotli)
        default: return nil
        }
    }

    var mimeType: String {
        header("content-type") ?? ""
    }

    /// Past the gzip header (RFC 1952 §2.3), where the DEFLATE stream starts.
    private static func gzipPayload(_ data: Data) -> Data? {
        let bytes = [UInt8](data.prefix(1024))
        guard bytes.count > 10, bytes[0] == 0x1f, bytes[1] == 0x8b, bytes[2] == 8 else { return nil }
        let flags = bytes[3]
        var offset = 10
        if flags & 0x04 != 0, offset + 2 <= bytes.count { // FEXTRA
            offset += 2 + (Int(bytes[offset]) | Int(bytes[offset + 1]) << 8)
        }
        for flag in [UInt8(0x08), 0x10] where flags & flag != 0 { // FNAME, FCOMMENT: zero-terminated
            while offset < bytes.count, bytes[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x02 != 0 { offset += 2 } // FHCRC
        return offset < data.count ? data.dropFirst(offset) : nil
    }

    private static func inflate(_ data: Data, _ algorithm: Algorithm) -> Data? {
        var position = data.startIndex
        guard let filter = try? InputFilter<Data>(.decompress, using: algorithm, readingFrom: { length in
            guard position < data.endIndex else { return nil }
            let end = data.index(position, offsetBy: min(length, data.endIndex - position))
            defer { position = end }
            return data[position ..< end]
        }) else { return nil }
        var output = Data()
        // A small body can expand enormously; past this the rest isn't worth reading.
        while output.count < 64 << 20, let page = try? filter.readData(ofLength: 1 << 16), !page.isEmpty {
            output.append(page)
        }
        return output.isEmpty && !data.isEmpty ? nil : output
    }
}

/// HTTP Archive 1.2 (http://www.softwareishard.com/blog/har-12-spec/), which browsers'
/// developer tools and other proxies import. Tunnels have no requests to export.
struct HAR: Encodable {
    let log: Log

    init(_ flows: [ProxyFlow]) {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        log = Log(creator: Creator(name: "WiFiDetect", version: version), entries: flows.filter { $0.kind != .tunnel }.map(Entry.init))
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    struct Log: Encodable {
        var version = "1.2"
        let creator: Creator
        let entries: [Entry]
    }

    struct Creator: Encodable {
        let name: String
        let version: String
    }

    struct Header: Encodable {
        let name: String
        let value: String
    }

    struct Entry: Encodable {
        let startedDateTime: String
        let time: Double
        let request: Request
        let response: Response
        let cache: [String: String] = [:]
        let timings: Timings
        let comment: String?
        let _webSocketMessages: [WebSocketFrame]?

        init(_ flow: ProxyFlow) {
            let finished = flow.finished ?? .now
            let responded = flow.responded ?? finished
            startedDateTime = flow.started.formatted(.iso8601.year().month().day().time(includingFractionalSeconds: true).timeZone(separator: .colon))
            time = finished.timeIntervalSince(flow.started) * 1000
            request = Request(flow)
            response = Response(flow)
            timings = Timings(send: 0, wait: responded.timeIntervalSince(flow.started) * 1000, receive: finished.timeIntervalSince(responded) * 1000)
            // The file name only: a full path would share the user's home folder with the HAR.
            let mapped = flow.mapLocal.map { "Mapped by Map Local to \(URL(filePath: $0).lastPathComponent); the server wasn't asked." }
            let remote = flow.mapRemote.map { "Sent by Map Remote to \($0)." }
            let notes = [
                flow.error, mapped, remote,
                flow.scriptNotes.isEmpty ? nil : flow.scriptNotes.joined(separator: " "),
                flow.request.truncated ? "Request body cut at 10 MB." : nil,
                flow.response.truncated ? "Response body cut at 10 MB." : nil,
                flow.droppedMessages > 0 ? "The oldest \(flow.droppedMessages) WebSocket messages weren't kept." : nil,
                flow.messages.contains { $0.size > $0.payload.count } ? "WebSocket messages cut at 64 KB." : nil,
            ]
            comment = notes.compactMap { $0 }.isEmpty ? nil : notes.compactMap { $0 }.joined(separator: " ")
            _webSocketMessages = flow.isWebSocket ? flow.messages.map(WebSocketFrame.init) : nil
        }
    }

    /// Chrome's extension for a WebSocket's messages, which its developer tools import.
    struct WebSocketFrame: Encodable {
        let type: String
        let time: Double
        let opcode: UInt8
        let data: String

        init(_ message: WebSocketMessage) {
            type = message.fromClient ? "send" : "receive"
            time = message.time.timeIntervalSince1970
            opcode = message.opcode
            data = message.opcode == 1 ? String(decoding: message.payload, as: UTF8.self) : message.payload.base64EncodedString()
        }
    }

    struct Request: Encodable {
        let method: String
        let url: String
        let httpVersion: String
        let cookies: [String] = []
        let headers: [Header]
        let queryString: [Header]
        let postData: PostData?
        let headersSize = -1
        let bodySize: Int

        init(_ flow: ProxyFlow) {
            method = flow.method
            url = flow.url
            httpVersion = flow.version
            headers = flow.request.headers.map { Header(name: $0.name, value: $0.value) }
            queryString = (URLComponents(string: flow.url)?.queryItems ?? []).map { Header(name: $0.name, value: $0.value ?? "") }
            let body = flow.request.decodedBody ?? flow.request.body
            postData = body.isEmpty ? nil : PostData(mimeType: flow.request.mimeType, text: String(data: body, encoding: .utf8) ?? body.base64EncodedString())
            bodySize = flow.request.size
        }
    }

    struct PostData: Encodable {
        let mimeType: String
        let text: String
    }

    struct Response: Encodable {
        let status: Int
        let statusText: String
        /// The client's, like the request's: the archive is of what the app saw.
        let httpVersion: String
        let cookies: [String] = []
        let headers: [Header]
        let content: Content
        let redirectURL: String
        let headersSize = -1
        let bodySize: Int

        init(_ flow: ProxyFlow) {
            status = flow.status ?? 0
            statusText = flow.reason
            httpVersion = flow.version
            headers = flow.response.headers.map { Header(name: $0.name, value: $0.value) }
            content = Content(flow.response)
            redirectURL = flow.response.header("location") ?? ""
            bodySize = flow.response.size
        }
    }

    struct Content: Encodable {
        let size: Int
        let compression: Int?
        let mimeType: String
        let text: String?
        let encoding: String?

        init(_ message: HTTPMessage) {
            let decoded = message.decodedBody
            let body = decoded ?? message.body
            size = body.count
            compression = decoded.map { message.body.count - $0.count }.flatMap { $0 == 0 ? nil : $0 }
            mimeType = message.mimeType
            if body.isEmpty {
                text = nil
                encoding = nil
            } else if let utf8 = String(data: body, encoding: .utf8) {
                text = utf8
                encoding = nil
            } else {
                text = body.base64EncodedString()
                encoding = "base64"
            }
        }
    }

    struct Timings: Encodable {
        let send: Double
        let wait: Double
        let receive: Double
    }
}
