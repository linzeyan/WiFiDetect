import Foundation
import Synchronization

/// Host patterns as people write them: `example.com` is that host only,
/// `*.example.com` any host under it at any depth (not example.com itself), `*` all.
struct HostPatterns: Sendable {
    private var exact: Set<String> = []
    private var suffixes: [String] = []
    private var all = false

    init(_ patterns: [String]) {
        for pattern in patterns.map(Self.normalize) where !pattern.isEmpty {
            if pattern == "*" {
                all = true
            } else if pattern.hasPrefix("*.") {
                suffixes.append(String(pattern.dropFirst()))
            } else {
                exact.insert(pattern)
            }
        }
    }

    func matches(_ host: String) -> Bool {
        let host = Self.normalize(host)
        return all || exact.contains(host) || suffixes.contains { host.hasSuffix($0) }
    }

    static func normalize(_ text: String) -> String {
        var text = text.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasSuffix(".") { text.removeLast() }
        return text
    }

    /// Apple's services refuse TLS interception ("Use Apple products on enterprise
    /// networks", support article 101555). These go straight out, around the proxy, so
    /// the App Store, iCloud and push keep working whatever the allow list says.
    static let appleServices = [
        "apple.com", "*.apple.com", "icloud.com", "*.icloud.com", "*.icloud-content.com",
        "*.mzstatic.com", "*.apple-cloudkit.com", "*.cdn-apple.com", "*.aaplimg.com",
        "*.apple.news", "*.apple-mapkit.com", "*.apple-dns.net", "*.apple-livephotoskit.com",
    ]

    /// macOS upgrades a plain DNS server such as 1.1.1.1 to its DNS-over-HTTPS name
    /// (RFC 9462), and mDNSResponder sends that through the system proxy. The proxy then
    /// resolves upstream hosts through mDNSResponder, which waits on the proxy: every
    /// app's lookups stalled for 30 s at a time until these went around it.
    // ponytail: the well-known public resolvers only; a router or ISP that designates
    // its own DoH name still loops. Read the designated names from DDR if that happens.
    static let encryptedDNS = [
        "one.one.one.one", "cloudflare-dns.com", "*.cloudflare-dns.com", "dns.google",
        "*.quad9.net", "*.nextdns.io", "*.adguard-dns.com", "*.opendns.com",
    ]
}

/// Settings › Proxy › "Capture apps that ignore the system proxy" (architecture §3,
/// Network extension).
struct CaptureApps: Codable, Equatable, Sendable {
    var isEnabled = false
    /// App bundles and programs, by path.
    var apps: [String] = []
}

/// Map Local: a request whose URL matches `pattern` is answered with the file at
/// `path` instead of by the server.
struct MapLocalRule: URLRule, Codable, Identifiable, Sendable {
    var id = UUID()
    var isEnabled = true
    var pattern: String
    var path: String
}

/// Map Remote: a request whose URL matches `pattern` goes to the server at
/// `destination` instead, with the same path and query.
struct MapRemoteRule: URLRule, Codable, Identifiable, Sendable {
    var id = UUID()
    var isEnabled = true
    var pattern: String
    var destination: String
}

/// Map Remote's server.
struct RemoteOrigin: Sendable, Equatable {
    let secure: Bool
    let host: String
    let port: Int

    /// `http://` or `https://`, a host and maybe a port, and nothing after: the path
    /// stays the request's own.
    // ponytail: no path rewriting, as in /v1 to /v2; add a path prefix if it's asked for.
    init?(_ text: String) {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespaces)),
              let scheme = components.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = components.host, !host.isEmpty,
              ["", "/"].contains(components.percentEncodedPath),
              components.query == nil, components.fragment == nil, components.user == nil
        else { return nil }
        secure = scheme == "https"
        self.host = host.lowercased()
        port = components.port ?? (secure ? 443 : 80)
    }

    /// The Host header the server gets.
    var authority: String { port == (secure ? 443 : 80) ? host : "\(host):\(port)" }
    var url: String { "\(secure ? "https" : "http")://\(authority)" }
}

/// A breakpoint: a request whose URL matches is held before it goes to the server, its
/// response before it goes to the client, or both, until the user sends it on.
struct BreakpointRule: URLRule, Codable, Identifiable, Sendable {
    var id = UUID()
    var isEnabled = true
    var pattern: String
    var request = true
    var response = true
}

/// A script: JavaScript that edits a matching request, its response or both on their way,
/// before any breakpoint holds them (see `ScriptRunner` for what the script sees).
struct ScriptRule: URLRule, Codable, Identifiable, Sendable {
    var id = UUID()
    var isEnabled = true
    var pattern: String
    var request = true
    var response = true
    var source = ScriptRule.template

    static let template = """
        // Edit what you're given, or return something new. Returning nothing sends on
        // what you were given, edits included. headers is a list of [name, value] pairs;
        // body is text, or null when it isn't text (leave it null to send it as it came).

        function onRequest(request) {
          // request.headers.push(["X-Debug", "1"])
          return request
        }

        function onResponse(request, response) {
          // response.body = response.body.replace("old", "new")
          return response
        }
        """
}

/// A rule that picks requests by URL, written the same way for every kind of rule.
protocol URLRule {
    var pattern: String { get }
}

extension URLRule {
    /// The pattern covers the whole URL, query included, with `*` standing for any run
    /// of characters. Without a scheme it covers http and https alike. Everything up to
    /// the first `/` is the host, compared case-insensitively as DNS does; the path is
    /// compared as written, since servers tell `/Users` from `/users`.
    func matches(_ url: String) -> Bool {
        var url = Self.lowercasingHost(url)
        if !pattern.contains("://"), let scheme = url.firstRange(of: "://") {
            url = String(url[scheme.upperBound...])
        }
        let regex = "^" + NSRegularExpression.escapedPattern(for: Self.lowercasingHost(pattern)).replacingOccurrences(of: "\\*", with: ".*") + "$"
        return url.range(of: regex, options: .regularExpression) != nil
    }

    private static func lowercasingHost(_ text: String) -> String {
        let host = text.firstRange(of: "://")?.upperBound ?? text.startIndex
        let path = text[host...].firstIndex { $0 == "/" || $0 == "?" } ?? text.endIndex
        return text[..<path].lowercased() + text[path...]
    }
}

struct HTTPMessage: Sendable {
    var headers: [(name: String, value: String)] = []
    var body = Data()
    /// The body went past `ProxyLog.bodyLimit`; `body` holds its start.
    var truncated = false
    /// Every body byte, kept or not.
    var size = 0

    func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    mutating func append(_ bytes: some Collection<UInt8>) {
        size += bytes.count
        let room = ProxyLog.bodyLimit - body.count
        if bytes.count > room { truncated = true }
        body.append(contentsOf: bytes.prefix(max(room, 0)))
    }
}

struct ProxyFlow: Identifiable, Sendable {
    enum Kind: Sendable {
        /// Plain HTTP, forwarded request by request.
        case http
        /// A CONNECT to an allowed host, decrypted.
        case https
        /// A CONNECT passed through unread: only the host and byte counts are known.
        case tunnel
    }

    let id: Int
    let kind: Kind
    let started: Date
    var method: String
    /// Scheme, host, port as the client asked; for a tunnel, `host:port`.
    var url: String
    var host: String
    /// The app the network extension captured the connection from (`ConnectPreface`);
    /// nil for apps that came through the system proxy, which don't say.
    var app: String?
    /// As the client spoke it: HTTP/1.1, or HTTP/2 on a decrypted connection that chose it.
    var version = "HTTP/1.1"
    /// As the server answered; nil when none did. An HTTP/2 client's server may only
    /// speak HTTP/1.1, which gRPC can't get through.
    var serverVersion: String?
    var request = HTTPMessage()
    var status: Int?
    var reason = ""
    var response = HTTPMessage()
    /// When the response head arrived; the wait in HAR terms.
    var responded: Date?
    var finished: Date?
    var error: String?
    /// The file a Map Local rule answered with; the server was never asked.
    var mapLocal: String?
    /// Where a Map Remote rule sent the request instead of `url`.
    var mapRemote: String?
    /// For a tunnel or a WebSocket, the bytes each way; for HTTP the body sizes say it.
    var bytesUp = 0
    var bytesDown = 0
    /// A WebSocket's messages after its 101, oldest first.
    var messages: [WebSocketMessage] = []
    /// The oldest messages let go, past `ProxyLog.messageLimit` or the body limit.
    var droppedMessages = 0
    private var messageBytes = 0
    /// The breakpoint holding this flow until the user sends it on.
    var paused: BreakpointPhase?
    /// What breakpoints did to it. After one, the request and response recorded are
    /// what was sent on, edits included.
    var breakpointNotes: [String] = []
    /// What scripts did to it, edits recorded as after a breakpoint.
    var scriptNotes: [String] = []
    /// A script threw or ran too long, and the message went on as it came.
    var scriptFailed = false

    var isWebSocket: Bool { status == 101 }

    mutating func record(_ message: WebSocketMessage) {
        messages.append(message)
        messageBytes += message.payload.count
        // ponytail: removeFirst shifts the array; fine at ten thousand, a ring buffer if
        // the limit grows by orders of magnitude.
        while messages.count > ProxyLog.messageLimit || messageBytes > ProxyLog.bodyLimit {
            messageBytes -= messages.removeFirst().payload.count
            droppedMessages += 1
        }
    }
}

enum BreakpointPhase: String, Sendable {
    case request, response
}

/// A held message as the user sends it on: the request's method and path, or the
/// response's status, with the headers and body.
struct EditedMessage: Sendable {
    var method = ""
    /// Origin-form, starting with `/`: the host stays the one the client asked for.
    var path = ""
    var status = 0
    var headers: [(name: String, value: String)] = []
    /// Nil sends the body on as it came, encoding and all; a new body goes unencoded.
    var body: Data?

    /// Headers typed one per line as `Name: value`; nil if a line isn't one.
    static func headers(from text: String) -> [(name: String, value: String)]? {
        var headers: [(name: String, value: String)] = []
        for line in text.split(whereSeparator: \.isNewline) where !line.allSatisfy(\.isWhitespace) {
            // At the first colon only: values such as a Host's port have their own.
            // An empty value is still a header.
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let name = parts[0].trimmingCharacters(in: .whitespaces)
            guard parts.count == 2, !name.isEmpty, !name.contains(where: \.isWhitespace) else { return nil }
            headers.append((name, parts[1].trimmingCharacters(in: .whitespaces)))
        }
        return headers
    }
}

enum BreakpointDecision: Sendable {
    case proceed(EditedMessage)
    case abort
}

/// What the proxy saw, written from NIO event loops and read once in a while by the
/// store: the same lock-and-snapshot shape as traffic capture.
final class ProxyLog: Sendable {
    /// Per body, as architecture §3 sets it: enough for any API payload, and a video
    /// download can't fill the memory.
    static let bodyLimit = 10 << 20
    /// The oldest go first beyond this.
    static let flowLimit = 10_000
    /// Per WebSocket, as many as a flow list; together they also stay under `bodyLimit`.
    static let messageLimit = 10_000

    struct State {
        var flows: [Int: ProxyFlow] = [:]
        var nextID = 1
        var version = 0
    }

    let state = Mutex(State())

    func begin(kind: ProxyFlow.Kind, method: String, url: String, host: String, app: String? = nil) -> Int {
        state.withLock { state in
            let id = state.nextID
            state.nextID += 1
            state.flows[id] = ProxyFlow(id: id, kind: kind, started: .now, method: method, url: url, host: host, app: app)
            // A paused flow stays: gone from the list, nothing could send it on.
            if state.flows.count > Self.flowLimit, let oldest = state.flows.lazy.filter({ $0.value.paused == nil }).map(\.key).min() {
                state.flows[oldest] = nil
            }
            state.version += 1
            return id
        }
    }

    func update(_ id: Int, _ change: (inout ProxyFlow) -> Void) {
        state.withLock { state in
            guard state.flows[id] != nil else { return }
            change(&state.flows[id]!)
            state.version += 1
        }
    }

    /// Keeps the paused flows, for the same reason the flow limit does.
    func clear() {
        state.withLock { state in
            state.flows = state.flows.filter { $0.value.paused != nil }
            state.version += 1
        }
    }
}
