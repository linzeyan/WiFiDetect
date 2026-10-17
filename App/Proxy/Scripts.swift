import Foundation
import JavaScriptCore
import NIOCore
import Synchronization

/// Runs scripts: JavaScript that edits a whole request or response, as a user at a
/// breakpoint would. Each run gets a JSContext of its own, made fresh with nothing in it but
/// the language: no network, no files, nothing kept from the run before.
///
/// What a script sees: `onRequest(request)` and `onResponse(request, response)`, where a
/// request is `{method, path, headers, body}` and a response `{status, headers, body}`.
/// Headers are a list of `[name, value]` pairs, so repeated ones like Set-Cookie stay apart
/// and in order. The body is the text, decoded as a breakpoint shows it, or null when it
/// isn't text; null going back means as it came. The function edits the object it's given
/// or returns a new one; returning nothing sends on the one it was given, edits included.
/// A script may leave either function out, and that side goes on as it came.
final class ScriptRunner: Sendable {
    /// Past this a script is given up on and the message goes on as it came.
    let timeout: TimeAmount
    /// A JSContext isn't thread-safe and a script blocks while it runs, so scripts take
    /// turns on a queue of their own, never on an event loop.
    private let queue = Mutex(ScriptRunner.makeQueue())

    init(timeout: TimeAmount = .seconds(5)) {
        self.timeout = timeout
    }

    /// The script's edit, nil when it has no function for the phase, or a failure saying
    /// what went wrong with it.
    func run(_ source: String, _ phase: BreakpointPhase, _ flow: ProxyFlow, path: String, on eventLoop: EventLoop) -> EventLoopFuture<EditedMessage?> {
        let promise = eventLoop.makePromise(of: EditedMessage?.self)
        // The script and the watchdog race to answer, both on the event loop.
        let answered = NIOLoopBoundBox.makeBoxSendingValue(false, eventLoop: eventLoop)
        let answer: @Sendable (Result<EditedMessage?, Error>) -> Bool = { result in
            guard !answered.value else { return false }
            answered.value = true
            promise.completeWith(result)
            return true
        }
        // JavaScriptCore's only way to stop a running script is private API, so a script
        // that never returns keeps its thread. The message goes on without it, and later
        // scripts get a new queue rather than wait behind it.
        // ponytail: a runaway spins a CPU core until WiFiDetect quits; run scripts in a
        // helper process that can be killed if that bites.
        let seconds = Duration.nanoseconds(timeout.nanoseconds).formatted(.units(allowed: [.seconds, .milliseconds], width: .wide))
        let watchdog = eventLoop.scheduleTask(in: timeout) { [self] in
            if answer(.failure(ProxyFailure(String(localized: "It didn't finish within \(seconds). JavaScriptCore has no public way to stop it, so it keeps one CPU core busy until WiFiDetect quits.")))) {
                queue.withLock { $0 = Self.makeQueue() }
            }
        }
        queue.withLock { $0 }.async {
            let result = Result { try Self.execute(source, phase, flow, path: path) }
            eventLoop.execute {
                if answer(result) { watchdog.cancel() }
            }
        }
        return promise.futureResult
    }

    /// What's wrong with a script's syntax, found without running it, so the editor can say
    /// while a loop at the script's top level can't hang the window.
    static func syntaxError(in source: String) -> String? {
        let context = JSContext()!
        let script = JSStringCreateWithCFString(source as CFString)
        defer { JSStringRelease(script) }
        var exception: JSValueRef?
        guard !JSCheckScriptSyntax(context.jsGlobalContextRef, script, nil, 1, &exception), let exception else { return nil }
        return describe(JSValue(jsValueRef: exception, in: context))
    }

    private static func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "com.zeyanlin.wifidetect.scripts")
    }

    private static func execute(_ source: String, _ phase: BreakpointPhase, _ flow: ProxyFlow, path: String) throws -> EditedMessage? {
        let context = JSContext()!
        context.evaluateScript(source)
        try check(context)
        let name = phase == .request ? "onRequest" : "onResponse"
        // Not a failure: a script that only edits responses shouldn't mark every request
        // in the list because its rule also has Request ticked, as new rules do.
        guard let function = context.objectForKeyedSubscript(name), function.isObject else { return nil }
        let requestText = text(flow.request)
        let responseText = text(flow.response)
        let request: [String: Any] = ["method": flow.method, "path": path, "headers": pairs(flow.request), "body": requestText ?? NSNull()]
        var arguments: [JSValue] = [JSValue(object: request, in: context)]
        if phase == .response {
            let response: [String: Any] = ["status": flow.status ?? 0, "headers": pairs(flow.response), "body": responseText ?? NSNull()]
            arguments.append(JSValue(object: response, in: context))
        }
        let returned = function.call(withArguments: arguments)
        try check(context)
        let message = returned.map { $0.isUndefined || $0.isNull ? arguments.last! : $0 } ?? arguments.last!
        guard message.isObject else {
            let value = message.toString() ?? String(localized: "a value")
            throw ProxyFailure(phase == .request
                ? String(localized: "\(name) returned \(value) instead of the request or nothing.")
                : String(localized: "\(name) returned \(value) instead of the response or nothing."))
        }

        // Checked as strictly as the breakpoint editor checks what's typed, and more: a line
        // break in a header would let the script write a header of its own past the encoder.
        var edit = EditedMessage()
        if phase == .request {
            guard let method = string(message, "method"), !method.isEmpty, !method.contains(where: \.isWhitespace) else {
                throw ProxyFailure(String(localized: "The method is text without spaces."))
            }
            guard let path = string(message, "path"), path.hasPrefix("/"), !path.contains(where: \.isWhitespace) else {
                throw ProxyFailure(String(localized: "The path is text that starts with / and has no spaces."))
            }
            edit.method = method
            edit.path = path
        } else {
            let status = message.forProperty("status")
            guard let status, status.isNumber, let code = Int(exactly: status.toDouble()), (100 ... 599).contains(code) else {
                throw ProxyFailure(String(localized: "The status is a whole number from 100 to 599."))
            }
            edit.status = code
        }
        guard let list = message.forProperty("headers"), list.isArray, let pairs = list.toArray() else {
            throw ProxyFailure(String(localized: "headers is a list of [name, value] pairs."))
        }
        edit.headers = try pairs.map { pair -> (name: String, value: String) in
            guard let pair = pair as? [Any], pair.count == 2, let name = pair[0] as? String, let value = pair[1] as? String,
                  !name.isEmpty, name.unicodeScalars.allSatisfy(token.contains),
                  !value.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" })
            else {
                throw ProxyFailure(String(localized: "Each header is a [name, value] pair of text: the name without spaces or colons, the value on one line. Not \(String(describing: pair))."))
            }
            return (name, value)
        }
        let body = message.forProperty("body")
        if let body, !body.isNull, !body.isUndefined {
            guard body.isString, let text = body.toString() else {
                throw ProxyFailure(String(localized: "The body is text, or null to send it as it came."))
            }
            // Unchanged text goes on as it came, encoding and all, as at a breakpoint.
            edit.body = text == (phase == .request ? requestText : responseText) ? nil : Data(text.utf8)
        }
        return edit
    }

    /// The body as a breakpoint shows it: decoded text, or nil when it isn't text.
    private static func text(_ message: HTTPMessage) -> String? {
        message.decodedBody.flatMap { String(data: $0, encoding: .utf8) }
    }

    private static func pairs(_ message: HTTPMessage) -> [[String]] {
        message.headers.map { [$0.name, $0.value] }
    }

    private static func string(_ object: JSValue, _ key: String) -> String? {
        guard let value = object.forProperty(key), value.isString else { return nil }
        return value.toString()
    }

    /// What RFC 9110 §5.6.2 allows in a header name.
    private static let token = Set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".unicodeScalars)

    private static func check(_ context: JSContext) throws {
        if let exception = context.exception {
            throw ProxyFailure(describe(exception))
        }
    }

    private static func describe(_ exception: JSValue) -> String {
        let text = exception.toString() ?? String(localized: "An exception")
        guard let line = exception.forProperty("line"), line.isNumber else { return text }
        return String(localized: "\(text) (line \(line.toInt32()))")
    }
}
