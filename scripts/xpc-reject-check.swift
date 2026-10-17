// Connects to the helper from a process that is NOT signed by our team: `make
// check-reject` compiles this with swiftc, which leaves only the linker's ad-hoc
// signature. The helper's code-signing requirement must reject it. Only meaningful
// right after the app's own Ping succeeded: if the helper is not running at all, the
// connection fails the same way and this would pass for the wrong reason.
//
// Compiled, not run with `swift file.swift`: the JIT emits no extended Objective-C
// method signatures, and NSXPCInterface throws without them.
import Foundation

@objc protocol HelperProtocol {
    func version(reply: @escaping @Sendable (String) -> Void)
}

let connection = NSXPCConnection(machServiceName: "com.zeyanlin.wifidetect.helper", options: .privileged)
connection.remoteObjectInterface = NSXPCInterface(with: HelperProtocol.self)
connection.resume()

let done = DispatchSemaphore(value: 0)
nonisolated(unsafe) var outcome = "TIMEOUT: no reply and no error within 5 s"
let proxy = connection.remoteObjectProxyWithErrorHandler { error in
    outcome = "REJECTED (expected): \(error.localizedDescription)"
    done.signal()
} as! HelperProtocol
proxy.version { version in
    outcome = "ACCEPTED (BAD): helper answered a foreign client with version \(version)"
    done.signal()
}
_ = done.wait(timeout: .now() + 5)
print(outcome)
exit(outcome.hasPrefix("REJECTED") ? 0 : 1)
