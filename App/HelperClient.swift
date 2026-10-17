import Foundation
import Observation
import os
import ServiceManagement

@MainActor @Observable
final class HelperClient {
    private(set) var status: SMAppService.Status = .notRegistered
    private let service = SMAppService.daemon(plistName: HelperConstants.daemonPlistName)
    @ObservationIgnored private var connection: NSXPCConnection?
    /// What the helper calls back with capture batches, on an XPC queue.
    @ObservationIgnored private let receiver: HelperClientProtocol
    /// The helper went away mid-connection (crashed, or was replaced); whatever it
    /// was doing for us has stopped. Capture and the proxy each register one.
    @ObservationIgnored var onInterruption: [() -> Void] = []

    init(receiver: HelperClientProtocol) {
        self.receiver = receiver
    }

    func refreshStatus() {
        status = service.status
    }

    /// Throws while the user has not yet allowed the daemon in System Settings ›
    /// General › Login Items; `status` then reads `.requiresApproval`.
    func register() throws {
        defer { refreshStatus() }
        try service.register()
    }

    func unregister() async throws {
        connection?.invalidate()
        try await service.unregister()
        refreshStatus()
    }

    func version() async throws -> String {
        try await call { helper, reply in helper.version { reply(.success($0)) } }
    }

    func startCapture(id: Int, interface: String, filter: String, pcap: FileHandle?) async throws {
        try await call { helper, reply in
            helper.startCapture(id: id, interface: interface, filter: filter, pcap: pcap) { reply(Self.result($0)) }
        }
    }

    func stopCapture() async throws {
        try await call { helper, reply in helper.stopCapture { reply(.success(())) } }
    }

    func socketOwners() async throws -> [SocketOwner] {
        let data: Data = try await call { helper, reply in helper.socketOwners { reply(.success($0)) } }
        return try PropertyListDecoder().decode([SocketOwner].self, from: data)
    }

    func enableSystemProxy(port: Int, bypass: [String]) async throws {
        try await call { helper, reply in helper.enableSystemProxy(port: port, bypass: bypass) { reply(Self.result($0)) } }
    }

    func restoreSystemProxy() async throws {
        try await call { helper, reply in helper.restoreSystemProxy { reply(Self.result($0)) } }
    }

    /// The helper answers with what went wrong, or nil.
    private nonisolated static func result(_ error: String?) -> Result<Void, Error> {
        error.map { .failure(HelperError.failed($0)) } ?? .success(())
    }

    /// Every call to the helper goes through here. launchd holds a message for a helper
    /// it can't start and tries again every 10 seconds, for ever (spikes, pitfall 70):
    /// without a deadline the call never returns, and the pages wait without a word.
    private func call<T: Sendable>(_ send: (HelperProtocol, @escaping @Sendable (Result<T, Error>) -> Void) -> Void) async throws -> T {
        let connection = self.connection ?? makeConnection()
        self.connection = connection
        return try await withCheckedThrowingContinuation { continuation in
            // Not a Mutex: the closures below escape, and a Mutex can't be captured.
            let answered = OSAllocatedUnfairLock(initialState: false)
            let answer: @Sendable (Result<T, Error>) -> Bool = { result in
                guard answered.withLock({ let first = !$0; $0 = true; return first }) else { return false }
                continuation.resume(with: result)
                return true
            }
            // remoteObjectProxy is always an NSXPC proxy for the declared interface. The
            // handler is called on an XPC queue; without @Sendable it would inherit
            // @MainActor and trap.
            send(connection.remoteObjectProxyWithErrorHandler { @Sendable error in _ = answer(.failure(error)) } as! HelperProtocol) { _ = answer($0) }
            Task {
                try? await Task.sleep(for: .seconds(10))
                // Dropped as well, so the message isn't carried out if the helper does start.
                if answer(.failure(HelperError.failed(String(localized: "The helper didn't answer within 10 seconds, so macOS probably can't start it, as happens after switching to another build of WiFiDetect. In Settings › Helper, uninstall it and install it again. If it still doesn't answer, restart the Mac.")))) {
                    connection.invalidate()
                    // At once, not when invalidationHandler gets round to it: a retry
                    // straight away would go out on this connection and fail at once.
                    if self.connection === connection { self.connection = nil }
                }
            }
        }
    }

    private func makeConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: HelperConstants.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: HelperClientProtocol.self)
        connection.exportedObject = receiver
        connection.setCodeSigningRequirement(HelperConstants.helperRequirement)
        // Called on an XPC queue; without @Sendable they would inherit @MainActor and trap.
        // Only while it's still the one in use: a call that timed out has already put
        // it aside, and a retry may have opened the next.
        let id = ObjectIdentifier(connection)
        connection.invalidationHandler = { @Sendable [weak self] in
            Task { @MainActor in
                if let self, self.connection.map(ObjectIdentifier.init) == id { self.connection = nil }
            }
        }
        connection.interruptionHandler = { @Sendable [weak self] in
            Task { @MainActor in self?.onInterruption.forEach { $0() } }
        }
        connection.resume()
        return connection
    }
}

enum HelperError: LocalizedError {
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .failed(let message): message
        }
    }
}
