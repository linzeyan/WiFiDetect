import Foundation
import Synchronization
import os

private let log = Logger(subsystem: "com.zeyanlin.wifidetect", category: "helper")

struct CaptureError: Error {
    let message: String
}

/// One libpcap handle, read on its own thread from `start()` until `stop()`.
final class Capture: @unchecked Sendable {
    // @unchecked: once started, `pending` and `dumper` belong to the capture thread;
    // the only cross-thread call is pcap_breakloop, which libpcap documents as safe
    // to call from another thread.
    private let id: Int
    private let handle: OpaquePointer
    private let linkType: Int32
    private var program: bpf_program?
    private var dumper: OpaquePointer?
    private var pending: [PacketSummary] = []
    private let send: @Sendable (Data) -> Void
    private let finished = DispatchSemaphore(value: 0)

    /// The most packets one message to the app carries.
    static let packetsPerMessage = 10_000

    /// Opens and compiles but doesn't filter or read yet, so a bad filter or
    /// interface fails here while the capture it would replace keeps running.
    init(id: Int, interface: String, filter: String, pcap: FileHandle?, send: @escaping @Sendable (Data) -> Void) throws(CaptureError) {
        // Validated against the kernel's interface list before it reaches libpcap.
        guard interface.utf8.count < IFNAMSIZ, if_nametoindex(interface) != 0 else {
            throw CaptureError(message: "No interface named \(interface).")
        }
        guard filter.utf8.count <= 1024 else { throw CaptureError(message: "The filter is too long.") }
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let handle = pcap_create(interface, &errbuf) else {
            throw CaptureError(message: errbuf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
        }
        // 1518 bytes: a whole frame at the usual 1500-byte MTU, with an Ethernet
        // header and one VLAN tag. A QUIC Initial is at least 1200 bytes and only
        // decrypts whole, its authentication tag being at the end; DNS answers and a
        // TCP ClientHello's first segment now arrive whole too. The cost over the
        // earlier 512 falls on bulk transfers' full-size frames: three times the
        // bytes copied into the kernel buffer and out to the helper, so the 2 MB
        // buffer holds a third as many before it drops. A recording keeps whole
        // frames.
        pcap_set_snaplen(handle, pcap == nil ? 1518 : 262_144)
        // Without a read timeout pcap_dispatch blocks until the buffer fills, so a
        // quiet interface would hold up both batching and stop().
        pcap_set_timeout(handle, 150)
        pcap_set_buffer_size(handle, 2 << 20)
        guard pcap_activate(handle) >= 0 else {
            defer { pcap_close(handle) }
            throw CaptureError(message: String(cString: pcap_geterr(handle)))
        }
        var program = bpf_program()
        guard pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) == 0 else {
            defer { pcap_close(handle) }
            throw CaptureError(message: String(cString: pcap_geterr(handle)))
        }
        if let pcap {
            // The app opened the file, so it belongs to the user, not root.
            guard let file = fdopen(dup(pcap.fileDescriptor), "w"), let dumper = pcap_dump_fopen(handle, file) else {
                pcap_freecode(&program)
                pcap_close(handle)
                throw CaptureError(message: "Couldn't write the PCAP file.")
            }
            self.dumper = dumper
        }
        self.id = id
        self.handle = handle
        self.linkType = pcap_datalink(handle)
        self.program = program
        self.send = send
    }

    deinit {
        if var program { pcap_freecode(&program) }
        if let dumper { pcap_dump_close(dumper) }
        pcap_close(handle)
    }

    func start() throws(CaptureError) {
        guard var program else { return }
        // Installing the filter also empties the kernel buffer, dropping what this
        // handle saw while the capture it replaces was still running: no packet is
        // counted by both.
        let installed = pcap_setfilter(handle, &program)
        pcap_freecode(&program)
        self.program = nil
        guard installed == 0 else { throw CaptureError(message: String(cString: pcap_geterr(handle))) }
        Thread { self.run() }.start()
    }

    /// Returns once the last batch is sent and the PCAP file is closed.
    func stop() {
        pcap_breakloop(handle)
        finished.wait()
    }

    private func run() {
        let context = Unmanaged.passUnretained(self).toOpaque().assumingMemoryBound(to: u_char.self)
        var flushed = ContinuousClock.now
        var error: String?
        while true {
            let count = pcap_dispatch(handle, -1, { context, header, bytes in
                Unmanaged<Capture>.fromOpaque(UnsafeRawPointer(context!)).takeUnretainedValue().receive(header!, bytes!)
            }, context)
            if count == PCAP_ERROR_BREAK { break }
            if count < 0 {
                error = String(cString: pcap_geterr(handle))
                break
            }
            if flushed.duration(to: .now) >= .milliseconds(250) {
                flush()
                flushed = .now
            }
        }
        flush(error: error)
        if let dumper { pcap_dump_close(dumper) }
        dumper = nil
        log.notice("capture \(self.id) ended: \(error ?? "stopped", privacy: .public)")
        finished.signal()
    }

    private func receive(_ header: UnsafePointer<pcap_pkthdr>, _ bytes: UnsafePointer<u_char>) {
        if let dumper {
            pcap_dump(UnsafeMutablePointer(dumper), header, bytes)
        }
        let frame = UnsafeRawBufferPointer(start: bytes, count: Int(header.pointee.caplen))
        let time = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1_000_000
        pending.append(PacketParser.parse(frame, wireLength: Int(header.pointee.len), time: time, linkType: linkType))
    }

    private func flush(error: String? = nil) {
        guard !pending.isEmpty || error != nil else { return }
        var stats = pcap_stat()
        pcap_stats(handle, &stats)
        // A recording stays readable while it grows.
        if let dumper { pcap_dump_flush(dumper) }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        // In parts: at 1 GB/s a quarter second is ~170,000 packets, and encoding them
        // at once peaked at 229 MB, its freed blocks then kept dirty in malloc's cache,
        // more after each burst (spikes, Phase 4 third batch). Parts sent sooner instead,
        // a batch capped by count, cost two thirds of a burst's packets: encoding then
        // fell inside the burst, and the kernel drops what arrives meanwhile.
        var start = 0
        repeat {
            let end = min(start + Self.packetsPerMessage, pending.count)
            // ps_drop is a running total, so every part can carry it.
            let batch = CaptureBatch(capture: id, packets: Array(pending[start ..< end]), dropped: Int(stats.ps_drop), error: end == pending.count ? error : nil)
            if let data = try? encoder.encode(batch) { send(data) }
            start = end
        } while start < pending.count
        // Not keeping its capacity: after a burst that's tens of MB held for nothing.
        pending.removeAll()
    }
}

/// One per connection: each app connection owns at most one capture, and the system
/// proxy while it has it enabled.
final class HelperService: NSObject, HelperProtocol, Sendable {
    private let capture = Mutex<Capture?>(nil)
    private let ownsProxy = Mutex(false)
    private let send: @Sendable (Data) -> Void

    init(send: @escaping @Sendable (Data) -> Void) {
        self.send = send
    }

    func version(reply: @escaping @Sendable (String) -> Void) {
        reply(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown")
    }

    func startCapture(id: Int, interface: String, filter: String, pcap: FileHandle?, reply: @escaping @Sendable (String?) -> Void) {
        do {
            let next = try Capture(id: id, interface: interface, filter: filter, pcap: pcap, send: send)
            try capture.withLock { (current: inout Capture?) throws(CaptureError) in
                current?.stop()
                current = nil
                try next.start()
                current = next
            }
            log.notice("capture \(id) started on \(interface, privacy: .public), filter \"\(filter, privacy: .public)\", pcap \(pcap != nil)")
            reply(nil)
        } catch {
            reply(error.message)
        }
    }

    func stopCapture(reply: @escaping @Sendable () -> Void) {
        stop()
        reply()
    }

    func socketOwners(reply: @escaping @Sendable (Data) -> Void) {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        reply((try? encoder.encode(listSocketOwners())) ?? Data())
    }

    func enableSystemProxy(port: Int, bypass: [String], reply: @escaping @Sendable (String?) -> Void) {
        // Only the team's app gets here, but the values still end up in every network
        // service's settings: host names and CIDR ranges, nothing else.
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*:/_")
        guard (1024 ... 65535).contains(port), bypass.count <= 512,
              bypass.allSatisfy({ !$0.isEmpty && $0.count <= 253 && $0.allSatisfy(allowed.contains) }) else {
            reply("Invalid proxy settings.")
            return
        }
        do {
            try SystemProxy.enable(port: port, bypass: bypass)
            ownsProxy.withLock { $0 = true }
            log.notice("system proxy set to 127.0.0.1:\(port)")
            reply(nil)
        } catch {
            log.error("enabling the system proxy failed: \(error.message, privacy: .public)")
            reply(error.message)
        }
    }

    func restoreSystemProxy(reply: @escaping @Sendable (String?) -> Void) {
        do {
            try restoreProxy()
            reply(nil)
        } catch {
            reply(error.message)
        }
    }

    private func restoreProxy() throws(ProxyError) {
        let wasOn = SystemProxy.isEnabled
        try SystemProxy.restore()
        ownsProxy.withLock { $0 = false }
        if wasOn {
            log.notice("system proxy restored")
        }
    }

    /// The connection is gone: the app quit, crashed or was killed.
    func stop() {
        capture.withLock { current in
            current?.stop()
            current = nil
        }
        if ownsProxy.withLock({ $0 }) {
            do {
                try restoreProxy()
            } catch {
                // The backup stays, so launchd keeps the helper alive (or starts it at
                // the next boot) and the restore runs again from the top.
                log.error("restoring the system proxy failed: \(error.message, privacy: .public)")
            }
        }
    }
}

/// Walks every process's file descriptors for IPv4/IPv6 sockets. Sockets that
/// Network.framework runs in user space never show up here, which is why the app
/// says "Unknown" rather than guess (docs: traffic research Q3).
func listSocketOwners() -> [SocketOwner] {
    var pids = [pid_t](repeating: 0, count: Int(proc_listallpids(nil, 0)) + 64)
    let count = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
    var owners: [SocketOwner] = []
    for pid in pids.prefix(Int(max(count, 0))) where pid > 0 {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { continue }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / MemoryLayout<proc_fdinfo>.stride)
        let used = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
        var process: (name: String, path: String)?
        for fd in fds.prefix(Int(max(used, 0)) / MemoryLayout<proc_fdinfo>.stride) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
            var info = socket_fdinfo()
            let infoSize = Int32(MemoryLayout<socket_fdinfo>.size)
            guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, infoSize) == infoSize,
                  [AF_INET, AF_INET6].contains(info.psi.soi_family) else { continue }
            let port = switch Int(info.psi.soi_kind) {
            case SOCKINFO_TCP: info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport
            case SOCKINFO_IN: info.psi.soi_proto.pri_in.insi_lport
            default: Int32(0)
            }
            guard port != 0 else { continue }
            if process == nil {
                var name = [CChar](repeating: 0, count: 256)
                var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                proc_name(pid, &name, UInt32(name.count))
                proc_pidpath(pid, &path, UInt32(path.count))
                process = (name.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }, path.withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
            }
            // The port sits in network byte order in the low 16 bits of an int.
            owners.append(SocketOwner(
                proto: UInt8(truncatingIfNeeded: info.psi.soi_protocol),
                localPort: UInt16(bigEndian: UInt16(truncatingIfNeeded: port)),
                pid: pid,
                name: process!.name,
                path: process!.path
            ))
        }
    }
    return owners
}

private let clients = Mutex(0)

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Enforced per message: a peer that fails the requirement gets its connection
        // invalidated before any exported method runs.
        connection.setCodeSigningRequirement(HelperConstants.appRequirement)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperClientProtocol.self)
        // Weak: the connection retains the service, which retains this closure.
        // NSXPCConnection is thread-safe; the SDK just doesn't mark it Sendable.
        nonisolated(unsafe) weak let peer = connection
        let service = HelperService { batch in
            (peer?.remoteObjectProxy as? HelperClientProtocol)?.didCapture(batch)
        }
        connection.exportedInterface = NSXPCInterface(with: HelperProtocol.self)
        connection.exportedObject = service
        let pid = connection.processIdentifier
        clients.withLock { $0 += 1 }
        connection.invalidationHandler = {
            service.stop()
            log.notice("connection from pid \(pid) invalidated")
            // launchd starts the helper again on the next connection. Exiting when idle
            // also means a rebuilt helper takes over as soon as the app quits.
            if clients.withLock({ $0 -= 1; return $0 }) == 0 {
                exit(0)
            }
        }
        log.notice("accepted connection from pid \(pid)")
        connection.resume()
        return true
    }
}

// A backup left over means whoever enabled the proxy is gone: this helper crashed
// with it on, or the Mac restarted. Nothing listens on that port any more.
if SystemProxy.isEnabled {
    do {
        try SystemProxy.restore()
        log.notice("restored the system proxy an earlier session left on")
    } catch {
        log.error("restoring the system proxy failed: \(error.message, privacy: .public)")
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
listener.delegate = delegate
listener.resume()
log.notice("helper listening on \(HelperConstants.machServiceName, privacy: .public)")
// launchd also starts the helper with no app around, to run the restore above; then
// nothing would ever invalidate a connection and let it exit.
DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
    if clients.withLock({ $0 }) == 0, !SystemProxy.isEnabled {
        exit(0)
    }
}
dispatchMain()
