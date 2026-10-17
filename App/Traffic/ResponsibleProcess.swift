import Foundation

/// The app an XPC service works for. Safari loads its pages through
/// com.apple.WebKit.Networking, an XPC service whose connections are its own: the
/// content filter's audit token names the service (WebKit hands the app's token over
/// only on iOS), and libproc's socket table doesn't see them at all. The system records
/// which app each service runs for, as privacy prompts need to know, and a private call
/// reads that.
enum ResponsibleProcess {
    typealias Function = @convention(c) (pid_t) -> pid_t

    /// Looked up at run time, there being no header for it. Without it services keep
    /// their own names; a test fails if it's ever gone.
    static let function = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_get_pid_responsible_for_pid")
        .map { unsafeBitCast($0, to: Function.self) }

    /// The process the system holds responsible for `pid`: the app for its XPC
    /// services, the terminal for what's run in it, else the process itself.
    static func responsible(for pid: pid_t) -> FlowReport.Process? {
        guard let function else { return nil }
        let host = function(pid)
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard host > 0, proc_pidpath(host, &path, UInt32(path.count)) > 0 else { return nil }
        let program = path.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        // The bundle, as the content filter names an app, rather than the program in it.
        let bundle = program.range(of: ".app/Contents/MacOS/", options: .backwards).map { String(program[..<$0.lowerBound]) + ".app" }
        return FlowReport.Process(pid: host, path: bundle ?? program)
    }

    /// The app `process` works for when it's an XPC service; nil for anything else, and
    /// for a service no app launched. Services only: a program run in a terminal is the
    /// terminal's responsibility too, and curl should stay curl.
    static func host(of process: FlowReport.Process, responsible: (pid_t) -> FlowReport.Process?) -> FlowReport.Process? {
        guard isService(process.path), let host = responsible(process.pid), host.pid > 1, host.pid != process.pid else { return nil }
        return host
    }

    /// A service's bundle, as the content filter names it, or the program inside it.
    static func isService(_ path: String) -> Bool {
        path.hasSuffix(".xpc") || path.contains(".xpc/")
    }
}
