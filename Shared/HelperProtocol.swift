import Foundation

enum HelperConstants {
    /// Mach service name, launchd label and code-signing identifier of the helper —
    /// one string, so the three cannot disagree.
    static let machServiceName = "com.zeyanlin.wifidetect.helper"
    static let daemonPlistName = "com.zeyanlin.wifidetect.helper.plist"
    static let appIdentifier = "com.zeyanlin.wifidetect"
    static let teamID = "NKJSLB6HBR"

    /// What the helper demands of the app connecting to it. Pinning the team (the
    /// leaf certificate's OU) rather than one certificate keeps Apple Development and
    /// Developer ID builds both valid.
    static let appRequirement = requirement(identifier: appIdentifier)
    /// What the app demands of the helper, so it never talks to an impostor that
    /// registered the same Mach service name.
    static let helperRequirement = requirement(identifier: machServiceName)

    static func requirement(identifier: String) -> String {
        "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}

/// Everything here runs as root. Keep it to operations that genuinely need root.
@objc protocol HelperProtocol {
    func version(reply: @escaping @Sendable (String) -> Void)

    /// Captures on `interface` and streams `CaptureBatch`es tagged `id` back through
    /// `HelperClientProtocol`, replacing this connection's running capture. Any
    /// settings change (interface, filter, recording) is a new call. A filter that
    /// doesn't compile replies with the error and leaves the running capture as is.
    /// `pcap`: an app-created file the helper writes every captured frame to, at full
    /// length; nil captures only the first 512 bytes, enough for the headers.
    func startCapture(id: Int, interface: String, filter: String, pcap: FileHandle?, reply: @escaping @Sendable (String?) -> Void)
    /// Replies once the last batch has been sent and any PCAP file is closed.
    func stopCapture(reply: @escaping @Sendable () -> Void)

    /// Every open TCP and UDP socket's process: property-list encoded
    /// `[SocketOwner]`. Root, because other users' and system daemons' sockets are
    /// out of an app's reach.
    func socketOwners(reply: @escaping @Sendable (Data) -> Void)

    /// Points every enabled network service's HTTP and HTTPS proxy at 127.0.0.1:`port`,
    /// except for `bypass` hosts. The settings it replaces are saved first and put back
    /// by `restoreSystemProxy`, or by the helper itself once this connection is gone.
    /// Replies nil on success, else the error text.
    func enableSystemProxy(port: Int, bypass: [String], reply: @escaping @Sendable (String?) -> Void)
    func restoreSystemProxy(reply: @escaping @Sendable (String?) -> Void)
}

struct SocketOwner: Codable, Equatable, Sendable {
    var proto: UInt8
    var localPort: UInt16
    var pid: Int32
    var name: String
    var path: String
    /// The process that opened the socket, when it's a system daemon acting for this
    /// one, as nsurlsessiond does for background downloads. Only the content filter
    /// tells; libproc sees the daemon alone.
    var via: String? = nil
}

/// Exported by the app, called by the helper.
@objc protocol HelperClientProtocol {
    /// A `CaptureBatch`, property-list encoded.
    func didCapture(_ batch: Data)
}
