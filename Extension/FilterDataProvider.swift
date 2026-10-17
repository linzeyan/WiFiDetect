import Foundation
import NetworkExtension

/// Names the app behind each new connection, and lets every one through: it never
/// blocks. The kernel passes traffic on by itself if this process dies, but every new
/// connection on the Mac waits for these callbacks, so they return at once and the
/// code-signing lookups happen afterwards, on a queue of their own.
final class FilterDataProvider: NEFilterDataProvider {
    private let lookups = DispatchQueue(label: "com.zeyanlin.wifidetect.filter.lookups", qos: .utility)

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        appLink.providerStarting(.filter)
        // Every flow but loopback, which a filter only sees through a rule of its own.
        apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { error in
            if let error {
                log.error("filter settings: \(error.localizedDescription, privacy: .public)")
            } else {
                log.notice("filter started")
            }
            completionHandler(error)
            if error != nil { appLink.providerStopped(.filter) }
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.notice("filter stopped: \(reason.rawValue)")
        completionHandler()
        appLink.providerStopped(.filter)
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard appLink.isListening, let socket = flow as? NEFilterSocketFlow else { return .allow() }
        if report(socket) {
            return .allow()
        }
        // The local port is often unset this early (the address isn't chosen until the
        // connection is), and is by the first byte either way. Both directions: in a
        // protocol where the server speaks first, the app may send nothing.
        return .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 1, filterOutbound: true, peekOutboundBytes: 1)
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        _ = (flow as? NEFilterSocketFlow).map(report)
        return .allow()
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        _ = (flow as? NEFilterSocketFlow).map(report)
        return .allow()
    }

    // A flow that ends before its first byte still ends allowed.
    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        .allow()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        .allow()
    }

    /// False while the local port isn't known yet.
    private func report(_ flow: NEFilterSocketFlow) -> Bool {
        guard let local = FlowReport.parse(flow.localFlowEndpoint) else { return false }
        let remote = FlowReport.parse(flow.remoteFlowEndpoint)
        let (proto, hostname) = (UInt8(truncatingIfNeeded: flow.socketProtocol), flow.remoteHostname)
        let (appToken, processToken) = (flow.sourceAppAuditToken, flow.sourceProcessAuditToken)
        let time = Date.now
        lookups.async {
            guard let app = appLink.identity(appToken) else { return }
            // The same process for most flows; another when a daemon such as
            // nsurlsessiond opened it for the app.
            let process = appLink.identity(processToken)
            appLink.report(FlowReport(
                time: time, proto: proto, local: local.address, localPort: local.port,
                remote: remote?.address, remotePort: remote?.port ?? 0, remoteHostname: hostname,
                app: app, via: process?.pid == app.pid ? nil : process
            ))
        }
        return true
    }
}
