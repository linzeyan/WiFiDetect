import Foundation
import Network
import NetworkExtension
import Security
import Testing
@testable import WiFiDetect

/// Which connections the transparent proxy takes. Each rule here is what keeps a
/// captured Mac from looping or losing the network.
struct CaptureGateTests {
    let now = Date(timeIntervalSince1970: 1_000_000)
    let chrome = "/Applications/Google Chrome.app"

    func gate(apps: [String]? = nil, renewedAgo: TimeInterval = 1) -> CaptureGate {
        var gate = CaptureGate()
        gate.renew(CaptureSettings(port: 9090, apps: apps ?? [chrome]), at: now - renewedAgo)
        return gate
    }

    func decide(_ gate: CaptureGate, path: String?, identifier: String? = "com.google.Chrome.helper", remote: Network.NWEndpoint.Host = "142.250.1.1", udp: Bool = false, at time: Date? = nil) -> CaptureGate.Decision {
        gate.decide(identifier: identifier, remote: remote, udp: udp, at: time ?? now) { path }
    }

    /// Most of a browser's connections come from helpers inside its bundle.
    @Test func listedAppAndItsHelpersGoToTheProxy() {
        #expect(decide(gate(), path: chrome) == .proxy(port: 9090))
        #expect(decide(gate(), path: chrome + "/Contents/Frameworks/Helper.app") == .proxy(port: 9090))
    }

    /// A bundle whose name merely starts the same is another app.
    @Test func otherAppsGoDirect() {
        #expect(decide(gate(), path: "/Applications/Google Chrome.app2/x") == .direct)
        #expect(decide(gate(), path: "/usr/bin/curl") == .direct)
        #expect(decide(gate(), path: nil) == .direct)
        #expect(decide(gate(), path: "") == .direct)
    }

    /// The proxy's own connections to servers come from WiFiDetect: captured, they'd
    /// go back into the proxy forever, even if the user put WiFiDetect on the list.
    @Test func wifiDetectItselfIsNeverCaptured() {
        let gate = gate(apps: ["/Applications/WiFiDetect.app"])
        for identifier in [HelperConstants.appIdentifier, HelperConstants.machServiceName, ExtensionConstants.identifier] {
            #expect(decide(gate, path: "/Applications/WiFiDetect.app", identifier: identifier) == .direct)
        }
    }

    /// The proxy listens on loopback, and link-local is printers and captive portals.
    @Test(arguments: ["127.0.0.1", "::1", "169.254.10.1", "fe80::1"] as [Network.NWEndpoint.Host])
    func localDestinationsGoDirect(_ remote: Network.NWEndpoint.Host) {
        #expect(decide(gate(), path: chrome, remote: remote) == .direct)
    }

    /// A hung app's proxy answers nothing; five missed renewals send flows direct.
    @Test func expiredLeaseGoesDirect() {
        #expect(decide(gate(renewedAgo: CaptureGate.lease - 1), path: chrome) == .proxy(port: 9090))
        #expect(decide(gate(renewedAgo: CaptureGate.lease + 1), path: chrome) == .direct)
    }

    /// The app quit or was killed: direct at once, without waiting out the lease.
    @Test func disconnectGoesDirectAtOnce() {
        var gate = gate()
        gate.disconnect()
        #expect(decide(gate, path: chrome) == .direct)
    }

    /// After the proxy refused a connection, the next ones don't wait 5 s each to find out.
    @Test func failedProxyBacksOff() {
        var gate = gate()
        gate.proxyFailed(at: now)
        gate.renew(gate.settings, at: now + 5)
        #expect(decide(gate, path: chrome, at: now + 6) == .direct)
        gate.renew(gate.settings, at: now + CaptureGate.backoff)
        #expect(decide(gate, path: chrome, at: now + CaptureGate.backoff + 1) == .proxy(port: 9090))
    }

    /// QUIC would go around the proxy; refused, the app retries over TCP.
    @Test func quicFromCapturedAppsIsRefused() {
        #expect(decide(gate(), path: chrome, udp: true) == .refuse)
        #expect(decide(gate(), path: "/usr/bin/curl", udp: true) == .direct)
    }

    /// Every HTTPS connection on the Mac reaches the gate; the code-signing lookup
    /// mustn't run for them while capture is off.
    @Test func pathIsNotLookedUpWhileOff() {
        var asked = false
        _ = CaptureGate().decide(identifier: nil, remote: "1.1.1.1", udp: false, at: now) {
            asked = true
            return chrome
        }
        #expect(!asked)
    }
}

struct ProxyRulesTests {
    /// What the system diverts at all: HTTPS over TCP and QUIC, v4 and v6, and never
    /// link-local.
    @Test func coversHTTPSAndLeavesOutLinkLocal() {
        func describe(_ rules: [NENetworkRule]?) -> Set<String> {
            Set((rules ?? []).map { rule in
                guard case .hostPort(let host, let port)? = rule.matchRemoteHostOrNetworkEndpoint else { return "?" }
                let proto = rule.matchProtocol == .TCP ? "tcp" : rule.matchProtocol == .UDP ? "udp" : "any"
                return "\(host)/\(rule.matchRemotePrefix):\(port) \(proto)"
            })
        }
        let settings = ProxyRules.settings
        #expect(describe(settings.includedNetworkRules) == ["0.0.0.0/0:443 tcp", "0.0.0.0/0:443 udp", "::/0:443 tcp", "::/0:443 udp"])
        #expect(describe(settings.excludedNetworkRules) == ["169.254.0.0/16:0 any", "fe80::/10:0 any"])
    }
}

struct FlowReportTests {
    /// A report without a local port could match nothing; the filter waits for data.
    @Test func unboundPortIsNotAnEndpoint() {
        #expect(FlowReport.parse(nil) == nil)
        #expect(FlowReport.parse(.hostPort(host: "0.0.0.0", port: 0)) == nil)
    }

    @Test func addressesAndPorts() throws {
        let v4 = try #require(FlowReport.parse(.hostPort(host: "192.168.1.10", port: 52000)))
        #expect(v4.address == IPAddress("192.168.1.10") && v4.port == 52000)
        let v6 = try #require(FlowReport.parse(.hostPort(host: "2001:db8::1", port: 443)))
        #expect(v6.address == IPAddress("2001:db8::1") && v6.port == 443)
    }

    func report(_ port: UInt16) -> FlowReport {
        FlowReport(time: .now, proto: 6, localPort: port, remotePort: 443, app: .init(pid: 1, path: "/x"))
    }

    /// The root extension's memory stays bounded if the app stops reading, and what's
    /// kept are the newest, whose connections are likeliest still open.
    @Test func bufferKeepsTheNewest() throws {
        var buffer = ReportBuffer()
        for port in 0 ..< UInt16(ReportBuffer.limit + 10) {
            buffer.append(report(port))
        }
        let batch = buffer.drain()
        let reports = try #require(batch.flatMap(ReportBuffer.decode))
        #expect(reports.count == ReportBuffer.limit)
        #expect(reports.first?.localPort == 10)
        #expect(reports.last?.localPort == UInt16(ReportBuffer.limit + 9))
        let rest = buffer.drain()
        #expect(rest == nil)
    }

    /// The batch crosses processes: what the extension encodes, the app must read,
    /// the daemon a flow came through included.
    @Test func batchRoundTrips() throws {
        var buffer = ReportBuffer()
        var original = report(52000)
        original.via = .init(pid: 2, path: "/usr/libexec/nsurlsessiond", identifier: "com.apple.nsurlsessiond")
        original.remoteHostname = "example.com"
        buffer.append(original)
        let batch = buffer.drain()
        #expect(batch.flatMap(ReportBuffer.decode) == [original])
    }

    /// The extension names apps from their audit tokens; a wrong lookup key would
    /// fail silently with every app unnamed. The test host is WiFiDetect itself.
    @Test func ownAuditTokenNamesThisApp() throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let status = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
        }
        try #require(status == KERN_SUCCESS)
        let process = try #require(ProcessIdentity.lookup(Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)))
        #expect(process.pid == getpid())
        #expect(process.path == Bundle.main.bundlePath)
        #expect(process.identifier == HelperConstants.appIdentifier)
    }
}

struct ConnectPrefaceTests {
    let hello = Data(TLSServerNameTests.clientHello("from-sni.example"))

    /// The name the app connected by beats the SNI, which beats the bare address: the
    /// proxy decrypts by host name.
    @Test func hostPrefersTheNameTheAppUsed() {
        #expect(ConnectPreface.host(remoteHostname: "api.example", hello: hello, address: "1.2.3.4") == "api.example")
        #expect(ConnectPreface.host(remoteHostname: nil, hello: hello, address: "1.2.3.4") == "from-sni.example")
        #expect(ConnectPreface.host(remoteHostname: nil, hello: Data(), address: "1.2.3.4") == "1.2.3.4")
    }

    /// The SNI comes from a local app's bytes and ends up in our request line.
    @Test func hostWithLineBreaksIsNotUsed() {
        let evil = Data(TLSServerNameTests.clientHello("a.example\r\nX-Evil: 1"))
        #expect(ConnectPreface.host(remoteHostname: "b.example\r\n", hello: evil, address: "1.2.3.4") == "1.2.3.4")
    }

    @Test func requestBracketsIPv6AndEncodesTheApp() {
        let text = String(decoding: ConnectPreface.request(host: "2001:db8::1", port: 443, app: "/Applications/My App.app"), as: UTF8.self)
        #expect(text == "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\nX-WiFiDetect-App: /Applications/My%20App.app\r\n\r\n")
    }

    /// Bytes behind the 200 are the server's and belong to the app.
    @Test func replyKeepsWhatFollowsThe200() {
        #expect(ConnectPreface.reply(Data("HTTP/1.1 200 OK\r\n".utf8)) == .incomplete)
        #expect(ConnectPreface.reply(Data("HTTP/1.1 200 OK\r\n\r\nxyz".utf8)) == .established(rest: Data("xyz".utf8)))
        #expect(ConnectPreface.reply(Data("HTTP/1.1 502 Bad Gateway\r\n\r\n".utf8)) == .refused("HTTP/1.1 502 Bad Gateway"))
        #expect(ConnectPreface.reply(Data("HTTP/1.1 2000 Odd\r\n\r\n".utf8)) == .refused("HTTP/1.1 2000 Odd"))
        #expect(ConnectPreface.reply(Data(repeating: 0x41, count: 9000)) == .refused("The proxy's answer is too long."))
    }

    /// The relay waits for the whole first record before it reads the server name.
    @Test func wholeRecord() {
        let hello = Data(TLSServerNameTests.clientHello("example.com"))
        #expect(TLS.hasWholeRecord(hello))
        #expect(!TLS.hasWholeRecord(hello.prefix(hello.count - 1)))
        #expect(!TLS.hasWholeRecord(hello.prefix(3)))
        #expect(!TLS.hasWholeRecord(Data()))
        // Not TLS: there's no name to wait for.
        #expect(TLS.hasWholeRecord(Data("GET / HTTP/1.1".utf8)))
    }
}

struct FlowAttributionTests {
    let now = Date(timeIntervalSince1970: 1_000_000)

    func flow(proto: UInt8 = 6, port: UInt16 = 52000, at time: Date? = nil) -> Flow {
        let key = FlowKey(proto: proto, local: IPAddress("192.168.1.2")!, localPort: port, remote: IPAddress("1.1.1.1")!, remotePort: 443)
        return Flow(key: key, firstSeen: time ?? now, lastSeen: time ?? now)
    }

    func report(proto: UInt8 = 6, port: UInt16 = 52000, path: String = "/Applications/Safari.app", at time: Date? = nil) -> FlowReport {
        FlowReport(time: time ?? now, proto: proto, localPort: port, remotePort: 443, app: .init(pid: 7, path: path))
    }

    let libproc = SocketOwner(proto: 6, localPort: 52000, pid: 9, name: "nsurlsessiond", path: "/usr/libexec/nsurlsessiond")

    /// The filter sees what libproc can't (user-space sockets, the app a daemon works
    /// for), so it wins; without a report nothing changes from before the filter.
    @Test func filterWinsOverLibproc() {
        var attribution = FlowAttribution()
        #expect(attribution.owner(of: flow(), libproc: libproc) == libproc)
        attribution.record([report()])
        #expect(attribution.owner(of: flow(), libproc: libproc)?.name == "Safari")
        #expect(attribution.owner(of: flow(), libproc: nil)?.path == "/Applications/Safari.app")
    }

    /// TCP and UDP port numbers are separate spaces.
    @Test func protocolIsPartOfTheMatch() {
        var attribution = FlowAttribution()
        attribution.record([report(proto: 17)])
        #expect(attribution.owner(of: flow(proto: 6)) == nil)
        #expect(attribution.owner(of: flow(proto: 17)) != nil)
    }

    /// Ports are reused: an old report on the same port is another connection's.
    @Test func staleReportDoesNotNameANewFlow() {
        var attribution = FlowAttribution()
        attribution.record([report(at: now - FlowAttribution.window - 1)])
        #expect(attribution.owner(of: flow()) == nil)
    }

    @Test func newestReportForAPortWins() {
        var attribution = FlowAttribution()
        attribution.record([report(path: "/Applications/Old.app"), report(path: "/Applications/New.app")])
        #expect(attribution.owner(of: flow())?.name == "New")
    }

    @Test func daemonIsShownAsVia() {
        var attribution = FlowAttribution()
        var report = report()
        report.via = .init(pid: 9, path: "/usr/libexec/nsurlsessiond")
        attribution.record([report])
        #expect(attribution.owner(of: flow())?.via == "nsurlsessiond (pid 9)")
    }

    let webKit = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc"
    let safari = FlowReport.Process(pid: 3, path: "/Applications/Safari.app")

    /// Safari's pages load through WebKit's networking service, whose sockets are its
    /// own; named after the service, every page would be "com.apple.WebKit.Networking".
    @Test func xpcServiceIsShownAsItsApp() {
        var attribution = FlowAttribution()
        attribution.responsible = { $0 == 7 ? safari : nil }
        attribution.record([report(path: webKit)])
        let owner = attribution.owner(of: flow(), libproc: nil)
        #expect(owner?.name == "Safari")
        #expect(owner?.pid == 3)
        #expect(owner?.via == "com.apple.WebKit.Networking (pid 7)")
    }

    /// The system holds a terminal responsible for what's run in it, and a daemon for
    /// itself; only an XPC service is shown as another process.
    @Test func onlyXPCServicesAreShownAsAnotherProcess() {
        var attribution = FlowAttribution()
        attribution.responsible = { _ in FlowReport.Process(pid: 4, path: "/System/Applications/Utilities/Terminal.app") }
        attribution.record([report(path: "/usr/bin/curl")])
        #expect(attribution.owner(of: flow())?.name == "curl")
    }

    /// A service launched for no app is responsible for itself, or for launchd.
    @Test func serviceWithoutAnAppKeepsItsName() {
        for host: pid_t in [7, 1] {
            var attribution = FlowAttribution()
            attribution.responsible = { _ in FlowReport.Process(pid: host, path: "/sbin/launchd") }
            attribution.record([report(path: webKit)])
            #expect(attribution.owner(of: flow())?.name == "com.apple.WebKit.Networking")
            #expect(attribution.owner(of: flow())?.via == nil)
        }
    }
}

struct ResponsibleProcessTests {
    /// The call is private, and a macOS release could drop or change it; every Safari
    /// connection would quietly go back to being named after WebKit's service.
    @Test func privateCallAnswers() throws {
        let process = try #require(ResponsibleProcess.responsible(for: getpid()))
        #expect(process.pid > 0)
        #expect(!process.path.isEmpty)
        #expect(!process.path.contains(".app/Contents/MacOS/"))
    }
}
