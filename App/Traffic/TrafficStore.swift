import Foundation
import Observation
import Synchronization

/// Takes the helper's batches on its XPC queue and folds them in there: tens of
/// thousands of packets a second never touch the main thread.
final class TrafficSink: NSObject, HelperClientProtocol, Sendable {
    let state = Mutex(FlowAggregator())

    func didCapture(_ batch: Data) {
        guard let batch = try? PropertyListDecoder().decode(CaptureBatch.self, from: batch) else { return }
        state.withLock { $0.ingest(batch) }
    }
}

struct Recording {
    let url: URL
    let capture: Int
    var packets = 0
}

/// A capture file the traffic pages show in place of live capture.
struct OpenFile {
    let url: URL
    /// From 0 to 1 while reading; nil once read.
    var progress: Double? = 0
    /// Why the file shows less than all of itself; what came before still shows.
    var error: String?
    var packets = 0
    /// The first and last second with a packet.
    var span: ClosedRange<Int>?
    /// The addresses taken to be the capturing machine's, which In and Out are relative to.
    var hosts: [IPAddress] = []
}

/// The content filter's reports, by protocol and local port. A report names a flow
/// that showed up around the same time only: ports are reused, and an old report on
/// one is about some earlier connection.
// ponytail: protocol and local port, as libproc is matched; a port reused within the
// window by another app is misnamed. Match the remote end too if that's ever seen.
struct FlowAttribution {
    /// A report comes as the connection opens, and capture sees its first packet
    /// within milliseconds; the rest is slack for a busy app.
    static let window: TimeInterval = 30
    private var reports: [Int: FlowReport] = [:]

    mutating func record(_ new: [FlowReport]) {
        for report in new {
            reports[Self.key(report.proto, report.localPort)] = report
        }
        // Past the window nothing can match them any more.
        if reports.count > 4096, let newest = new.map(\.time).max() {
            reports = reports.filter { newest.timeIntervalSince($0.value.time) <= Self.window }
        }
    }

    func owner(of flow: Flow) -> SocketOwner? {
        guard let report = reports[Self.key(flow.key.proto, flow.key.localPort)],
              abs(report.time.timeIntervalSince(flow.firstSeen)) <= Self.window else { return nil }
        return SocketOwner(report)
    }

    /// The filter's answer wins: it sees the sockets Network.framework runs in user
    /// space, which libproc doesn't, and the app a daemon worked for. Without one the
    /// answer is libproc's, as it was before there was a filter.
    func owner(of flow: Flow, libproc: SocketOwner?) -> SocketOwner? {
        owner(of: flow) ?? libproc
    }

    private static func key(_ proto: UInt8, _ port: UInt16) -> Int {
        Int(proto) << 16 | Int(port)
    }
}

extension SocketOwner {
    init(_ report: FlowReport) {
        func name(_ process: FlowReport.Process) -> String {
            process.path.isEmpty ? process.identifier ?? "pid \(process.pid)" : URL(filePath: process.path).deletingPathExtension().lastPathComponent
        }
        self.init(
            proto: report.proto, localPort: report.localPort, pid: report.app.pid,
            name: name(report.app), path: report.app.path.isEmpty ? name(report.app) : report.app.path,
            via: report.via.map { "\(name($0)) (pid \($0.pid))" }
        )
    }
}

@MainActor @Observable
final class TrafficStore {
    let helper: HelperClient
    @ObservationIgnored private let sink: TrafficSink

    private(set) var interfaces: [CaptureInterface] = []
    private(set) var interface = primaryInterface() ?? "en0"
    /// The filter in effect, or the one the next start uses.
    private(set) var filter = ""
    private(set) var isCapturing = false
    private(set) var isChanging = false
    /// The ongoing recording, or the last one, kept so its final count stays visible.
    private(set) var recording: Recording?
    private(set) var isRecording = false
    private(set) var error: String?

    // A snapshot of the aggregator, taken once a second.
    private(set) var flows: [Flow] = []
    private(set) var seconds: [Int: TrafficCounts] = [:]
    private(set) var totals = TrafficCounts()
    private(set) var dropped = 0
    /// The last whole second; the current one is still filling.
    private(set) var now = Int(Date.now.timeIntervalSince1970) - 1
    private(set) var dnsNames: [IPAddress: String] = [:]
    /// PTR lookups, for addresses no captured DNS answer named.
    private(set) var reverseNames: [IPAddress: String] = [:]
    /// Each flow's process, looked up once when the flow first shows up, and named
    /// again whenever the content filter reports on it. A nil value means looked up
    /// and not found: the socket closed first, or Network.framework ran it in user
    /// space and there's no filter.
    private(set) var programs: [FlowKey: SocketOwner?] = [:]
    /// Evicted flows' share of the Overview's top lists.
    private(set) var topTotals = TopTotals()
    /// Shown instead of live capture while set.
    private(set) var file: OpenFile?
    /// The connections a file keeps (`FlowAggregator.prune(keepingLatest:)`), as many as
    /// the proxy's flow list. The Connections page states it in words.
    nonisolated static let fileFlowLimit = 10_000

    @ObservationIgnored private var reader: CaptureFileReader?
    @ObservationIgnored private var captureID = 0
    @ObservationIgnored private var version = -1
    @ObservationIgnored private var visited = false
    @ObservationIgnored private var lookedUp: Set<IPAddress> = []
    @ObservationIgnored private var isAttributing = false
    @ObservationIgnored private var attribution = FlowAttribution()
    @ObservationIgnored private var geoCache: [IPAddress: GeoInfo] = [:]
    // getnameinfo blocks, for seconds when a resolver times out; a few at a time keeps
    // a burst of new hosts from tying up a thread each.
    @ObservationIgnored private let resolver: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 4
        queue.qualityOfService = .utility
        return queue
    }()

    init() {
        let sink = TrafficSink()
        self.sink = sink
        helper = HelperClient(receiver: sink)
        helper.onInterruption.append { [weak self] in
            guard let self, isCapturing else { return }
            isCapturing = false
            isRecording = false
            error = String(localized: "The helper stopped unexpectedly. Start the capture again.")
        }
        refreshInterfaces()
        // Lives as long as the app, like the store.
        Task {
            while true {
                self.snapshot()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func refreshInterfaces() {
        interfaces = captureInterfaces()
        // The picker needs its selection among the options, even if it went down.
        if !interfaces.contains(where: { $0.name == interface }) {
            interfaces.append(CaptureInterface(name: interface, label: interface))
        }
    }

    func startOnFirstVisit() async {
        guard !visited else { return }
        visited = true
        await start()
    }

    func start() async {
        await apply { try await self.restart(filter: self.filter, pcap: nil) }
        isCapturing = error == nil
    }

    func stop() async {
        await apply { try await self.helper.stopCapture() }
        isCapturing = false
        isRecording = false
    }

    func select(interface name: String) async {
        let previous = interface
        interface = name
        guard isCapturing else { return }
        await apply { try await self.restart(filter: self.filter, pcap: nil) }
        if error != nil {
            interface = previous
        }
    }

    /// While capturing, a filter that doesn't compile leaves the old one running.
    /// Like the interface, it can't change mid-recording: the views disable both.
    func apply(filter text: String) async {
        let text = text.trimmingCharacters(in: .whitespaces)
        guard isCapturing else {
            filter = text
            await start()
            return
        }
        await apply { try await self.restart(filter: text, pcap: nil) }
        if error == nil {
            filter = text
        }
    }

    func startRecording(to url: URL) async {
        await apply {
            // Created here, so the file belongs to the user; the helper only writes to it.
            guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
                throw HelperError.failed(String(localized: "Couldn't create \(url.lastPathComponent)."))
            }
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            let id = try await self.restart(filter: self.filter, pcap: handle)
            self.recording = Recording(url: url, capture: id)
        }
        isRecording = error == nil
        isCapturing = isCapturing || isRecording
    }

    func stopRecording() async {
        await apply { try await self.restart(filter: self.filter, pcap: nil) }
        isRecording = false
    }

    /// Shows a capture file in place of live capture, which stops and starts afresh on
    /// the way back: the pages, and whatever reads them, see one set of traffic at a time.
    /// The views keep this from ending a recording.
    func open(_ url: URL) async {
        if isCapturing {
            await stop()
        }
        reader?.cancel()
        let reader = CaptureFileReader()
        self.reader = reader
        file = OpenFile(url: url)
        // Visiting a traffic page must not start live capture over the file.
        visited = true
        clearSnapshot()
        Thread {
            let failure: String?
            do throws(CaptureFileError) {
                try reader.read(url, flowLimit: Self.fileFlowLimit) { fraction in
                    Task { @MainActor in
                        // Not after the end: the file's read by then.
                        if reader === self.reader, self.file?.progress != nil { self.file?.progress = fraction }
                    }
                }
                failure = nil
            } catch {
                failure = error.message
            }
            Task { @MainActor in self.finished(reader, error: failure) }
        }.start()
    }

    func backToLive() async {
        reader?.cancel()
        reader = nil
        file = nil
        sink.state.withLock { $0 = FlowAggregator() }
        clearSnapshot()
        now = Int(Date.now.timeIntervalSince1970) - 1
        if helper.status == .enabled {
            await start()
        } else {
            // Starts once the helper is installed and a traffic page shows.
            visited = false
        }
    }

    private func finished(_ reader: CaptureFileReader, error: String?) {
        // A file replaced, or left for live, while it was being read.
        guard reader === self.reader else { return }
        file?.progress = nil
        file?.error = error
        snapshot()
    }

    /// What the pages show belongs to the traffic it came from.
    private func clearSnapshot() {
        flows = []
        seconds = [:]
        totals = TrafficCounts()
        dropped = 0
        dnsNames = [:]
        programs = [:]
        topTotals = TopTotals()
        version = -1
    }

    /// Every settings change replaces the helper's capture with a new one.
    @discardableResult
    private func restart(filter: String, pcap: FileHandle?) async throws -> Int {
        captureID += 1
        let id = captureID
        try await helper.startCapture(id: id, interface: interface, filter: filter, pcap: pcap)
        return id
    }

    private func apply(_ change: () async throws -> Void) async {
        isChanging = true
        defer { isChanging = false }
        do {
            try await change()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func snapshot() {
        let reading = reader
        // A file's own packets tell which machine it was captured on (CaptureFileReader).
        let addresses = reading == nil ? localAddresses() : nil
        let now = Int(Date.now.timeIntervalSince1970) - 1
        let pruned = (reading?.sink ?? sink).state.withLock { state -> (copy: FlowAggregator, evicted: [Flow])? in
            if let addresses, state.localAddresses != addresses {
                state.localAddresses = addresses
            }
            guard state.version != version else { return nil }
            // A file's clock stopped when it was written: by today's, all its history is
            // over an hour old, so it keeps all of it.
            let evicted = reading == nil
                ? state.prune(before: now - Int(TimeWindow.oneHour.rawValue), now: .now)
                : state.prune(keepingLatest: Self.fileFlowLimit)
            return (state, evicted)
        }
        if reading == nil {
            self.now = now
        }
        guard let pruned else { return }
        let (copy, evicted) = pruned
        version = copy.version
        // Named now, while `programs` still has their owners.
        if !evicted.isEmpty {
            topTotals.retire(evicted) { name(of: $0, by: $1) }
        }
        flows = Array(copy.flows.values)
        // An evicted flow's owner goes too: kept, it would grow without bound, and if
        // the same ports came back under another process they'd show the old one.
        let attributed = programs.filter { copy.flows[$0.key] != nil }
        if attributed.count != programs.count {
            programs = attributed
        }
        seconds = copy.seconds
        totals = copy.totals
        dropped = copy.dropped.values.reduce(0, +)
        if let id = recording?.capture {
            recording?.packets = copy.packets[id] ?? 0
        }
        if isCapturing, let failure = copy.failures[captureID] {
            isCapturing = false
            isRecording = false
            error = failure
        }
        if dnsNames != copy.names {
            dnsNames = copy.names
        }
        if reading != nil {
            file?.packets = copy.totals.packetsIn + copy.totals.packetsOut
            file?.hosts = copy.localAddresses.sorted()
            if let first = copy.seconds.keys.min(), let last = copy.seconds.keys.max() {
                file?.span = first ... last
                // The chart ends where the file does.
                self.now = last
            }
        }
        lookUpUnnamed()
        // The helper's socket table is this Mac's, now: it can't say which program sent
        // a file's packets, and asked anyway it would name whatever holds the port today.
        // The content filter's reports are this Mac's, now, too.
        if reading == nil {
            applyAttribution()
            attributeNewFlows()
        }
    }

    /// The content filter's reports (`NetworkExtensionClient`).
    func attribute(_ reports: [FlowReport]) {
        attribution.record(reports)
        if reader == nil {
            applyAttribution()
        }
    }

    /// Late too: a report can come after libproc has answered, or said Unknown.
    private func applyAttribution() {
        for flow in flows {
            if let owner = attribution.owner(of: flow), (programs[flow.key] ?? nil) != owner {
                programs[flow.key] = owner
            }
        }
    }

    /// One socket table per second at most, however many flows are new: the helper
    /// walks every process's descriptors to build it.
    private func attributeNewFlows() {
        let pending = flows.filter { programs[$0.key] == nil }
        guard !pending.isEmpty, !isAttributing else { return }
        isAttributing = true
        Task {
            defer { isAttributing = false }
            guard let owners = try? await helper.socketOwners() else { return }
            // A port several processes share (SO_REUSEPORT, mDNS) goes to the first.
            let byPort = Dictionary(owners.map { (Int($0.proto) << 16 | Int($0.localPort), $0) }) { first, _ in first }
            for flow in pending {
                programs[flow.key] = .some(attribution.owner(of: flow, libproc: byPort[Int(flow.key.proto) << 16 | Int(flow.key.localPort)]))
            }
        }
    }

    /// Country and network of an internet address; cached, the lookup decodes a
    /// database record each time.
    func geo(_ address: IPAddress) -> GeoInfo? {
        guard address.scope == .internet else { return nil }
        if let cached = geoCache[address] {
            return cached
        }
        let info = GeoIP.shared.lookup(address)
        geoCache[address] = info
        return info
    }

    /// The connection's own TLS server name, then captured DNS (F2.8): both are the
    /// name the program asked for, where a PTR record is often a provider's machine
    /// name.
    func domain(of flow: Flow) -> String? {
        flow.serverName ?? dnsNames[flow.key.remote] ?? reverseNames[flow.key.remote]
    }

    func name(of flow: Flow, by grouping: Grouping) -> String? {
        switch grouping {
        case .host: domain(of: flow) ?? flow.key.remote.description
        case .service: serviceName(flow.key)
        // Flows still being looked up are left out rather than counted as Unknown.
        case .program: programs[flow.key].map { $0?.name ?? String(localized: "Unknown") }
        case .country: geo(flow.key.remote)?.countryLabel ?? flow.key.remote.scope.label
        }
    }

    func top(_ grouping: Grouping) -> [(name: String, bytes: Int)] {
        topTotals.top(grouping, live: flows) { name(of: $0, by: grouping) }
    }

    private func lookUpUnnamed() {
        for flow in flows {
            let address = flow.key.remote
            // Internet addresses only. A PTR query for a private address goes out over
            // mDNS, and that alone makes macOS ask the user for Local Network access;
            // devices on this network announce their names over mDNS anyway.
            guard flow.serverName == nil, dnsNames[address] == nil, address.scope == .internet,
                  lookedUp.insert(address).inserted else { continue }
            resolver.addOperation {
                guard let name = address.reverseName() else { return }
                Task { @MainActor in self.reverseNames[address] = name }
            }
        }
    }
}
