import AppKit
import Charts
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

// MARK: Formatting

func bytes(_ count: Int) -> String {
    // Spelled out, zero reads "Zero kB", which jars on an axis of figures.
    Int64(count).formatted(.byteCount(style: .decimal, spellsOutZero: false))
}

extension SocketOwner: CustomStringConvertible {
    var description: String {
        via.map { String(localized: "\(path) (pid \(pid)), through \($0)") } ?? "\(path) (pid \(pid))"
    }
}

extension FlowKey {
    var protocolName: String {
        switch proto {
        case 1: "ICMP"
        case 2: "IGMP"
        case PacketParser.tcp: "TCP"
        case PacketParser.udp: "UDP"
        case 58: "ICMPv6"
        default: "IP \(proto)"
        }
    }

    var localEndpoint: String { endpoint(local, localPort) }
    var remoteEndpoint: String { endpoint(remote, remotePort) }

    private func endpoint(_ address: IPAddress, _ port: UInt16) -> String {
        guard proto == PacketParser.tcp || proto == PacketParser.udp else { return address.description }
        return address.isV4 ? "\(address):\(port)" : "[\(address)]:\(port)"
    }
}

// MARK: Pages

/// Capture needs the root helper; until it's installed and allowed, that's the page.
/// A capture file needs nothing of it.
struct TrafficPage<Content: View>: View {
    @Environment(TrafficStore.self) private var traffic
    @ViewBuilder let content: Content

    var body: some View {
        Group {
            if traffic.helper.status == .enabled || traffic.file != nil {
                content
                    // The first visit starts capturing; after that it's the user's call.
                    .task { await traffic.startOnFirstVisit() }
            } else {
                HelperSetupView()
            }
        }
        .task {
            traffic.helper.refreshStatus()
            traffic.refreshInterfaces()
        }
    }
}

struct TrafficOverview: View {
    private enum Metric: CaseIterable, Identifiable {
        case bytes, packets

        var id: Self { self }

        var label: String {
            switch self {
            case .bytes: String(localized: "Bytes")
            case .packets: String(localized: "Packets")
            }
        }
    }

    @Environment(TrafficStore.self) private var traffic
    @State private var window = TimeWindow.fiveMinutes
    @State private var metric = Metric.bytes
    @State private var selectedDate: Date?

    var body: some View {
        TrafficPage {
            // A file's chart spans the whole file: the window is for following live traffic.
            // At least two seconds: a file of one would leave the axis no width.
            let span = traffic.file?.span?.count
            let seconds = span.map { max($0, 2) } ?? Int(window.rawValue)
            let rates = traffic.seconds.rates(window: seconds, end: traffic.now)
            VStack(alignment: .leading, spacing: 20) {
                CaptureBar()
                header(rates.last)
                HStack {
                    if span == nil {
                        Picker("Time window", selection: $window) {
                            ForEach(TimeWindow.allCases) { Text($0.label).tag($0) }
                        }
                    }
                    Picker("Measure", selection: $metric) {
                        ForEach(Metric.allCases) { Text($0.label).tag($0) }
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                chart(rates, seconds: seconds, format: span == nil ? window.axisFormat : Self.axisFormat(seconds), quarters: span == nil && window == .oneMinute)
                topLists
            }
            .padding(20)
            .toolbar { CaptureToolbar() }
        }
        .navigationTitle("Traffic")
    }

    private func header(_ latest: TrafficRate?) -> some View {
        HStack(alignment: .top, spacing: 20) {
            // Always bytes: the Measure picker switches the chart, not these.
            if let span = traffic.file?.span?.count {
                // A file's last second is no more "now" than any other.
                tile("Average download", "\(bytes(traffic.totals.bytesIn / span))/s", large: true)
                tile("Average upload", "\(bytes(traffic.totals.bytesOut / span))/s", large: true)
            } else {
                tile("Download", latest.map { "\(bytes($0.counts.bytesIn / $0.span))/s" }, large: true)
                tile("Upload", latest.map { "\(bytes($0.counts.bytesOut / $0.span))/s" }, large: true)
            }
            Spacer()
            tile("Received", bytes(traffic.totals.bytesIn))
            tile("Sent", bytes(traffic.totals.bytesOut))
            tile("Packets", (traffic.totals.packetsIn + traffic.totals.packetsOut).formatted())
            // Packets the kernel threw away because the helper didn't read them in time.
            // A file doesn't say what its capture dropped.
            if traffic.file == nil {
                tile("Dropped", traffic.dropped.formatted())
            }
        }
    }

    private func tile(_ label: LocalizedStringKey, _ value: String?, large: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).foregroundStyle(.secondary)
            Text(value ?? "—")
                .font(large ? .system(size: 32, weight: .semibold) : .title2.weight(.semibold))
                .monospacedDigit()
        }
        .frame(minWidth: large ? 150 : 90, alignment: .leading)
    }

    private func rate(_ perSecond: Double) -> String {
        metric == .bytes ? "\(bytes(Int(perSecond)))/s" : "\(Int(perSecond.rounded()).formatted()) pkt/s"
    }

    private func value(_ rate: TrafficRate, inbound: Bool) -> Double {
        let count = switch (metric, inbound) {
        case (.bytes, true): rate.counts.bytesIn
        case (.bytes, false): rate.counts.bytesOut
        case (.packets, true): rate.counts.packetsIn
        case (.packets, false): rate.counts.packetsOut
        }
        return Double(count) / Double(rate.span)
    }

    /// A file's axis: seconds for a few minutes, the day once it spans days.
    private static func axisFormat(_ seconds: Int) -> Date.FormatStyle {
        seconds <= 300 ? .dateTime.hour().minute().second() : seconds <= 86_400 ? .dateTime.hour().minute() : .dateTime.month().day().hour()
    }

    /// Mirrored: download above the zero line, upload below, on one shared scale.
    private func chart(_ rates: [TrafficRate], seconds: Int, format: Date.FormatStyle, quarters: Bool) -> some View {
        let selected = selectedDate.flatMap { date in
            rates.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }
        }
        let end = Date(timeIntervalSince1970: TimeInterval(traffic.now))
        // A bucket is plotted at its start, so the oldest sits seconds - 1 before the
        // newest. A whole window back left a blank second: a quarter of a 4-second file.
        let domain = end.addingTimeInterval(-TimeInterval(seconds - 1)) ... end
        // The legend shows these, and the color scale is keyed by them.
        let download = String(localized: "Download"), upload = String(localized: "Upload")
        return VStack(alignment: .leading, spacing: 8) {
            Text(metric == .bytes ? "Throughput (bytes per second)" : "Packets per second").font(.headline)
            Chart {
                ForEach(rates, id: \.date) { rate in
                    ForEach([true, false], id: \.self) { inbound in
                        let direction = inbound ? download : upload
                        let y = value(rate, inbound: inbound) * (inbound ? 1 : -1)
                        AreaMark(x: .value("Time", rate.date), y: .value("Rate", y), series: .value("Direction", direction))
                            .foregroundStyle(by: .value("Direction", direction))
                            .opacity(0.15)
                        LineMark(x: .value("Time", rate.date), y: .value("Rate", y), series: .value("Direction", direction))
                            .foregroundStyle(by: .value("Direction", direction))
                            .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    }
                }
                RuleMark(y: .value("Zero", 0))
                    .foregroundStyle(Color.reference)
                    .lineStyle(StrokeStyle(lineWidth: 1))
                if let selected {
                    RuleMark(x: .value("Time", selected.date))
                        .foregroundStyle(Color.cursor)
                        .lineStyle(StrokeStyle(lineWidth: 1))
                        .annotation(position: .top, spacing: 0, overflowResolution: .init(x: .fit(to: .chart), y: .fit(to: .plot))) {
                            tooltip(selected, withDate: seconds > 86_400)
                        }
                }
            }
            .chartForegroundStyleScale([download: Color.inbound, upload: Color.outbound])
            .chartLegend(position: .top, alignment: .leading)
            .chartXScale(domain: domain)
            .chartXAxis { timeAxis(domain, labels: format, quarters: quarters) }
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisGridLine(stroke: .hairline)
                    AxisValueLabel {
                        if let v = value.as(Double.self) {
                            Text(rate(abs(v)))
                        }
                    }
                }
            }
            .chartXSelection(value: $selectedDate)
            .frame(minHeight: 200)
        }
    }

    /// F2.4: where the bytes went, by host, service, program and country.
    private var topLists: some View {
        HStack(alignment: .top, spacing: 24) {
            TopList(title: "Hosts", entries: top(.host))
            TopList(title: "Services", entries: top(.service))
            TopList(title: "Programs", entries: top(.program), empty: traffic.file == nil ? "—" : String(localized: "Not recorded in capture files"))
            VStack(alignment: .leading, spacing: 6) {
                TopList(title: "Countries", entries: top(.country))
                // CC BY 4.0 asks for this credit wherever the data shows.
                Link("IP Geolocation by DB-IP", destination: URL(string: "https://db-ip.com")!)
                    .font(.caption)
            }
        }
    }

    private func top(_ grouping: Grouping) -> [TopList.Entry] {
        traffic.top(grouping).map { TopList.Entry(name: $0.name, bytes: $0.bytes) }
    }

    private func tooltip(_ selected: TrafficRate, withDate: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(selected.date, format: withDate ? .dateTime.month().day().hour().minute().second() : .dateTime.hour().minute().second())
                .foregroundStyle(.secondary)
            tooltipRow("Download", .inbound, rate(value(selected, inbound: true)))
            tooltipRow("Upload", .outbound, rate(value(selected, inbound: false)))
        }
        .font(.caption)
        .padding(8)
        .background(.regularMaterial, in: .rect(cornerRadius: 6))
    }

    private func tooltipRow(_ label: LocalizedStringKey, _ color: Color, _ value: String) -> some View {
        HStack(spacing: 6) {
            Capsule().fill(color).frame(width: 10, height: 3)
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).monospacedDigit()
        }
    }
}

/// A flow plus the names resolved for it, so every column sorts the same way.
private struct ConnectionRow: Identifiable {
    let flow: Flow
    let domain: String
    let service: String
    let location: String
    let network: String
    let program: String
    /// Full path and pid, for the tooltip.
    let process: String?
    /// The starred name the connection goes under; nil if it isn't a favorite.
    let favorite: String?
    /// The blacklist entry its remote address falls in.
    let blacklisted: IPRange?

    var id: FlowKey { flow.key }
}

/// Five names and their byte totals, with a bar behind each so the shares read at a
/// glance. The bar is a wash in one hue; the text stays in ink.
private struct TopList: View {
    struct Entry: Identifiable {
        let name: String
        let bytes: Int

        var id: String { name }
    }

    let title: LocalizedStringKey
    let entries: [Entry]
    var empty = "—"

    var body: some View {
        let largest = entries.map(\.bytes).max() ?? 1
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline).padding(.bottom, 2)
            if entries.isEmpty {
                Text(empty).foregroundStyle(.secondary)
            }
            ForEach(entries) { entry in
                HStack {
                    Text(entry.name).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    Text(bytes(entry.bytes)).monospacedDigit().foregroundStyle(.secondary)
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(alignment: .leading) {
                    GeometryReader { geometry in
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.inbound.opacity(0.15))
                            .frame(width: geometry.size.width * Double(entry.bytes) / Double(max(largest, 1)))
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ConnectionsView: View {
    private enum Show: CaseIterable, Identifiable {
        case all, favorites, blacklisted

        var id: Self { self }

        var label: String {
            switch self {
            case .all: String(localized: "All")
            case .favorites: String(localized: "Favorites")
            case .blacklisted: String(localized: "Blacklisted")
            }
        }
    }

    @Environment(TrafficStore.self) private var traffic
    @Environment(Watchlist.self) private var watchlist
    @State private var search = ""
    @State private var show = Show.all
    // What the context menu acts on, besides the row clicked.
    @State private var selection: Set<FlowKey> = []
    @State private var sortOrder = [KeyPathComparator(\ConnectionRow.flow.lastSeen, order: .reverse)]
    // Which columns show, persisted: seventeen don't fit, so the less used ones start
    // hidden and the header's context menu brings them back.
    @SceneStorage("connectionColumns") private var columns = TableColumnCustomization<ConnectionRow>()

    var body: some View {
        TrafficPage {
            let all = traffic.flows.map { flow in
                let geo = traffic.geo(flow.key.remote)
                let domain = traffic.domain(of: flow)
                return ConnectionRow(
                    flow: flow,
                    domain: domain ?? "",
                    service: serviceName(flow.key) ?? "",
                    location: geo?.countryLabel ?? flow.key.remote.scope.label,
                    network: geo?.networkLabel ?? "",
                    // Blank until looked up, which takes up to a second; never looked up
                    // for a file, which has no record of programs.
                    program: traffic.file != nil ? "—" : traffic.programs[flow.key].map { $0?.name ?? String(localized: "Unknown") } ?? "",
                    process: traffic.file != nil ? String(localized: "Capture files don't record which program sent a packet.") : traffic.programs[flow.key]??.description,
                    favorite: watchlist.favorites.match(domain: domain, address: flow.key.remote),
                    blacklisted: watchlist.blacklistEntry(for: flow.key.remote)
                )
            }
            let rows = all.filter(matches).sorted(using: sortOrder)
            let blacklisted = all.count { $0.blacklisted != nil }
            let shown = rows.count == all.count ? String(localized: "\(rows.count) connections") : String(localized: "\(rows.count) of \(all.count) connections")
            VStack(spacing: 0) {
                CaptureBar().padding(12)
                Divider()
                Table(rows, selection: $selection, sortOrder: $sortOrder, columnCustomization: $columns) {
                    markColumns
                    addressColumns
                    countColumns
                }
                .contextMenu(forSelectionType: FlowKey.self) { keys in
                    let picked = rows.filter { keys.contains($0.id) }
                    if !picked.isEmpty {
                        let starred = picked.allSatisfy { $0.favorite != nil }
                        Button(starred ? "Remove from Favorites" : "Add to Favorites") {
                            for row in picked {
                                star(row, !starred)
                            }
                        }
                    }
                }
                .overlay {
                    if all.isEmpty, let file = traffic.file {
                        ContentUnavailableView(file.progress != nil ? "Reading the File" : "No Connections in This File", systemImage: "doc.text.magnifyingglass")
                    } else if all.isEmpty {
                        ContentUnavailableView(traffic.isCapturing ? "Waiting for Traffic" : "Not Capturing", systemImage: "network")
                    } else if rows.isEmpty, search.isEmpty {
                        // Only the Show picker can empty the table without a search.
                        ContentUnavailableView(show == .favorites ? "No Connections to Favorites" : "No Blacklisted Connections", systemImage: show == .favorites ? "star" : "nosign")
                    } else if rows.isEmpty {
                        ContentUnavailableView.search(text: search)
                    }
                }
                Divider()
                // Under the table, where someone missing a row looks. Spelled out rather
                // than formatted from FlowAggregator.idleLimit and fileFlowLimit: a
                // duration follows the system locale and would put "10分鐘" in an English
                // sentence.
                Text(traffic.file == nil ? "Connections idle for 10 minutes are removed." : "Every connection in the file is listed, up to the 10,000 most recently active.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.vertical, 6)
            }
            .searchable(text: $search, prompt: "Address, domain, program or service")
            .toolbar {
                ToolbarItem {
                    Picker("Show", selection: $show) {
                        ForEach(Show.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                }
                CaptureToolbar()
            }
            // The blacklisted count stays whatever Show and the search leave in the table.
            .navigationSubtitle(blacklisted > 0 ? String(localized: "\(shown), \(blacklisted) blacklisted") : shown)
        }
        .navigationTitle("Connections")
    }

    private func star(_ row: ConnectionRow, _ isFavorite: Bool) {
        watchlist.favorites.set(isFavorite, domain: row.domain.isEmpty ? nil : row.domain, address: row.flow.key.remote)
    }

    /// Ahead of the addresses, where a flagged connection is seen first.
    @TableColumnBuilder<ConnectionRow, KeyPathComparator<ConnectionRow>>
    private var markColumns: some TableColumnContent<ConnectionRow, KeyPathComparator<ConnectionRow>> {
        TableColumn(Text("★").accessibilityLabel("Favorite")) { (row: ConnectionRow) in
            let host = row.favorite ?? (row.domain.isEmpty ? row.flow.key.remote.description : row.domain)
            Button(row.favorite == nil ? "Add to Favorites" : "Remove from Favorites", systemImage: row.favorite == nil ? "star" : "star.fill") {
                star(row, row.favorite == nil)
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help(row.favorite == nil ? "Add \(host) to Favorites" : "Remove \(host) from Favorites")
        }
        .width(min: 22, ideal: 24, max: 30)
        .customizationID("favorite")
        TableColumn("Blacklist") { (row: ConnectionRow) in
            if let entry = row.blacklisted {
                Label {
                    Text("Blacklisted")
                } icon: {
                    Image(systemName: "nosign").foregroundStyle(Color.statusCritical)
                }
                .help(entry.description == row.flow.key.remote.description ? "On your blacklist" : "In \(entry.description) on your blacklist")
            }
        }
        .width(min: 90, ideal: 105)
        .customizationID("blacklist")
    }

    // Builders with their types spelled out: seventeen columns in one closure is more
    // than the type checker will take.
    @TableColumnBuilder<ConnectionRow, KeyPathComparator<ConnectionRow>>
    private var addressColumns: some TableColumnContent<ConnectionRow, KeyPathComparator<ConnectionRow>> {
        TableColumn("Protocol", value: \.flow.key.protocolName).width(min: 55, ideal: 60)
            .customizationID("protocol")
        TableColumn("Local", value: \.flow.key.local) { (row: ConnectionRow) in Text(row.flow.key.localEndpoint) }.width(min: 120, ideal: 150)
            .customizationID("local").defaultVisibility(.hidden)
        TableColumn("Remote", value: \.flow.key.remote) { (row: ConnectionRow) in Text(row.flow.key.remoteEndpoint) }.width(min: 120, ideal: 170)
            .customizationID("remote")
        TableColumn("Domain", value: \.domain).width(min: 100, ideal: 180)
            .customizationID("domain")
        TableColumn("Service", value: \.service).width(min: 50, ideal: 70)
            .customizationID("service")
        TableColumn("Program", value: \.program) { (row: ConnectionRow) in Text(row.program).help(row.process ?? "") }.width(min: 70, ideal: 110)
            .customizationID("program")
        TableColumn("Location", value: \.location).width(min: 70, ideal: 120)
            .customizationID("location")
        TableColumn("Network", value: \.network).width(min: 100, ideal: 180)
            .customizationID("network").defaultVisibility(.hidden)
    }

    @TableColumnBuilder<ConnectionRow, KeyPathComparator<ConnectionRow>>
    private var countColumns: some TableColumnContent<ConnectionRow, KeyPathComparator<ConnectionRow>> {
        TableColumn("In", value: \.flow.counts.bytesIn) { (row: ConnectionRow) in Text(bytes(row.flow.counts.bytesIn)).monospacedDigit() }.width(min: 60, ideal: 75)
            .customizationID("in")
        TableColumn("Out", value: \.flow.counts.bytesOut) { (row: ConnectionRow) in Text(bytes(row.flow.counts.bytesOut)).monospacedDigit() }.width(min: 60, ideal: 75)
            .customizationID("out")
        TableColumn("Packets in", value: \.flow.counts.packetsIn) { (row: ConnectionRow) in Text(row.flow.counts.packetsIn.formatted()).monospacedDigit() }.width(min: 60, ideal: 70)
            .customizationID("packetsIn").defaultVisibility(.hidden)
        TableColumn("Packets out", value: \.flow.counts.packetsOut) { (row: ConnectionRow) in Text(row.flow.counts.packetsOut.formatted()).monospacedDigit() }.width(min: 60, ideal: 70)
            .customizationID("packetsOut").defaultVisibility(.hidden)
        // `value:` takes no optional key path; the comparator does, unknowns first.
        TableColumn("RTT", sortUsing: KeyPathComparator(\ConnectionRow.flow.rtt)) { (row: ConnectionRow) in
            Text(row.flow.rtt.map { milliseconds($0 * 1000) } ?? "—").monospacedDigit()
                .help("Round trip of the TCP handshake, timed at \(traffic.file == nil ? String(localized: "this Mac") : String(localized: "the capturing machine")): its SYN to the SYN-ACK when it opened the connection, its SYN-ACK to the ACK when the other end did. “—” when the capture missed the handshake, and for anything but TCP.")
        }.width(min: 50, ideal: 65)
            .customizationID("rtt")
        TableColumn("First seen", value: \.flow.firstSeen) { (row: ConnectionRow) in Text(row.flow.firstSeen, format: .dateTime.hour().minute().second()) }.width(min: 85, ideal: 95)
            .customizationID("firstSeen").defaultVisibility(.hidden)
        TableColumn("Last seen", value: \.flow.lastSeen) { (row: ConnectionRow) in Text(row.flow.lastSeen, format: .dateTime.hour().minute().second()) }.width(min: 85, ideal: 95)
            .customizationID("lastSeen")
    }

    private func matches(_ row: ConnectionRow) -> Bool {
        switch show {
        case .all: break
        case .favorites: guard row.favorite != nil else { return false }
        case .blacklisted: guard row.blacklisted != nil else { return false }
        }
        guard !search.isEmpty else { return true }
        let key = row.flow.key
        return [key.protocolName, key.localEndpoint, key.remoteEndpoint, row.domain, row.service, row.location, row.network, row.program]
            .contains { $0.localizedStandardContains(search) }
    }
}

// MARK: Capture controls

/// Interface, filter, and what the capture is up to. Filter errors land right under
/// the field they came from. None of it applies to a file, which shows its own bar.
struct CaptureBar: View {
    @Environment(TrafficStore.self) private var traffic
    @State private var draft = ""

    var body: some View {
        if let file = traffic.file {
            FileBar(file: file)
        } else {
            liveBar
        }
    }

    private var liveBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Picker("Interface", selection: Binding { traffic.interface } set: { name in
                    Task { await traffic.select(interface: name) }
                }) {
                    ForEach(traffic.interfaces) { Text($0.label).tag($0.name) }
                }
                .fixedSize()
                TextField("Filter", text: $draft, prompt: Text("Capture filter (BPF), e.g. tcp port 443"))
                    .font(.body.monospaced())
                    .onSubmit { Task { await traffic.apply(filter: draft) } }
                if draft.trimmingCharacters(in: .whitespaces) != traffic.filter {
                    Text("Press Return to apply").font(.caption).foregroundStyle(.secondary)
                }
            }
            // Changing either mid-recording would end the file.
            .disabled(traffic.isRecording || traffic.isChanging)
            if let error = traffic.error {
                Label {
                    Text(error).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            } else if let recording = traffic.recording {
                recordingStatus(recording)
            }
        }
        .onAppear { draft = traffic.filter }
    }

    private func recordingStatus(_ recording: Recording) -> some View {
        HStack(spacing: 8) {
            if traffic.isRecording {
                Label {
                    Text("Recording \(recording.packets.formatted()) packets to \(recording.url.lastPathComponent)")
                } icon: {
                    Image(systemName: "record.circle.fill").foregroundStyle(Color.statusCritical)
                }
            } else {
                Label("Saved \(recording.packets.formatted()) packets to \(recording.url.lastPathComponent)", systemImage: "checkmark.circle")
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([recording.url]) }
                    .buttonStyle(.link)
            }
        }
    }
}

/// Which file shows, how much of it, and the way back to live capture. Says what a file
/// can't: which program sent a packet, and for certain which machine captured it.
private struct FileBar: View {
    @Environment(TrafficStore.self) private var traffic
    let file: OpenFile

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Label("Showing \(file.url.lastPathComponent)", systemImage: "doc.text.magnifyingglass")
                    .font(.headline)
                if let progress = file.progress {
                    ProgressView(value: progress) {
                        Text("Reading… \(file.packets.formatted()) packets so far")
                    }
                    .frame(maxWidth: 360)
                } else if let span = file.span {
                    let dates = Date(timeIntervalSince1970: TimeInterval(span.lowerBound)) ..< Date(timeIntervalSince1970: TimeInterval(span.upperBound + 1))
                    Text("\(file.packets.formatted()) packets, \(dates.formatted(.interval.year().month().day().hour().minute().second()))")
                } else if file.error == nil {
                    Text("No packets in this file.")
                }
                if let error = file.error {
                    Label {
                        Text(error).textSelection(.enabled)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusWarning)
                    }
                }
                if let first = file.hosts.first {
                    let others = file.hosts.count - 1
                    let seenFrom = others > 0 ? String(localized: "\(first.description) and \(others) more addresses") : first.description
                    Text("In and Out are as seen from \(seenFrom), taken as the capturing machine for being in the most conversations. Capture files don't record programs.")
                        .font(.caption).foregroundStyle(.secondary)
                        .help(file.hosts.map(\.description).joined(separator: "\n"))
                }
            }
            Spacer()
            Button("Back to Live") { Task { await traffic.backToLive() } }
        }
    }
}

struct CaptureToolbar: ToolbarContent {
    @Environment(TrafficStore.self) private var traffic

    var body: some ToolbarContent {
        ToolbarItemGroup {
            // A file can't be recorded or paused; its bar has the way back to live.
            if traffic.file == nil {
                if traffic.isRecording {
                    Button { Task { await traffic.stopRecording() } } label: {
                        Label("Stop Recording", systemImage: "stop.circle")
                    }
                } else {
                    Button { record() } label: {
                        Label("Record PCAP…", systemImage: "record.circle")
                    }
                }
                if traffic.isCapturing {
                    Button { Task { await traffic.stop() } } label: {
                        Label("Stop Capture", systemImage: "pause.fill")
                    }
                } else {
                    Button { Task { await traffic.start() } } label: {
                        Label("Start Capture", systemImage: "play.fill")
                    }
                }
            }
            Button {
                if let url = chooseCaptureFile() {
                    Task { await traffic.open(url) }
                }
            } label: {
                Label("Open Capture…", systemImage: "folder")
            }
            // Opening a file stops the capture, and would end the recording with it.
            .disabled(traffic.isRecording)
        }
    }

    private func record() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap", conformingTo: .data) ?? .data]
        // Local time: the ISO 8601 style defaults to UTC, which names a file after a
        // moment the user doesn't recognize.
        let stamp = Date.ISO8601FormatStyle(timeSeparator: .omitted, timeZone: .current).year().month().day().time(includingFractionalSeconds: false)
        panel.nameFieldStringValue = "WiFiDetect \(Date.now.formatted(stamp)).pcap"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await traffic.startRecording(to: url) }
    }
}

/// For the toolbar and File › Open Capture…: pcap or pcapng, which libpcap tells apart
/// by their first bytes.
@MainActor func chooseCaptureFile() -> URL? {
    let panel = NSOpenPanel()
    panel.allowedContentTypes = ["pcap", "pcapng"].compactMap { UTType(filenameExtension: $0, conformingTo: .data) }
    return panel.runModal() == .OK ? panel.url : nil
}

/// Install flow for the root helper: register, then wait for the user to allow it
/// in Login Items. macOS sends no notification when they do, so this polls.
struct HelperSetupView: View {
    var title: LocalizedStringKey = "Install the Capture Helper"
    var purpose: LocalizedStringKey = "Seeing traffic means reading packets, which macOS allows only as root. WiFiDetect installs a small helper that does just that, and nothing else."
    @Environment(TrafficStore.self) private var traffic
    @State private var error: String?

    var body: some View {
        let helper = traffic.helper
        ContentUnavailableView {
            Label(title, systemImage: "lock.shield")
        } description: {
            Text(purpose)
            if helper.status == .requiresApproval {
                Text("Allow “WiFiDetect” in System Settings › General › Login Items › Allow in the Background.")
            }
            if let error {
                Text(error).foregroundStyle(Color.statusCritical)
            }
        } actions: {
            if helper.status == .requiresApproval {
                Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                    .buttonStyle(.borderedProminent)
            } else {
                Button("Install Helper") {
                    do {
                        try helper.register()
                        error = nil
                    } catch {
                        // Registration throws while approval is pending; the status
                        // tells that case apart from a real failure.
                        if helper.status != .requiresApproval {
                            self.error = error.localizedDescription
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .task {
            while !Task.isCancelled {
                helper.refreshStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }
}
