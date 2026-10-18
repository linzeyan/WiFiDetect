import SwiftUI

extension RouterFlowKey {
    /// Source in the local slot and destination in the remote one, for FlowKey's
    /// protocol names and endpoint formatting.
    var tuple: FlowKey {
        FlowKey(proto: proto, local: source, localPort: sourcePort, remote: destination, remotePort: destinationPort)
    }
}

/// A flow plus the names resolved for it, so every column sorts the same way.
private struct RouterFlowRow: Identifiable {
    let flow: RouterFlow
    let location: String

    var id: RouterFlowKey { flow.key }
}

/// Traffic › Router Flows: what routers report over NetFlow v9 or IPFIX, for every
/// device behind them rather than this Mac alone.
struct RouterFlowsView: View {
    @Environment(RouterFlowStore.self) private var store
    @Environment(TrafficStore.self) private var traffic
    @State private var search = ""
    @State private var sortOrder = [KeyPathComparator(\RouterFlowRow.flow.lastSeen, order: .reverse)]

    var body: some View {
        let all = store.flows.map { flow in
            // The end out on the internet is the one a country says something about.
            let key = flow.key
            let outside = key.destination.scope == .internet ? key.destination : key.source
            return RouterFlowRow(flow: flow, location: traffic.geo(outside)?.countryLabel ?? outside.scope.label)
        }
        let rows = all.filter(matches).sorted(using: sortOrder)
        VStack(spacing: 0) {
            ExportersBar().padding(12)
            Divider()
            Table(rows, sortOrder: $sortOrder) {
                TableColumn("Exporter", value: \.flow.key.exporter) { (row: RouterFlowRow) in Text(row.flow.key.exporter.description) }.width(min: 90, ideal: 110)
                TableColumn("Protocol", value: \.flow.key.tuple.protocolName).width(min: 55, ideal: 60)
                TableColumn("Source", value: \.flow.key.source) { (row: RouterFlowRow) in Text(row.flow.key.tuple.localEndpoint) }.width(min: 120, ideal: 170)
                TableColumn("Destination", value: \.flow.key.destination) { (row: RouterFlowRow) in Text(row.flow.key.tuple.remoteEndpoint) }.width(min: 120, ideal: 170)
                TableColumn("Location", value: \.location).width(min: 70, ideal: 120)
                TableColumn("Bytes", value: \.flow.bytes) { (row: RouterFlowRow) in Text(bytes(row.flow.bytes)).monospacedDigit() }.width(min: 60, ideal: 75)
                TableColumn("Packets", value: \.flow.packets) { (row: RouterFlowRow) in Text(row.flow.packets.formatted()).monospacedDigit() }.width(min: 60, ideal: 70)
                TableColumn("First seen", value: \.flow.firstSeen) { (row: RouterFlowRow) in Text(row.flow.firstSeen, format: .dateTime.hour().minute().second()) }.width(min: 85, ideal: 95)
                TableColumn("Last seen", value: \.flow.lastSeen) { (row: RouterFlowRow) in Text(row.flow.lastSeen, format: .dateTime.hour().minute().second()) }.width(min: 85, ideal: 95)
            }
            .overlay {
                if all.isEmpty {
                    ContentUnavailableView(store.isEnabled ? "No Flow Records Yet" : "Collector Off", systemImage: "wifi.router")
                } else if rows.isEmpty {
                    ContentUnavailableView.search(text: search)
                }
            }
            Divider()
            // Spelled out, as on the Connections page: a formatted duration follows the
            // system locale.
            Text("Flows no record has updated for 10 minutes are removed, and at most the 10,000 most recently updated are kept.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12).padding(.vertical, 6)
        }
        .searchable(text: $search, prompt: "Exporter, address, protocol or location")
        .navigationTitle("Router Flows")
        .navigationSubtitle(rows.count == all.count ? "\(rows.count) flows" : "\(rows.count) of \(all.count) flows")
    }

    private func matches(_ row: RouterFlowRow) -> Bool {
        guard !search.isEmpty else { return true }
        let tuple = row.flow.key.tuple
        return [row.flow.key.exporter.description, tuple.protocolName, tuple.localEndpoint, tuple.remoteEndpoint, row.location]
            .contains { $0.localizedStandardContains(search) }
    }
}

/// Which routers have been heard from, and when: the first thing to check when the
/// table stays empty.
private struct ExportersBar: View {
    @Environment(RouterFlowStore.self) private var store
    @Environment(\.openSettings) private var openSettings
    @AppStorage(SettingsKey.settingsTab) private var settingsTab = SettingsTab.wifi

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !store.isEnabled {
                HStack {
                    Text("The flow collector is off.")
                    Button("Turn It On in Settings…") {
                        settingsTab = .traffic
                        openSettings()
                    }
                    .buttonStyle(.link)
                }
            } else if let error = store.error {
                Label {
                    Text(error).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusCritical)
                }
            } else if store.exporters.isEmpty, let port = store.listening {
                // This Mac's own network addresses: what the router's export setting asks for.
                let addresses = localAddresses().filter { $0.isV4 && $0.scope == .privateNetwork }.sorted().map(\.description)
                Text("Listening for NetFlow v9 and IPFIX on UDP port \(String(port)). Set your router to export flows to \(addresses.isEmpty ? String(localized: "this Mac") : addresses.formattedList(.or)), port \(String(port)).")
            }
            ForEach(store.exporters) { exporter in
                HStack(spacing: 8) {
                    Label(exporter.address.description, systemImage: "wifi.router")
                    Text(exporter.version == FlowExport.ipfix ? "IPFIX" : "NetFlow v9").foregroundStyle(.secondary)
                    Text("last heard \(exporter.lastHeard.formatted(.dateTime.hour().minute().second())), \(exporter.records.formatted()) records")
                        .foregroundStyle(.secondary)
                    if exporter.unreadSets > 0 {
                        Label {
                            Text("\(exporter.unreadSets.formatted()) data sets dropped before their template came")
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusWarning)
                        }
                        .help("A router sends the layout of its records (a template) every few minutes. Records that arrive before it can't be read; the count stops growing once it comes.")
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Settings › Traffic: the collector's switch and port.
struct RouterFlowSettings: View {
    @Environment(RouterFlowStore.self) private var store

    var body: some View {
        @Bindable var store = store
        Section {
            Toggle("Collect flows from routers", isOn: $store.isEnabled)
            TextField("UDP port", value: Binding { store.port } set: { store.port = min(max($0, 1024), 65535) }, format: .number.grouping(.never))
            if let error = store.error {
                Text(error).foregroundStyle(Color.statusCritical).textSelection(.enabled)
            } else if let port = store.listening {
                LabeledContent("Status", value: String(localized: "Listening on UDP port \(port)"))
            }
        } header: {
            Text("Router flows")
        } footer: {
            Text("NetFlow v9 and IPFIX from routers set to export to this Mac, shown in Traffic › Router Flows. 4739 is IPFIX's registered port; routers often default to 2055 for NetFlow. Listens on every network interface: anything that reaches this Mac on the port can add flows.")
        }
    }
}
