import Foundation
import Observation
import UserNotifications

// MARK: Blacklist

/// An address and a prefix length, as a blacklist line gives them: 203.0.113.0/24, or a
/// single address, which is a /32 or a /128.
struct IPRange: Hashable, CustomStringConvertible {
    let address: IPAddress
    let prefix: Int

    /// Bits past the prefix are ignored, as most tools do, so a pasted 192.168.1.5/24
    /// still means the whole /24.
    init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let address = IPAddress(String(parts[0])) else { return nil }
        let bits = address.isV4 ? 32 : 128
        if parts.count == 2 {
            // Digits only: Int() alone would take "+24".
            guard parts[1].allSatisfy({ $0.isASCII && $0.isNumber }), let prefix = Int(parts[1]), prefix <= bits else { return nil }
            self.prefix = prefix
        } else {
            prefix = bits
        }
        self.address = address
    }

    func contains(_ other: IPAddress) -> Bool {
        // Swift's << shifts every bit out at the full width, so /0 needs no case of its own.
        switch (address, other) {
        case let (.v4(base), .v4(value)):
            let mask = UInt32.max << (32 - prefix)
            return base & mask == value & mask
        case let (.v6(baseHigh, baseLow), .v6(high, low)):
            let highMask = UInt64.max << (64 - min(prefix, 64))
            let lowMask = UInt64.max << (128 - max(prefix, 64))
            return baseHigh & highMask == high & highMask && baseLow & lowMask == low & lowMask
        default:
            return false
        }
    }

    var description: String {
        prefix == (address.isV4 ? 32 : 128) ? address.description : "\(address)/\(prefix)"
    }
}

/// The user's own list. Only theirs: a downloaded one would bring a network fetch and its
/// publisher's license with it.
// ponytail: a linear scan per address (Watchlist caches the answer), and the list lives as
// text in UserDefaults and a TextEditor; fine for hand-kept lists of a few thousand lines.
// A sorted range table in a file of its own if someone imports six-figure lists.
struct Blacklist {
    private(set) var entries: [IPRange] = []
    /// Lines that are neither blank, a comment nor an address or range, numbered from 1,
    /// so Settings can point at each one instead of quietly skipping it.
    private(set) var invalid: [(line: Int, text: String)] = []

    /// One address or range per line. Text after # or ; is a comment, as published lists
    /// annotate theirs, so a file of one imports as it is.
    init(_ text: String) {
        // isNewline, not "\n": a file saved on Windows ends its lines with \r\n, which
        // Swift reads as one Character.
        for (index, line) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let entry = line.prefix { $0 != "#" && $0 != ";" }.trimmingCharacters(in: .whitespaces)
            guard !entry.isEmpty else { continue }
            if let range = IPRange(entry) {
                entries.append(range)
            } else {
                invalid.append((index + 1, entry))
            }
        }
    }

    func entry(containing address: IPAddress) -> IPRange? {
        entries.first { $0.contains(address) }
    }
}

// MARK: Favorites

/// Starred hosts: the domain a connection had when starred, or its address if it had none.
struct Favorites {
    var hosts: Set<String> = []

    /// The starred name a connection goes under. Both are tried: a host starred by its
    /// address before its name was known stays starred once the name turns up. Domains
    /// compare without case, as DNS does.
    func match(domain: String?, address: IPAddress) -> String? {
        if let domain = domain?.lowercased(), hosts.contains(domain) {
            return domain
        }
        let ip = address.description
        return hosts.contains(ip) ? ip : nil
    }

    mutating func set(_ isFavorite: Bool, domain: String?, address: IPAddress) {
        if isFavorite {
            guard match(domain: domain, address: address) == nil else { return }
            hosts.insert(domain?.lowercased() ?? address.description)
        } else {
            // Either name may be the starred one.
            hosts.remove(address.description)
            if let domain {
                hosts.remove(domain.lowercased())
            }
        }
    }
}

// MARK: Notifications

/// Hands out each connection once, for the notifications about new ones.
struct NewFlows {
    /// How old a connection is before it's handed out: time for its TLS server name to
    /// arrive, so a favorite starred by domain is known on its first connection even when
    /// DNS travels encrypted.
    static let settle: TimeInterval = 2
    private var handedOut: Set<FlowKey> = []

    mutating func take(_ flows: [Flow], now: Date) -> [Flow] {
        // Only what's still in the table: an evicted connection that comes back on the
        // same ports is a new one, as in the table, and the set doesn't grow without bound.
        handedOut.formIntersection(flows.map(\.key))
        return flows.filter { now.timeIntervalSince($0.firstSeen) >= Self.settle && handedOut.insert($0.key).inserted }
    }
}

enum TrafficDirection: String, Codable, CaseIterable {
    case download, upload, total

    var label: String {
        switch self {
        case .download: String(localized: "Download")
        case .upload: String(localized: "Upload")
        case .total: String(localized: "Download and upload")
        }
    }

    func bytes(_ counts: TrafficCounts) -> Int {
        switch self {
        case .download: counts.bytesIn
        case .upload: counts.bytesOut
        case .total: counts.bytesIn + counts.bytesOut
        }
    }
}

/// Traffic over a limit for several whole seconds in a row; a one-second spike isn't
/// worth a notification. It goes up once per run, not every second the run lasts, and
/// comes down when a second dips back under.
struct ThresholdAlarm {
    static let seconds = 5
    /// Bytes per second.
    var limit = 0
    var direction = TrafficDirection.total
    private(set) var isRaised = false

    /// True when the alarm goes up. `end` is the last second to count.
    mutating func update(_ history: [Int: TrafficCounts], end: Int) -> Bool {
        let over = (end - Self.seconds + 1 ... end).allSatisfy { direction.bytes(history[$0] ?? TrafficCounts()) > limit }
        defer { isRaised = over }
        return over && !isRaised
    }
}

/// One notification per subject a minute at most, so a storm of connections or traffic
/// hovering at the limit can't bury the user in them.
struct RateLimiter {
    static let interval: TimeInterval = 60
    private var sent: [String: Date] = [:]

    mutating func allow(_ subject: String, at now: Date) -> Bool {
        sent = sent.filter { now.timeIntervalSince($0.value) < Self.interval }
        guard sent[subject] == nil else { return false }
        sent[subject] = now
        return true
    }
}

/// Which events notify; one value in UserDefaults.
struct Alerts: Codable {
    var traffic = false
    /// Megabytes per second, as Settings shows it.
    var trafficLimit = 10.0
    var trafficDirection = TrafficDirection.total
    var blacklist = false
    var favorites = false

    var isAnyOn: Bool { traffic || blacklist || favorites }
}

/// Favorites, the blacklist, and the notifications they and the traffic limit send.
/// App-wide like the traffic store, so notifications keep coming with every window closed.
@MainActor @Observable
final class Watchlist {
    var favorites: Favorites {
        didSet { UserDefaults.standard.set(favorites.hosts.sorted(), forKey: SettingsKey.favorites) }
    }
    /// As the user wrote it, bad lines and all, so they can fix them.
    var blacklistText: String {
        didSet {
            UserDefaults.standard.set(blacklistText, forKey: SettingsKey.blacklist)
            blacklist = Blacklist(blacklistText)
            verdicts = [:]
        }
    }
    private(set) var blacklist: Blacklist
    var alerts: Alerts {
        didSet {
            UserDefaults.standard.set(try? JSONEncoder().encode(alerts), forKey: SettingsKey.alerts)
            // Asked only once one is turned on; macOS prompts the first time only.
            if alerts.isAnyOn, !oldValue.isAnyOn {
                requestAuthorization()
            }
        }
    }
    private(set) var authorization = UNAuthorizationStatus.notDetermined

    @ObservationIgnored private let traffic: TrafficStore
    @ObservationIgnored private var verdicts: [IPAddress: IPRange?] = [:]
    @ObservationIgnored private var newFlows = NewFlows()
    @ObservationIgnored private var alarm = ThresholdAlarm()
    @ObservationIgnored private var limiter = RateLimiter()
    @ObservationIgnored private let presenter = Presenter()

    init(traffic: TrafficStore) {
        self.traffic = traffic
        let defaults = UserDefaults.standard
        favorites = Favorites(hosts: Set(defaults.stringArray(forKey: SettingsKey.favorites) ?? []))
        let text = defaults.string(forKey: SettingsKey.blacklist) ?? ""
        blacklistText = text
        blacklist = Blacklist(text)
        alerts = defaults.data(forKey: SettingsKey.alerts).flatMap { try? JSONDecoder().decode(Alerts.self, from: $0) } ?? Alerts()
        UNUserNotificationCenter.current().delegate = presenter
        Task { await refreshAuthorization() }
        // Lives as long as the app, like the traffic store's snapshots.
        Task {
            while true {
                self.check()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// The entry an address falls in. Cached: the table asks for every row each second.
    func blacklistEntry(for address: IPAddress) -> IPRange? {
        // Read on every call, cache hit or not, so a view that asks redraws when the list
        // changes; and no list, the usual case, costs nothing.
        guard !blacklist.entries.isEmpty else { return nil }
        if let cached = verdicts[address] {
            return cached
        }
        let entry = blacklist.entry(containing: address)
        verdicts[address] = .some(entry)
        return entry
    }

    /// Read again whenever Settings shows, since the user changes it in System Settings.
    func refreshAuthorization() async {
        authorization = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    private func requestAuthorization() {
        Task {
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            await refreshAuthorization()
        }
    }

    private func check() {
        // An open capture file's connections and traffic are history, not news. Nothing is
        // handed out while it's open, so back to live, what's new then still notifies.
        guard traffic.file == nil else { return }
        let now = Date.now
        // Every second, notifications on or off: one turned on later then hears only
        // about connections that are new from then on, not the whole table at once.
        let fresh = newFlows.take(traffic.flows, now: now)
        alarm.limit = Int(alerts.trafficLimit * 1_000_000)
        alarm.direction = alerts.trafficDirection
        // A second before the store's last: the helper sends packets every 250 ms, so the
        // latest second can still be short of its last batch.
        let raised = alarm.update(traffic.seconds, end: traffic.now - 1)
        if alerts.traffic, raised, limiter.allow("traffic", at: now) {
            let limit = "\(bytes(alarm.limit))/s"
            let latest = alarm.direction.bytes(traffic.seconds[traffic.now - 1] ?? TrafficCounts())
            let what = alarm.direction == .total ? String(localized: "Traffic") : alarm.direction.label
            post("traffic", title: String(localized: "\(what) above \(limit)"),
                 body: String(localized: "Above \(limit) for \(ThresholdAlarm.seconds) seconds in a row, at \(bytes(latest))/s in the last one."))
        }
        if alerts.blacklist {
            let hits = fresh.compactMap { flow in blacklistEntry(for: flow.key.remote).map { (flow, $0) } }
                .filter { limiter.allow("blacklist \($0.1)", at: now) }
            // One notification for everything new this second, however many entries it hit.
            if hits.count == 1 {
                let (flow, entry) = hits[0]
                let peer = traffic.domain(of: flow).map { "\(flow.key.remote) (\($0))" } ?? flow.key.remote.description
                let listed = entry.description == flow.key.remote.description
                    ? String(localized: "It's on your blacklist.") : String(localized: "It's in \(entry.description) on your blacklist.")
                post("blacklist", title: String(localized: "Blacklisted address"),
                     body: String(localized: "\(newConnection(flow, with: peer)) \(listed)", comment: "Two sentences: the new connection, then where it is on the blacklist."))
            } else if !hits.isEmpty {
                post("blacklist", title: String(localized: "Blacklisted addresses"), body: String(localized: "New connections with \(list(hits.map { $0.0.key.remote.description })), all on your blacklist."))
            }
        }
        if alerts.favorites {
            let hits = fresh.compactMap { flow in favorites.match(domain: traffic.domain(of: flow), address: flow.key.remote).map { (flow, $0) } }
                .filter { limiter.allow("favorite \($0.1)", at: now) }
            if hits.count == 1 {
                let (flow, host) = hits[0]
                let address = flow.key.remote.description
                post("favorite", title: String(localized: "\(host) is active"), body: newConnection(flow, with: host == address ? host : "\(host) (\(address))"))
            } else if !hits.isEmpty {
                post("favorite", title: String(localized: "Favorite hosts are active"), body: String(localized: "New connections with \(list(hits.map { $0.1 }))."))
            }
        }
    }

    /// The program leads when it's known; it's looked up within a second of the
    /// connection showing up, so by the time it settles it usually is. A whole sentence
    /// either way: a translation can't be built from the front half of one.
    private func newConnection(_ flow: Flow, with peer: String) -> String {
        if let program = traffic.programs[flow.key] ?? nil {
            return String(localized: "\(program.name) has a new connection with \(peer).")
        }
        return String(localized: "New connection with \(peer).")
    }

    private func list(_ names: [String]) -> String {
        let shown = names.count > 3 ? Array(names.prefix(3)) + [String(localized: "\(names.count - 3) more")] : names
        return shown.formatted(.list(type: .and))
    }

    private func post(_ kind: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.threadIdentifier = kind
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }
}

/// macOS shows nothing while the app is frontmost unless its delegate asks; these are
/// worth a banner whichever app is in front.
private final class Presenter: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}
