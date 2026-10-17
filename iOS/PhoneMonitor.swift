import CoreLocation
import Network
import NetworkExtension
import Observation

/// The system's four-level rating of the link (iOS 26). iOS gives apps no Wi-Fi signal
/// strength at all (docs/research/wifi-signal-apis.md), so this is the closest there
/// is, and it is never shown as dBm or called signal strength (spec F4.2).
enum LinkRating {
    /// Before iOS 26.
    case unsupported
    case unknown, minimal, moderate, good
}

/// This iPhone's own connection over Wi-Fi (spec F4.2, F4.3): the link rating, and
/// round trips the app times itself.
@MainActor @Observable
final class PhoneMonitor: NSObject, CLLocationManagerDelegate {
    /// One public anycast address answers from nearby almost everywhere, and a fixed
    /// address keeps DNS out of the timing.
    static let internetHost = IPv4Address("1.1.1.1")!

    private(set) var isOnWiFi = false
    private(set) var rating = LinkRating.unsupported
    private(set) var router: IPv4Address?
    private(set) var routerPings = PingStats()
    private(set) var internetPings = PingStats()
    private(set) var ssid: String?
    private(set) var locationStatus: CLAuthorizationStatus

    /// Pings run only while someone is looking: they cost battery and radio time.
    var isActive = false {
        didSet { if isActive != oldValue { restartPings() } }
    }

    @ObservationIgnored private let pathMonitor = NWPathMonitor(requiredInterfaceType: .wifi)
    @ObservationIgnored private let locationManager = CLLocationManager()
    @ObservationIgnored private var interface: Int?
    @ObservationIgnored private var pingers: [Pinger] = []

    override init() {
        locationStatus = locationManager.authorizationStatus
        super.init()
        #if DEBUG
        if Demo.isOn {
            showDemo()
            return
        }
        #endif
        locationManager.delegate = self
        pathMonitor.pathUpdateHandler = { [weak self] path in
            MainActor.assumeIsolated { self?.pathChanged(path) }
        }
        pathMonitor.start(queue: .main)
    }

    func requestLocation() {
        locationManager.requestWhenInUseAuthorization()
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        MainActor.assumeIsolated {
            locationStatus = locationManager.authorizationStatus
            Task { await refreshName() }
        }
    }

    private func pathChanged(_ path: NWPath) {
        if #available(iOS 26, *) {
            rating = switch path.linkQuality {
            case .good: .good
            case .moderate: .moderate
            case .minimal: .minimal
            default: .unknown
            }
        }
        let isOnWiFi = path.status == .satisfied
        let router = path.gateways.lazy.compactMap { endpoint -> IPv4Address? in
            if case .hostPort(.ipv4(let address), _) = endpoint { address } else { nil }
        }.first
        let interface = path.availableInterfaces.first { $0.type == .wifi }?.index
        // A new network starts the figures afresh: the old router's say nothing about this one.
        if isOnWiFi != self.isOnWiFi || router != self.router || interface != self.interface {
            (self.isOnWiFi, self.router, self.interface) = (isOnWiFi, router, interface)
            restartPings()
            Task { await refreshName() }
        }
    }

    private func restartPings() {
        #if DEBUG
        // The page appearing would otherwise clear the made-up figures.
        if Demo.isOn { return }
        #endif
        for pinger in pingers { pinger.stop() }
        pingers = []
        routerPings = PingStats()
        internetPings = PingStats()
        guard isActive, isOnWiFi, let interface else { return }
        // Bound to the Wi-Fi interface: with Wi-Fi Assist or a network without internet,
        // the default route can be cellular, and this page is about Wi-Fi.
        let index = UInt32(interface)
        if let router {
            pingers.append(Pinger(address: router.inAddr, interface: index) { [weak self] result in
                Task { @MainActor in self?.routerPings.append(result) }
            })
        }
        pingers.append(Pinger(address: Self.internetHost.inAddr, interface: index) { [weak self] result in
            Task { @MainActor in self?.internetPings.append(result) }
        })
        for pinger in pingers { pinger.start() }
    }

    #if DEBUG
    /// A good link with a router a few ms away (Demo).
    private func showDemo() {
        (isOnWiFi, rating, router, ssid, locationStatus) = (true, .good, IPv4Address("192.168.1.1"), "Home", .authorizedWhenInUse)
        routerPings = Demo.pings(until: .now, median: 3.2, spread: 1.1)
        internetPings = Demo.pings(until: .now, median: 14, spread: 3)
    }
    #endif

    private func refreshName() async {
        let name = isOnWiFi ? await Self.currentSSID() : nil
        if name != ssid { ssid = name }
    }

    /// nil without Location authorization or the Access Wi-Fi Information entitlement.
    nonisolated private static func currentSSID() async -> String? {
        await NEHotspotNetwork.fetchCurrent()?.ssid
    }
}

extension IPv4Address {
    var inAddr: in_addr {
        rawValue.withUnsafeBytes { in_addr(s_addr: $0.loadUnaligned(as: UInt32.self)) }
    }
}
