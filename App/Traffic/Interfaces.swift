import Darwin
import SystemConfiguration

struct CaptureInterface: Hashable, Identifiable {
    let name: String
    let label: String

    var id: String { name }
}

/// Interfaces that are up and have an address: the only ones with traffic to see.
func captureInterfaces() -> [CaptureInterface] {
    let names = Set(interfaceAddresses().filter { $0.isUp }.map(\.name))
    // "Wi-Fi (en0)" reads better than "en0"; utun and the like have no display name.
    let displayNames = (SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []).reduce(into: [String: String]()) { names, interface in
        if let bsd = SCNetworkInterfaceGetBSDName(interface) as String?, let display = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String? {
            names[bsd] = display
        }
    }
    return names.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.map { name in
        CaptureInterface(name: name, label: displayNames[name].map { "\($0) (\(name))" } ?? (name == "lo0" ? "Loopback (lo0)" : name))
    }
}

/// The interface carrying the default route, usually en0.
func primaryInterface() -> String? {
    let global = SCDynamicStoreCopyValue(nil, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
    return global?["PrimaryInterface"] as? String
}

/// Every address on this Mac, IPv6 temporary and link-local ones included: any of
/// them can be the source of an outbound packet.
func localAddresses() -> Set<IPAddress> {
    Set(interfaceAddresses().compactMap(\.address))
}

private func interfaceAddresses() -> [(name: String, isUp: Bool, address: IPAddress?)] {
    var head: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&head) == 0 else { return [] }
    defer { freeifaddrs(head) }
    return sequence(first: head, next: { $0?.pointee.ifa_next }).compactMap { pointer in
        guard let entry = pointer?.pointee, let sockaddr = entry.ifa_addr else { return nil }
        let address: IPAddress? = switch Int32(sockaddr.pointee.sa_family) {
        case AF_INET:
            sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin_addr) { IPAddress(v4Bytes: $0) } }
        case AF_INET6:
            sockaddr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin6_addr) { IPAddress(v6Bytes: $0) } }
        default:
            nil
        }
        guard let address else { return nil }
        return (String(cString: entry.ifa_name), entry.ifa_flags & UInt32(IFF_UP) != 0, address)
    }
}
