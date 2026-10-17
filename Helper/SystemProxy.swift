import Foundation
import SystemConfiguration

struct ProxyError: Error {
    let message: String
}

/// Points the HTTP and HTTPS proxy of every enabled network service at the app's
/// proxy, and puts back what was there. The originals go to a root-only file first,
/// so the restore can happen in a later process: after the app is killed, after this
/// helper crashes, after a restart. While the file exists launchd keeps the helper
/// running (KeepAlive PathState in its plist), and a helper that starts and finds it
/// restores at once.
enum SystemProxy {
    static let backup = URL(filePath: "/Library/Application Support/WiFiDetect/proxy-backup.plist")
    /// Local names never go through the proxy, on top of what the user already excluded
    /// and what the app asks for.
    private static let localExceptions = ["*.local", "169.254/16", "127.0.0.1", "localhost"]

    static var isEnabled: Bool { FileManager.default.fileExists(atPath: backup.path) }

    static func enable(port: Int, bypass: [String]) throws(ProxyError) {
        try edit { prefs throws(ProxyError) in
            let services = proxyProtocols(prefs)
            // The first enable saves the originals; enabling again (say, on another
            // port) keeps them, or this proxy would be saved as the user's setting.
            var originals = try readBackup() ?? [:]
            for (id, proxies) in services where originals[id] == nil {
                originals[id] = SCNetworkProtocolGetConfiguration(proxies) as? [String: Any] ?? [:]
            }
            try writeBackup(originals)
            for (id, proxies) in services {
                var config = originals[id] ?? [:]
                let excluded = config[kSCPropNetProxiesExceptionsList as String] as? [String] ?? []
                config[kSCPropNetProxiesHTTPEnable as String] = 1
                config[kSCPropNetProxiesHTTPProxy as String] = "127.0.0.1"
                config[kSCPropNetProxiesHTTPPort as String] = port
                config[kSCPropNetProxiesHTTPSEnable as String] = 1
                config[kSCPropNetProxiesHTTPSProxy as String] = "127.0.0.1"
                config[kSCPropNetProxiesHTTPSPort as String] = port
                config[kSCPropNetProxiesExceptionsList as String] = Array(Set(excluded + localExceptions + bypass)).sorted()
                // A PAC file or auto-discovery would take precedence over the manual proxy.
                config[kSCPropNetProxiesProxyAutoConfigEnable as String] = 0
                config[kSCPropNetProxiesProxyAutoDiscoveryEnable as String] = 0
                guard SCNetworkProtocolSetConfiguration(proxies, config as CFDictionary) else {
                    throw ProxyError(message: "Couldn't set the proxy of network service \(id): \(lastError())")
                }
            }
        }
    }

    static func restore() throws(ProxyError) {
        guard let originals = try readBackup() else { return }
        try edit { prefs throws(ProxyError) in
            for (id, config) in originals {
                // A service deleted since has nothing left to restore.
                guard let service = SCNetworkServiceCopy(prefs, id as CFString),
                      let proxies = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else { continue }
                guard SCNetworkProtocolSetConfiguration(proxies, config as CFDictionary) else {
                    throw ProxyError(message: "Couldn't restore the proxy of network service \(id): \(lastError())")
                }
            }
        }
        // Only once the originals are applied: until then a later attempt still has them.
        do {
            try FileManager.default.removeItem(at: backup)
        } catch {
            throw ProxyError(message: "Couldn't remove \(backup.path): \(error.localizedDescription)")
        }
    }

    /// Under the system-wide preferences lock, then committed and applied.
    private static func edit(_ change: (SCPreferences) throws(ProxyError) -> Void) throws(ProxyError) {
        guard let prefs = SCPreferencesCreate(nil, "wifidetect-helper" as CFString, nil), SCPreferencesLock(prefs, true) else {
            throw ProxyError(message: "Couldn't open the network settings: \(lastError())")
        }
        defer { SCPreferencesUnlock(prefs) }
        try change(prefs)
        guard SCPreferencesCommitChanges(prefs), SCPreferencesApplyChanges(prefs) else {
            throw ProxyError(message: "Couldn't save the network settings: \(lastError())")
        }
    }

    /// The Proxies protocol of every enabled service in the current location.
    private static func proxyProtocols(_ prefs: SCPreferences) -> [(String, SCNetworkProtocol)] {
        guard let set = SCNetworkSetCopyCurrent(prefs), let services = SCNetworkSetCopyServices(set) as? [SCNetworkService] else { return [] }
        return services.compactMap { service in
            guard SCNetworkServiceGetEnabled(service), let id = SCNetworkServiceGetServiceID(service),
                  let proxies = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else { return nil }
            return (id as String, proxies)
        }
    }

    private static func readBackup() throws(ProxyError) -> [String: [String: Any]]? {
        guard let data = try? Data(contentsOf: backup) else { return nil }
        guard let originals = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: [String: Any]] else {
            throw ProxyError(message: "\(backup.path) is unreadable; restore the proxy settings in System Settings › Network.")
        }
        return originals
    }

    private static func writeBackup(_ originals: [String: [String: Any]]) throws(ProxyError) {
        do {
            let folder = backup.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try PropertyListSerialization.data(fromPropertyList: originals, format: .binary, options: 0)
            try data.write(to: backup, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
        } catch {
            throw ProxyError(message: "Couldn't save the current proxy settings: \(error.localizedDescription)")
        }
    }

    private static func lastError() -> String {
        String(cString: SCErrorString(SCError()))
    }
}
