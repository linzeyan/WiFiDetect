import Foundation
import NetworkExtension

// One process for both providers. Network Extension starts it once a configuration
// that uses it is on: the content filter, or the transparent proxy while capturing.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

let listener = NSXPCListener(machServiceName: ExtensionConstants.machServiceName)
listener.delegate = appLink
listener.resume()
log.notice("extension listening on \(ExtensionConstants.machServiceName, privacy: .public)")
dispatchMain()
