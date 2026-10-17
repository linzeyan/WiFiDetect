import Security
import Testing
@testable import WiFiDetect

/// A wrong requirement string fails silently at runtime: XPC just invalidates the
/// connection, which looks exactly like "the helper is not running".
struct CodeSigningRequirementTests {
    @Test(arguments: [HelperConstants.appRequirement, HelperConstants.helperRequirement, ExtensionConstants.extensionRequirement])
    func requirementCompiles(_ text: String) {
        var requirement: SecRequirement?
        #expect(SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess)
    }

    /// The test host is the app itself, signed the way `make build` signs it. If this
    /// fails, the helper would reject our own app — wrong team ID or identifier.
    @Test func appRequirementAcceptsTheSignedApp() throws {
        var requirement: SecRequirement?
        try #require(SecRequirementCreateWithString(HelperConstants.appRequirement as CFString, [], &requirement) == errSecSuccess)
        var code: SecCode?
        try #require(SecCodeCopySelf([], &code) == errSecSuccess)
        #expect(SecCodeCheckValidity(code!, [], requirement) == errSecSuccess)
    }
}
