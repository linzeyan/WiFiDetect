import CryptoKit
import Foundation
import NIOSSL
import Security
import SystemConfiguration
import Synchronization
import SwiftASN1
import X509

/// The root that signs a certificate for each host the proxy decrypts. Created on
/// this Mac on first use; its private key is a non-extractable key in the login
/// keychain, so it signs without ever being in this process's memory or on disk.
final class CertificateAuthority: Sendable {
    let certificate: Certificate
    let der: [UInt8]
    private let issuerKey: Certificate.PrivateKey
    private let keyIdentifier: ArraySlice<UInt8>
    /// One key for every leaf, made fresh each launch: leaves live only in memory, and
    /// a per-host key would cost a key generation on every new host.
    private let leafKey = P256.Signing.PrivateKey()
    private let chainRoot: NIOSSLCertificate
    private let contexts = Mutex<[String: NIOSSLContext]>([:])

    init(certificate: Certificate, key: Certificate.PrivateKey) throws {
        self.certificate = certificate
        self.der = try certificate.derBytes
        issuerKey = key
        keyIdentifier = SubjectKeyIdentifier(hash: certificate.publicKey).keyIdentifier
        chainRoot = try NIOSSLCertificate(bytes: der, format: .der)
    }

    /// A new root for `key`. Ten years: it's this Mac's own root, and replacing it
    /// means trusting a new one.
    static func makeRoot(key: Certificate.PrivateKey, now: Date = .now) throws -> Certificate {
        let name = try DistinguishedName {
            OrganizationName("WiFiDetect")
            CommonName("WiFiDetect CA (\(SCDynamicStoreCopyComputerName(nil, nil) as String? ?? "this Mac"))")
        }
        return try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: key.publicKey,
            notValidBefore: now.addingTimeInterval(-86_400),
            notValidAfter: now.addingTimeInterval(10 * 365 * 86_400),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                // Path length 0: it signs leaves, never another CA.
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: key.publicKey)
            },
            issuerPrivateKey: key
        )
    }

    /// A server certificate for `host` that Apple's TLS stack accepts (Apple 103769):
    /// SAN, serverAuth EKU, SHA-256, at most 825 days.
    func issue(for host: String, now: Date = .now) throws -> Certificate {
        let name: GeneralName = if let address = IPAddress(host) {
            .ipAddress(ASN1OctetString(contentBytes: address.bytes[...]))
        } else {
            .dnsName(host)
        }
        return try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: now.addingTimeInterval(-86_400),
            notValidAfter: now.addingTimeInterval(365 * 86_400),
            issuer: certificate.subject,
            // Clients match the SAN; the common name is only what a certificate viewer shows.
            subject: try DistinguishedName { CommonName(String(host.prefix(64))) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames([name])
                AuthorityKeyIdentifier(keyIdentifier: keyIdentifier)
            },
            issuerPrivateKey: issuerKey
        )
    }

    /// The TLS context that presents `host`'s certificate to the client, issued on first
    /// use and kept for the rest of the run.
    func serverContext(for host: String) throws -> NIOSSLContext {
        if let context = contexts.withLock({ $0[host] }) {
            return context
        }
        let leaf = try NIOSSLCertificate(bytes: try issue(for: host).derBytes, format: .der)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(leaf), .certificate(chainRoot)],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leafKey.pemRepresentation.utf8), format: .pem))
        )
        // HTTP/2 for clients that offer it (F3.8), so sites don't downgrade through the
        // proxy. WebSockets stay on HTTP/1.1: NIO's settings leave out RFC 8441's
        // extended CONNECT, so browsers open those on a connection of their own.
        configuration.applicationProtocols = ["h2", "http/1.1"]
        let context = try NIOSSLContext(configuration: configuration)
        contexts.withLock { $0[host] = context }
        return context
    }

    /// Whether macOS accepts what this CA signs for TLS, as Safari would check it.
    /// Blocking: call it off the main thread.
    func isTrusted() -> Bool {
        let host = "wifidetect.test"
        guard let leaf = try? SecCertificateCreateWithData(nil, Data(issue(for: host).derBytes) as CFData),
              let root = SecCertificateCreateWithData(nil, Data(der) as CFData) else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates([leaf, root] as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess,
              let trust else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}

extension Certificate {
    var derBytes: [UInt8] {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(self)
            return serializer.serializedBytes
        }
    }
}

extension IPAddress {
    /// Network order.
    var bytes: [UInt8] {
        switch self {
        case .v4(let value): withUnsafeBytes(of: value.bigEndian, Array.init)
        case .v6(let high, let low): withUnsafeBytes(of: high.bigEndian, Array.init) + withUnsafeBytes(of: low.bigEndian, Array.init)
        }
    }
}

struct KeychainError: LocalizedError {
    let message: String
    var errorDescription: String? { message }

    init(_ what: String, _ status: OSStatus) {
        let reason = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
        message = "\(what): \(reason)"
    }
}

/// Where the CA lives: the private key in the login keychain, the certificate (which
/// is public) in Application Support.
enum CertificateStore {
    private static let tag = Data("com.zeyanlin.wifidetect.ca".utf8)
    static let certificateFile = URL.applicationSupportDirectory.appending(path: "WiFiDetect/ca.cer")

    /// The CA made earlier, or nil if there is none or its two halves don't match.
    static func load() throws -> CertificateAuthority? {
        guard let key = try privateKey(), let data = try? Data(contentsOf: certificateFile) else { return nil }
        let certificate = try Certificate(derEncoded: Array(data))
        let signer = try Certificate.PrivateKey(key)
        guard certificate.publicKey == signer.publicKey else { return nil }
        return try CertificateAuthority(certificate: certificate, key: signer)
    }

    static func create() throws -> CertificateAuthority {
        try remove(includingTrust: false)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrLabel as String: "WiFiDetect CA",
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrIsExtractable as String: false,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let signer = try Certificate.PrivateKey(key)
        let authority = try CertificateAuthority(certificate: try CertificateAuthority.makeRoot(key: signer), key: signer)
        try FileManager.default.createDirectory(at: certificateFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(authority.der).write(to: certificateFile, options: .atomic)
        return authority
    }

    /// Adds the certificate to the login keychain and marks it trusted for TLS.
    /// macOS asks for the user's password; this blocks until they answer.
    static func trust(_ authority: CertificateAuthority) throws {
        let certificate = try secCertificate(authority)
        let added = SecItemAdd([kSecClass: kSecClassCertificate, kSecValueRef: certificate] as CFDictionary, nil)
        guard added == errSecSuccess || added == errSecDuplicateItem else {
            throw KeychainError(String(localized: "Couldn't add the certificate to the keychain"), added)
        }
        // For TLS servers only: the CA can't vouch for code, mail or anything else.
        let settings: [[String: Any]] = [[
            kSecTrustSettingsPolicy as String: SecPolicyCreateSSL(true, nil),
            kSecTrustSettingsResult as String: SecTrustSettingsResult.trustRoot.rawValue,
        ]]
        let status = SecTrustSettingsSetTrustSettings(certificate, .user, settings as CFArray)
        guard status == errSecSuccess else { throw KeychainError(String(localized: "Couldn't trust the certificate"), status) }
    }

    /// Deletes the trust setting, the keychain items and the file. Trust settings
    /// also ask for the password, so this blocks like `trust`.
    static func remove(includingTrust: Bool = true) throws {
        if includingTrust, let data = try? Data(contentsOf: certificateFile),
           let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            let status = SecTrustSettingsRemoveTrustSettings(certificate, .user)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError(String(localized: "Couldn't remove the trust setting"), status)
            }
            SecItemDelete([kSecClass: kSecClassCertificate, kSecMatchItemList: [certificate]] as CFDictionary)
        }
        let deleted = SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag] as CFDictionary)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
            throw KeychainError(String(localized: "Couldn't delete the private key"), deleted)
        }
        try? FileManager.default.removeItem(at: certificateFile)
    }

    private static func privateKey() throws -> SecKey? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecReturnRef: true,
        ] as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let item else { throw KeychainError(String(localized: "Couldn't read the private key"), status) }
        return (item as! SecKey)
    }

    private static func secCertificate(_ authority: CertificateAuthority) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, Data(authority.der) as CFData) else {
            throw KeychainError(String(localized: "The CA certificate is malformed"), errSecDecode)
        }
        return certificate
    }
}
