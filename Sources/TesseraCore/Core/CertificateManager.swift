import Foundation
import Security

public enum CertificateError: Error, LocalizedError, Equatable {
    case wrongPassword
    case invalidP12
    case noIdentityInFile
    case unreadableCertificate
    case keychain(OSStatus)
    case notFound

    public var errorDescription: String? {
        switch self {
        case .wrongPassword:
            return "The .p12 password is incorrect. This is the password you chose when exporting the certificate, not your Apple Account password."
        case .invalidP12: return "The file is not a valid .p12 certificate bundle."
        case .noIdentityInFile: return "The .p12 file does not contain a certificate with a private key."
        case .unreadableCertificate: return "The certificate could not be read."
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error"
            return "\(message) (\(status))"
        case .notFound: return "The signing identity was not found."
        }
    }
}

/// Imports and manages signing identities. Private keys stay in the Keychain
/// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and are never copied to disk or logged.
public struct CertificateManager: Sendable {
    public init() {}

    /// Builds public identity metadata from a DER certificate. Pure, and testable without a Keychain.
    public static func summarize(certificateDER: Data, hasPrivateKey: Bool) -> SigningIdentityInfo? {
        guard let summary = X509Parser.parse(der: certificateDER) else { return nil }
        return SigningIdentityInfo(
            id: Fingerprint.sha1Hex(certificateDER),
            commonName: summary.commonName ?? "",
            organization: summary.organization,
            teamIdentifier: summary.organizationalUnit,
            notBefore: summary.notBefore,
            notAfter: summary.notAfter,
            hasPrivateKey: hasPrivateKey
        )
    }

    /// Whether `profile` authorises the certificate behind `identity`.
    public static func profile(_ profile: ProvisioningProfile, authorizes identity: SigningIdentityInfo) -> Bool {
        profile.developerCertificateSHA1s.contains(identity.id.uppercased())
    }

    // MARK: - Keychain-backed operations

    /// Imports a `.p12` file, stores the identity in the Keychain, and returns its metadata.
    public func importP12(_ data: Data, password: String) throws -> SigningIdentityInfo {
        var items: CFArray?
        let options: [String: Any] = [kSecImportExportPassphrase as String: password]
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        switch status {
        case errSecSuccess: break
        case errSecAuthFailed: throw CertificateError.wrongPassword
        case errSecDecode: throw CertificateError.invalidP12
        default: throw CertificateError.keychain(status)
        }

        guard let entries = items as? [[String: Any]],
              let first = entries.first,
              let identityRef = first[kSecImportItemIdentity as String] else {
            throw CertificateError.noIdentityInFile
        }
        let identity = identityRef as! SecIdentity

        let attributes: [String: Any] = [
            kSecValueRef as String: identity,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw CertificateError.keychain(addStatus)
        }

        guard let info = Self.describe(identity) else { throw CertificateError.unreadableCertificate }
        return info
    }

    public func listIdentities() -> [SigningIdentityInfo] {
        allIdentities()
            .compactMap { Self.describe($0) }
            .sorted { $0.notAfter > $1.notAfter }
    }

    /// Returns the Keychain identity for signing. `SecIdentity` is not `Sendable`, so callers
    /// should use it immediately and not store it.
    public func identity(withID id: String) -> SecIdentity? {
        allIdentities().first { Self.describe($0)?.id == id.uppercased() }
    }

    public func delete(identityID id: String) throws {
        guard let identity = identity(withID: id) else { throw CertificateError.notFound }

        var targets: [CFTypeRef] = [identity]
        var key: SecKey?
        if SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key { targets.append(key) }
        var certificate: SecCertificate?
        if SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate { targets.append(certificate) }

        for target in targets {
            let status = SecItemDelete([kSecValueRef as String: target] as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw CertificateError.keychain(status)
            }
        }
    }

    // MARK: - Helpers

    private func allIdentities() -> [SecIdentity] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return [] }
        if let array = result as? [SecIdentity] { return array }
        if let single = result, CFGetTypeID(single) == SecIdentityGetTypeID() {
            return [single as! SecIdentity]
        }
        return []
    }

    private static func describe(_ identity: SecIdentity) -> SigningIdentityInfo? {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
        var key: SecKey?
        let hasKey = SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess && key != nil
        return summarize(certificateDER: SecCertificateCopyData(certificate) as Data, hasPrivateKey: hasKey)
    }
}
