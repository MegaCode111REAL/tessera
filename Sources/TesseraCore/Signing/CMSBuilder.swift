import Foundation
import Security

/// A key that can produce RSA PKCS#1 v1.5 / SHA-256 signatures, plus its certificate.
/// Private key material never leaves the implementation.
public protocol CMSSigningKey: Sendable {
    /// DER encoding of the signing certificate.
    var certificateDER: Data { get }
    /// Length in bytes of a signature (the RSA modulus size).
    var signatureLength: Int { get }
    /// Signs `message` (the implementation hashes it with SHA-256).
    func sign(_ message: Data) throws -> Data
}

/// A `CMSSigningKey` backed by a `SecKey` (a Keychain identity, or an in-memory key).
public struct SecKeySigningKey: CMSSigningKey, @unchecked Sendable {
    private let privateKey: SecKey
    public let certificateDER: Data

    public init(privateKey: SecKey, certificateDER: Data) throws {
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, .rsaSignatureMessagePKCS1v15SHA256) else {
            throw CodeSigningError.key("Only RSA signing keys are supported.")
        }
        self.privateKey = privateKey
        self.certificateDER = certificateDER
    }

    public init(identity: SecIdentity) throws {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            throw CodeSigningError.key("The certificate could not be read from the Keychain.")
        }
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else {
            throw CodeSigningError.key("The private key for this certificate is not available.")
        }
        try self.init(privateKey: key, certificateDER: SecCertificateCopyData(certificate) as Data)
    }

    public var signatureLength: Int { SecKeyGetBlockSize(privateKey) }

    public func sign(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, &error
        ) as Data? else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw CodeSigningError.key("Signing failed: \(reason)")
        }
        return signature
    }
}

/// Builds the detached CMS (PKCS#7) signature that goes in code-signature slot 0x10000.
///
/// The signed attributes follow what Apple's tools produce: content type, signing time,
/// the `cdhashes` plist, the SHA-256 hash-agility attribute, and the message digest of the
/// primary CodeDirectory.
public enum CMSBuilder {
    private static let oidSignedData = "1.2.840.113549.1.7.2"
    private static let oidData = "1.2.840.113549.1.7.1"
    private static let oidContentType = "1.2.840.113549.1.9.3"
    private static let oidMessageDigest = "1.2.840.113549.1.9.4"
    private static let oidSigningTime = "1.2.840.113549.1.9.5"
    private static let oidSHA256 = "2.16.840.1.101.3.4.2.1"
    private static let oidRSAEncryption = "1.2.840.113549.1.1.1"
    private static let oidAppleCDHashesPlist = "1.2.840.113635.100.9.1"
    private static let oidAppleCDHashesV2 = "1.2.840.113635.100.9.2"

    /// Size of the CMS blob for `key`, measured by building one with placeholder data.
    static func estimatedSize(for key: CMSSigningKey) -> Int {
        let dummy = Data(count: 256)
        return (try? build(primaryDirectory: dummy, alternateDirectory: dummy, key: key, signingTime: Date(), dummySignature: true).count)
            ?? 8192
    }

    public static func build(
        primaryDirectory: Data,
        alternateDirectory: Data?,
        key: CMSSigningKey,
        signingTime: Date,
        dummySignature: Bool = false
    ) throws -> Data {
        guard let ids = DERReader.issuerAndSerial(ofCertificate: key.certificateDER) else {
            throw CodeSigningError.key("The signing certificate could not be parsed.")
        }

        // cdhashes: the first 20 bytes of the hash of each CodeDirectory.
        var cdHashes = [HashKind.sha1.hash(primaryDirectory)]
        if let alternateDirectory { cdHashes.append(Data(HashKind.sha256.hash(alternateDirectory).prefix(20))) }
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["cdhashes": cdHashes] as [String: Any],
            format: .xml,
            options: 0
        )

        func attribute(_ oid: String, _ values: [Data]) -> Data {
            DER.sequence([DER.oid(oid), DER.set(values)])
        }

        var attributes: [Data] = [
            attribute(oidContentType, [DER.oid(oidData)]),
            attribute(oidSigningTime, [DER.utcTime(signingTime)]),
            attribute(oidAppleCDHashesPlist, [DER.octetString(plist)]),
            attribute(oidMessageDigest, [DER.octetString(HashKind.sha256.hash(primaryDirectory))]),
        ]
        if let alternateDirectory {
            attributes.append(attribute(oidAppleCDHashesV2, [
                DER.sequence([DER.oid(oidSHA256), DER.octetString(HashKind.sha256.hash(alternateDirectory))]),
            ]))
        }
        let sortedAttributes = attributes.sorted { $0.lexicographicallyPrecedes($1) }
        let attributeBytes = DER.concat(sortedAttributes)

        // The signature covers the attributes encoded as a SET (tag 0x31), not the [0] form used in the structure.
        let signature: Data
        if dummySignature {
            signature = Data(count: key.signatureLength)
        } else {
            signature = try key.sign(DER.tlv(0x31, attributeBytes))
        }

        let sha256Identifier = DER.sequence([DER.oid(oidSHA256), DER.null()])
        let signerInfo = DER.sequence([
            DER.integer(1),
            DER.sequence([ids.issuer, ids.serial]),
            sha256Identifier,
            DER.tlv(0xA0, attributeBytes),
            DER.sequence([DER.oid(oidRSAEncryption), DER.null()]),
            DER.octetString(signature),
        ])

        let signedData = DER.sequence([
            DER.integer(1),
            DER.set([sha256Identifier]),
            DER.sequence([DER.oid(oidData)]),
            DER.tlv(0xA0, key.certificateDER),
            DER.set([signerInfo]),
        ])
        return DER.sequence([DER.oid(oidSignedData), DER.contextConstructed(0, signedData)])
    }
}
