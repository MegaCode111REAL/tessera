import Foundation

/// Public metadata about an imported signing identity (certificate + private key).
/// The private key itself never leaves the Keychain and is never part of this model.
public struct SigningIdentityInfo: Codable, Hashable, Sendable, Identifiable {
    /// Uppercase hex SHA-1 fingerprint of the certificate.
    public var id: String
    public var commonName: String
    public var organization: String?
    /// Team identifier, taken from the certificate subject's organizational unit.
    public var teamIdentifier: String?
    public var notBefore: Date
    public var notAfter: Date
    public var hasPrivateKey: Bool

    public init(
        id: String,
        commonName: String,
        organization: String? = nil,
        teamIdentifier: String? = nil,
        notBefore: Date,
        notAfter: Date,
        hasPrivateKey: Bool
    ) {
        self.id = id
        self.commonName = commonName
        self.organization = organization
        self.teamIdentifier = teamIdentifier
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.hasPrivateKey = hasPrivateKey
    }

    public func isExpired(at date: Date = Date()) -> Bool { notAfter <= date }
    public func isValid(at date: Date = Date()) -> Bool { notBefore <= date && date < notAfter }

    public var displayName: String {
        commonName.isEmpty ? id : commonName
    }
}
