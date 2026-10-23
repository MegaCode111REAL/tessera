import Foundation

public enum ProfileParserError: Error, LocalizedError, Equatable {
    case notAProfile
    case malformedPlist
    case missingField(String)

    public var errorDescription: String? {
        switch self {
        case .notAProfile: return "The file is not a provisioning profile."
        case .malformedPlist: return "The provisioning profile's property list could not be read."
        case .missingField(let name): return "The provisioning profile is missing “\(name)”."
        }
    }
}

/// Parses `.mobileprovision` files. The profile is a CMS-signed envelope around an XML
/// property list; Tessera reads the plist but does not (yet) verify Apple's CMS signature.
public struct ProfileParser: Sendable {
    public init() {}

    public func parse(_ data: Data) throws -> ProvisioningProfile {
        let plistData = try Self.extractPlist(from: data)
        guard let object = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
              let dict = object as? [String: Any] else {
            throw ProfileParserError.malformedPlist
        }

        guard let uuid = dict["UUID"] as? String else { throw ProfileParserError.missingField("UUID") }
        guard let name = dict["Name"] as? String else { throw ProfileParserError.missingField("Name") }
        guard let expiration = dict["ExpirationDate"] as? Date else { throw ProfileParserError.missingField("ExpirationDate") }
        guard let entitlementsDict = dict["Entitlements"] as? [String: Any] else { throw ProfileParserError.missingField("Entitlements") }

        let entitlements = entitlementsDict.toPlistValues()
        guard let applicationIdentifier = entitlements["application-identifier"]?.stringValue else {
            throw ProfileParserError.missingField("application-identifier")
        }

        let certificates = (dict["DeveloperCertificates"] as? [Data]) ?? []

        return ProvisioningProfile(
            id: uuid,
            name: name,
            teamIdentifier: (dict["TeamIdentifier"] as? [String])?.first,
            teamName: dict["TeamName"] as? String,
            applicationIdentifierPrefixes: (dict["ApplicationIdentifierPrefix"] as? [String]) ?? [],
            applicationIdentifier: applicationIdentifier,
            creationDate: (dict["CreationDate"] as? Date) ?? .distantPast,
            expirationDate: expiration,
            platforms: (dict["Platform"] as? [String]) ?? [],
            provisionedDevices: dict["ProvisionedDevices"] as? [String],
            provisionsAllDevices: (dict["ProvisionsAllDevices"] as? Bool) ?? false,
            entitlements: entitlements,
            developerCertificateSHA1s: certificates.map { Fingerprint.sha1Hex($0) }
        )
    }

    /// Locates the XML plist inside the CMS envelope (or accepts a bare plist).
    static func extractPlist(from data: Data) throws -> Data {
        let start = data.range(of: Data("<?xml".utf8))
        let end = data.range(of: Data("</plist>".utf8), options: .backwards)
        if let start, let end, start.lowerBound < end.upperBound {
            return Data(data[start.lowerBound..<end.upperBound])
        }
        // A bare binary plist is also accepted.
        if data.starts(with: Data("bplist".utf8)) {
            return data
        }
        throw ProfileParserError.notAProfile
    }
}
