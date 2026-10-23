import Foundation

public struct ProvisioningProfile: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case development
        case adHoc
        case enterprise
        case appStore

        public var displayName: String {
            switch self {
            case .development: return "Development"
            case .adHoc: return "Ad Hoc"
            case .enterprise: return "Enterprise"
            case .appStore: return "App Store"
            }
        }
    }

    /// The profile UUID.
    public var id: String
    public var name: String
    public var teamIdentifier: String?
    public var teamName: String?
    public var applicationIdentifierPrefixes: [String]
    /// The full `application-identifier` entitlement, e.g. `ABCDE12345.com.example.*`.
    public var applicationIdentifier: String
    public var creationDate: Date
    public var expirationDate: Date
    public var platforms: [String]
    public var provisionedDevices: [String]?
    public var provisionsAllDevices: Bool
    public var entitlements: [String: PlistValue]
    /// Uppercase hex SHA-1 fingerprints of the certificates the profile authorises.
    public var developerCertificateSHA1s: [String]

    public init(
        id: String,
        name: String,
        teamIdentifier: String? = nil,
        teamName: String? = nil,
        applicationIdentifierPrefixes: [String] = [],
        applicationIdentifier: String,
        creationDate: Date,
        expirationDate: Date,
        platforms: [String] = [],
        provisionedDevices: [String]? = nil,
        provisionsAllDevices: Bool = false,
        entitlements: [String: PlistValue] = [:],
        developerCertificateSHA1s: [String] = []
    ) {
        self.id = id
        self.name = name
        self.teamIdentifier = teamIdentifier
        self.teamName = teamName
        self.applicationIdentifierPrefixes = applicationIdentifierPrefixes
        self.applicationIdentifier = applicationIdentifier
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.platforms = platforms
        self.provisionedDevices = provisionedDevices
        self.provisionsAllDevices = provisionsAllDevices
        self.entitlements = entitlements
        self.developerCertificateSHA1s = developerCertificateSHA1s
    }

    public var getTaskAllow: Bool {
        entitlements["get-task-allow"]?.boolValue ?? false
    }

    public var kind: Kind {
        if provisionsAllDevices { return .enterprise }
        if provisionedDevices != nil {
            return getTaskAllow ? .development : .adHoc
        }
        return .appStore
    }

    /// The bundle-identifier part of the application identifier, without the team prefix.
    /// `ABCDE12345.com.example.*` becomes `com.example.*`.
    public var bundleIdentifierPattern: String {
        for prefix in applicationIdentifierPrefixes + [teamIdentifier].compactMap({ $0 }) {
            if applicationIdentifier.hasPrefix(prefix + ".") {
                return String(applicationIdentifier.dropFirst(prefix.count + 1))
            }
        }
        if let dot = applicationIdentifier.firstIndex(of: ".") {
            return String(applicationIdentifier[applicationIdentifier.index(after: dot)...])
        }
        return applicationIdentifier
    }

    public func isExpired(at date: Date = Date()) -> Bool {
        expirationDate <= date
    }

    public func hasStarted(at date: Date = Date()) -> Bool {
        creationDate <= date
    }

    /// Whether the profile's application identifier covers `bundleIdentifier`.
    public func allowsBundleIdentifier(_ bundleIdentifier: String) -> Bool {
        let pattern = bundleIdentifierPattern
        if pattern == "*" { return true }
        if pattern.hasSuffix("*") {
            return bundleIdentifier.hasPrefix(String(pattern.dropLast()))
        }
        return pattern == bundleIdentifier
    }

    public var isWildcard: Bool {
        bundleIdentifierPattern.hasSuffix("*")
    }
}
