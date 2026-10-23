import Foundation

public struct NestedBundle: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case appExtension
        case framework
        case watchApp
        case dynamicLibrary
        case other

        public var displayName: String {
            switch self {
            case .appExtension: return "App Extension"
            case .framework: return "Framework"
            case .watchApp: return "Watch App"
            case .dynamicLibrary: return "Dynamic Library"
            case .other: return "Other"
            }
        }
    }

    public var id: String { relativePath }
    /// Path relative to the `.app` directory, e.g. `Frameworks/Foo.framework`.
    public var relativePath: String
    public var kind: Kind
    public var bundleIdentifier: String?
    public var executableName: String?
    public var hasCodeSignature: Bool

    public init(
        relativePath: String,
        kind: Kind,
        bundleIdentifier: String? = nil,
        executableName: String? = nil,
        hasCodeSignature: Bool = false
    ) {
        self.relativePath = relativePath
        self.kind = kind
        self.bundleIdentifier = bundleIdentifier
        self.executableName = executableName
        self.hasCodeSignature = hasCodeSignature
    }

    /// Number of path components below the app bundle. Used to sign deepest components first.
    public var depth: Int {
        relativePath.split(separator: "/").count
    }
}

public struct AppMetadata: Codable, Hashable, Sendable {
    public var bundleIdentifier: String
    public var displayName: String
    public var shortVersion: String
    public var buildVersion: String
    public var minimumOSVersion: String?
    public var supportedPlatforms: [String]
    public var deviceFamilies: [Int]
    public var executableName: String?
    /// Architectures detected in the main executable, e.g. `["arm64"]`.
    public var architectures: [String]
    /// True when the main executable still carries FairPlay encryption (cannot be re-signed).
    public var isEncrypted: Bool
    public var hasCodeSignature: Bool
    public var hasEmbeddedProfile: Bool
    /// Name of the `.app` folder inside `Payload/`.
    public var appFolderName: String
    public var nestedBundles: [NestedBundle]
    /// Entitlements read from the existing code signature, if one is present.
    public var existingEntitlements: [String: PlistValue]
    public var embeddedProfile: ProvisioningProfile?
    /// Sum of uncompressed entry sizes in the archive.
    public var uncompressedSize: UInt64
    /// Relative path (inside the `.app`) of a loose icon image, if one was found.
    public var iconRelativePath: String?

    public init(
        bundleIdentifier: String,
        displayName: String,
        shortVersion: String,
        buildVersion: String,
        minimumOSVersion: String? = nil,
        supportedPlatforms: [String] = [],
        deviceFamilies: [Int] = [],
        executableName: String? = nil,
        architectures: [String] = [],
        isEncrypted: Bool = false,
        hasCodeSignature: Bool = false,
        hasEmbeddedProfile: Bool = false,
        appFolderName: String,
        nestedBundles: [NestedBundle] = [],
        existingEntitlements: [String: PlistValue] = [:],
        embeddedProfile: ProvisioningProfile? = nil,
        uncompressedSize: UInt64 = 0,
        iconRelativePath: String? = nil
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
        self.shortVersion = shortVersion
        self.buildVersion = buildVersion
        self.minimumOSVersion = minimumOSVersion
        self.supportedPlatforms = supportedPlatforms
        self.deviceFamilies = deviceFamilies
        self.executableName = executableName
        self.architectures = architectures
        self.isEncrypted = isEncrypted
        self.hasCodeSignature = hasCodeSignature
        self.hasEmbeddedProfile = hasEmbeddedProfile
        self.appFolderName = appFolderName
        self.nestedBundles = nestedBundles
        self.existingEntitlements = existingEntitlements
        self.embeddedProfile = embeddedProfile
        self.uncompressedSize = uncompressedSize
        self.iconRelativePath = iconRelativePath
    }

    public var extensions: [NestedBundle] { nestedBundles.filter { $0.kind == .appExtension } }
    public var frameworks: [NestedBundle] { nestedBundles.filter { $0.kind == .framework } }
    public var watchApps: [NestedBundle] { nestedBundles.filter { $0.kind == .watchApp } }

    public var versionDescription: String {
        buildVersion.isEmpty || buildVersion == shortVersion
            ? shortVersion
            : "\(shortVersion) (\(buildVersion))"
    }
}
