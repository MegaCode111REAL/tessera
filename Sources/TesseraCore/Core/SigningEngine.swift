import Foundation

public struct SigningStep: Codable, Hashable, Sendable, Identifiable {
    public var id: String { relativePath }
    /// Path relative to the `.app` directory. The main app itself uses an empty string.
    public var relativePath: String
    public var kind: NestedBundle.Kind?
    public var isMainApp: Bool
    public var bundleIdentifier: String?

    public init(relativePath: String, kind: NestedBundle.Kind?, isMainApp: Bool, bundleIdentifier: String?) {
        self.relativePath = relativePath
        self.kind = kind
        self.isMainApp = isMainApp
        self.bundleIdentifier = bundleIdentifier
    }

    public var displayName: String {
        isMainApp ? "Main app" : relativePath
    }
}

public struct SigningPlan: Codable, Hashable, Sendable {
    /// Components in the order they must be signed: nested code first, main app last.
    public var steps: [SigningStep]
    public var originalBundleIdentifier: String
    public var targetBundleIdentifier: String
}

public enum SigningPlanner {
    /// Orders signing so every component is signed after the code nested inside it.
    public static func makePlan(
        metadata: AppMetadata,
        targetBundleIdentifier: String? = nil
    ) -> SigningPlan {
        let target = targetBundleIdentifier ?? metadata.bundleIdentifier

        func rank(_ kind: NestedBundle.Kind) -> Int {
            switch kind {
            case .dynamicLibrary: return 0
            case .framework: return 1
            case .other: return 2
            case .appExtension: return 3
            case .watchApp: return 4
            }
        }

        let nested = metadata.nestedBundles.sorted { lhs, rhs in
            if lhs.depth != rhs.depth { return lhs.depth > rhs.depth }
            if rank(lhs.kind) != rank(rhs.kind) { return rank(lhs.kind) < rank(rhs.kind) }
            return lhs.relativePath < rhs.relativePath
        }

        var steps = nested.map { bundle -> SigningStep in
            SigningStep(
                relativePath: bundle.relativePath,
                kind: bundle.kind,
                isMainApp: false,
                bundleIdentifier: rewrittenBundleIdentifier(
                    bundle.bundleIdentifier,
                    original: metadata.bundleIdentifier,
                    target: target
                )
            )
        }
        steps.append(SigningStep(relativePath: "", kind: nil, isMainApp: true, bundleIdentifier: target))

        return SigningPlan(
            steps: steps,
            originalBundleIdentifier: metadata.bundleIdentifier,
            targetBundleIdentifier: target
        )
    }

    /// Nested bundle identifiers that extend the app's identifier follow it when the app is renamed.
    static func rewrittenBundleIdentifier(_ nested: String?, original: String, target: String) -> String? {
        guard let nested else { return nil }
        guard original != target, nested.hasPrefix(original + ".") else { return nested }
        return target + nested.dropFirst(original.count)
    }
}

public enum SigningCapability: Equatable, Sendable {
    case available
    case unavailable(reason: String)

    public var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

public enum SigningError: Error, LocalizedError, Equatable {
    case unsupported(String)
    case identityUnavailable
    case verificationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .unsupported(let reason): return reason
        case .identityUnavailable: return "The selected signing identity could not be loaded from the Keychain."
        case .verificationFailed(let message): return "Signature verification failed: \(message)"
        }
    }
}

public struct SigningRequest: Sendable {
    public var appBundle: URL
    public var plan: SigningPlan
    /// `nil` requests an ad-hoc signature: no certificate, no profile, entitlements kept as they are.
    public var identityID: String?
    public var profile: ProvisioningProfile?
    public var profileData: Data?

    public var isAdHoc: Bool { identityID == nil }

    public init(appBundle: URL, plan: SigningPlan, identityID: String?, profile: ProvisioningProfile?, profileData: Data?) {
        self.appBundle = appBundle
        self.plan = plan
        self.identityID = identityID
        self.profile = profile
        self.profileData = profileData
    }
}

/// A code-signing implementation. `BundleSigner` is the real one; `UnavailableSigningEngine`
/// remains for builds that must not sign.
public protocol SigningEngine: Sendable {
    var capability: SigningCapability { get }

    /// Signs the components listed in `request.plan`, nested code first, modifying the bundle in place.
    func sign(_ request: SigningRequest, onStep: @Sendable (SigningStep) -> Void) async throws

    /// Independently verifies the signatures of a signed bundle and returns any problems found.
    func verify(appBundle: URL, plan: SigningPlan, profile: ProvisioningProfile?) async throws -> [ValidationIssue]
}

/// Honest placeholder: reports signing as unsupported instead of producing a misleading output.
public struct UnavailableSigningEngine: SigningEngine {
    public static let defaultReason =
        "On-device code signing has not been verified yet. Tessera will not create a signed IPA until a signing "
        + "implementation has been proven end-to-end on a real device, so it cannot produce one that might not install."

    public let reason: String

    public init(reason: String = UnavailableSigningEngine.defaultReason) {
        self.reason = reason
    }

    public var capability: SigningCapability { .unavailable(reason: reason) }

    public func sign(_ request: SigningRequest, onStep: @Sendable (SigningStep) -> Void) async throws {
        throw SigningError.unsupported(reason)
    }

    public func verify(appBundle: URL, plan: SigningPlan, profile: ProvisioningProfile?) async throws -> [ValidationIssue] {
        throw SigningError.unsupported(reason)
    }
}
