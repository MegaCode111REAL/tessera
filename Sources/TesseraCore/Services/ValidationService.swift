import Foundation

/// Pure validation rules for imported builds and signing jobs. Nothing here touches disk or the Keychain.
public struct ValidationService: Sendable {
    public var now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// Entitlements that the signer sets itself and that never need to appear in the profile check.
    private static let signerManagedEntitlements: Set<String> = [
        "application-identifier",
        "com.apple.developer.team-identifier",
        "get-task-allow",
        "keychain-access-groups",
        "beta-reports-active",
    ]

    // MARK: - Import-time checks

    /// Findings available as soon as an archive has been inspected.
    public func inspectionIssues(for metadata: AppMetadata) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if metadata.isEncrypted {
            issues.append(.init(
                code: "ENCRYPTED_BINARY", severity: .error,
                message: "The main executable is encrypted (an App Store build), and encrypted binaries cannot be re-signed."
            ))
        }
        if metadata.executableName == nil {
            issues.append(.init(code: "NO_EXECUTABLE", severity: .error, message: "Info.plist does not name an executable."))
        } else if metadata.architectures.isEmpty {
            issues.append(.init(code: "NO_ARCHITECTURE", severity: .warning, message: "The main executable could not be read as a Mach-O binary."))
        }
        if metadata.supportedPlatforms.contains(where: { $0.lowercased().contains("simulator") }) {
            issues.append(.init(code: "SIMULATOR_BUILD", severity: .error, message: "This is a simulator build and cannot run on a device."))
        } else if !metadata.architectures.isEmpty, !metadata.architectures.contains(where: { $0.hasPrefix("arm64") }) {
            issues.append(.init(code: "NO_ARM64", severity: .error, message: "No arm64 slice was found (found: \(metadata.architectures.joined(separator: ", ")))."))
        }

        if !metadata.hasCodeSignature {
            issues.append(.init(code: "UNSIGNED", severity: .info, message: "The main executable has no code signature."))
        }
        if let profile = metadata.embeddedProfile, profile.isExpired(at: now()) {
            issues.append(.init(code: "EMBEDDED_PROFILE_EXPIRED", severity: .warning, message: "The embedded provisioning profile expired on \(Self.format(profile.expirationDate))."))
        }
        let unsigned = metadata.nestedBundles.filter { !$0.hasCodeSignature && $0.kind != .other }
        if metadata.hasCodeSignature, !unsigned.isEmpty {
            issues.append(.init(code: "NESTED_UNSIGNED", severity: .warning, message: "\(unsigned.count) nested component(s) have no signature, for example \(unsigned[0].relativePath)."))
        }
        if !metadata.watchApps.isEmpty {
            issues.append(.init(code: "WATCH_COMPONENTS", severity: .info, message: "Watch components are present and must be signed with their own compatible profile."))
        }
        return issues
    }

    // MARK: - Signing checks

    public func validateForSigning(
        metadata: AppMetadata,
        profile: ProvisioningProfile?,
        identity: SigningIdentityInfo?,
        targetBundleIdentifier: String? = nil,
        deviceIdentifier: String? = nil
    ) -> [ValidationIssue] {
        var issues = inspectionIssues(for: metadata).filter { $0.severity == .error }
        let date = now()
        let target = targetBundleIdentifier ?? metadata.bundleIdentifier

        guard let profile else {
            issues.append(.init(code: "MISSING_PROFILE", severity: .error, message: "No provisioning profile is selected."))
            return issues + identityIssues(identity, profile: nil, date: date)
        }

        // Profile validity
        if profile.isExpired(at: date) {
            issues.append(.init(code: "PROFILE_EXPIRED", severity: .error, message: "The profile “\(profile.name)” expired on \(Self.format(profile.expirationDate))."))
        } else if !profile.hasStarted(at: date) {
            issues.append(.init(code: "PROFILE_NOT_YET_VALID", severity: .error, message: "The profile “\(profile.name)” is not valid until \(Self.format(profile.creationDate))."))
        }
        if !profile.platforms.isEmpty, !profile.platforms.contains(where: { $0.lowercased() == "ios" }) {
            issues.append(.init(code: "PROFILE_PLATFORM", severity: .error, message: "The profile is for \(profile.platforms.joined(separator: ", ")), not iOS."))
        }
        if profile.kind == .appStore {
            issues.append(.init(code: "APP_STORE_PROFILE", severity: .warning, message: "App Store profiles produce builds that cannot be installed outside TestFlight or the App Store."))
        }

        // Bundle identifiers
        if !profile.allowsBundleIdentifier(target) {
            issues.append(.init(code: "BUNDLE_ID_MISMATCH", severity: .error, message: "The profile covers “\(profile.bundleIdentifierPattern)”, which does not match the app's bundle identifier “\(target)”."))
        }
        let plan = SigningPlanner.makePlan(metadata: metadata, targetBundleIdentifier: target)
        for step in plan.steps where !step.isMainApp && (step.kind == .appExtension || step.kind == .watchApp) {
            guard let id = step.bundleIdentifier else { continue }
            if !profile.allowsBundleIdentifier(id) {
                issues.append(.init(code: "NESTED_BUNDLE_ID_MISMATCH", severity: .error, message: "\(step.relativePath) uses “\(id)”, which this profile does not cover. Extensions and watch apps need a wildcard profile or their own profile."))
            }
        }

        // Entitlements
        let unmatched = metadata.existingEntitlements.keys
            .filter { !Self.signerManagedEntitlements.contains($0) && profile.entitlements[$0] == nil }
            .sorted()
        for key in unmatched {
            issues.append(.init(code: "ENTITLEMENT_NOT_IN_PROFILE", severity: .warning, message: "The app requests “\(key)”, which the profile does not grant. It must be removed when signing or the build will not install."))
        }

        // Device eligibility
        if let devices = profile.provisionedDevices {
            if let device = deviceIdentifier {
                if !devices.contains(where: { $0.caseInsensitiveCompare(device) == .orderedSame }) {
                    issues.append(.init(code: "DEVICE_NOT_REGISTERED", severity: .error, message: "This device is not registered in the profile."))
                }
            } else {
                issues.append(.init(code: "DEVICE_UNVERIFIED", severity: .info, message: "Tessera cannot read this device's UDID, so it cannot confirm eligibility. The build will install only on the \(devices.count) device(s) registered in the profile."))
            }
        }

        return issues + identityIssues(identity, profile: profile, date: date)
    }

    private func identityIssues(_ identity: SigningIdentityInfo?, profile: ProvisioningProfile?, date: Date) -> [ValidationIssue] {
        guard let identity else {
            return [.init(code: "MISSING_IDENTITY", severity: .error, message: "No signing certificate is selected.")]
        }
        var issues: [ValidationIssue] = []
        if !identity.hasPrivateKey {
            issues.append(.init(code: "NO_PRIVATE_KEY", severity: .error, message: "The certificate “\(identity.displayName)” has no private key on this device."))
        }
        if identity.isExpired(at: date) {
            issues.append(.init(code: "CERTIFICATE_EXPIRED", severity: .error, message: "The certificate “\(identity.displayName)” expired on \(Self.format(identity.notAfter))."))
        } else if date < identity.notBefore {
            issues.append(.init(code: "CERTIFICATE_NOT_YET_VALID", severity: .error, message: "The certificate “\(identity.displayName)” is not valid until \(Self.format(identity.notBefore))."))
        }
        if let profile {
            if !CertificateManager.profile(profile, authorizes: identity) {
                issues.append(.init(code: "CERTIFICATE_NOT_IN_PROFILE", severity: .error, message: "The profile “\(profile.name)” does not include the certificate “\(identity.displayName)”."))
            }
            if let team = identity.teamIdentifier, let profileTeam = profile.teamIdentifier, team != profileTeam {
                issues.append(.init(code: "TEAM_MISMATCH", severity: .warning, message: "The certificate's team (\(team)) differs from the profile's team (\(profileTeam))."))
            }
        }
        return issues
    }

    public func report(for artifact: AppArtifact, issues: [ValidationIssue]) -> ValidationReport {
        ValidationReport(
            artifactName: artifact.metadata.displayName,
            bundleIdentifier: artifact.metadata.bundleIdentifier,
            generatedAt: now(),
            issues: issues
        )
    }

    static func format(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .omitted)
    }
}
