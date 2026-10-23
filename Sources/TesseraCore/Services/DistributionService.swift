import Foundation

public enum DistributionError: Error, LocalizedError, Equatable {
    case httpsRequired(String)
    case invalidURL(String)
    case missingHost(String)

    public var errorDescription: String? {
        switch self {
        case .missingHost(let what): return "\(what) needs a host name, for example https://example.com/app.ipa."
        case .httpsRequired(let what): return "\(what) must use HTTPS. iOS refuses over-the-air installs from plain HTTP."
        case .invalidURL(let what): return "“\(what)” is not a valid URL."
        }
    }
}

/// Builds `itms-services` manifests. Only used when the chosen mechanism needs one.
public enum ManifestBuilder {
    /// Foundation accepts `https:app.ipa` and `https:/app.ipa` as HTTPS URLs even though they have
    /// no host, so both the scheme and a non-empty host are checked.
    static func requireHostedHTTPS(_ url: URL, _ what: String) throws {
        guard url.scheme?.lowercased() == "https" else { throw DistributionError.httpsRequired(what) }
        guard let host = url.host, !host.isEmpty else { throw DistributionError.missingHost(what) }
    }

    /// Creates the manifest property list for an HTTPS-hosted IPA.
    public static func makeManifest(ipaURL: URL, bundleIdentifier: String, bundleVersion: String, title: String) throws -> Data {
        try requireHostedHTTPS(ipaURL, "The IPA URL")
        let manifest: [String: Any] = [
            "items": [[
                "assets": [[
                    "kind": "software-package",
                    "url": ipaURL.absoluteString,
                ]],
                "metadata": [
                    "bundle-identifier": bundleIdentifier,
                    "bundle-version": bundleVersion,
                    "kind": "software",
                    "title": title,
                ],
            ]],
        ]
        return try PropertyListSerialization.data(fromPropertyList: manifest, format: .xml, options: 0)
    }

    /// The URL that asks iOS to install from `manifestURL`.
    public static func installURL(manifestURL: URL) throws -> URL {
        try requireHostedHTTPS(manifestURL, "The manifest URL")
        var components = URLComponents()
        components.scheme = "itms-services"
        components.host = ""
        components.queryItems = [
            URLQueryItem(name: "action", value: "download-manifest"),
            URLQueryItem(name: "url", value: manifestURL.absoluteString),
        ]
        guard let url = components.url else { throw DistributionError.invalidURL(manifestURL.absoluteString) }
        return url
    }
}

/// Works out which distribution mechanisms genuinely apply to a build. It never promises that
/// a build will install: each option lists the conditions that must hold, and anything Tessera
/// cannot verify on-device is marked as conditional.
public struct DistributionService: Sendable {
    public var now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// - Parameters:
    ///   - profile: The profile the build is (or will be) signed with, or the embedded profile.
    ///   - hasVerifiedSignedOutput: True only when Tessera produced a signed IPA and verified its signature.
    ///   - verifiedNotarization: A notarization result that was actually fetched from Apple, if any.
    public func evaluate(
        profile: ProvisioningProfile?,
        hasVerifiedSignedOutput: Bool,
        verifiedNotarization: NotarizationStatus? = nil
    ) -> DistributionResult {
        var options: [DistributionOption] = []
        let profileUsable = profile.map { !$0.isExpired(at: now()) } ?? false
        let signedNote = "A signed IPA that Tessera has verified."

        // 1. Registered devices (development / Ad Hoc)
        if let profile, profile.kind == .development || profile.kind == .adHoc {
            var requirements = [
                signedNote,
                "Installation only on the \(profile.provisionedDevices?.count ?? 0) device(s) registered in the profile.",
                "Profile valid until \(ValidationService.format(profile.expirationDate)).",
                "iOS apps cannot install arbitrary IPAs themselves; use an authorized method such as Xcode, Apple Configurator or an over-the-air manifest.",
            ]
            var blockers: [String] = []
            if !profileUsable { blockers.append("The profile has expired.") }
            if !hasVerifiedSignedOutput { blockers.append("No verified signed build exists yet.") }
            if profile.kind == .development { requirements.append("Development profiles are intended for testing.") }
            options.append(DistributionOption(
                mechanism: .registeredDevices,
                title: "\(profile.kind.displayName) (registered devices)",
                applicability: blockers.isEmpty ? .applicable : .conditional,
                summary: "Install on devices whose identifiers are listed in the \(profile.kind.displayName) profile.",
                requirements: requirements,
                blockers: blockers
            ))
        } else {
            options.append(DistributionOption(
                mechanism: .registeredDevices,
                title: "Registered devices",
                applicability: .notApplicable,
                summary: "Needs a Development or Ad Hoc provisioning profile.",
                blockers: [profile == nil ? "No provisioning profile is selected." : "The selected profile is \(profile!.kind.displayName)."]
            ))
        }

        // 2. Over the air via itms-services
        if let profile, [.development, .adHoc, .enterprise].contains(profile.kind) {
            var blockers: [String] = []
            if !profileUsable { blockers.append("The profile has expired.") }
            if !hasVerifiedSignedOutput { blockers.append("No verified signed build exists yet.") }
            options.append(DistributionOption(
                mechanism: .overTheAir,
                title: "Over the air (itms-services)",
                // Hosting and device trust cannot be verified on-device, so this is never "applicable".
                applicability: .conditional,
                summary: "Install from a manifest hosted over HTTPS.",
                requirements: [
                    "An HTTPS URL for both the IPA and the manifest, served with a certificate iOS trusts.",
                    profile.kind == .enterprise
                        ? "Apple Developer Enterprise Program membership; the user must trust the enterprise profile on the device."
                        : "The installing device must be registered in the profile.",
                    "Tessera cannot host files itself; you must provide hosting.",
                ],
                blockers: blockers
            ))
        } else {
            options.append(DistributionOption(
                mechanism: .overTheAir,
                title: "Over the air (itms-services)",
                applicability: .notApplicable,
                summary: "Needs a Development, Ad Hoc or Enterprise profile.",
                blockers: ["No suitable provisioning profile is selected."]
            ))
        }

        // 3. Alternative distribution
        options.append(DistributionOption(
            mechanism: .alternativeDistribution,
            title: "Alternative distribution",
            applicability: .conditional,
            summary: "Web distribution or alternative marketplaces, where Apple permits them.",
            requirements: [
                "Availability depends on your region and on Apple having authorized you as a developer or marketplace.",
                "Apple's iOS notarization process applies to these channels; submit through the officially supported process.",
                "Tessera cannot determine your eligibility on-device.",
            ]
        ))

        // 4. TestFlight / App Store
        if let profile, profile.kind == .appStore {
            options.append(DistributionOption(
                mechanism: .testFlightOrAppStore,
                title: "TestFlight / App Store",
                applicability: .conditional,
                summary: "Upload through App Store Connect.",
                requirements: ["Upload with Xcode or Transporter; Tessera does not upload builds."]
            ))
        } else {
            options.append(DistributionOption(
                mechanism: .testFlightOrAppStore,
                title: "TestFlight / App Store",
                applicability: .notApplicable,
                summary: "Needs an App Store distribution profile and an upload through App Store Connect."
            ))
        }

        // 5. Manual export
        options.append(DistributionOption(
            mechanism: .manualExport,
            title: "Export the file",
            applicability: .applicable,
            summary: "Share the IPA and validation report. Installing it still requires another authorized method.",
            requirements: ["Exporting does not install anything or confirm the build is installable."]
        ))

        let notarization: NotarizationStatus
        if let verifiedNotarization {
            notarization = verifiedNotarization
        } else if let profile, [.development, .adHoc, .enterprise].contains(profile.kind) {
            notarization = .notApplicable(reason: "Development, Ad Hoc and Enterprise distribution do not use notarization. macOS Developer ID notarization does not apply to iOS IPAs.")
        } else {
            notarization = .notSubmitted
        }

        return DistributionResult(options: options, notarization: notarization, generatedAt: now())
    }
}
