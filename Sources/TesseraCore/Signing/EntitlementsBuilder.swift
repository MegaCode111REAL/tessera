import Foundation

/// Decides which entitlements a re-signed component gets.
///
/// An app can only keep entitlements that its provisioning profile grants. The identity
/// entitlements (`application-identifier`, team identifier) always come from the profile and
/// the target bundle identifier, never from the original signature.
public enum EntitlementsBuilder {
    public struct Result: Equatable, Sendable {
        public var entitlements: [String: PlistValue]
        /// Entitlements the app asked for that the profile does not cover, so they were left out.
        public var dropped: [String]
    }

    public static func build(
        requested: [String: PlistValue],
        profile: ProvisioningProfile,
        bundleIdentifier: String
    ) -> Result {
        let team = profile.teamIdentifier ?? profile.applicationIdentifierPrefixes.first ?? ""
        let applicationIdentifier = team.isEmpty ? bundleIdentifier : "\(team).\(bundleIdentifier)"

        var result: [String: PlistValue] = [:]
        var dropped: [String] = []

        let identityKeys: Set<String> = [
            "application-identifier",
            "com.apple.application-identifier",
            "com.apple.developer.team-identifier",
        ]

        for key in requested.keys.sorted() where !identityKeys.contains(key) {
            let value = requested[key]!
            guard let granted = profile.entitlements[key] else {
                dropped.append(key)
                continue
            }
            if key == "keychain-access-groups" {
                result[key] = keychainGroups(requested: value, granted: granted, team: team, applicationIdentifier: applicationIdentifier)
                continue
            }
            if ValidationService.entitlementSatisfied(requested: value, granted: granted) {
                result[key] = value
            } else {
                dropped.append(key)
            }
        }

        result["application-identifier"] = .string(applicationIdentifier)
        if !team.isEmpty { result["com.apple.developer.team-identifier"] = .string(team) }
        if let taskAllow = profile.entitlements["get-task-allow"] { result["get-task-allow"] = taskAllow }
        if result["keychain-access-groups"] == nil, profile.entitlements["keychain-access-groups"] != nil {
            result["keychain-access-groups"] = keychainGroups(
                requested: .array([]), granted: profile.entitlements["keychain-access-groups"]!,
                team: team, applicationIdentifier: applicationIdentifier
            )
        }
        return Result(entitlements: result, dropped: dropped)
    }

    /// Keeps requested groups the profile covers; falls back to the app's own group.
    private static func keychainGroups(
        requested: PlistValue,
        granted: PlistValue,
        team: String,
        applicationIdentifier: String
    ) -> PlistValue {
        let wanted: [String] = (requested.arrayValue ?? []).compactMap(\.stringValue)
        let allowed: [String] = (granted.arrayValue ?? []).compactMap(\.stringValue)

        // Group names often start with the original team's identifier; rewrite them to this team.
        let kept = wanted.compactMap { group -> String? in
            let suffix = group.split(separator: ".", maxSplits: 1).dropFirst().first.map(String.init) ?? group
            let candidate = team.isEmpty ? group : "\(team).\(suffix)"
            let covered = allowed.contains { pattern in
                pattern == candidate || (pattern.hasSuffix("*") && candidate.hasPrefix(String(pattern.dropLast())))
            }
            return covered ? candidate : nil
        }
        var groups = kept
        if groups.isEmpty {
            let hasWildcard = allowed.contains { $0.hasSuffix("*") }
            if hasWildcard || allowed.contains(applicationIdentifier) {
                groups = [applicationIdentifier]
            } else {
                groups = allowed
            }
        }
        return .array(groups.map { .string($0) })
    }
}
