import Foundation

/// Signs an extracted `.app` bundle in place, nested code first.
///
/// With a key provider and profile it produces a certificate signature; without an identity it
/// produces an ad-hoc signature (the equivalent of `ldid -S` / "fakesign"), which iOS accepts only
/// on devices that skip signature checks (for example with TrollStore or a jailbreak).
public struct BundleSigner: SigningEngine {
    public typealias KeyProvider = @Sendable (_ identityID: String) throws -> CMSSigningKey

    private let keyProvider: KeyProvider?

    public init(keyProvider: KeyProvider? = nil) {
        self.keyProvider = keyProvider
    }

    public var capability: SigningCapability { .available }

    public func sign(_ request: SigningRequest, onStep: @Sendable (SigningStep) -> Void) async throws {
        let key = try resolveKey(for: request)
        try Self.perform(request, key: key, onStep: onStep)
    }

    public func verify(appBundle: URL, plan: SigningPlan, profile: ProvisioningProfile?) async throws -> [ValidationIssue] {
        SignatureVerifier.verify(appBundle: appBundle, plan: plan)
    }

    private func resolveKey(for request: SigningRequest) throws -> CMSSigningKey? {
        guard let identityID = request.identityID else { return nil }
        guard request.profile != nil, request.profileData != nil else {
            throw SigningError.unsupported("A provisioning profile is required to sign with a certificate.")
        }
        guard let keyProvider else { throw SigningError.identityUnavailable }
        return try keyProvider(identityID)
    }

    // MARK: - Work

    static func perform(_ request: SigningRequest, key: CMSSigningKey?, onStep: (SigningStep) -> Void) throws {
        let appBundle = request.appBundle
        let nestedRoots = request.plan.steps
            .filter { !$0.isMainApp }
            .map { appBundle.appendingPathComponent($0.relativePath).path }
        var signedFiles = Set<String>()

        for step in request.plan.steps {
            try Task.checkCancellation()
            onStep(step)
            let url = step.isMainApp ? appBundle : appBundle.appendingPathComponent(step.relativePath)
            if step.kind == .dynamicLibrary {
                try signLoose(url, request: request, key: key, signed: &signedFiles)
            } else {
                try signBundle(url, step: step, nestedRoots: nestedRoots, request: request, key: key, signed: &signedFiles)
            }
        }
    }

    private static func signBundle(
        _ bundle: URL,
        step: SigningStep,
        nestedRoots: [String],
        request: SigningRequest,
        key: CMSSigningKey?,
        signed: inout Set<String>
    ) throws {
        let fm = FileManager.default
        let label = step.displayName
        let infoURL = bundle.appendingPathComponent("Info.plist")

        guard let infoData = try? Data(contentsOf: infoURL) else {
            throw SigningError.unsupported("\(label) has no Info.plist, so it cannot be signed.")
        }
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard var info = (try? PropertyListSerialization.propertyList(from: infoData, options: [], format: &format)) as? [String: Any],
              let executableName = info["CFBundleExecutable"] as? String, !executableName.isEmpty else {
            throw SigningError.unsupported("\(label) has an unreadable Info.plist or no CFBundleExecutable.")
        }
        let executableURL = bundle.appendingPathComponent(executableName)
        guard fm.fileExists(atPath: executableURL.path) else {
            throw SigningError.unsupported("The executable “\(executableName)” of \(label) is missing.")
        }

        // Bundle identifier rewrite (and the references that follow it).
        let originalID = info["CFBundleIdentifier"] as? String ?? ""
        let bundleID = step.bundleIdentifier ?? originalID
        var changed = false
        if bundleID != originalID {
            info["CFBundleIdentifier"] = bundleID
            changed = true
        }
        if request.plan.originalBundleIdentifier != request.plan.targetBundleIdentifier {
            changed = rewriteReferences(in: &info, plan: request.plan) || changed
        }
        if changed {
            let rewritten = try PropertyListSerialization.data(fromPropertyList: info, format: format, options: 0)
            try rewritten.write(to: infoURL)
        }

        // Original entitlements, read before the old signature is replaced.
        var existing: [String: PlistValue] = [:]
        if let xml = MachOInspector.inspect(fileAt: executableURL)?.entitlementsXML,
           let object = try? PropertyListSerialization.propertyList(from: xml, options: [], format: nil),
           let dict = object as? [String: Any] {
            existing = dict.toPlistValues()
        }

        try? fm.removeItem(at: bundle.appendingPathComponent("_CodeSignature"))
        if let key, let profileData = request.profileData, step.kind != .framework {
            _ = key
            try profileData.write(to: bundle.appendingPathComponent("embedded.mobileprovision"))
        }

        // Loose Mach-O files inside this bundle (but not inside deeper bundles) are signed first.
        let relatives = try fm.subpathsOfDirectory(atPath: bundle.path).sorted()
        for relative in relatives where relative != executableName {
            let fileURL = bundle.appendingPathComponent(relative)
            if nestedRoots.contains(where: { $0 != bundle.path && fileURL.path.hasPrefix($0 + "/") }) { continue }
            if signed.contains(fileURL.path) { continue }
            guard isRegularFile(fileURL), looksLikeMachO(fileURL) else { continue }
            try signLoose(fileURL, request: request, key: key, signed: &signed)
        }

        // Entitlements.
        let entitlements: [String: PlistValue]?
        if step.kind == .framework {
            entitlements = nil
        } else if let profile = request.profile, key != nil {
            entitlements = EntitlementsBuilder.build(requested: existing, profile: profile, bundleIdentifier: bundleID).entitlements
        } else {
            entitlements = existing.isEmpty ? nil : existing
        }

        // Resources seal, then the executable.
        let resources = try CodeResourcesBuilder.build(bundle: bundle, executableName: executableName)
        let signatureDirectory = bundle.appendingPathComponent("_CodeSignature", isDirectory: true)
        try fm.createDirectory(at: signatureDirectory, withIntermediateDirectories: true)
        try resources.write(to: signatureDirectory.appendingPathComponent("CodeResources"))

        let materials = CodeSigningMaterials(
            identifier: bundleID,
            teamIdentifier: key == nil ? nil : request.profile?.teamIdentifier,
            entitlements: entitlements,
            infoPlist: try Data(contentsOf: infoURL),
            codeResources: resources,
            key: key
        )
        try signFile(executableURL, materials: materials)
        signed.insert(executableURL.path)
    }

    private static func signLoose(_ url: URL, request: SigningRequest, key: CMSSigningKey?, signed: inout Set<String>) throws {
        guard !signed.contains(url.path) else { return }
        let materials = CodeSigningMaterials(
            identifier: url.lastPathComponent,
            teamIdentifier: key == nil ? nil : request.profile?.teamIdentifier,
            key: key
        )
        try signFile(url, materials: materials)
        signed.insert(url.path)
    }

    private static func signFile(_ url: URL, materials: CodeSigningMaterials) throws {
        let fm = FileManager.default
        let original = try Data(contentsOf: url)
        let permissions = (try? fm.attributesOfItem(atPath: url.path))?[.posixPermissions]
        let output: Data
        do {
            output = try MachOSigner.sign(original, materials: materials)
        } catch let error as CodeSigningError {
            throw SigningError.unsupported("\(url.lastPathComponent): \(error.localizedDescription)")
        }
        try output.write(to: url)
        if let permissions { try? fm.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path) }
    }

    /// Updates keys that point at the app's bundle identifier (watch apps and their extensions).
    private static func rewriteReferences(in info: inout [String: Any], plan: SigningPlan) -> Bool {
        var changed = false
        if let companion = info["WKCompanionAppBundleIdentifier"] as? String,
           let rewritten = SigningPlanner.rewrittenBundleIdentifier(companion, original: plan.originalBundleIdentifier, target: plan.targetBundleIdentifier),
           companion == plan.originalBundleIdentifier || rewritten != companion {
            let value = companion == plan.originalBundleIdentifier ? plan.targetBundleIdentifier : rewritten
            if value != companion {
                info["WKCompanionAppBundleIdentifier"] = value
                changed = true
            }
        }
        if var ext = info["NSExtension"] as? [String: Any],
           var attributes = ext["NSExtensionAttributes"] as? [String: Any],
           let watchApp = attributes["WKAppBundleIdentifier"] as? String,
           let rewritten = SigningPlanner.rewrittenBundleIdentifier(watchApp, original: plan.originalBundleIdentifier, target: plan.targetBundleIdentifier),
           rewritten != watchApp {
            attributes["WKAppBundleIdentifier"] = rewritten
            ext["NSExtensionAttributes"] = attributes
            info["NSExtension"] = ext
            changed = true
        }
        return changed
    }

    static func isRegularFile(_ url: URL) -> Bool {
        let type = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType
        return type == .typeRegular
    }

    /// True when the file starts with a 64-bit Mach-O or universal-binary magic number.
    static func looksLikeMachO(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: 4), head.count == 4 else { return false }
        let bytes = [UInt8](head)
        guard bytes == [0xCF, 0xFA, 0xED, 0xFE] || bytes == [0xCA, 0xFE, 0xBA, 0xBE] else { return false }
        return MachOInspector.inspect(fileAt: url) != nil
    }
}
