import Foundation

public enum InspectionError: Error, LocalizedError, Equatable {
    case missingPayload
    case noAppBundle
    case multipleAppBundles([String])
    case missingInfoPlist(String)
    case malformedInfoPlist(String)
    case missingKey(String)

    public var errorDescription: String? {
        switch self {
        case .missingPayload: return "The archive has no Payload folder, so it is not a valid IPA."
        case .noAppBundle: return "The archive's Payload folder does not contain an .app bundle."
        case .multipleAppBundles(let names): return "The archive contains more than one app bundle (\(names.joined(separator: ", ")))."
        case .missingInfoPlist(let path): return "No Info.plist was found in \(path)."
        case .malformedInfoPlist(let path): return "The Info.plist in \(path) could not be read."
        case .missingKey(let key): return "The app's Info.plist is missing “\(key)”."
        }
    }
}

/// Discovers the main app bundle and its nested code in an extracted archive.
public struct BundleInspector: Sendable {
    public init() {}

    /// Finds the single `Payload/*.app` directory under `root`.
    public func locateAppBundle(in root: URL) throws -> URL {
        let fm = FileManager.default
        let payload = root.appendingPathComponent("Payload", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: payload.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw InspectionError.missingPayload
        }
        let names = ((try? fm.contentsOfDirectory(atPath: payload.path)) ?? [])
            .filter { $0.hasSuffix(".app") }
            .sorted()
        guard !names.isEmpty else { throw InspectionError.noAppBundle }
        guard names.count == 1 else { throw InspectionError.multipleAppBundles(names) }
        return payload.appendingPathComponent(names[0], isDirectory: true)
    }

    public func readInfoPlist(in bundle: URL) throws -> [String: Any] {
        let url = bundle.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: url) else {
            throw InspectionError.missingInfoPlist(bundle.lastPathComponent)
        }
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = object as? [String: Any] else {
            throw InspectionError.malformedInfoPlist(bundle.lastPathComponent)
        }
        return dict
    }

    /// Builds metadata for an extracted `.app` bundle.
    public func inspect(appBundle: URL, uncompressedSize: UInt64 = 0) throws -> AppMetadata {
        let info = try readInfoPlist(in: appBundle)
        guard let bundleID = info["CFBundleIdentifier"] as? String, !bundleID.isEmpty else {
            throw InspectionError.missingKey("CFBundleIdentifier")
        }

        let folderName = appBundle.lastPathComponent
        let fallbackName = folderName.hasSuffix(".app") ? String(folderName.dropLast(4)) : folderName
        let displayName = (info["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleName"] as? String)
            ?? fallbackName

        let executableName = info["CFBundleExecutable"] as? String
        var machO: MachOInfo?
        if let executableName {
            machO = MachOInspector.inspect(fileAt: appBundle.appendingPathComponent(executableName))
        }

        var entitlements: [String: PlistValue] = [:]
        if let xml = machO?.entitlementsXML,
           let object = try? PropertyListSerialization.propertyList(from: xml, options: [], format: nil),
           let dict = object as? [String: Any] {
            entitlements = dict.toPlistValues()
        }

        let profileURL = appBundle.appendingPathComponent("embedded.mobileprovision")
        let hasProfile = FileManager.default.fileExists(atPath: profileURL.path)
        var embeddedProfile: ProvisioningProfile?
        if hasProfile, let data = try? Data(contentsOf: profileURL) {
            embeddedProfile = try? ProfileParser().parse(data)
        }

        return AppMetadata(
            bundleIdentifier: bundleID,
            displayName: displayName,
            shortVersion: (info["CFBundleShortVersionString"] as? String) ?? "",
            buildVersion: (info["CFBundleVersion"] as? String) ?? "",
            minimumOSVersion: info["MinimumOSVersion"] as? String,
            supportedPlatforms: (info["CFBundleSupportedPlatforms"] as? [String]) ?? [],
            deviceFamilies: ((info["UIDeviceFamily"] as? [Any]) ?? []).compactMap { ($0 as? NSNumber)?.intValue },
            executableName: executableName,
            architectures: machO?.architectures ?? [],
            isEncrypted: machO?.isEncrypted ?? false,
            hasCodeSignature: machO?.hasCodeSignature ?? false,
            hasEmbeddedProfile: hasProfile,
            appFolderName: folderName,
            nestedBundles: discoverNestedBundles(in: appBundle),
            existingEntitlements: entitlements,
            embeddedProfile: embeddedProfile,
            uncompressedSize: uncompressedSize,
            iconRelativePath: locateIcon(in: appBundle, info: info)
        )
    }

    /// Finds app extensions, frameworks, watch apps and loose dynamic libraries.
    public func discoverNestedBundles(in appBundle: URL) -> [NestedBundle] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: appBundle.path) else { return [] }

        var results: [NestedBundle] = []
        for case let relativePath as String in enumerator {
            let kind: NestedBundle.Kind
            if relativePath.hasSuffix(".appex") {
                kind = .appExtension
            } else if relativePath.hasSuffix(".framework") {
                kind = .framework
            } else if relativePath.hasSuffix(".app") {
                kind = relativePath.hasPrefix("Watch/") ? .watchApp : .other
            } else if relativePath.hasSuffix(".dylib") {
                kind = .dynamicLibrary
            } else {
                continue
            }

            let url = appBundle.appendingPathComponent(relativePath)
            var isDirectory: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDirectory) else { continue }

            if kind == .dynamicLibrary {
                guard !isDirectory.boolValue else { continue }
                results.append(NestedBundle(
                    relativePath: relativePath,
                    kind: kind,
                    executableName: url.lastPathComponent,
                    hasCodeSignature: MachOInspector.inspect(fileAt: url)?.hasCodeSignature ?? false
                ))
                continue
            }

            guard isDirectory.boolValue else { continue }
            let info = try? readInfoPlist(in: url)
            let executable = info?["CFBundleExecutable"] as? String
            let signed = executable
                .flatMap { MachOInspector.inspect(fileAt: url.appendingPathComponent($0)) }?
                .hasCodeSignature ?? false
            results.append(NestedBundle(
                relativePath: relativePath,
                kind: kind,
                bundleIdentifier: info?["CFBundleIdentifier"] as? String,
                executableName: executable,
                hasCodeSignature: signed
            ))
        }
        return results.sorted { $0.relativePath < $1.relativePath }
    }

    /// Picks the largest loose PNG matching the declared icon names. Icons that exist only in
    /// an asset catalog (`Assets.car`) are not readable without Apple's tooling, so none is returned.
    public func locateIcon(in appBundle: URL, info: [String: Any]) -> String? {
        var names = Set<String>()

        func collect(_ icons: Any?) {
            guard let icons = icons as? [String: Any] else { return }
            if let primary = icons["CFBundlePrimaryIcon"] as? [String: Any] {
                for file in (primary["CFBundleIconFiles"] as? [String]) ?? [] { names.insert(file) }
                if let name = primary["CFBundleIconName"] as? String { names.insert(name) }
            }
        }
        collect(info["CFBundleIcons"])
        collect(info["CFBundleIcons~ipad"])
        for file in (info["CFBundleIconFiles"] as? [String]) ?? [] { names.insert(file) }
        names.insert("AppIcon")

        let fm = FileManager.default
        let files = (try? fm.contentsOfDirectory(atPath: appBundle.path)) ?? []
        var best: (name: String, size: UInt64)?
        for file in files where file.lowercased().hasSuffix(".png") {
            guard names.contains(where: { file.hasPrefix($0) }) else { continue }
            let path = appBundle.appendingPathComponent(file).path
            let attributes = try? fm.attributesOfItem(atPath: path)
            let size = (attributes?[.size] as? NSNumber)?.uint64Value ?? 0
            if best == nil || size > best!.size { best = (file, size) }
        }
        return best?.name
    }
}
