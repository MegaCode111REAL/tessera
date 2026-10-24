import Foundation

/// Builds `_CodeSignature/CodeResources`, the sealed list of a bundle's resources.
enum CodeResourcesBuilder {
    /// Hashes every file in `bundle` except the main executable and the bundle's own `_CodeSignature`.
    static func build(bundle: URL, executableName: String?) throws -> Data {
        let fm = FileManager.default
        let paths: [String]
        do {
            paths = try fm.subpathsOfDirectory(atPath: bundle.path).sorted()
        } catch {
            throw CodeSigningError.resources("The bundle \(bundle.lastPathComponent) could not be read: \(error.localizedDescription)")
        }

        var files: [String: Any] = [:]
        var files2: [String: Any] = [:]

        for relative in paths {
            if relative == "_CodeSignature" || relative.hasPrefix("_CodeSignature/") { continue }
            if relative == executableName { continue }
            let name = (relative as NSString).lastPathComponent
            if name == ".DS_Store" || relative.hasPrefix("__MACOSX") { continue }
            if name == "locversion.plist", relative.contains(".lproj/") { continue }

            let url = bundle.appendingPathComponent(relative)
            let attributes = try fm.attributesOfItem(atPath: url.path)
            let type = attributes[.type] as? FileAttributeType
            let optional = relative.contains(".lproj/") && !relative.hasPrefix("Base.lproj/")

            if type == .typeSymbolicLink {
                let target = try fm.destinationOfSymbolicLink(atPath: url.path)
                var entry: [String: Any] = ["symlink": target]
                files[relative] = entry
                if optional { entry["optional"] = true }
                files2[relative] = entry
                continue
            }
            guard type == .typeRegular else { continue }

            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            let sha1 = HashKind.sha1.hash(data)
            let sha256 = HashKind.sha256.hash(data)

            if optional {
                files[relative] = ["hash": sha1, "optional": true] as [String: Any]
            } else {
                files[relative] = sha1
            }

            if relative == "Info.plist" || relative == "PkgInfo" { continue }
            var entry: [String: Any] = ["hash": sha1, "hash2": sha256]
            if optional { entry["optional"] = true }
            files2[relative] = entry
        }

        let rules: [String: Any] = [
            "^.*": true,
            "^.*\\.lproj/": ["optional": true, "weight": 1000.0] as [String: Any],
            "^.*\\.lproj/locversion.plist$": ["omit": true, "weight": 1100.0] as [String: Any],
            "^Base\\.lproj/": ["weight": 1010.0] as [String: Any],
            "^version.plist$": true,
        ]
        let rules2: [String: Any] = [
            "^.*": true,
            "^.*\\.lproj/": ["optional": true, "weight": 1000.0] as [String: Any],
            "^.*\\.lproj/locversion.plist$": ["omit": true, "weight": 1100.0] as [String: Any],
            "^Base\\.lproj/": ["weight": 1010.0] as [String: Any],
            "^Info\\.plist$": ["omit": true, "weight": 20.0] as [String: Any],
            "^PkgInfo$": ["omit": true, "weight": 20.0] as [String: Any],
            "^embedded\\.provisionprofile$": ["weight": 20.0] as [String: Any],
            "^version\\.plist$": ["weight": 20.0] as [String: Any],
        ]

        let plist: [String: Any] = ["files": files, "files2": files2, "rules": rules, "rules2": rules2]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    /// Re-checks a bundle against its `CodeResources` and returns human-readable problems.
    static func verify(bundle: URL, executableName: String?) -> [String] {
        let fm = FileManager.default
        let url = bundle.appendingPathComponent("_CodeSignature/CodeResources")
        guard let data = try? Data(contentsOf: url),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let plist = object as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            return ["_CodeSignature/CodeResources is missing or unreadable."]
        }

        var problems: [String] = []
        for (path, value) in files2 {
            let fileURL = bundle.appendingPathComponent(path)
            guard let entry = value as? [String: Any] else { continue }
            if entry["symlink"] != nil { continue }
            let optional = entry["optional"] as? Bool ?? false
            guard let actual = try? Data(contentsOf: fileURL, options: .mappedIfSafe) else {
                if !optional { problems.append("\(path) is listed in CodeResources but missing.") }
                continue
            }
            if let expected = entry["hash2"] as? Data, expected != HashKind.sha256.hash(actual) {
                problems.append("\(path) does not match its recorded hash.")
            }
        }

        let listed = Set(files2.keys)
        let present = (try? fm.subpathsOfDirectory(atPath: bundle.path)) ?? []
        for relative in present {
            if relative == "_CodeSignature" || relative.hasPrefix("_CodeSignature/") { continue }
            if relative == executableName || relative == "Info.plist" || relative == "PkgInfo" { continue }
            let name = (relative as NSString).lastPathComponent
            if name == ".DS_Store" || relative.hasPrefix("__MACOSX") { continue }
            if name == "locversion.plist", relative.contains(".lproj/") { continue }
            var isDirectory: ObjCBool = false
            _ = fm.fileExists(atPath: bundle.appendingPathComponent(relative).path, isDirectory: &isDirectory)
            if isDirectory.boolValue { continue }
            if !listed.contains(relative) { problems.append("\(relative) is not covered by CodeResources.") }
        }
        return problems.sorted()
    }
}
