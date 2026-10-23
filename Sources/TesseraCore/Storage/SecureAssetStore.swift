import Foundation

public struct StorageUsage: Equatable, Sendable {
    public var library: UInt64
    public var exports: UInt64
    public var profiles: UInt64
    public var icons: UInt64
    public var temporary: UInt64

    public init(library: UInt64 = 0, exports: UInt64 = 0, profiles: UInt64 = 0, icons: UInt64 = 0, temporary: UInt64 = 0) {
        self.library = library
        self.exports = exports
        self.profiles = profiles
        self.icons = icons
        self.temporary = temporary
    }

    public var total: UInt64 { library + exports + profiles + icons + temporary }
}

public enum StoreError: Error, LocalizedError, Equatable {
    case copyFailed(String)
    case notFound(String)

    public var errorDescription: String? {
        switch self {
        case .copyFailed(let message): return "Could not copy the file: \(message)"
        case .notFound(let name): return "“\(name)” was not found in Tessera's storage."
        }
    }
}

/// File storage inside the app's protected container.
///
/// Layout (all excluded from iCloud/iTunes backup):
/// - `Library/`   imported archives
/// - `Exports/`   signed IPAs and validation reports
/// - `Profiles/`  provisioning profiles
/// - `Icons/`     cached app icons
/// - `Work/`      temporary extraction and signing workspaces
///
/// Private keys are never written here; they live only in the Keychain (see `CertificateManager`).
public final class SecureAssetStore: Sendable {
    public let root: URL
    public let libraryDirectory: URL
    public let exportsDirectory: URL
    public let profilesDirectory: URL
    public let iconsDirectory: URL
    public let workDirectory: URL

    public init(root: URL? = nil) throws {
        let fm = FileManager.default
        let base = try root ?? fm.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ).appendingPathComponent("Tessera", isDirectory: true)

        self.root = base
        libraryDirectory = base.appendingPathComponent("Library", isDirectory: true)
        exportsDirectory = base.appendingPathComponent("Exports", isDirectory: true)
        profilesDirectory = base.appendingPathComponent("Profiles", isDirectory: true)
        iconsDirectory = base.appendingPathComponent("Icons", isDirectory: true)
        workDirectory = base.appendingPathComponent("Work", isDirectory: true)

        for directory in [base, libraryDirectory, exportsDirectory, profilesDirectory, iconsDirectory, workDirectory] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
            Self.excludeFromBackup(directory)
        }
        Self.applyProtection(profilesDirectory, sensitive: true)
        for directory in [libraryDirectory, exportsDirectory, iconsDirectory, workDirectory] {
            Self.applyProtection(directory, sensitive: false)
        }
    }

    // MARK: - Workspaces

    /// Creates an empty temporary directory for one extraction or signing job.
    public func makeWorkspace() throws -> URL {
        let url = workDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    public func removeWorkspace(_ url: URL) {
        // Only ever delete inside our own Work directory.
        guard url.standardizedFileURL.path.hasPrefix(workDirectory.standardizedFileURL.path + "/") else { return }
        try? FileManager.default.removeItem(at: url)
    }

    /// Removes every temporary workspace. Call at launch and from Settings.
    @discardableResult
    public func cleanTemporaryFiles() -> UInt64 {
        let before = Self.size(of: workDirectory)
        let contents = (try? FileManager.default.contentsOfDirectory(at: workDirectory, includingPropertiesForKeys: nil)) ?? []
        for item in contents { try? FileManager.default.removeItem(at: item) }
        return before
    }

    // MARK: - Library files

    public func libraryURL(for fileName: String) -> URL {
        libraryDirectory.appendingPathComponent(fileName)
    }

    public func exportURL(for fileName: String) -> URL {
        exportsDirectory.appendingPathComponent(fileName)
    }

    public func iconURL(for fileName: String) -> URL {
        iconsDirectory.appendingPathComponent(fileName)
    }

    /// Copies a user-selected archive into the library and returns the stored file name and size.
    public func storeArchive(from source: URL, fileExtension: String) throws -> (fileName: String, size: UInt64) {
        let fileName = "\(UUID().uuidString).\(fileExtension.lowercased())"
        let destination = libraryURL(for: fileName)
        do {
            try FileManager.default.copyItem(at: source, to: destination)
        } catch {
            throw StoreError.copyFailed(error.localizedDescription)
        }
        Self.excludeFromBackup(destination)
        Self.applyProtection(destination, sensitive: false)
        return (fileName, Self.size(of: destination))
    }

    public func saveIcon(_ data: Data, artifactID: UUID) -> String? {
        let fileName = "\(artifactID.uuidString).png"
        do {
            try data.write(to: iconURL(for: fileName), options: .atomic)
            return fileName
        } catch {
            return nil
        }
    }

    public func removeFiles(for artifact: AppArtifact) {
        let fm = FileManager.default
        try? fm.removeItem(at: libraryURL(for: artifact.storedFileName))
        if let signed = artifact.signedFileName { try? fm.removeItem(at: exportURL(for: signed)) }
        if let icon = artifact.iconFileName { try? fm.removeItem(at: iconURL(for: icon)) }
    }

    // MARK: - Provisioning profiles

    /// Stores raw profile bytes under the profile's UUID.
    public func saveProfile(data: Data, profile: ProvisioningProfile) throws {
        let url = profilesDirectory.appendingPathComponent("\(profile.id).mobileprovision")
        try data.write(to: url, options: .atomic)
        Self.excludeFromBackup(url)
        Self.applyProtection(url, sensitive: true)
    }

    public func profileData(id: String) throws -> Data {
        let url = profilesDirectory.appendingPathComponent("\(id).mobileprovision")
        guard let data = try? Data(contentsOf: url) else { throw StoreError.notFound("\(id).mobileprovision") }
        return data
    }

    public func deleteProfile(id: String) {
        try? FileManager.default.removeItem(at: profilesDirectory.appendingPathComponent("\(id).mobileprovision"))
    }

    public func listProfiles() -> [ProvisioningProfile] {
        let urls = (try? FileManager.default.contentsOfDirectory(at: profilesDirectory, includingPropertiesForKeys: nil)) ?? []
        let parser = ProfileParser()
        return urls
            .filter { $0.pathExtension == "mobileprovision" }
            .compactMap { url in (try? Data(contentsOf: url)).flatMap { try? parser.parse($0) } }
            .sorted { $0.expirationDate > $1.expirationDate }
    }

    // MARK: - Usage

    public func storageUsage() -> StorageUsage {
        StorageUsage(
            library: Self.size(of: libraryDirectory),
            exports: Self.size(of: exportsDirectory),
            profiles: Self.size(of: profilesDirectory),
            icons: Self.size(of: iconsDirectory),
            temporary: Self.size(of: workDirectory)
        )
    }

    // MARK: - Helpers

    static func size(of url: URL) -> UInt64 {
        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDirectory) else { return 0 }
        if !isDirectory.boolValue {
            let attributes = try? fm.attributesOfItem(atPath: url.path)
            return (attributes?[.size] as? NSNumber)?.uint64Value ?? 0
        }
        guard let enumerator = fm.enumerator(atPath: url.path) else { return 0 }
        var total: UInt64 = 0
        for case let relative as String in enumerator {
            let attributes = try? fm.attributesOfItem(atPath: url.appendingPathComponent(relative).path)
            if (attributes?[.type] as? FileAttributeType) == .typeRegular {
                total += (attributes?[.size] as? NSNumber)?.uint64Value ?? 0
            }
        }
        return total
    }

    private static func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    private static func applyProtection(_ url: URL, sensitive: Bool) {
        #if os(iOS)
        // Sensitive material is unreadable while the device is locked. Large files that jobs may
        // touch in the background use "until first unlock" so a locked screen doesn't kill a job.
        let level: FileProtectionType = sensitive ? .complete : .completeUntilFirstUserAuthentication
        try? FileManager.default.setAttributes([.protectionKey: level], ofItemAtPath: url.path)
        #endif
    }
}
