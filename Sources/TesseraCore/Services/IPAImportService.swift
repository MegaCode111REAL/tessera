import Foundation

public enum ImportError: Error, LocalizedError, Equatable {
    case notAnArchive(String)
    case fileTooLarge(UInt64)
    case fileUnreadable(String)

    public var errorDescription: String? {
        switch self {
        case .notAnArchive(let name): return "“\(name)” is not an .ipa file."
        case .fileTooLarge(let size): return "The file is \(size / 1_048_576) MB, which exceeds Tessera's import limit."
        case .fileUnreadable(let name): return "“\(name)” could not be read."
        }
    }
}

/// Imports a user-selected archive: validates it, copies it into the library, extracts its
/// metadata, and records it in the repository.
public struct IPAImportService: Sendable {
    public static let defaultMaxFileSize: UInt64 = 8 * 1024 * 1024 * 1024

    private let store: SecureAssetStore
    private let metadataService: MetadataService
    private let validation: ValidationService
    private let repository: LibraryRepository
    private let maxFileSize: UInt64

    public init(
        store: SecureAssetStore,
        metadataService: MetadataService,
        validation: ValidationService = ValidationService(),
        repository: LibraryRepository,
        maxFileSize: UInt64 = IPAImportService.defaultMaxFileSize
    ) {
        self.store = store
        self.metadataService = metadataService
        self.validation = validation
        self.repository = repository
        self.maxFileSize = maxFileSize
    }

    /// Imports the file at `url`, which may be a security-scoped URL from the Files picker.
    public func importArchive(from url: URL) async throws -> AppArtifact {
        let name = url.lastPathComponent
        guard let format = ArchiveFormat(fileExtension: url.pathExtension) else {
            throw ImportError.notAnArchive(name)
        }
        guard format.isSupported else {
            // Surfaces the adapter's "not supported yet" message for formats like .tipa.
            _ = try FormatAdapterRegistry.adapter(for: format)
            throw ImportError.notAnArchive(name)
        }

        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value else {
            throw ImportError.fileUnreadable(name)
        }
        guard size <= maxFileSize else { throw ImportError.fileTooLarge(size) }

        let stored = try store.storeArchive(from: url, fileExtension: format.fileExtension)
        let storedURL = store.libraryURL(for: stored.fileName)
        let service = metadataService

        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try service.inspectArchive(at: storedURL, format: format)
            }.value

            let id = UUID()
            let issues = validation.inspectionIssues(for: result.metadata)
            let iconName = result.iconData.flatMap { store.saveIcon($0, artifactID: id) }
            let artifact = AppArtifact(
                id: id,
                originalFileName: name,
                fileSize: stored.size,
                format: format,
                storedFileName: stored.fileName,
                iconFileName: iconName,
                metadata: result.metadata,
                status: issues.contains { $0.severity == .error } ? .needsAttention : .imported,
                issues: issues
            )
            await repository.upsert(artifact)
            return artifact
        } catch ArchiveError.cannotOpen(_) {
            // Report the user's file name, not the internal name of the stored copy.
            try? FileManager.default.removeItem(at: storedURL)
            throw ArchiveError.cannotOpen(name)
        } catch {
            try? FileManager.default.removeItem(at: storedURL)
            throw error
        }
    }
}
