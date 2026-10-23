import Foundation

public struct InspectionResult: Sendable {
    public var metadata: AppMetadata
    public var iconData: Data?

    public init(metadata: AppMetadata, iconData: Data? = nil) {
        self.metadata = metadata
        self.iconData = iconData
    }
}

/// Extracts app metadata from an archive. The archive is unpacked into a temporary workspace
/// (needed to read nested bundles and Mach-O headers) that is always removed afterwards.
public struct MetadataService: Sendable {
    private let engine: ArchiveEngine
    private let inspector: BundleInspector
    private let store: SecureAssetStore

    public init(engine: ArchiveEngine = ArchiveEngine(), inspector: BundleInspector = BundleInspector(), store: SecureAssetStore) {
        self.engine = engine
        self.inspector = inspector
        self.store = store
    }

    /// Blocking; call from a background task.
    public func inspectArchive(at url: URL, format: ArchiveFormat = .ipa) throws -> InspectionResult {
        let inspection = try engine.inspect(archiveAt: url, format: format)
        guard inspection.hasPayload else { throw InspectionError.missingPayload }
        guard !inspection.appBundlePaths.isEmpty else { throw InspectionError.noAppBundle }
        guard inspection.appBundlePaths.count == 1 else {
            throw InspectionError.multipleAppBundles(inspection.appBundlePaths.map { ($0 as NSString).lastPathComponent })
        }

        let workspace = try store.makeWorkspace()
        defer { store.removeWorkspace(workspace) }

        try engine.extract(archiveAt: url, to: workspace, format: format)
        let appURL = try inspector.locateAppBundle(in: workspace)
        let metadata = try inspector.inspect(appBundle: appURL, uncompressedSize: inspection.totalUncompressedBytes)

        var icon: Data?
        if let relative = metadata.iconRelativePath {
            icon = try? Data(contentsOf: appURL.appendingPathComponent(relative))
        }
        return InspectionResult(metadata: metadata, iconData: icon)
    }
}
