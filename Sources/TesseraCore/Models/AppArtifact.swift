import Foundation

/// A build tracked in the local library.
public struct AppArtifact: Codable, Hashable, Sendable, Identifiable {
    public enum Status: String, Codable, Sendable, CaseIterable {
        case imported
        case validated
        case signed
        case exported
        case needsAttention

        public var displayName: String {
            switch self {
            case .imported: return "Imported"
            case .validated: return "Validated"
            case .signed: return "Signed"
            case .exported: return "Exported"
            case .needsAttention: return "Needs Attention"
            }
        }
    }

    public var id: UUID
    public var originalFileName: String
    public var importedAt: Date
    /// Size of the archive on disk in bytes.
    public var fileSize: UInt64
    public var format: ArchiveFormat
    /// File name of the stored copy, relative to the library directory.
    public var storedFileName: String
    /// File name of a signed output, relative to the exports directory.
    public var signedFileName: String?
    /// File name of a cached icon, relative to the icons directory.
    public var iconFileName: String?
    public var metadata: AppMetadata
    public var status: Status
    public var issues: [ValidationIssue]

    public init(
        id: UUID = UUID(),
        originalFileName: String,
        importedAt: Date = Date(),
        fileSize: UInt64,
        format: ArchiveFormat = .ipa,
        storedFileName: String,
        signedFileName: String? = nil,
        iconFileName: String? = nil,
        metadata: AppMetadata,
        status: Status = .imported,
        issues: [ValidationIssue] = []
    ) {
        self.id = id
        self.originalFileName = originalFileName
        self.importedAt = importedAt
        self.fileSize = fileSize
        self.format = format
        self.storedFileName = storedFileName
        self.signedFileName = signedFileName
        self.iconFileName = iconFileName
        self.metadata = metadata
        self.status = status
        self.issues = issues
    }
}
