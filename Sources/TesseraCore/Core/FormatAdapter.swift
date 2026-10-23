import Foundation
import ZIPFoundation

/// Archive formats Tessera knows about. Only `.ipa` is enabled today; `.tipa` is a
/// placeholder so adding it later means registering an adapter, not reworking the app.
public enum ArchiveFormat: String, Codable, Hashable, Sendable, CaseIterable {
    case ipa
    case tipa

    public var fileExtension: String { rawValue }

    public init?(fileExtension: String) {
        self.init(rawValue: fileExtension.lowercased())
    }

    /// Whether an adapter for this format is currently enabled.
    public var isSupported: Bool {
        FormatAdapterRegistry.isEnabled(self)
    }
}

public struct ArchiveEntryInfo: Hashable, Sendable {
    public enum Kind: String, Sendable {
        case file
        case directory
        case symlink
    }

    public var path: String
    public var kind: Kind
    public var uncompressedSize: UInt64
    public var compressedSize: UInt64

    public init(path: String, kind: Kind, uncompressedSize: UInt64, compressedSize: UInt64) {
        self.path = path
        self.kind = kind
        self.uncompressedSize = uncompressedSize
        self.compressedSize = compressedSize
    }
}

/// Abstracts reading, extracting and packaging one archive format.
public protocol FormatAdapter: Sendable {
    var format: ArchiveFormat { get }

    func listEntries(at archiveURL: URL) throws -> [ArchiveEntryInfo]

    /// Reads one entry into memory, refusing entries larger than `maxBytes`.
    func readEntry(_ path: String, at archiveURL: URL, maxBytes: UInt64) throws -> Data

    /// Safely extracts the whole archive into `destination`, enforcing `limits`.
    func extract(
        archiveAt archiveURL: URL,
        to destination: URL,
        limits: ExtractionLimits,
        progress: (@Sendable (Double) -> Void)?
    ) throws

    /// Packages the contents of `directory` (which should contain `Payload/`) into an archive.
    func package(directory: URL, to archiveURL: URL) throws
}

public enum FormatAdapterRegistry {
    public static func isEnabled(_ format: ArchiveFormat) -> Bool {
        switch format {
        case .ipa: return true
        case .tipa: return false
        }
    }

    public static func adapter(for format: ArchiveFormat) throws -> FormatAdapter {
        guard isEnabled(format) else {
            throw ArchiveError.unsupportedFormat(".\(format.fileExtension) archives are not supported yet.")
        }
        return ZipFormatAdapter(format: format)
    }
}

/// ZIP-based adapter. IPA files are ZIP archives with a `Payload/` directory, and `.tipa`
/// files use the same container, so a future `.tipa` adapter can reuse this type.
public struct ZipFormatAdapter: FormatAdapter {
    public let format: ArchiveFormat

    public init(format: ArchiveFormat) {
        self.format = format
    }

    private func open(_ url: URL) throws -> Archive {
        // `try?` keeps this compiling whether ZIPFoundation's initialiser is failable or throwing.
        guard let archive = try? Archive(url: url, accessMode: .read) else {
            throw ArchiveError.cannotOpen(url.lastPathComponent)
        }
        return archive
    }

    private func info(for entry: Entry) -> ArchiveEntryInfo {
        let kind: ArchiveEntryInfo.Kind
        switch entry.type {
        case .file: kind = .file
        case .directory: kind = .directory
        case .symlink: kind = .symlink
        }
        return ArchiveEntryInfo(
            path: entry.path,
            kind: kind,
            uncompressedSize: UInt64(truncatingIfNeeded: entry.uncompressedSize),
            compressedSize: UInt64(truncatingIfNeeded: entry.compressedSize)
        )
    }

    public func listEntries(at archiveURL: URL) throws -> [ArchiveEntryInfo] {
        let archive = try open(archiveURL)
        return archive.map { info(for: $0) }
    }

    public func readEntry(_ path: String, at archiveURL: URL, maxBytes: UInt64) throws -> Data {
        let archive = try open(archiveURL)
        guard let entry = archive[path] else {
            throw ArchiveError.missingEntry(path)
        }
        let declared = UInt64(truncatingIfNeeded: entry.uncompressedSize)
        guard declared <= maxBytes else {
            throw ArchiveError.entryTooLarge(path: path, size: declared)
        }
        var data = Data()
        do {
            _ = try archive.extract(entry) { chunk in
                data.append(chunk)
                if UInt64(data.count) > maxBytes {
                    throw ArchiveError.entryTooLarge(path: path, size: UInt64(data.count))
                }
            }
        } catch let error as ArchiveError {
            throw error
        } catch {
            throw ArchiveError.extractionFailed("\(path): \(error.localizedDescription)")
        }
        return data
    }

    public func extract(
        archiveAt archiveURL: URL,
        to destination: URL,
        limits: ExtractionLimits,
        progress: (@Sendable (Double) -> Void)?
    ) throws {
        let archive = try open(archiveURL)
        let entries = archive.map { (entry: $0, info: info(for: $0)) }
        try ArchiveSafety.checkLimits(entries.map(\.info), limits: limits)

        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)

        var seen = Set<String>()
        let total = max(entries.count, 1)
        for (index, item) in entries.enumerated() {
            try Task.checkCancellation()
            let normalized = try ArchiveSafety.validate(entryPath: item.info.path)
            guard seen.insert(normalized).inserted else {
                throw ArchiveError.unsafePath("duplicate entry \(normalized)")
            }
            let target = try ArchiveSafety.resolve(normalized, inside: destination)

            switch item.info.kind {
            case .symlink:
                throw ArchiveError.symlinkNotAllowed(normalized)
            case .directory:
                try fm.createDirectory(at: target, withIntermediateDirectories: true)
            case .file:
                try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
                do {
                    _ = try archive.extract(item.entry, to: target)
                } catch {
                    throw ArchiveError.extractionFailed("\(normalized): \(error.localizedDescription)")
                }
            }
            progress?(Double(index + 1) / Double(total))
        }
    }

    public func package(directory: URL, to archiveURL: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: archiveURL.path) {
            try fm.removeItem(at: archiveURL)
        }
        do {
            try fm.zipItem(at: directory, to: archiveURL, shouldKeepParent: false, compressionMethod: .deflate)
        } catch {
            throw ArchiveError.packagingFailed(error.localizedDescription)
        }
    }
}
