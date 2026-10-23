import Foundation

public struct ExtractionLimits: Sendable, Equatable {
    public var maxEntryCount: Int
    public var maxTotalUncompressedBytes: UInt64
    public var maxSingleEntryBytes: UInt64
    /// Maximum uncompressed/compressed ratio for entries larger than 1 MiB (decompression-bomb guard).
    public var maxCompressionRatio: Double

    public init(
        maxEntryCount: Int = 100_000,
        maxTotalUncompressedBytes: UInt64 = 8 * 1024 * 1024 * 1024,
        maxSingleEntryBytes: UInt64 = 4 * 1024 * 1024 * 1024,
        maxCompressionRatio: Double = 1000
    ) {
        self.maxEntryCount = maxEntryCount
        self.maxTotalUncompressedBytes = maxTotalUncompressedBytes
        self.maxSingleEntryBytes = maxSingleEntryBytes
        self.maxCompressionRatio = maxCompressionRatio
    }

    public static let `default` = ExtractionLimits()
}

public enum ArchiveError: Error, LocalizedError, Equatable {
    case unsupportedFormat(String)
    case cannotOpen(String)
    case unsafePath(String)
    case symlinkNotAllowed(String)
    case tooManyEntries(Int)
    case entryTooLarge(path: String, size: UInt64)
    case archiveTooLarge(UInt64)
    case suspiciousCompressionRatio(String)
    case missingEntry(String)
    case extractionFailed(String)
    case packagingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedFormat(let message): return message
        case .cannotOpen(let name): return "“\(name)” is not a readable archive."
        case .unsafePath(let path): return "The archive contains an unsafe path: \(path)."
        case .symlinkNotAllowed(let path): return "The archive contains a symbolic link (\(path)), which Tessera refuses to extract."
        case .tooManyEntries(let count): return "The archive has too many entries (\(count))."
        case .entryTooLarge(let path, let size): return "“\(path)” is too large (\(size) bytes)."
        case .archiveTooLarge(let size): return "The archive would expand to \(size) bytes, which exceeds the safety limit."
        case .suspiciousCompressionRatio(let path): return "“\(path)” has a suspicious compression ratio and was rejected."
        case .missingEntry(let path): return "The archive does not contain “\(path)”."
        case .extractionFailed(let message): return "Extraction failed: \(message)"
        case .packagingFailed(let message): return "Packaging failed: \(message)"
        }
    }
}

/// Pure, side-effect-free safety checks shared by all archive adapters.
public enum ArchiveSafety {
    /// Validates and normalises an archive entry path. Rejects absolute paths, `..`
    /// components, backslashes, NUL bytes and drive-letter prefixes.
    public static func validate(entryPath: String) throws -> String {
        guard !entryPath.isEmpty,
              !entryPath.contains("\0"),
              !entryPath.contains("\\"),
              !entryPath.hasPrefix("/") else {
            throw ArchiveError.unsafePath(entryPath)
        }
        let chars = Array(entryPath)
        if chars.count >= 2, chars[1] == ":", chars[0].isLetter {
            throw ArchiveError.unsafePath(entryPath)
        }
        var components: [Substring] = []
        for component in entryPath.split(separator: "/", omittingEmptySubsequences: true) {
            if component == ".." { throw ArchiveError.unsafePath(entryPath) }
            if component == "." { continue }
            components.append(component)
        }
        guard !components.isEmpty else { throw ArchiveError.unsafePath(entryPath) }
        return components.joined(separator: "/")
    }

    /// Resolves `relativePath` under `root` and confirms the result stays inside `root`.
    public static func resolve(_ relativePath: String, inside root: URL) throws -> URL {
        let rootPath = root.standardizedFileURL.path
        let target = root.appendingPathComponent(relativePath).standardizedFileURL
        guard target.path.hasPrefix(rootPath + "/") else {
            throw ArchiveError.unsafePath(relativePath)
        }
        return target
    }

    public static func checkLimits(_ entries: [ArchiveEntryInfo], limits: ExtractionLimits) throws {
        guard entries.count <= limits.maxEntryCount else {
            throw ArchiveError.tooManyEntries(entries.count)
        }
        var total: UInt64 = 0
        for entry in entries where entry.kind == .file {
            guard entry.uncompressedSize <= limits.maxSingleEntryBytes else {
                throw ArchiveError.entryTooLarge(path: entry.path, size: entry.uncompressedSize)
            }
            if entry.uncompressedSize > 1_048_576, entry.compressedSize > 0 {
                let ratio = Double(entry.uncompressedSize) / Double(entry.compressedSize)
                if ratio > limits.maxCompressionRatio {
                    throw ArchiveError.suspiciousCompressionRatio(entry.path)
                }
            }
            let (sum, overflow) = total.addingReportingOverflow(entry.uncompressedSize)
            if overflow || sum > limits.maxTotalUncompressedBytes {
                throw ArchiveError.archiveTooLarge(overflow ? UInt64.max : sum)
            }
            total = sum
        }
    }
}

/// Result of inspecting an archive without extracting it.
public struct ArchiveInspection: Sendable {
    public var entries: [ArchiveEntryInfo]
    public var totalUncompressedBytes: UInt64
    /// Paths such as `Payload/Foo.app` for each top-level app bundle found.
    public var appBundlePaths: [String]

    public var hasPayload: Bool {
        entries.contains { $0.path == "Payload/" || $0.path.hasPrefix("Payload/") }
    }
}

/// Safely inspects, extracts and packages archives through a `FormatAdapter`.
public struct ArchiveEngine: Sendable {
    public let limits: ExtractionLimits

    public init(limits: ExtractionLimits = .default) {
        self.limits = limits
    }

    /// Lists an archive, validates every path against the safety rules and limits,
    /// and locates the `Payload/*.app` bundles. Nothing is written to disk.
    public func inspect(archiveAt url: URL, format: ArchiveFormat = .ipa) throws -> ArchiveInspection {
        let adapter = try FormatAdapterRegistry.adapter(for: format)
        let entries = try adapter.listEntries(at: url)
        try ArchiveSafety.checkLimits(entries, limits: limits)

        var total: UInt64 = 0
        var apps = Set<String>()
        for entry in entries {
            let normalized = try ArchiveSafety.validate(entryPath: entry.path)
            if entry.kind == .symlink { throw ArchiveError.symlinkNotAllowed(normalized) }
            if entry.kind == .file { total += entry.uncompressedSize }
            let parts = normalized.split(separator: "/")
            if parts.count >= 2, parts[0] == "Payload", parts[1].hasSuffix(".app") {
                apps.insert("Payload/\(parts[1])")
            }
        }
        return ArchiveInspection(
            entries: entries,
            totalUncompressedBytes: total,
            appBundlePaths: apps.sorted()
        )
    }

    public func readEntry(_ path: String, from url: URL, format: ArchiveFormat = .ipa, maxBytes: UInt64 = 16 * 1024 * 1024) throws -> Data {
        try FormatAdapterRegistry.adapter(for: format).readEntry(path, at: url, maxBytes: maxBytes)
    }

    public func extract(
        archiveAt url: URL,
        to destination: URL,
        format: ArchiveFormat = .ipa,
        progress: (@Sendable (Double) -> Void)? = nil
    ) throws {
        let adapter = try FormatAdapterRegistry.adapter(for: format)
        try adapter.extract(archiveAt: url, to: destination, limits: limits, progress: progress)
    }

    public func package(directory: URL, to url: URL, format: ArchiveFormat = .ipa) throws {
        try FormatAdapterRegistry.adapter(for: format).package(directory: directory, to: url)
    }
}
