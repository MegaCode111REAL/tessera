import Foundation

public enum ReportFormat: String, Sendable, CaseIterable {
    case json
    case markdown

    public var fileExtension: String { self == .json ? "json" : "md" }
}

/// Produces files the user can share: IPAs under friendly names and validation reports.
public struct ExportService: Sendable {
    private let store: SecureAssetStore

    public init(store: SecureAssetStore) {
        self.store = store
    }

    /// The signed output for `artifact`, if one exists on disk.
    public func signedIPAURL(for artifact: AppArtifact) -> URL? {
        guard let name = artifact.signedFileName else { return nil }
        let url = store.exportURL(for: name)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    public func originalURL(for artifact: AppArtifact) -> URL {
        store.libraryURL(for: artifact.storedFileName)
    }

    /// A user-friendly file name such as `My App-1.2 (34).ipa`, with path-unsafe characters removed.
    public static func friendlyFileName(for artifact: AppArtifact, signed: Bool) -> String {
        let base = artifact.metadata.displayName
        let version = artifact.metadata.versionDescription
        var name = version.isEmpty ? base : "\(base)-\(version)"
        if signed { name += "-signed" }
        let unsafe = CharacterSet(charactersIn: "/\\:*?\"<>|\0")
        name = name.components(separatedBy: unsafe).joined(separator: "_")
        return "\(name).\(artifact.format.fileExtension)"
    }

    /// Returns a temporary URL with a friendly name for the share sheet. Uses a hard link when
    /// possible so a large IPA is not duplicated on disk.
    public func shareableURL(for artifact: AppArtifact, signed: Bool) throws -> URL {
        let source: URL
        if signed {
            guard let signedURL = signedIPAURL(for: artifact) else { throw StoreError.notFound("signed output") }
            source = signedURL
        } else {
            source = originalURL(for: artifact)
        }

        let fm = FileManager.default
        let directory = fm.temporaryDirectory.appendingPathComponent("Tessera-Share", isDirectory: true)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let destination = directory.appendingPathComponent(Self.friendlyFileName(for: artifact, signed: signed))
        try? fm.removeItem(at: destination)
        do {
            try fm.linkItem(at: source, to: destination)
        } catch {
            try fm.copyItem(at: source, to: destination)
        }
        return destination
    }

    /// Writes a validation report into the exports directory and returns its URL.
    public func writeReport(_ report: ValidationReport, format: ReportFormat) throws -> URL {
        let stamp = ISO8601DateFormatter().string(from: report.generatedAt)
            .replacingOccurrences(of: ":", with: "-")
        let safeID = report.bundleIdentifier.replacingOccurrences(of: "/", with: "_")
        let url = store.exportURL(for: "\(safeID)-validation-\(stamp).\(format.fileExtension)")

        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(report).write(to: url, options: .atomic)
        case .markdown:
            try Data(Self.markdown(for: report).utf8).write(to: url, options: .atomic)
        }
        return url
    }

    public static func markdown(for report: ValidationReport) -> String {
        var lines: [String] = []
        lines.append("# Validation Report: \(report.artifactName)")
        lines.append("")
        lines.append("- Bundle identifier: `\(report.bundleIdentifier)`")
        lines.append("- Generated: \(ISO8601DateFormatter().string(from: report.generatedAt))")
        lines.append("- Result: " + (report.canProceed
            ? "No blocking problems (\(report.warnings.count) warning(s))"
            : "\(report.errors.count) blocking problem(s)"))

        let sections: [(String, ValidationIssue.Severity)] = [("Errors", .error), ("Warnings", .warning), ("Notes", .info)]
        for (title, severity) in sections {
            let matching = report.issues.filter { $0.severity == severity }
            guard !matching.isEmpty else { continue }
            lines.append("")
            lines.append("## \(title)")
            lines.append("")
            for issue in matching {
                lines.append("- **\(issue.code)**: \(issue.message)")
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }
}
