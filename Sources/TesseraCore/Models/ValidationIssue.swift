import Foundation

public struct ValidationIssue: Codable, Hashable, Sendable, Identifiable {
    public enum Severity: String, Codable, Sendable, CaseIterable {
        case info
        case warning
        case error

        public var rank: Int {
            switch self {
            case .info: return 0
            case .warning: return 1
            case .error: return 2
            }
        }
    }

    public var id: String { "\(code)|\(message)" }
    public var code: String
    public var severity: Severity
    public var message: String

    public init(code: String, severity: Severity, message: String) {
        self.code = code
        self.severity = severity
        self.message = message
    }
}

public struct ValidationReport: Codable, Hashable, Sendable {
    public var artifactName: String
    public var bundleIdentifier: String
    public var generatedAt: Date
    public var issues: [ValidationIssue]

    public init(artifactName: String, bundleIdentifier: String, generatedAt: Date = Date(), issues: [ValidationIssue]) {
        self.artifactName = artifactName
        self.bundleIdentifier = bundleIdentifier
        self.generatedAt = generatedAt
        self.issues = issues
    }

    public var errors: [ValidationIssue] { issues.filter { $0.severity == .error } }
    public var warnings: [ValidationIssue] { issues.filter { $0.severity == .warning } }

    /// True when no blocking errors were found. Warnings do not block.
    public var canProceed: Bool { errors.isEmpty }
}
