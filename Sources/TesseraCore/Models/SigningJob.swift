import Foundation

public struct SigningJob: Codable, Hashable, Sendable, Identifiable {
    public enum State: String, Codable, Sendable {
        case queued
        case running
        case succeeded
        case failed
        /// The required signing operation is not available; no output was produced.
        case unsupported
        case cancelled
    }

    public struct LogLine: Codable, Hashable, Sendable {
        public var date: Date
        public var message: String

        public init(date: Date = Date(), message: String) {
            self.date = date
            self.message = message
        }
    }

    public var id: UUID
    public var artifactID: UUID
    public var artifactName: String
    public var identityID: String?
    public var profileID: String?
    public var state: State
    public var currentStep: String?
    public var progress: Double
    public var createdAt: Date
    public var finishedAt: Date?
    public var log: [LogLine]
    public var issues: [ValidationIssue]
    /// File name of the signed IPA, relative to the exports directory.
    public var outputFileName: String?
    public var failureReason: String?

    public init(
        id: UUID = UUID(),
        artifactID: UUID,
        artifactName: String,
        identityID: String? = nil,
        profileID: String? = nil,
        state: State = .queued,
        currentStep: String? = nil,
        progress: Double = 0,
        createdAt: Date = Date(),
        finishedAt: Date? = nil,
        log: [LogLine] = [],
        issues: [ValidationIssue] = [],
        outputFileName: String? = nil,
        failureReason: String? = nil
    ) {
        self.id = id
        self.artifactID = artifactID
        self.artifactName = artifactName
        self.identityID = identityID
        self.profileID = profileID
        self.state = state
        self.currentStep = currentStep
        self.progress = progress
        self.createdAt = createdAt
        self.finishedAt = finishedAt
        self.log = log
        self.issues = issues
        self.outputFileName = outputFileName
        self.failureReason = failureReason
    }

    public mutating func append(_ message: String) {
        log.append(LogLine(message: message))
    }
}
