import Foundation

public struct DistributionOption: Codable, Hashable, Sendable, Identifiable {
    public enum Mechanism: String, Codable, Sendable {
        case registeredDevices
        /// `itms-services` installs from an HTTPS-hosted manifest.
        case overTheAir
        case alternativeDistribution
        case testFlightOrAppStore
        case manualExport
    }

    public enum Applicability: String, Codable, Sendable {
        /// The build's profile and signing state satisfy this mechanism's technical requirements.
        case applicable
        /// Might work, but depends on things Tessera cannot verify on-device.
        case conditional
        case notApplicable
    }

    public var id: String { mechanism.rawValue }
    public var mechanism: Mechanism
    public var title: String
    public var applicability: Applicability
    public var summary: String
    public var requirements: [String]
    public var blockers: [String]

    public init(
        mechanism: Mechanism,
        title: String,
        applicability: Applicability,
        summary: String,
        requirements: [String] = [],
        blockers: [String] = []
    ) {
        self.mechanism = mechanism
        self.title = title
        self.applicability = applicability
        self.summary = summary
        self.requirements = requirements
        self.blockers = blockers
    }
}

/// Notarization state. Tessera never invents a status: anything other than `.verified`
/// means no verifiable Apple submission result exists for the build.
public enum NotarizationStatus: Codable, Hashable, Sendable {
    case notApplicable(reason: String)
    case notSubmitted
    case unverified(reason: String)
    case verified(submissionID: String, state: String, checkedAt: Date)

    public var summary: String {
        switch self {
        case .notApplicable(let reason): return "Not applicable: \(reason)"
        case .notSubmitted: return "No submission has been made."
        case .unverified(let reason): return "Unverified: \(reason)"
        case .verified(let id, let state, let checkedAt):
            return "Apple reported “\(state)” for submission \(id) at \(ISO8601DateFormatter().string(from: checkedAt))."
        }
    }
}

public struct DistributionResult: Codable, Hashable, Sendable {
    public var options: [DistributionOption]
    public var notarization: NotarizationStatus
    public var generatedAt: Date

    public init(options: [DistributionOption], notarization: NotarizationStatus, generatedAt: Date = Date()) {
        self.options = options
        self.notarization = notarization
        self.generatedAt = generatedAt
    }
}
