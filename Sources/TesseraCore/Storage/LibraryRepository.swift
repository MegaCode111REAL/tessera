import Foundation

/// Lightweight persistence for library records and signing-job history.
///
/// The plan allows "SwiftData or a lightweight database". This uses atomic JSON files so the
/// logic is plain Codable, testable without a model container, and easy to migrate later.
public actor LibraryRepository {
    private let artifactsURL: URL
    private let jobsURL: URL
    private var artifacts: [UUID: AppArtifact]
    private var jobs: [UUID: SigningJob]

    private static let maxStoredJobs = 200

    public init(directory: URL) {
        artifactsURL = directory.appendingPathComponent("library.json")
        jobsURL = directory.appendingPathComponent("jobs.json")
        let loadedArtifacts: [AppArtifact] = Self.load(artifactsURL)
        let loadedJobs: [SigningJob] = Self.load(jobsURL)
        artifacts = Dictionary(uniqueKeysWithValues: loadedArtifacts.map { ($0.id, $0) })
        jobs = Dictionary(uniqueKeysWithValues: loadedJobs.map { ($0.id, $0) })
    }

    // MARK: - Artifacts

    public func allArtifacts() -> [AppArtifact] {
        artifacts.values.sorted { $0.importedAt > $1.importedAt }
    }

    public func artifact(id: UUID) -> AppArtifact? {
        artifacts[id]
    }

    public func upsert(_ artifact: AppArtifact) {
        artifacts[artifact.id] = artifact
        saveArtifacts()
    }

    @discardableResult
    public func removeArtifact(id: UUID) -> AppArtifact? {
        let removed = artifacts.removeValue(forKey: id)
        if removed != nil { saveArtifacts() }
        return removed
    }

    // MARK: - Jobs

    public func allJobs() -> [SigningJob] {
        jobs.values.sorted { $0.createdAt > $1.createdAt }
    }

    public func upsert(_ job: SigningJob) {
        jobs[job.id] = job
        if jobs.count > Self.maxStoredJobs {
            let overflow = jobs.values.sorted { $0.createdAt < $1.createdAt }.prefix(jobs.count - Self.maxStoredJobs)
            for old in overflow { jobs.removeValue(forKey: old.id) }
        }
        saveJobs()
    }

    public func clearJobs() {
        jobs.removeAll()
        saveJobs()
    }

    // MARK: - Persistence

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// Loads a JSON array. A corrupt file is set aside (not deleted) and the store starts empty.
    private static func load<T: Decodable>(_ url: URL) -> [T] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        if let values = try? makeDecoder().decode([T].self, from: data) { return values }
        let aside = url.deletingPathExtension().appendingPathExtension("corrupt.json")
        try? FileManager.default.removeItem(at: aside)
        try? FileManager.default.moveItem(at: url, to: aside)
        return []
    }

    private func saveArtifacts() {
        write(Array(artifacts.values), to: artifactsURL)
    }

    private func saveJobs() {
        write(Array(jobs.values), to: jobsURL)
    }

    private func write<T: Encodable>(_ values: [T], to url: URL) {
        guard let data = try? Self.makeEncoder().encode(values) else { return }
        #if os(iOS)
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try? data.write(to: url, options: .atomic)
        #endif
    }
}
