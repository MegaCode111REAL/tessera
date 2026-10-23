import Foundation
import Observation
import TesseraCore

struct AppAlert: Identifiable {
    let id = UUID()
    var title: String
    var message: String
}

/// UI-facing state. All heavy work is delegated to `TesseraCore` services.
@MainActor
@Observable
final class AppState {
    let dependencies: AppDependencies

    var artifacts: [AppArtifact] = []
    var profiles: [ProvisioningProfile] = []
    var identities: [SigningIdentityInfo] = []
    var jobs: [SigningJob] = []
    var storageUsage = StorageUsage(library: 0, exports: 0, profiles: 0, icons: 0, temporary: 0)

    var isBusy = false
    var busyMessage = ""
    var alert: AppAlert?
    var runningJob: SigningJob?
    /// Local diagnostics. Never contains key material, passwords or file contents.
    var diagnostics: [String] = []

    init(dependencies: AppDependencies) {
        self.dependencies = dependencies
    }

    var signingCapability: SigningCapability {
        dependencies.coordinator.capability
    }

    // MARK: - Loading

    func reload() async {
        artifacts = await dependencies.repository.allArtifacts()
        jobs = await dependencies.repository.allJobs()
        profiles = dependencies.store.listProfiles()
        identities = dependencies.certificates.listIdentities()
        storageUsage = dependencies.store.storageUsage()
    }

    func artifact(id: UUID?) -> AppArtifact? {
        guard let id else { return nil }
        return artifacts.first { $0.id == id }
    }

    func log(_ message: String) {
        let stamp = Date().formatted(date: .omitted, time: .standard)
        diagnostics.append("\(stamp)  \(message)")
        if diagnostics.count > 500 { diagnostics.removeFirst(diagnostics.count - 500) }
    }

    // MARK: - Library

    func importArchives(_ urls: [URL]) async {
        guard !urls.isEmpty else { return }
        isBusy = true
        defer { isBusy = false; busyMessage = "" }

        var failures: [String] = []
        for url in urls {
            busyMessage = "Importing \(url.lastPathComponent)…"
            do {
                let artifact = try await dependencies.importService.importArchive(from: url)
                log("Imported \(artifact.metadata.bundleIdentifier) \(artifact.metadata.versionDescription)")
            } catch {
                failures.append("\(url.lastPathComponent): \(error.localizedDescription)")
                log("Import failed for \(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        await reload()
        if !failures.isEmpty {
            alert = AppAlert(title: failures.count == 1 ? "Couldn't import file" : "Couldn't import \(failures.count) files",
                             message: failures.joined(separator: "\n\n"))
        }
    }

    func delete(_ artifact: AppArtifact) async {
        await dependencies.repository.removeArtifact(id: artifact.id)
        dependencies.store.removeFiles(for: artifact)
        log("Removed \(artifact.metadata.bundleIdentifier)")
        await reload()
    }

    // MARK: - Profiles

    func importProfile(from url: URL) async {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            let profile = try ProfileParser().parse(data)
            try dependencies.store.saveProfile(data: data, profile: profile)
            log("Imported profile \(profile.name)")
            if profile.isExpired() {
                alert = AppAlert(title: "Profile imported, but expired",
                                 message: "“\(profile.name)” expired on \(profile.expirationDate.formatted(date: .abbreviated, time: .omitted)) and can't be used to sign.")
            }
        } catch {
            alert = AppAlert(title: "Couldn't import profile", message: error.localizedDescription)
            log("Profile import failed: \(error.localizedDescription)")
        }
        await reload()
    }

    func deleteProfile(_ profile: ProvisioningProfile) async {
        dependencies.store.deleteProfile(id: profile.id)
        await reload()
    }

    // MARK: - Certificates

    func importP12(from url: URL, password: String) async -> Bool {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            let identity = try dependencies.certificates.importP12(data, password: password)
            log("Imported signing identity \(identity.displayName)")
            await reload()
            return true
        } catch {
            alert = AppAlert(title: "Couldn't import certificate", message: error.localizedDescription)
            log("Certificate import failed: \(error.localizedDescription)")
            return false
        }
    }

    func deleteIdentity(_ identity: SigningIdentityInfo) async {
        do {
            try dependencies.certificates.delete(identityID: identity.id)
            log("Removed signing identity \(identity.displayName)")
        } catch {
            alert = AppAlert(title: "Couldn't remove certificate", message: error.localizedDescription)
        }
        await reload()
    }

    // MARK: - Signing

    /// Live validation shown in the wizard before anything runs.
    func validationIssues(
        artifact: AppArtifact,
        identityID: String?,
        profile: ProvisioningProfile?,
        targetBundleIdentifier: String?
    ) -> [ValidationIssue] {
        dependencies.validation.validateForSigning(
            metadata: artifact.metadata,
            profile: profile,
            identity: identities.first { $0.id == identityID },
            targetBundleIdentifier: targetBundleIdentifier?.isEmpty == true ? nil : targetBundleIdentifier
        )
    }

    func runSigning(
        artifact: AppArtifact,
        identityID: String?,
        profile: ProvisioningProfile?,
        targetBundleIdentifier: String?
    ) async -> SigningJob {
        let request = SigningCoordinator.Request(
            artifact: artifact,
            identityID: identityID,
            profile: profile,
            targetBundleIdentifier: targetBundleIdentifier?.isEmpty == true ? nil : targetBundleIdentifier
        )
        log("Started signing job for \(artifact.metadata.bundleIdentifier)")
        let job = await dependencies.coordinator.run(request) { [weak self] update in
            Task { @MainActor in self?.runningJob = update }
        }
        runningJob = nil
        log("Signing job finished: \(job.state.rawValue)")
        await reload()
        return job
    }

    // MARK: - Distribution & export

    func distribution(for artifact: AppArtifact) -> DistributionResult {
        let signedURL = dependencies.export.signedIPAURL(for: artifact)
        let succeeded = jobs.first { $0.artifactID == artifact.id && $0.state == .succeeded }
        let profile = succeeded.flatMap { job in profiles.first { $0.id == job.profileID } }
            ?? artifact.metadata.embeddedProfile
        return dependencies.distribution.evaluate(
            profile: profile,
            hasVerifiedSignedOutput: signedURL != nil && succeeded != nil
        )
    }

    func shareableURL(for artifact: AppArtifact, signed: Bool) -> URL? {
        try? dependencies.export.shareableURL(for: artifact, signed: signed)
    }

    func writeReport(for artifact: AppArtifact, format: ReportFormat) -> URL? {
        let report = dependencies.validation.report(for: artifact, issues: artifact.issues)
        return try? dependencies.export.writeReport(report, format: format)
    }

    // MARK: - Settings

    func cleanTemporaryFiles() async {
        let freed = dependencies.store.cleanTemporaryFiles()
        log("Cleaned temporary files (\(ByteCountFormatter.string(fromByteCount: Int64(freed), countStyle: .file)))")
        await reload()
    }

    func clearActivity() async {
        await dependencies.repository.clearJobs()
        await reload()
    }
}
