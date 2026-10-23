import Foundation

/// Runs signing jobs: validate, plan, check the engine's capability, then (if supported)
/// extract, sign, verify, package and record the result.
///
/// With `UnavailableSigningEngine` the job ends in `.unsupported` after validation, and no
/// output file is created. The signing path after the capability check cannot run until a
/// real engine has been verified on-device (plan phase 4).
public actor SigningCoordinator {
    private let engine: SigningEngine
    private let archiveEngine: ArchiveEngine
    private let inspector: BundleInspector
    private let validation: ValidationService
    private let certificates: CertificateManager
    private let store: SecureAssetStore
    private let repository: LibraryRepository

    public init(
        engine: SigningEngine = UnavailableSigningEngine(),
        archiveEngine: ArchiveEngine = ArchiveEngine(),
        inspector: BundleInspector = BundleInspector(),
        validation: ValidationService = ValidationService(),
        certificates: CertificateManager = CertificateManager(),
        store: SecureAssetStore,
        repository: LibraryRepository
    ) {
        self.engine = engine
        self.archiveEngine = archiveEngine
        self.inspector = inspector
        self.validation = validation
        self.certificates = certificates
        self.store = store
        self.repository = repository
    }

    public nonisolated var capability: SigningCapability { engine.capability }

    public struct Request: Sendable {
        public var artifact: AppArtifact
        public var identityID: String?
        public var profile: ProvisioningProfile?
        public var targetBundleIdentifier: String?
        public var deviceIdentifier: String?

        public init(artifact: AppArtifact, identityID: String?, profile: ProvisioningProfile?, targetBundleIdentifier: String? = nil, deviceIdentifier: String? = nil) {
            self.artifact = artifact
            self.identityID = identityID
            self.profile = profile
            self.targetBundleIdentifier = targetBundleIdentifier
            self.deviceIdentifier = deviceIdentifier
        }
    }

    /// Runs one job to completion and returns its final state. `onUpdate` is called after each change.
    public func run(_ request: Request, onUpdate: @escaping @Sendable (SigningJob) -> Void = { _ in }) async -> SigningJob {
        var job = SigningJob(
            artifactID: request.artifact.id,
            artifactName: request.artifact.metadata.displayName,
            identityID: request.identityID,
            profileID: request.profile?.id,
            state: .running
        )
        func publish(_ step: String? = nil, progress: Double? = nil) async {
            if let step { job.currentStep = step; job.append(step) }
            if let progress { job.progress = progress }
            await repository.upsert(job)
            onUpdate(job)
        }

        await publish("Validating")

        // 1. Validate
        let identity = request.identityID.flatMap { id in certificates.listIdentities().first { $0.id == id } }
        let issues = validation.validateForSigning(
            metadata: request.artifact.metadata,
            profile: request.profile,
            identity: identity,
            targetBundleIdentifier: request.targetBundleIdentifier,
            deviceIdentifier: request.deviceIdentifier
        )
        job.issues = issues
        let errors = issues.filter { $0.severity == .error }
        if !errors.isEmpty {
            return await finish(&job, state: .failed, reason: "Validation found \(errors.count) blocking problem(s).", artifact: request.artifact, status: .needsAttention, onUpdate: onUpdate)
        }

        // 2. Plan
        let plan = SigningPlanner.makePlan(metadata: request.artifact.metadata, targetBundleIdentifier: request.targetBundleIdentifier)
        await publish("Prepared a signing plan for \(plan.steps.count) component(s)", progress: 0.2)

        // 3. Capability gate: unsupported operations fail safely, with no output.
        if case .unavailable(let reason) = engine.capability {
            return await finish(&job, state: .unsupported, reason: reason, artifact: request.artifact, status: .validated, onUpdate: onUpdate)
        }

        guard let profile = request.profile, let identityID = request.identityID else {
            return await finish(&job, state: .failed, reason: "A profile and identity are required.", artifact: request.artifact, status: .needsAttention, onUpdate: onUpdate)
        }

        // 4. Sign in a private workspace that is always removed.
        let workspace: URL
        do {
            workspace = try store.makeWorkspace()
        } catch {
            return await finish(&job, state: .failed, reason: error.localizedDescription, artifact: request.artifact, status: .needsAttention, onUpdate: onUpdate)
        }
        defer { store.removeWorkspace(workspace) }

        do {
            await publish("Extracting", progress: 0.3)
            let archiveURL = store.libraryURL(for: request.artifact.storedFileName)
            try archiveEngine.extract(archiveAt: archiveURL, to: workspace, format: request.artifact.format)
            try Task.checkCancellation()

            let appBundle = try inspector.locateAppBundle(in: workspace)
            let profileData = try store.profileData(id: profile.id)
            try profileData.write(to: appBundle.appendingPathComponent("embedded.mobileprovision"), options: .atomic)

            await publish("Signing", progress: 0.5)
            let signingRequest = SigningRequest(appBundle: appBundle, plan: plan, identityID: identityID, profile: profile, profileData: profileData)
            try await engine.sign(signingRequest) { _ in }
            try Task.checkCancellation()

            await publish("Verifying signatures", progress: 0.8)
            let verification = try await engine.verify(appBundle: appBundle, plan: plan, profile: profile)
            job.issues += verification
            if verification.contains(where: { $0.severity == .error }) {
                return await finish(&job, state: .failed, reason: "The signed output did not pass verification.", artifact: request.artifact, status: .needsAttention, onUpdate: onUpdate)
            }

            await publish("Packaging", progress: 0.9)
            let outputName = "\(UUID().uuidString).\(request.artifact.format.fileExtension)"
            try archiveEngine.package(directory: workspace, to: store.exportURL(for: outputName), format: request.artifact.format)
            job.outputFileName = outputName

            var updated = request.artifact
            updated.signedFileName = outputName
            updated.status = .signed
            await repository.upsert(updated)
            return await finish(&job, state: .succeeded, reason: nil, artifact: nil, status: nil, onUpdate: onUpdate)
        } catch is CancellationError {
            return await finish(&job, state: .cancelled, reason: "Cancelled.", artifact: nil, status: nil, onUpdate: onUpdate)
        } catch {
            return await finish(&job, state: .failed, reason: error.localizedDescription, artifact: request.artifact, status: .needsAttention, onUpdate: onUpdate)
        }
    }

    private func finish(
        _ job: inout SigningJob,
        state: SigningJob.State,
        reason: String?,
        artifact: AppArtifact?,
        status: AppArtifact.Status?,
        onUpdate: @Sendable (SigningJob) -> Void
    ) async -> SigningJob {
        job.state = state
        job.failureReason = reason
        job.finishedAt = Date()
        job.currentStep = nil
        job.progress = state == .succeeded ? 1 : job.progress
        if let reason { job.append(reason) }
        await repository.upsert(job)

        if var artifact, let status {
            artifact.status = status
            artifact.issues = job.issues
            await repository.upsert(artifact)
        }
        onUpdate(job)
        return job
    }
}
