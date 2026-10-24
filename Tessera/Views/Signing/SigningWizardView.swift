import SwiftUI
import TesseraCore

/// The eight-step signing flow from the plan, shown as one scrolling form so the user can
/// see exactly what blocks a job before running it.
struct SigningWizardView: View {
    @Environment(AppState.self) private var state
    @Environment(AppRouter.self) private var router

    @State private var artifactID: UUID?
    @State private var identityID: String?
    @State private var profileID: String?
    @State private var bundleIDOverride = ""
    @State private var adHoc = false
    @State private var lastJob: SigningJob?
    @State private var isRunning = false
    @State private var shareItem: ShareItem?

    private var artifact: AppArtifact? { state.artifact(id: artifactID) }
    private var profile: ProvisioningProfile? { state.profiles.first { $0.id == profileID } }

    private var issues: [ValidationIssue] {
        guard let artifact, !adHoc else { return [] }
        return state.validationIssues(
            artifact: artifact,
            identityID: identityID,
            profile: profile,
            targetBundleIdentifier: bundleIDOverride
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                if !state.signingCapability.isAvailable {
                    Section { CapabilityBanner(capability: state.signingCapability) }
                }

                Section {
                    Picker("Build", selection: $artifactID) {
                        Text("Choose…").tag(UUID?.none)
                        ForEach(state.artifacts) { item in
                            Text("\(item.metadata.displayName) \(item.metadata.versionDescription)").tag(UUID?.some(item.id))
                        }
                    }
                } header: {
                    stepHeader(1, "Select an IPA")
                } footer: {
                    if state.artifacts.isEmpty { Text("Import an IPA in the Library first.") }
                }

                Section {
                    Toggle("Ad-hoc (fakesign, no certificate)", isOn: $adHoc)
                } footer: {
                    Text(adHoc ? "No certificate or profile is used. The result will not install on a stock iPhone; it is for devices that skip signature checks. Entitlements are kept as they are." : "Signs with your .p12 certificate and .mobileprovision profile.")
                }

                if !adHoc {
                Section {
                    Picker("Identity", selection: $identityID) {
                        Text("Choose…").tag(String?.none)
                        ForEach(state.identities) { identity in
                            Text(identity.displayName).tag(String?.some(identity.id))
                        }
                    }
                } header: {
                    stepHeader(2, "Select a signing identity")
                } footer: {
                    if state.identities.isEmpty { Text("Import a .p12 certificate in the Certificates tab.") }
                }

                Section {
                    Picker("Profile", selection: $profileID) {
                        Text("Choose…").tag(String?.none)
                        ForEach(state.profiles) { item in
                            Text("\(item.name) (\(item.kind.displayName))").tag(String?.some(item.id))
                        }
                    }
                } header: {
                    stepHeader(3, "Select a provisioning profile")
                } footer: {
                    if state.profiles.isEmpty { Text("Import a .mobileprovision in the Profiles tab.") }
                }
                }

                if let artifact {
                    reviewSection(artifact)
                    validationSection
                    runSection(artifact)
                }

                if let job = state.runningJob ?? lastJob {
                    resultSection(job)
                }
            }
            .navigationTitle("Signing")
            .onAppear(perform: adoptFocusedArtifact)
            .onChange(of: router.focusedArtifactID) { _, _ in adoptFocusedArtifact() }
            .sheet(item: $shareItem) { item in ShareSheet(items: [item.url]) }
        }
    }

    // MARK: - Sections

    private func reviewSection(_ artifact: AppArtifact) -> some View {
        Section {
            LabeledContent("Bundle ID", value: artifact.metadata.bundleIdentifier)
            TextField("Override bundle ID (optional)", text: $bundleIDOverride)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            if let profile {
                LabeledContent("Profile covers", value: profile.bundleIdentifierPattern)
                LabeledContent("Entitlements granted", value: "\(profile.entitlements.count)")
            }
            LabeledContent("Entitlements requested", value: "\(artifact.metadata.existingEntitlements.count)")

            let plan = SigningPlanner.makePlan(
                metadata: artifact.metadata,
                targetBundleIdentifier: bundleIDOverride.isEmpty ? nil : bundleIDOverride
            )
            DisclosureGroup("Signing order (\(plan.steps.count) components)") {
                ForEach(Array(plan.steps.enumerated()), id: \.element.id) { index, step in
                    HStack(alignment: .firstTextBaseline) {
                        Text("\(index + 1).").foregroundStyle(.secondary)
                        VStack(alignment: .leading) {
                            Text(step.displayName).font(.footnote)
                            if let id = step.bundleIdentifier {
                                Text(id).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        } header: {
            stepHeader(4, "Review bundle IDs and entitlements")
        }
    }

    private var validationSection: some View {
        Section {
            if issues.isEmpty {
                Label("No problems found", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            } else {
                IssueList(issues: issues)
            }
        } header: {
            stepHeader(5, "Validate compatibility")
        }
    }

    private func runSection(_ artifact: AppArtifact) -> some View {
        let blocked = issues.contains { $0.severity == .error }
        return Section {
            Button {
                Task { await run(artifact) }
            } label: {
                HStack {
                    Text(state.signingCapability.isAvailable ? "Sign" : "Run validation")
                    Spacer()
                    if isRunning { ProgressView() }
                }
            }
            .disabled(isRunning)

            if blocked {
                Text("Blocking problems above will stop the job.").font(.footnote).foregroundStyle(.secondary)
            }
            if !state.signingCapability.isAvailable {
                Text("Signing is unavailable, so this records a validation result and does not create a signed IPA.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        } header: {
            stepHeader(6, "Run signing")
        }
    }

    private func resultSection(_ job: SigningJob) -> some View {
        Section {
            HStack {
                Text(job.artifactName)
                Spacer()
                StatusBadge(text: stateLabel(job.state), color: Theme.color(for: job.state))
            }
            if job.state == .running {
                ProgressView(value: job.progress)
                if let step = job.currentStep { Text(step).font(.footnote).foregroundStyle(.secondary) }
            }
            if let reason = job.failureReason {
                Text(reason).font(.footnote).foregroundStyle(.secondary)
            }
            if job.state == .succeeded, let artifact = state.artifact(id: job.artifactID) {
                Button("Share signed IPA", systemImage: "square.and.arrow.up") {
                    shareItem = state.shareableURL(for: artifact, signed: true).map(ShareItem.init)
                }
            }
            if let artifact = state.artifact(id: job.artifactID) {
                Button("Share validation report", systemImage: "doc.text") {
                    shareItem = state.writeReport(for: artifact, format: .markdown).map(ShareItem.init)
                }
            }
        } header: {
            stepHeader(7, "Verify and export")
        }
    }

    // MARK: - Helpers

    private func stepHeader(_ number: Int, _ title: String) -> some View {
        Text("\(number). \(title)")
    }

    private func stateLabel(_ state: SigningJob.State) -> String {
        switch state {
        case .queued: return "Queued"
        case .running: return "Running"
        case .succeeded: return "Succeeded"
        case .failed: return "Failed"
        case .unsupported: return "Unsupported"
        case .cancelled: return "Cancelled"
        }
    }

    private func run(_ artifact: AppArtifact) async {
        isRunning = true
        defer { isRunning = false }
        lastJob = await state.runSigning(
            artifact: artifact,
            identityID: identityID,
            profile: profile,
            targetBundleIdentifier: bundleIDOverride,
            adHoc: adHoc
        )
    }

    private func adoptFocusedArtifact() {
        if let id = router.focusedArtifactID {
            artifactID = id
            router.focusedArtifactID = nil
        }
    }
}
