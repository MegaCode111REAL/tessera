import SwiftUI
import TesseraCore

struct DistributionView: View {
    @Environment(AppState.self) private var state
    @Environment(AppRouter.self) private var router
    @Environment(\.openURL) private var openURL

    @State private var artifactID: UUID?
    @State private var manifestURLText = ""
    @State private var ipaURLText = ""
    @State private var shareItem: ShareItem?

    private var artifact: AppArtifact? { state.artifact(id: artifactID) }

    var body: some View {
        NavigationStack {
            Form {
                Section("Build") {
                    Picker("Build", selection: $artifactID) {
                        Text("Choose…").tag(UUID?.none)
                        ForEach(state.artifacts) { item in
                            Text("\(item.metadata.displayName) \(item.metadata.versionDescription)").tag(UUID?.some(item.id))
                        }
                    }
                }

                if let artifact {
                    let result = state.distribution(for: artifact)

                    Section {
                        ForEach(result.options) { option in
                            OptionRow(option: option) { use(option, for: artifact) }
                        }
                    } header: {
                        Text("Applicable methods")
                    } footer: {
                        Text("These reflect Apple's requirements for the selected profile. Tessera never promises that a build will install.")
                    }

                    Section("Notarization") {
                        Text(result.notarization.summary).font(.subheadline)
                        Text("Apple's macOS notarization service is not a general endpoint for iOS IPAs. Tessera shows a result only when Apple has returned a verifiable one.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }

                    Section {
                        TextField("https://example.com/app.plist", text: $manifestURLText)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                    } header: {
                        Text("Over-the-air manifest URL")
                    } footer: {
                        Text("Both the manifest and the IPA must be hosted over HTTPS by you. Tessera does not upload anything. Opening an install link hands the URL to iOS, which contacts your server.")
                    }

                    Section {
                        TextField("https://example.com/app.ipa", text: $ipaURLText)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                        Button("Create manifest file", systemImage: "doc.badge.plus") { createManifest(for: artifact) }
                            .disabled(ipaURLText.isEmpty)
                    } header: {
                        Text("Manifest builder")
                    } footer: {
                        Text("Creates the manifest property list for the IPA URL above so you can upload it next to the IPA.")
                    }
                }
            }
            .navigationTitle("Distribution")
            .onAppear(perform: adoptFocusedArtifact)
            .onChange(of: router.focusedArtifactID) { _, _ in adoptFocusedArtifact() }
            .sheet(item: $shareItem) { item in ShareSheet(items: [item.url]) }
        }
    }

    // MARK: - Actions

    private func use(_ option: DistributionOption, for artifact: AppArtifact) {
        let signedURL = state.dependencies.export.signedIPAURL(for: artifact)
        let verified = signedURL != nil && state.jobs.contains { $0.artifactID == artifact.id && $0.state == .succeeded }

        let fileURL: URL?
        switch option.mechanism {
        case .manualExport:
            // Prefer the signed output; otherwise export the original, clearly named.
            fileURL = state.shareableURL(for: artifact, signed: signedURL != nil)
        case .registeredDevices:
            fileURL = verified ? state.shareableURL(for: artifact, signed: true) : nil
        default:
            fileURL = nil
        }

        let handoff = state.dependencies.installation.prepare(
            option: option,
            fileURL: fileURL,
            manifestURL: URL(string: manifestURLText.trimmingCharacters(in: .whitespaces)),
            hasVerifiedSignedOutput: verified
        )

        switch handoff {
        case .shareFile(let url):
            shareItem = ShareItem(url: url)
        case .overTheAir(let url):
            openURL(url)
        case .unavailable(let reason):
            state.alert = AppAlert(title: option.title, message: reason)
        }
    }

    private func createManifest(for artifact: AppArtifact) {
        guard let ipaURL = URL(string: ipaURLText.trimmingCharacters(in: .whitespaces)) else {
            state.alert = AppAlert(title: "Invalid URL", message: "Enter the full HTTPS URL where the IPA will be hosted.")
            return
        }
        do {
            let data = try ManifestBuilder.makeManifest(
                ipaURL: ipaURL,
                bundleIdentifier: artifact.metadata.bundleIdentifier,
                bundleVersion: artifact.metadata.buildVersion.isEmpty ? artifact.metadata.shortVersion : artifact.metadata.buildVersion,
                title: artifact.metadata.displayName
            )
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Tessera-Share", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let url = directory.appendingPathComponent("manifest.plist")
            try data.write(to: url, options: .atomic)
            shareItem = ShareItem(url: url)
        } catch {
            state.alert = AppAlert(title: "Couldn't create manifest", message: error.localizedDescription)
        }
    }

    private func adoptFocusedArtifact() {
        if let id = router.focusedArtifactID {
            artifactID = id
            router.focusedArtifactID = nil
        }
    }
}

private struct OptionRow: View {
    let option: DistributionOption
    let onUse: () -> Void

    var body: some View {
        DisclosureGroup {
            Text(option.summary).font(.subheadline)
            ForEach(option.requirements, id: \.self) { requirement in
                Label(requirement, systemImage: "checklist").font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(option.blockers, id: \.self) { blocker in
                Label(blocker, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange)
            }
            if option.applicability != .notApplicable {
                Button("Continue", action: onUse)
            }
        } label: {
            HStack {
                Text(option.title)
                Spacer()
                StatusBadge(text: label(for: option.applicability), color: Theme.color(for: option.applicability))
            }
        }
    }

    private func label(for applicability: DistributionOption.Applicability) -> String {
        switch applicability {
        case .applicable: return "Applicable"
        case .conditional: return "Conditional"
        case .notApplicable: return "Not applicable"
        }
    }
}
