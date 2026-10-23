import SwiftUI
import TesseraCore

struct InspectorView: View {
    @Environment(AppState.self) private var state
    @Environment(AppRouter.self) private var router
    let artifactID: UUID
    @State private var shareItem: ShareItem?

    var body: some View {
        if let artifact = state.artifact(id: artifactID) {
            content(artifact)
        } else {
            ContentUnavailableView("Build not found", systemImage: "questionmark.folder")
        }
    }

    @ViewBuilder
    private func content(_ artifact: AppArtifact) -> some View {
        let metadata = artifact.metadata

        List {
            Section {
                HStack(spacing: 14) {
                    AppIconView(artifact: artifact, size: 64)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(metadata.displayName).font(.title3.bold())
                        Text(metadata.bundleIdentifier).font(.footnote).foregroundStyle(.secondary)
                        StatusBadge(text: artifact.status.displayName, color: Theme.color(for: artifact.status))
                    }
                }
            }

            if !artifact.issues.isEmpty {
                Section("Findings") { IssueList(issues: artifact.issues) }
            }

            Section("App") {
                LabeledContent("Version", value: metadata.versionDescription)
                LabeledContent("Minimum iOS", value: metadata.minimumOSVersion ?? "Unknown")
                LabeledContent("Platforms", value: metadata.supportedPlatforms.isEmpty ? "Not declared" : metadata.supportedPlatforms.joined(separator: ", "))
                LabeledContent("Devices", value: deviceFamilies(metadata.deviceFamilies))
                LabeledContent("Architectures", value: metadata.architectures.isEmpty ? "Unknown" : metadata.architectures.joined(separator: ", "))
                LabeledContent("Archive size", value: Format.bytes(artifact.fileSize))
                LabeledContent("Expanded size", value: Format.bytes(metadata.uncompressedSize))
                LabeledContent("Format", value: ".\(artifact.format.fileExtension)")
            }

            Section("Signature") {
                LabeledContent("Code signature", value: metadata.hasCodeSignature ? "Present" : "None")
                LabeledContent("Encrypted binary", value: metadata.isEncrypted ? "Yes" : "No")
                LabeledContent("Embedded profile", value: metadata.hasEmbeddedProfile ? "Present" : "None")
            }

            if let profile = metadata.embeddedProfile {
                Section("Embedded Profile") {
                    ProfileSummaryRows(profile: profile)
                }
            }

            if !metadata.existingEntitlements.isEmpty {
                Section("Entitlements (current signature)") {
                    ForEach(metadata.existingEntitlements.keys.sorted(), id: \.self) { key in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key).font(.footnote.monospaced())
                            Text(metadata.existingEntitlements[key]?.displayString ?? "")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(3)
                        }
                    }
                }
            }

            nestedSection("App Extensions", metadata.extensions)
            nestedSection("Watch Apps", metadata.watchApps)
            nestedSection("Frameworks", metadata.frameworks)
        }
        .navigationTitle(metadata.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { router.showSigning(for: artifact.id) } label: { Label("Sign…", systemImage: "signature") }
                    Button { router.showDistribution(for: artifact.id) } label: { Label("Distribution", systemImage: "paperplane") }
                    Divider()
                    Button {
                        shareItem = state.shareableURL(for: artifact, signed: false).map(ShareItem.init)
                    } label: {
                        Label("Share Original IPA", systemImage: "square.and.arrow.up")
                    }
                    Button {
                        shareItem = state.writeReport(for: artifact, format: .markdown).map(ShareItem.init)
                    } label: {
                        Label("Share Validation Report", systemImage: "doc.text")
                    }
                } label: {
                    Label("Actions", systemImage: "ellipsis.circle")
                }
            }
        }
        .sheet(item: $shareItem) { item in
            ShareSheet(items: [item.url])
        }
    }

    @ViewBuilder
    private func nestedSection(_ title: String, _ bundles: [NestedBundle]) -> some View {
        if !bundles.isEmpty {
            Section("\(title) (\(bundles.count))") {
                ForEach(bundles) { bundle in
                    VStack(alignment: .leading, spacing: 2) {
                        Text((bundle.relativePath as NSString).lastPathComponent).font(.subheadline)
                        HStack(spacing: 6) {
                            if let id = bundle.bundleIdentifier {
                                Text(id).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                            Image(systemName: bundle.hasCodeSignature ? "checkmark.seal" : "seal")
                                .foregroundStyle(bundle.hasCodeSignature ? .green : .secondary)
                                .accessibilityLabel(bundle.hasCodeSignature ? "Signed" : "Unsigned")
                        }
                    }
                }
            }
        }
    }

    private func deviceFamilies(_ families: [Int]) -> String {
        guard !families.isEmpty else { return "Not declared" }
        return families.map { $0 == 1 ? "iPhone" : $0 == 2 ? "iPad" : "Family \($0)" }.joined(separator: ", ")
    }
}

/// Shared rows describing a provisioning profile.
struct ProfileSummaryRows: View {
    let profile: ProvisioningProfile

    var body: some View {
        LabeledContent("Name", value: profile.name)
        LabeledContent("Type", value: profile.kind.displayName)
        if let team = profile.teamName ?? profile.teamIdentifier {
            LabeledContent("Team", value: team)
        }
        LabeledContent("App ID", value: profile.bundleIdentifierPattern)
        LabeledContent("Expires") {
            HStack {
                Text(Format.date(profile.expirationDate))
                if profile.isExpired() { StatusBadge(text: "Expired", color: .red) }
            }
        }
        if let devices = profile.provisionedDevices {
            LabeledContent("Registered devices", value: "\(devices.count)")
        }
        LabeledContent("Certificates", value: "\(profile.developerCertificateSHA1s.count)")
    }
}
