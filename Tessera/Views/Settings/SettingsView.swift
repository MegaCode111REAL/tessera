import SwiftUI
import TesseraCore

struct SettingsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        NavigationStack {
            Form {
                Section("Signing") {
                    switch state.signingCapability {
                    case .available:
                        Label("Signing engine available", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                    case .unavailable:
                        CapabilityBanner(capability: state.signingCapability)
                    }
                }

                Section("Storage") {
                    let usage = state.storageUsage
                    LabeledContent("Library", value: Format.bytes(usage.library))
                    LabeledContent("Exports", value: Format.bytes(usage.exports))
                    LabeledContent("Profiles", value: Format.bytes(usage.profiles))
                    LabeledContent("Icons", value: Format.bytes(usage.icons))
                    LabeledContent("Temporary files", value: Format.bytes(usage.temporary))
                    LabeledContent("Total", value: Format.bytes(usage.total)).fontWeight(.semibold)
                    Button("Clean Temporary Files", systemImage: "trash") {
                        Task { await state.cleanTemporaryFiles() }
                    }
                    .disabled(usage.temporary == 0)
                }

                Section("Diagnostics") {
                    NavigationLink("Logs (\(state.diagnostics.count))") { DiagnosticsView() }
                }

                Section {
                    Label("Private keys stay in this device's Keychain and are never written to files or logs.", systemImage: "lock.shield")
                    Label("Tessera never asks for your Apple Account password.", systemImage: "person.crop.circle.badge.xmark")
                    Label("Imported files stay in Tessera's protected storage and are excluded from backups.", systemImage: "externaldrive.badge.checkmark")
                    Label("Archives are checked for unsafe paths, symbolic links and decompression bombs before extraction.", systemImage: "shield.checkered")
                } header: {
                    Text("Privacy and Security")
                } footer: {
                    Text("Tessera makes no network requests of its own. If you open an over-the-air install link, iOS contacts the HTTPS server you specified.")
                }

                Section("About") {
                    LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–")
                }
            }
            .navigationTitle("Settings")
        }
    }
}

struct DiagnosticsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        List {
            if state.diagnostics.isEmpty {
                Text("Nothing logged yet.").foregroundStyle(.secondary)
            }
            ForEach(Array(state.diagnostics.enumerated()), id: \.offset) { _, line in
                Text(line).font(.caption.monospaced())
            }
        }
        .navigationTitle("Logs")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !state.diagnostics.isEmpty {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: state.diagnostics.joined(separator: "\n"))
                }
            }
        }
    }
}
