import SwiftUI
import TesseraCore

struct ProfilesView: View {
    @Environment(AppState.self) private var state
    @State private var showingImporter = false

    var body: some View {
        NavigationStack {
            Group {
                if state.profiles.isEmpty {
                    ContentUnavailableView {
                        Label("No profiles", systemImage: "doc.badge.gearshape")
                    } description: {
                        Text("Import a .mobileprovision file to check and sign builds against it.")
                    } actions: {
                        Button("Import Profile") { showingImporter = true }.buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        ForEach(state.profiles) { profile in
                            NavigationLink {
                                ProfileDetailView(profile: profile)
                            } label: {
                                ProfileRow(profile: profile)
                            }
                            .swipeActions {
                                Button(role: .destructive) {
                                    Task { await state.deleteProfile(profile) }
                                } label: { Label("Delete", systemImage: "trash") }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Profiles")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingImporter = true } label: { Label("Import", systemImage: "plus") }
                }
            }
            .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls):
                    Task { for url in urls { await state.importProfile(from: url) } }
                case .failure(let error):
                    state.alert = AppAlert(title: "Couldn't open files", message: error.localizedDescription)
                }
            }
        }
    }
}

struct ProfileRow: View {
    let profile: ProvisioningProfile

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(profile.name).font(.headline).lineLimit(1)
                Spacer()
                if profile.isExpired() {
                    StatusBadge(text: "Expired", color: .red)
                } else {
                    StatusBadge(text: profile.kind.displayName, color: .blue)
                }
            }
            Text(profile.bundleIdentifierPattern).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Text("Expires \(Format.date(profile.expirationDate))").font(.caption).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

struct ProfileDetailView: View {
    let profile: ProvisioningProfile

    var body: some View {
        List {
            Section("Profile") { ProfileSummaryRows(profile: profile) }

            if !profile.platforms.isEmpty {
                Section("Platforms") { Text(profile.platforms.joined(separator: ", ")) }
            }

            Section("Entitlements (\(profile.entitlements.count))") {
                ForEach(profile.entitlements.keys.sorted(), id: \.self) { key in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(key).font(.footnote.monospaced())
                        Text(profile.entitlements[key]?.displayString ?? "")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(4)
                    }
                }
            }

            if let devices = profile.provisionedDevices {
                Section("Registered devices (\(devices.count))") {
                    ForEach(devices, id: \.self) { Text($0).font(.caption.monospaced()) }
                }
            }

            Section("Authorized certificates (\(profile.developerCertificateSHA1s.count))") {
                ForEach(profile.developerCertificateSHA1s, id: \.self) { Text($0).font(.caption2.monospaced()) }
            }
        }
        .navigationTitle(profile.name)
        .navigationBarTitleDisplayMode(.inline)
    }
}
