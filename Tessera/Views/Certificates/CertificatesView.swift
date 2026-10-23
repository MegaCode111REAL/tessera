import SwiftUI
import TesseraCore

struct CertificatesView: View {
    @Environment(AppState.self) private var state

    @State private var showingImporter = false
    @State private var pendingURL: URL?
    @State private var password = ""
    @State private var askingForPassword = false

    var body: some View {
        NavigationStack {
            Group {
                if state.identities.isEmpty {
                    ContentUnavailableView {
                        Label("No certificates", systemImage: "key.slash")
                    } description: {
                        Text("Import a .p12 file exported from Keychain Access or the Apple Developer portal. Private keys are stored only in this device's Keychain.")
                    } actions: {
                        Button("Import .p12") { showingImporter = true }.buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        ForEach(state.identities) { identity in
                            IdentityRow(identity: identity)
                                .swipeActions {
                                    Button(role: .destructive) {
                                        Task { await state.deleteIdentity(identity) }
                                    } label: { Label("Delete", systemImage: "trash") }
                                }
                        }
                    }
                }
            }
            .navigationTitle("Certificates")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingImporter = true } label: { Label("Import", systemImage: "plus") }
                }
            }
            .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    pendingURL = url
                    password = ""
                    askingForPassword = true
                case .failure(let error):
                    state.alert = AppAlert(title: "Couldn't open file", message: error.localizedDescription)
                }
            }
            .alert("Certificate Password", isPresented: $askingForPassword) {
                SecureField("Password", text: $password)
                Button("Import") {
                    guard let url = pendingURL else { return }
                    let entered = password
                    password = ""
                    pendingURL = nil
                    Task { _ = await state.importP12(from: url, password: entered) }
                }
                Button("Cancel", role: .cancel) {
                    password = ""
                    pendingURL = nil
                }
            } message: {
                Text("Enter the password you chose when exporting the .p12. This is not your Apple Account password, and Tessera never asks for that.")
            }
        }
    }
}

struct IdentityRow: View {
    let identity: SigningIdentityInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(identity.displayName).font(.headline).lineLimit(1)
                Spacer()
                if identity.isExpired() {
                    StatusBadge(text: "Expired", color: .red)
                } else if !identity.isValid() {
                    StatusBadge(text: "Not yet valid", color: .orange)
                } else {
                    StatusBadge(text: "Valid", color: .green)
                }
            }
            if let team = identity.teamIdentifier {
                Text("Team \(team)").font(.caption).foregroundStyle(.secondary)
            }
            Text("Expires \(Format.date(identity.notAfter))").font(.caption).foregroundStyle(.secondary)
            Label(identity.hasPrivateKey ? "Private key in Keychain" : "No private key", systemImage: identity.hasPrivateKey ? "lock.fill" : "lock.open")
                .font(.caption)
                .foregroundStyle(identity.hasPrivateKey ? Color.secondary : Color.orange)
            Text("SHA-1 \(identity.id)").font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}
