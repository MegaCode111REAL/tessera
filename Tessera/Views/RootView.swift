import SwiftUI

struct RootView: View {
    @Environment(AppState.self) private var state
    @Environment(AppRouter.self) private var router

    private var downloadPrompt: String {
        guard let url = state.pendingDownload else { return "" }
        return "A link is asking Tessera to download a file from \(url.host ?? "an unknown server"):\n\n\(url.absoluteString)\n\nOnly continue if you trust this site. The file is added to your library and is not installed or run."
    }

    var body: some View {
        @Bindable var state = state
        @Bindable var router = router

        TabView(selection: $router.selectedTab) {
            LibraryView()
                .tabItem { Label(AppTab.library.title, systemImage: AppTab.library.systemImage) }
                .tag(AppTab.library)
            SigningWizardView()
                .tabItem { Label(AppTab.signing.title, systemImage: AppTab.signing.systemImage) }
                .tag(AppTab.signing)
            CertificatesView()
                .tabItem { Label(AppTab.certificates.title, systemImage: AppTab.certificates.systemImage) }
                .tag(AppTab.certificates)
            ProfilesView()
                .tabItem { Label(AppTab.profiles.title, systemImage: AppTab.profiles.systemImage) }
                .tag(AppTab.profiles)
            DistributionView()
                .tabItem { Label(AppTab.distribution.title, systemImage: AppTab.distribution.systemImage) }
                .tag(AppTab.distribution)
            ActivityView()
                .tabItem { Label(AppTab.activity.title, systemImage: AppTab.activity.systemImage) }
                .tag(AppTab.activity)
            SettingsView()
                .tabItem { Label(AppTab.settings.title, systemImage: AppTab.settings.systemImage) }
                .tag(AppTab.settings)
        }
        .tint(Theme.tileColors[1])
        .overlay {
            if state.isBusy {
                ZStack {
                    Color.black.opacity(0.25).ignoresSafeArea()
                    VStack(spacing: 12) {
                        ProgressView()
                        Text(state.busyMessage).font(.subheadline)
                    }
                    .padding(24)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                }
            }
        }
        .alert(item: $state.alert) { alert in
            Alert(title: Text(alert.title), message: Text(alert.message), dismissButton: .default(Text("OK")))
        }
        .confirmationDialog(
            "Download this IPA?",
            isPresented: Binding(
                get: { state.pendingDownload != nil },
                set: { if !$0 { state.cancelPendingDownload() } }
            ),
            titleVisibility: .visible
        ) {
            Button("Download and Import") {
                Task {
                    if let id = await state.confirmPendingDownload() {
                        router.showArtifact(id)
                    }
                }
            }
            Button("Cancel", role: .cancel) { state.cancelPendingDownload() }
        } message: {
            Text(downloadPrompt)
        }
    }
}
