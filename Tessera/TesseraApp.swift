import SwiftUI
import TesseraCore

@main
struct TesseraApp: App {
    @State private var appState: AppState?
    @State private var router = AppRouter()
    private let startupError: String?

    init() {
        do {
            let dependencies = try AppDependencies.make()
            _appState = State(initialValue: AppState(dependencies: dependencies))
            startupError = nil
        } catch {
            _appState = State(initialValue: nil)
            startupError = error.localizedDescription
        }
    }

    var body: some Scene {
        WindowGroup {
            if let appState {
                RootView()
                    .environment(appState)
                    .environment(router)
                    .task { await appState.reload() }
            } else {
                ContentUnavailableView(
                    "Tessera couldn't start",
                    systemImage: "exclamationmark.triangle",
                    description: Text(startupError ?? "Its storage could not be prepared.")
                )
            }
        }
    }
}
