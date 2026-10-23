import SwiftUI
import TesseraCore

enum LibrarySort: String, CaseIterable, Identifiable {
    case recent = "Recently Imported"
    case name = "Name"
    case size = "Size"

    var id: String { rawValue }
}

struct LibraryView: View {
    @Environment(AppState.self) private var state
    @Environment(AppRouter.self) private var router

    @State private var search = ""
    @State private var sort: LibrarySort = .recent
    @State private var statusFilter: AppArtifact.Status?
    @State private var showingImporter = false

    private var visibleArtifacts: [AppArtifact] {
        var items = state.artifacts
        if let statusFilter { items = items.filter { $0.status == statusFilter } }
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        if !query.isEmpty {
            items = items.filter {
                $0.metadata.displayName.localizedCaseInsensitiveContains(query)
                    || $0.metadata.bundleIdentifier.localizedCaseInsensitiveContains(query)
                    || $0.originalFileName.localizedCaseInsensitiveContains(query)
            }
        }
        switch sort {
        case .recent: return items.sorted { $0.importedAt > $1.importedAt }
        case .name: return items.sorted { $0.metadata.displayName.localizedCaseInsensitiveCompare($1.metadata.displayName) == .orderedAscending }
        case .size: return items.sorted { $0.fileSize > $1.fileSize }
        }
    }

    var body: some View {
        @Bindable var router = router

        NavigationStack(path: $router.libraryPath) {
            Group {
                if state.artifacts.isEmpty {
                    ContentUnavailableView {
                        VStack(spacing: 12) {
                            MosaicLogo(size: 84)
                            Text("No builds yet").font(.title2.bold())
                        }
                    } description: {
                        Text("Import an .ipa from the Files app to inspect it. Everything stays on this device.")
                    } actions: {
                        Button("Import IPA") { showingImporter = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    List {
                        ForEach(visibleArtifacts) { artifact in
                            NavigationLink(value: artifact.id) {
                                LibraryRow(artifact: artifact)
                            }
                            .swipeActions {
                                Button(role: .destructive) {
                                    Task { await state.delete(artifact) }
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                    .overlay {
                        if visibleArtifacts.isEmpty {
                            ContentUnavailableView.search
                        }
                    }
                }
            }
            .navigationTitle("Library")
            .searchable(text: $search, prompt: "Name or bundle ID")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Picker("Sort", selection: $sort) {
                            ForEach(LibrarySort.allCases) { Text($0.rawValue).tag($0) }
                        }
                        Picker("Status", selection: $statusFilter) {
                            Text("All").tag(AppArtifact.Status?.none)
                            ForEach(AppArtifact.Status.allCases, id: \.self) {
                                Text($0.displayName).tag(AppArtifact.Status?.some($0))
                            }
                        }
                    } label: {
                        Label("Sort and Filter", systemImage: "line.3.horizontal.decrease.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingImporter = true } label: { Label("Import", systemImage: "plus") }
                }
            }
            .navigationDestination(for: UUID.self) { id in
                InspectorView(artifactID: id)
            }
            .fileImporter(
                isPresented: $showingImporter,
                // `.item` lets every file show; the import service validates the extension itself.
                allowedContentTypes: [.item],
                allowsMultipleSelection: true
            ) { result in
                switch result {
                case .success(let urls):
                    Task { await state.importArchives(urls) }
                case .failure(let error):
                    state.alert = AppAlert(title: "Couldn't open files", message: error.localizedDescription)
                }
            }
        }
    }
}

struct LibraryRow: View {
    let artifact: AppArtifact

    var body: some View {
        HStack(spacing: 12) {
            AppIconView(artifact: artifact)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(artifact.metadata.displayName).font(.headline).lineLimit(1)
                    Spacer(minLength: 4)
                    StatusBadge(text: artifact.status.displayName, color: Theme.color(for: artifact.status))
                }
                Text(artifact.metadata.bundleIdentifier)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text("\(artifact.metadata.versionDescription) · \(Format.bytes(artifact.fileSize))")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}
