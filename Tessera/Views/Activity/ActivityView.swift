import SwiftUI
import TesseraCore

struct ActivityView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        NavigationStack {
            Group {
                if state.jobs.isEmpty {
                    ContentUnavailableView(
                        "No activity",
                        systemImage: "clock.arrow.circlepath",
                        description: Text("Signing and validation jobs appear here.")
                    )
                } else {
                    List(state.jobs) { job in
                        NavigationLink {
                            JobDetailView(job: job)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(job.artifactName).font(.headline).lineLimit(1)
                                    Spacer()
                                    StatusBadge(text: job.state.rawValue.capitalized, color: Theme.color(for: job.state))
                                }
                                Text(job.createdAt.formatted(date: .abbreviated, time: .shortened))
                                    .font(.caption).foregroundStyle(.secondary)
                                if let reason = job.failureReason {
                                    Text(reason).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Activity")
            .toolbar {
                if !state.jobs.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Clear", role: .destructive) { Task { await state.clearActivity() } }
                    }
                }
            }
        }
    }
}

struct JobDetailView: View {
    let job: SigningJob

    var body: some View {
        List {
            Section("Job") {
                LabeledContent("Build", value: job.artifactName)
                LabeledContent("State") {
                    StatusBadge(text: job.state.rawValue.capitalized, color: Theme.color(for: job.state))
                }
                LabeledContent("Started", value: job.createdAt.formatted(date: .abbreviated, time: .standard))
                if let finished = job.finishedAt {
                    LabeledContent("Finished", value: finished.formatted(date: .abbreviated, time: .standard))
                }
                if let reason = job.failureReason {
                    Text(reason).font(.footnote).foregroundStyle(.secondary)
                }
            }
            if !job.issues.isEmpty {
                Section("Findings") { IssueList(issues: job.issues) }
            }
            Section("Log") {
                if job.log.isEmpty {
                    Text("No log entries.").foregroundStyle(.secondary)
                }
                ForEach(Array(job.log.enumerated()), id: \.offset) { _, line in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(line.message).font(.footnote)
                        Text(line.date.formatted(date: .omitted, time: .standard))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Job")
        .navigationBarTitleDisplayMode(.inline)
    }
}
