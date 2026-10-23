import SwiftUI
import TesseraCore

/// Small design system: a mosaic-inspired palette and a few reusable pieces.
enum Theme {
    static let tileColors: [Color] = [
        Color(red: 0.13, green: 0.55, blue: 0.62),
        Color(red: 0.25, green: 0.33, blue: 0.75),
        Color(red: 0.93, green: 0.55, blue: 0.20),
        Color(red: 0.78, green: 0.28, blue: 0.55),
    ]

    static func color(for status: AppArtifact.Status) -> Color {
        switch status {
        case .imported: return .blue
        case .validated: return .teal
        case .signed: return .green
        case .exported: return .indigo
        case .needsAttention: return .orange
        }
    }

    static func color(for severity: ValidationIssue.Severity) -> Color {
        switch severity {
        case .info: return .blue
        case .warning: return .orange
        case .error: return .red
        }
    }

    static func symbol(for severity: ValidationIssue.Severity) -> String {
        switch severity {
        case .info: return "info.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    static func color(for state: SigningJob.State) -> Color {
        switch state {
        case .queued: return .gray
        case .running: return .blue
        case .succeeded: return .green
        case .failed: return .red
        case .unsupported: return .orange
        case .cancelled: return .gray
        }
    }

    static func color(for applicability: DistributionOption.Applicability) -> Color {
        switch applicability {
        case .applicable: return .green
        case .conditional: return .orange
        case .notApplicable: return .gray
        }
    }
}

struct StatusBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}

struct IssueRow: View {
    let issue: ValidationIssue

    var body: some View {
        Label {
            Text(issue.message)
                .font(.subheadline)
        } icon: {
            Image(systemName: Theme.symbol(for: issue.severity))
                .foregroundStyle(Theme.color(for: issue.severity))
        }
    }
}

struct IssueList: View {
    let issues: [ValidationIssue]

    var body: some View {
        ForEach(issues.sorted { $0.severity.rank > $1.severity.rank }) { issue in
            IssueRow(issue: issue)
        }
    }
}

struct CapabilityBanner: View {
    let capability: SigningCapability

    var body: some View {
        if case .unavailable(let reason) = capability {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Signing isn't available yet").font(.subheadline.weight(.semibold))
                    Text(reason).font(.footnote).foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "lock.trianglebadge.exclamationmark").foregroundStyle(.orange)
            }
        }
    }
}

struct AppIconView: View {
    @Environment(AppState.self) private var state
    let artifact: AppArtifact
    var size: CGFloat = 44

    var body: some View {
        Group {
            if let image = loadImage() {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                ZStack {
                    LinearGradient(colors: [Theme.tileColors[1], Theme.tileColors[0]], startPoint: .topLeading, endPoint: .bottomTrailing)
                    Image(systemName: "app.dashed").font(.system(size: size * 0.45)).foregroundStyle(.white)
                }
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
    }

    private func loadImage() -> UIImage? {
        guard let name = artifact.iconFileName else { return nil }
        return UIImage(contentsOfFile: state.dependencies.store.iconURL(for: name).path)
    }
}

enum Format {
    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
    }

    static func date(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .omitted)
    }
}
