import SwiftUI

enum AppTab: String, CaseIterable, Hashable, Identifiable {
    case library
    case signing
    case certificates
    case profiles
    case distribution
    case activity
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .library: return "Library"
        case .signing: return "Signing"
        case .certificates: return "Certificates"
        case .profiles: return "Profiles"
        case .distribution: return "Distribution"
        case .activity: return "Activity"
        case .settings: return "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .library: return "square.grid.2x2"
        case .signing: return "signature"
        case .certificates: return "key"
        case .profiles: return "doc.badge.gearshape"
        case .distribution: return "paperplane"
        case .activity: return "clock.arrow.circlepath"
        case .settings: return "gearshape"
        }
    }
}

/// Navigation state shared across tabs, so the Library can hand a build to the Signing wizard.
@Observable
final class AppRouter {
    var selectedTab: AppTab = .library
    var libraryPath: [UUID] = []
    /// Build pre-selected when jumping to Signing or Distribution from elsewhere.
    var focusedArtifactID: UUID?

    /// Jumps to a build's inspector in the Library tab.
    func showArtifact(_ id: UUID) {
        selectedTab = .library
        libraryPath = [id]
    }

    func showSigning(for artifactID: UUID) {
        focusedArtifactID = artifactID
        selectedTab = .signing
    }

    func showDistribution(for artifactID: UUID) {
        focusedArtifactID = artifactID
        selectedTab = .distribution
    }
}
