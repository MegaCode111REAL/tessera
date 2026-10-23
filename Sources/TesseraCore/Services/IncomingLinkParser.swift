import Foundation

/// What Tessera should do with a URL it was asked to open.
public enum IncomingAction: Equatable, Sendable {
    /// A local file handed to the app (share sheet, "Open in", AirDrop, Files).
    case importFile(URL)
    /// An HTTPS location to download an IPA from. The UI must ask the user before fetching it.
    case download(URL)
    case invalid(String)
}

/// Interprets URLs delivered to the app.
///
/// Supported forms:
/// - `tessera://install?url=<percent-encoded https URL of an .ipa>`
/// - `tessera://import?url=<...>` (same behaviour)
/// - a `file://` URL for an `.ipa` (or `.tipa`) file
///
/// "Install" means *download into the Tessera library*: iOS does not let an ordinary app install
/// arbitrary IPAs, so the link fetches the file and opens it in the inspector.
public enum IncomingLinkParser {
    public static let scheme = "tessera"
    public static let maxURLLength = 2048
    static let actionHosts: Set<String> = ["install", "import"]
    static let queryNames = ["url", "ipa"]

    /// Builds a `tessera://install` link for an HTTPS IPA location.
    public static func makeInstallLink(for ipaURL: URL) -> URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = "install"
        components.queryItems = [URLQueryItem(name: "url", value: ipaURL.absoluteString)]
        return components.url
    }

    public static func parse(_ url: URL) -> IncomingAction {
        if url.isFileURL {
            guard ArchiveFormat(fileExtension: url.pathExtension) != nil else {
                return .invalid("Only .ipa files can be opened in Tessera.")
            }
            return .importFile(url)
        }

        guard url.scheme?.lowercased() == scheme else {
            return .invalid("Tessera can't open this kind of link.")
        }
        guard let host = url.host?.lowercased(), actionHosts.contains(host) else {
            return .invalid("Unknown Tessera link. Use tessera://install?url=https://…")
        }
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let value = components.queryItems?.first(where: { queryNames.contains($0.name.lowercased()) })?.value,
              !value.isEmpty else {
            return .invalid("The link doesn't say which IPA to download. Add ?url=https://… to it.")
        }
        return validateDownload(value)
    }

    static func validateDownload(_ text: String) -> IncomingAction {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count <= maxURLLength, let target = URL(string: trimmed) else {
            return .invalid("The download address isn't a valid URL.")
        }
        guard target.scheme?.lowercased() == "https" else {
            return .invalid("Only HTTPS download links are accepted.")
        }
        guard let host = target.host, !host.isEmpty else {
            return .invalid("The download address has no host.")
        }
        guard target.user == nil, target.password == nil else {
            return .invalid("Download addresses with embedded credentials are not accepted.")
        }
        return .download(target)
    }
}
