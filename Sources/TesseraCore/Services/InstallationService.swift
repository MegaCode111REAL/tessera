import Foundation

/// What the UI may offer for getting a build onto a device.
public enum InstallationHandoff: Equatable, Sendable {
    /// Present the system share sheet for this file (AirDrop, Files, another installer the user trusts).
    case shareFile(URL)
    /// Open this `itms-services` URL. Only produced for HTTPS manifests and a verified signed build.
    case overTheAir(URL)
    /// No authorized handoff exists; `reason` explains why in user-facing terms.
    case unavailable(reason: String)
}

/// Prepares installation handoffs, but only through mechanisms authorized for the build.
/// It never claims an install will succeed; it only decides whether a handoff may be offered.
public struct InstallationService: Sendable {
    public init() {}

    public func prepare(
        option: DistributionOption,
        fileURL: URL?,
        manifestURL: URL?,
        hasVerifiedSignedOutput: Bool
    ) -> InstallationHandoff {
        switch option.mechanism {
        case .manualExport:
            guard let fileURL else { return .unavailable(reason: "There is no file to export.") }
            return .shareFile(fileURL)

        case .registeredDevices:
            guard option.applicability != .notApplicable else {
                return .unavailable(reason: option.blockers.first ?? "This build is not eligible for registered-device installation.")
            }
            guard hasVerifiedSignedOutput, let fileURL else {
                return .unavailable(reason: "A verified signed build is required. Export it and install with an authorized method such as Xcode or Apple Configurator.")
            }
            return .shareFile(fileURL)

        case .overTheAir:
            guard option.applicability != .notApplicable else {
                return .unavailable(reason: option.blockers.first ?? "This build is not eligible for over-the-air installation.")
            }
            guard hasVerifiedSignedOutput else {
                return .unavailable(reason: "Over-the-air installation needs a verified signed build.")
            }
            guard let manifestURL else {
                return .unavailable(reason: "Provide the HTTPS URL of your hosted manifest. Tessera cannot host files itself.")
            }
            do {
                return .overTheAir(try ManifestBuilder.installURL(manifestURL: manifestURL))
            } catch {
                return .unavailable(reason: error.localizedDescription)
            }

        case .alternativeDistribution:
            return .unavailable(reason: "Alternative distribution goes through Apple's authorized web or marketplace process, which Tessera cannot perform for you.")

        case .testFlightOrAppStore:
            return .unavailable(reason: "Upload to App Store Connect with Xcode or Transporter, then install through TestFlight.")
        }
    }
}
