
# Tessera — Complete Development Plan

## 1. Project Overview

Build **Tessera** as a native iOS and iPadOS app for managing, inspecting, signing, and distributing compatible app builds. The app must operate on-device without requiring a Mac or a permanently running server.

- **Working name:** Tessera
- **Platform:** iOS and iPadOS
- **Language:** Swift
- **UI:** SwiftUI
- **Initial archive format:** `.ipa`
- **Future archive format:** `.tipa`

## 2. Core Requirements

- Import IPA files using the Files picker.
- Maintain a local library of imported and exported builds.
- Inspect bundle identifiers, versions, architectures where detectable, signatures, entitlements, provisioning profiles, frameworks, extensions, and embedded resources.
- Import and securely manage Apple Developer signing certificates, private keys, and provisioning profiles.
- Store private keys securely using Keychain and protected file storage.
- Sign compatible apps locally when a complete signing implementation is available and the iOS runtime permits it.
- Validate bundle identifiers, certificate validity, profile expiry, device eligibility, entitlements, and nested code signatures.
- Export signed IPAs and detailed validation reports.
- Support eligible installation workflows through authorized iOS distribution mechanisms.
- Track Apple distribution submission status when an officially supported process applies.
- Add `.tipa` support using a modular archive-format interface.
- Never claim that a signed IPA is installable unless its distribution and provisioning requirements are satisfied.

## 3. Technical Architecture

### Presentation layer

SwiftUI screens for Library, IPA Inspector, Signing, Certificates, Profiles, Distribution, Activity, and Settings.

### Application services

- `IPAImportService`: imports and validates user-selected files.
- `MetadataService`: extracts app metadata and bundle information.
- `SigningCoordinator`: coordinates signing jobs and reports progress.
- `ValidationService`: checks profiles, certificates, entitlements, and signatures.
- `ExportService`: creates output files and reports.
- `DistributionService`: evaluates supported distribution methods.
- `InstallationService`: prepares eligible installation handoffs.

### Core engines

- `ArchiveEngine`: safely extracts and packages archives.
- `BundleInspector`: discovers the main app and nested extensions and frameworks.
- `SigningEngine`: implements code signing through a verified compatible implementation.
- `ProfileParser`: parses provisioning profiles and relevant properties.
- `CertificateManager`: manages identities and certificate metadata.
- `FormatAdapter`: abstracts archive formats for future `.tipa` support.

### Storage

- Keychain: private keys and sensitive credential material where supported.
- Protected app container: imported files, metadata, job history, and temporary workspaces.
- SwiftData or a lightweight database: library records and job status.

## 4. Suggested Project Structure

```text
Tessera/
  TesseraApp.swift
  App/
    AppState.swift
    AppRouter.swift
    AppDependencies.swift
  Models/
    AppArtifact.swift
    AppMetadata.swift
    SigningIdentity.swift
    ProvisioningProfile.swift
    SigningJob.swift
    DistributionResult.swift
  Views/
    Library/
    Inspector/
    Signing/
    Certificates/
    Profiles/
    Distribution/
    Activity/
    Settings/
  Services/
    IPAImportService.swift
    MetadataService.swift
    SigningCoordinator.swift
    ValidationService.swift
    ExportService.swift
    DistributionService.swift
    InstallationService.swift
  Core/
    ArchiveEngine.swift
    BundleInspector.swift
    SigningEngine.swift
    ProfileParser.swift
    CertificateManager.swift
    FormatAdapter.swift
  Storage/
    SecureAssetStore.swift
    LibraryRepository.swift
  Resources/
  Tests/
```

## 5. User Interface

### Library

- Import button and Files integration.
- App icon, name, version, bundle ID, and file size.
- Search, sorting, and filtering.
- Build status: Imported, Validated, Signed, Exported, or Needs Attention.

### IPA Inspector

- App metadata and supported platform details.
- Signature and certificate information.
- Provisioning profile details and expiry.
- Entitlements and nested executable inventory.
- Warnings for missing, invalid, or incompatible assets.

### Signing Wizard

1. Select an IPA.
2. Select a signing identity.
3. Select a provisioning profile.
4. Review bundle identifiers and entitlements.
5. Validate compatibility.
6. Run signing if supported.
7. Verify the output signature.
8. Export the result.

### Distribution

- Show which distribution mechanisms are applicable.
- Prepare manifests and hosted files only when the selected mechanism requires them.
- Explain HTTPS hosting and device/profile requirements.
- Display submission status only when supported and verifiable.
- Do not treat macOS Developer ID notarization as iOS IPA notarization.

### Settings

- Secure asset management.
- Temporary-file cleanup.
- Storage usage.
- Diagnostics and logs.
- Privacy and security controls.

## 6. Signing Pipeline

1. Import and safely inspect the IPA.
2. Validate archive structure and locate `Payload/*.app`.
3. Discover embedded frameworks, extensions, and other signed code.
4. Parse the existing signature, entitlements, and provisioning profile.
5. Select a compatible certificate and private key.
6. Verify profile expiry, application identifier, certificate authorization, device eligibility, and permitted entitlements.
7. Prepare a signing plan for nested components and the main app.
8. Sign in the correct dependency order using a verified implementation.
9. Package the resulting app without corrupting required resources.
10. Verify signatures, embedded profiles, entitlements, and output integrity.
11. Export the IPA and a validation report.

If any required signing operation is unavailable on iOS, report it as unsupported rather than creating a misleading output.

## 7. Installation and Distribution

- Do not assume an ordinary iOS app can install arbitrary IPAs directly.
- Support installation handoff only through a mechanism authorized for the specific build and distribution channel.
- For `itms-services` workflows, require the appropriate manifest, HTTPS hosting, and a valid signed build.
- Respect Ad Hoc registered-device restrictions, provisioning rules, and applicable enterprise or alternative-distribution requirements.
- Do not promise installation without notarization where notarization is required by the chosen distribution channel.
- Explain when an exported IPA must be installed using another authorized method.

## 8. Notarization

- Determine whether the selected distribution channel supports or requires Apple's iOS notarization process.
- Use official Apple submission APIs and credentials only where applicable.
- Never send private signing keys to an unrelated third-party service.
- Display eligibility, submission status, and verifiable results.
- Explain that Apple's macOS notarization service is not a universal endpoint for iOS IPA files.

## 9. Security Requirements

- Never request or store the user's Apple Account password.
- Keep private keys in protected storage and avoid logging secret material.
- Use temporary directories for extraction and signing jobs.
- Defend against ZIP path traversal, symlinks, decompression bombs, malformed archives, and oversized files.
- Clean up temporary files after success, failure, or cancellation.
- Validate all archive paths before extraction.
- Use HTTPS for supported distribution hosting.
- Clearly disclose any external network activity.

## 10. Testing

- Import valid, malformed, and oversized IPA files.
- Test archives with missing Payload directories and malformed Info.plist files.
- Test expired certificates and profiles.
- Test mismatched bundle identifiers and missing entitlements.
- Test apps containing frameworks, app extensions, and watch components.
- Verify signed output with independent signature-validation tools where available.
- Test cancellation, low storage, memory pressure, and app termination during processing.
- Test all export and installation handoffs on real iOS devices.
- Confirm that unsupported operations fail safely and explain why.

## 11. Development Phases

1. **Foundation:** Create the SwiftUI project, navigation, design system, and app icon.
2. **IPA inspection:** Implement Files import, archive inspection, metadata extraction, and library storage.
3. **Signing assets:** Implement certificate and profile import, secure storage, and validation.
4. **Signing feasibility:** Evaluate signing libraries and iOS runtime restrictions; implement the signing engine only after proving end-to-end feasibility on-device.
5. **Export:** Implement packaging, signature verification, and diagnostics.
6. **Installation:** Implement supported installation handoffs and distribution eligibility checks.
7. **Notarization:** Add applicable Apple submission and status workflows.
8. **Future formats:** Add `.tipa` through the archive-format adapter.
9. **Release testing:** Perform security, compatibility, performance, and real-device testing.

## 12. Definition of Done

- Users can import and inspect IPAs entirely on-device.
- Signing assets are stored securely.
- Every supported signing operation produces a verifiable result.
- Incompatible profiles and unsupported operations are explained clearly.
- Export works reliably without corrupting app bundles.
- Installation options accurately reflect Apple's distribution requirements.
- Notarization status is never fabricated or confused with signing.
- The project builds cleanly and includes automated tests for its core logic.
- Future `.tipa` support does not require rewriting the application architecture.

## 13. Reference Material

- Apple registered-device distribution: https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices
- Apple provisioning profiles: https://developer.apple.com/documentation/appstoreconnectapi/profiles
- Apple alternative web distribution: https://developer.apple.com/documentation/marketplacekit/distributing-your-app-from-your-website
- Feather source repository for architectural research: https://github.com/FeatherApp/Feather

Before reusing Feather code, review its current licence and comply with all applicable terms. Treat all signing and installation capabilities as verified only after testing against the current iOS SDK and real devices.
