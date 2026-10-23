# Tessera

iOS/iPadOS app for managing, inspecting, signing and distributing IPA builds on-device. See [`plan.md`](plan.md) for the full development plan.

> **Status: early.** The inspection, signing-asset, validation, export and distribution-eligibility layers are implemented. **Code signing itself is not**: the signing engine is an honest "unavailable" stub until a signing approach is proven on a real device (plan phase 4). Tessera will not produce a signed IPA it cannot verify.
>
> This code was written without access to a Swift compiler, so **expect a round of compile fixes on the first build**. CI (below) will surface them.

## What works today

| Area | Status |
| --- | --- |
| Import `.ipa` via Files, local library with search/sort/filter | Implemented |
| Safe archive handling (path traversal, symlinks, zip bombs, size/entry limits) | Implemented + tested |
| Inspector: bundle ID, versions, architectures, FairPlay encryption, signature, entitlements, embedded profile, extensions, frameworks, watch apps | Implemented |
| Import `.p12` identities (private keys stay in the Keychain) and `.mobileprovision` profiles | Implemented |
| Validation: profile/cert expiry, bundle ID and nested-ID coverage, cert-in-profile, entitlements, device eligibility | Implemented + tested |
| Signing wizard UI, signing order planner | Implemented |
| **On-device code signing** | **Not implemented** (reports "unsupported", produces no output) |
| Export original IPA, validation reports (Markdown/JSON), over-the-air manifest builder | Implemented |
| Distribution eligibility (never promises installability; notarization is never fabricated) | Implemented + tested |
| `.tipa` | Architecture ready (`FormatAdapter`); disabled |
| Apple notarization submission | Not implemented |

## Layout

- `Sources/TesseraCore`: platform logic as a Swift package (models, `ArchiveEngine`, `BundleInspector`, `ProfileParser`, `CertificateManager`, `SigningEngine`, services, storage).
- `Tessera/`: the SwiftUI app (Library, Inspector, Signing, Certificates, Profiles, Distribution, Activity, Settings).
- `Tests/TesseraCoreTests`: unit tests for the core logic.
- `project.yml`: [XcodeGen](https://github.com/yonaskolb/XcodeGen) spec for the app target.

## Build

Requires Xcode 16+ on macOS (a Mac VM works).

```sh
brew install xcodegen
xcodegen generate
open Tessera.xcodeproj
```

Set your own team and bundle identifier in `project.yml` (or in Xcode) before running on a device.

Run the core tests without Xcode:

```sh
swift test
```

GitHub Actions (`.github/workflows/ci.yml`) runs `swift test` and a simulator build on macOS for every push.

## Security notes

- Private keys are kept only in the Keychain (`WhenUnlockedThisDeviceOnly`) and are never written to files or logs.
- Tessera never asks for an Apple Account password.
- Imported files live in the app container, excluded from backups; profiles use complete file protection.
- Provisioning profiles are parsed but Apple's CMS signature on them is **not yet verified**.
- Tessera makes no network requests of its own.

## Next steps

1. Get CI green (fix first-build compile errors).
2. Phase 4: evaluate signing approaches on a real device. Review the licence of any reference project (e.g. Feather) before reusing code.
3. Wire the chosen signer behind `SigningEngine`, verify output independently, then enable export of signed IPAs.
4. Notarization workflows, then `.tipa`.
