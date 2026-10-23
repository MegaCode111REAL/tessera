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
| Share an `.ipa` to Tessera (share sheet, "Open in…", AirDrop, Files) | Implemented |
| `tessera://install?url=<https URL>` link: confirms, downloads the IPA into the library, opens the inspector | Implemented + tested |
| Distribution eligibility (never promises installability; notarization is never fabricated) | Implemented + tested |
| `.tipa` | Architecture ready (`FormatAdapter`); disabled |
| Apple notarization submission | Not implemented |

## Layout

- `Sources/TesseraCore`: platform logic as a Swift package (models, `ArchiveEngine`, `BundleInspector`, `ProfileParser`, `CertificateManager`, `SigningEngine`, services, storage).
- `Tessera/`: the SwiftUI app (Library, Inspector, Signing, Certificates, Profiles, Distribution, Activity, Settings).
- `Tests/TesseraCoreTests`: unit tests for the core logic.
- `project.yml`: [XcodeGen](https://github.com/yonaskolb/XcodeGen) spec for the app target.

## No Mac?

You don't need one to build. Every push to `main` runs the `unsigned-ipa` CI job, which uploads `Tessera-unsigned.ipa` as a downloadable artifact (Actions run page, "Artifacts"). The file is **unsigned**: sign and install it with a sideloader you already trust. The same job also publishes `Tessera-fake-signed-ipas`: copies of the real build fake-signed with `ldid` plus a hand-made, *fake* embedded profile (valid and expired variants), purely for testing Tessera's inspector. They will not install or run. See [`docs/TESTING.md`](docs/TESTING.md).

To get signing files for a **paid** developer account without a Mac, generate the certificate request with OpenSSL:

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout dev.key -out dev.csr \
  -subj "/CN=Your Name/emailAddress=you@example.com"
# Upload dev.csr in the developer portal (Certificates > Apple Development), download the .cer, then:
openssl x509 -inform DER -in dev.cer -out dev.pem
openssl pkcs12 -export -inkey dev.key -in dev.pem -out dev.p12
```

Then create a profile in the portal (it needs your device's UDID) and import the `.p12` and `.mobileprovision` in Tessera. OpenSSL 3 writes `.p12` files with newer encryption that some iOS versions reject; if import reports a wrong password for a correct one, add `-legacy` (or `-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1`) to the `pkcs12` command. Free Apple IDs have no portal access, so they can't use this route.

## Build

Requires Xcode 16+ on macOS (or just use the CI artifact above).

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
- The only network code is `DownloadService`, used for `tessera://install` links. It runs only after the user confirms the exact URL, accepts HTTPS only (no embedded credentials, no redirects to HTTP), sends no cookies, and enforces a size limit.

## Install links

```
tessera://install?url=https%3A%2F%2Fexample.com%2Fapp.ipa
```

"Install" here means *download into Tessera's library and inspect*. iOS doesn't allow an ordinary app to install arbitrary IPAs, so Tessera never claims otherwise. `tessera://import?url=…` behaves the same. Files shared to the app go straight to the importer.

## Next steps

1. Get CI green (fix first-build compile errors).
2. Phase 4: evaluate signing approaches on a real device. Review the licence of any reference project (e.g. Feather) before reusing code.
3. Wire the chosen signer behind `SigningEngine`, verify output independently, then enable export of signed IPAs.
4. Notarization workflows, then `.tipa`.
