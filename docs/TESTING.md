# Manual testing

Automated tests (`swift test`, run by CI) cover the core logic and push the sample IPAs below through the real import pipeline. This checklist is for what only a device can show: the UI, Files/share-sheet integration, the `tessera://` scheme, and behaviour under real iOS restrictions.

## Setup

1. Get `Tessera-unsigned.ipa` from the latest green CI run on `main` (Actions > run > Artifacts) and install it on the device or virtual device using whatever method it supports.
2. Put the files from [`TestAssets/`](../TestAssets) where the device can open them (a Files-app upload, or download them in Safari from the repository).

`scripts/make_test_ipas.py` regenerates the samples. None of them are real apps.

## Tessera inspecting itself

The CI run that builds `Tessera-unsigned.ipa` also publishes an artifact **Tessera-fake-signed-ipas** with two copies of the real Tessera build (made by `scripts/fake_sign_ipa.py`; the executable is untouched):

| File | Expected in the inspector |
| --- | --- |
| `Tessera-fake-signed.ipa` | Name *Tessera*, `dev.tessera.app`, 0.1.0 (1), arm64, an embedded profile *Tessera Fake Dev (test only)*: Development, App ID `dev.tessera.app`, 2 devices, expires 2036. No "profile expired" warning. |
| `Tessera-fake-signed-expired.ipa` | Same build with an embedded *Ad Hoc* profile that expired in 2021: an "embedded profile expired" warning. |

The code-signature row reflects the real binary (the linker normally gives it an ad-hoc signature, so it may read "Present" with no entitlements). Whatever it shows, note it: that is the first look at a real Xcode-built binary, which the hand-made samples below can't tell us. Unlike the samples, there is no icon unless the build has a loose icon file (asset-catalog icons can't be read yet).

These are **not** validly signed and will not install; they exist to exercise the inspector and validation.

## Import and inspect

Import each file from the Library tab (+). Expected results:

| File | Expected |
| --- | --- |
| `valid-sample.ipa` | Imports as **Imported**. Name *TesseraSample*, `com.example.tesserasample`, 1.0 (1), arm64, iPhone and iPad, a blue icon, 1 extension, 1 framework, signature "None". One info note: no code signature. |
| `signed-sample.ipa` | Imports as **Imported** with **no findings**. Signature "Present", embedded profile *Tessera Sample Dev* (Development, team TEAM123456, App ID `com.example.signedsample`, 2 devices, 1 certificate, expires 2036), 5 entitlements listed, extension and framework both shown signed, orange icon. |
| `signed-expired-profile.ipa` | Imports as **Imported** with two warnings: embedded profile expired (2021) and 1 nested component unsigned. Profile type Ad Hoc, 1 device. |
| `encrypted.ipa` | Imports as **Needs Attention** with an error that the executable is encrypted. |
| `simulator.ipa` | Imports as **Needs Attention** with an error that it is a simulator build. |
| `no-payload.ipa` | Alert: the archive has no Payload folder. Nothing added to the Library. |
| `traversal.ipa` | Alert: unsafe path `Payload/../../escaped.txt`. Nothing added. |
| `symlink.ipa` | Alert: symbolic link refused. Nothing added. |
| `two-apps.ipa` | Alert: more than one app bundle (One.app, Two.app). Nothing added. |
| `not-a-zip.ipa` | Alert: "not-a-zip.ipa" is not a readable archive. Nothing added. |

After the failures, Settings > Storage should show **0 bytes** of temporary files.

The two `signed-*` samples are **fake**: they contain a signature-shaped blob carrying entitlements, a hand-built profile, and no real CodeDirectory or CMS signature. They exist to exercise the inspector and validation, and they will not install anywhere. Tessera currently detects that a signature is *present* and reads its entitlements; it does not cryptographically verify signatures.

To try the signing checks with them, import a `.p12` and the matching profile: with these samples the certificate will not be in the embedded profile, so "certificate not in profile" is the expected blocking result.

## Share to Tessera

- From the Files app, share/open `valid-sample.ipa` with Tessera. It should import and jump to the inspector.
- Also try an `.ipa` from another app's share sheet or AirDrop, and a non-IPA file (expect "Only .ipa files can be opened").

## `tessera://` links

Type these into the browser's address bar on the device:

```
tessera://install?url=https%3A%2F%2Fraw.githubusercontent.com%2FMegaCode111REAL%2Ftessera%2Fmain%2FTestAssets%2Fvalid-sample.ipa
```

Expected: a confirmation dialog naming `raw.githubusercontent.com` and the full URL. Cancel imports nothing. "Download and Import" imports the build and opens its inspector.

These must all be refused with a message, with no download and no confirmation:

```
tessera://install?url=http://example.com/a.ipa
tessera://install?url=https://user:pass@example.com/a.ipa
tessera://install
tessera://delete?url=https://example.com/a.ipa
```

## Certificates, profiles, signing

- Certificates: import a `.p12`. A wrong password shows the "not your Apple Account password" message; a right one lists the identity with its expiry and a private-key indicator.
- Profiles: import a `.mobileprovision`. Check the type, expiry, App ID, device count and certificates shown.
- Signing tab: pick a build, identity and profile. Mismatches (bundle ID, expired items, certificate not in the profile) must appear as blocking problems. With the current engine, running a job ends **Unsupported** and creates no signed IPA.

## About virtual devices (e.g. Corellium)

They are very useful for iterating on the UI, import, share sheet and URL scheme. Do **not** treat a signing or install result from a virtual device as proof for a stock iPhone: they usually run with relaxed code-signing and sandbox rules. The plan's final signing and installation checks must still pass on a real, unmodified device.

## What to report

For anything unexpected, a screenshot plus the text from Settings > Diagnostics > Logs is enough. Never share a `.p12`, its password or a private key.
