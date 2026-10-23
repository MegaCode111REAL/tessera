#!/usr/bin/env python3
"""Makes a *fake-signed* copy of an IPA, for testing Tessera's inspector and validation.

Usage:  python3 scripts/fake_sign_ipa.py INPUT.ipa OUTPUT.ipa [--expired]

What it does (standard library only):
  - reads the app's bundle identifier from its Info.plist,
  - adds an embedded.mobileprovision whose App ID matches it (valid until 2036, or expired in 2021
    with --expired and the Ad Hoc type),
  - adds a _CodeSignature/CodeResources stub,
  - copies every other entry byte-for-byte (the app's executable is NOT modified).

The result is NOT validly signed and will not install anywhere. The profile is hand-built and is not
signed by Apple. Do not use this for anything except testing.
"""
import datetime
import plistlib
import sys
import zipfile

FAKE_CERTIFICATE = b"tessera-fake-certificate-bytes"   # same stand-in as scripts/make_test_ipas.py
TEAM = "TEAM123456"


def mobileprovision(bundle_id: str, expired: bool) -> bytes:
    data = {
        "UUID": "CCCCCCCC-1111-2222-3333-444444444444" if not expired else "DDDDDDDD-1111-2222-3333-444444444444",
        "Name": "Tessera Fake AdHoc (expired, test only)" if expired else "Tessera Fake Dev (test only)",
        "TeamName": "Tessera Sample Team",
        "TeamIdentifier": [TEAM],
        "ApplicationIdentifierPrefix": [TEAM],
        "CreationDate": datetime.datetime(2020, 1, 1, 12, 0, 0) if expired else datetime.datetime(2025, 1, 1, 12, 0, 0),
        "ExpirationDate": datetime.datetime(2021, 1, 1) if expired else datetime.datetime(2036, 1, 1),
        "Platform": ["iOS"],
        "ProvisionedDevices": ["00008030-000A11223344002E"] if expired
                              else ["00008030-000A11223344002E", "00008110-000B55667788801E"],
        "DeveloperCertificates": [FAKE_CERTIFICATE],
        "Entitlements": {
            "application-identifier": f"{TEAM}.{bundle_id}",
            "com.apple.developer.team-identifier": TEAM,
            "get-task-allow": not expired,
            "keychain-access-groups": [f"{TEAM}.*"],
        },
    }
    # Stand-in bytes for the CMS envelope that wraps a real profile's plist.
    return b"\x30\x82\x01\x00" + plistlib.dumps(data) + b"\x00\x01"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    expired = "--expired" in sys.argv[1:]
    if len(args) != 2:
        print(__doc__)
        return 2
    source, target = args

    with zipfile.ZipFile(source) as zin:
        names = zin.namelist()
        apps = sorted({n.split("/")[1] for n in names if n.startswith("Payload/") and n.split("/")[1].endswith(".app")})
        if len(apps) != 1:
            print(f"error: expected exactly one Payload/*.app, found {apps}")
            return 1
        app = f"Payload/{apps[0]}"
        bundle_id = plistlib.loads(zin.read(f"{app}/Info.plist"))["CFBundleIdentifier"]

        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                relative = info.filename[len(app) + 1:] if info.filename.startswith(app + "/") else ""
                if relative == "embedded.mobileprovision" or relative.startswith("_CodeSignature"):
                    continue   # replaced below
                zout.writestr(info, zin.read(info), compress_type=info.compress_type)

            for path, data in [
                (f"{app}/embedded.mobileprovision", mobileprovision(bundle_id, expired)),
                (f"{app}/_CodeSignature/CodeResources", plistlib.dumps({"files": {}, "files2": {}})),
            ]:
                entry = zipfile.ZipInfo(path)
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                zout.writestr(entry, data)

    # Verify: everything except the two added entries is byte-identical to the input.
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(target) as zout:
        added = {f"{app}/embedded.mobileprovision", f"{app}/_CodeSignature/CodeResources"}
        for name in zin.namelist():
            if name in added or name.startswith(f"{app}/_CodeSignature"):
                continue
            assert zin.read(name) == zout.read(name), f"{name} changed"
        assert added <= set(zout.namelist())
    kind = "expired Ad Hoc" if expired else "valid Development"
    print(f"wrote {target}: {bundle_id}, {kind} fake profile, executable untouched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
