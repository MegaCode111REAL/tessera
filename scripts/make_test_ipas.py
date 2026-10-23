#!/usr/bin/env python3
"""Generates small sample IPAs for manually testing Tessera's import, inspection and safety checks.

Standard library only. Usage:  python3 scripts/make_test_ipas.py [output_dir]
None of these are real apps: the "executables" are minimal Mach-O headers.
"""
import datetime
import plistlib
import struct
import sys
import zlib
import zipfile
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "TestAssets")

# Stand-in for a certificate in a profile's DeveloperCertificates. Tessera only hashes these bytes.
FAKE_CERTIFICATE = b"tessera-fake-certificate-bytes"


def superblob(entitlements: dict) -> bytes:
    """A fake embedded-signature SuperBlob. Only the entitlements slot is real; there is no
    CodeDirectory or CMS signature, so this is NOT a valid signature, just enough to be detected."""
    if not entitlements:
        return struct.pack(">III", 0xFADE0CC0, 12, 0)
    xml = plistlib.dumps(entitlements)
    blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    return struct.pack(">IIIII", 0xFADE0CC0, 20 + len(blob), 1, 5, 20) + blob


def macho(encrypted: bool = False, signature=None) -> bytes:
    """A minimal 64-bit arm64 Mach-O with an LC_UUID, optionally FairPlay-encrypted, and optionally
    carrying a fake code signature. `signature` is None (unsigned) or a dict of entitlements to embed
    (an empty dict gives a signature with no entitlements)."""
    uuid = struct.pack("<II16s", 0x1B, 24, bytes(range(16)))
    # LC_ENCRYPTION_INFO_64: cmd, size, cryptoff, cryptsize, cryptid, pad
    enc = struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x1000, 1, 0) if encrypted else b""
    signed = signature is not None
    count = 1 + (1 if encrypted else 0) + (1 if signed else 0)
    commands_size = len(uuid) + len(enc) + (16 if signed else 0)
    signature_offset = (32 + commands_size + 15) // 16 * 16

    out = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, count, commands_size, 0, 0) + uuid + enc
    if not signed:
        return out + bytes(64)
    blob = superblob(signature)
    out += struct.pack("<IIII", 0x1D, 16, signature_offset, len(blob))   # LC_CODE_SIGNATURE
    assert len(out) == 32 + commands_size
    return out + bytes(signature_offset - len(out)) + blob


def mobileprovision(name: str, uuid: str, expires, bundle_id: str, devices, development: bool) -> bytes:
    """A provisioning profile: a real XML plist inside a fake stand-in for the CMS envelope."""
    team = "TEAM123456"
    entitlements = {
        "application-identifier": f"{team}.{bundle_id}",
        "com.apple.developer.team-identifier": team,
        "get-task-allow": development,
        "aps-environment": "development",
        "keychain-access-groups": [f"{team}.*"],
    }
    data = {
        "UUID": uuid,
        "Name": name,
        "TeamName": "Tessera Sample Team",
        "TeamIdentifier": [team],
        "ApplicationIdentifierPrefix": [team],
        "CreationDate": datetime.datetime(2025, 1, 1, 12, 0, 0),
        "ExpirationDate": expires,
        "Platform": ["iOS"],
        "ProvisionedDevices": devices,
        "DeveloperCertificates": [FAKE_CERTIFICATE],
        "Entitlements": entitlements,
    }
    return b"\x30\x82\x01\x00" + plistlib.dumps(data) + b"\x00\x01"


def png(size: int, rgb: tuple) -> bytes:
    """A solid-colour PNG, built without any imaging library."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    row = b"\x00" + bytes(rgb) * size
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(row * size, 9))
            + chunk(b"IEND", b""))


def info(bundle_id: str, name: str, executable: str, platforms=("iPhoneOS",), **extra) -> bytes:
    data = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": name,
        "CFBundleDisplayName": name,
        "CFBundleExecutable": executable,
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "MinimumOSVersion": "17.0",
        "CFBundleSupportedPlatforms": list(platforms),
        "UIDeviceFamily": [1, 2],
    }
    data.update(extra)
    return plistlib.dumps(data)


def add(zf: zipfile.ZipFile, path: str, data: bytes, executable: bool = False) -> None:
    entry = zipfile.ZipInfo(path)
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3
    entry.external_attr = (0o100755 if executable else 0o100644) << 16
    zf.writestr(entry, data)


def valid_app(zf: zipfile.ZipFile, app: str, name: str, bundle_id: str,
              encrypted: bool = False, platforms=("iPhoneOS",), nested: bool = True) -> None:
    root = f"Payload/{app}"
    icons = {"CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}}
    add(zf, f"{root}/Info.plist", info(bundle_id, name, name, platforms, **icons))
    add(zf, f"{root}/{name}", macho(encrypted), executable=True)
    add(zf, f"{root}/AppIcon60x60@2x.png", png(120, (64, 84, 191)))
    if nested:
        add(zf, f"{root}/Frameworks/Core.framework/Info.plist", info(f"{bundle_id}.core", "Core", "Core"))
        add(zf, f"{root}/Frameworks/Core.framework/Core", macho(), executable=True)
        add(zf, f"{root}/PlugIns/Share.appex/Info.plist", info(f"{bundle_id}.share", "Share", "Share"))
        add(zf, f"{root}/PlugIns/Share.appex/Share", macho(), executable=True)


def signed_app(zf: zipfile.ZipFile, app: str, name: str, bundle_id: str, profile: bytes,
               unsigned_extension: bool = False) -> None:
    """A build that looks signed: fake code signature with entitlements, an embedded profile,
    a _CodeSignature folder, and signed nested code (optionally leaving the extension unsigned)."""
    root = f"Payload/{app}"
    team = "TEAM123456"
    entitlements = {
        "application-identifier": f"{team}.{bundle_id}",
        "com.apple.developer.team-identifier": team,
        "get-task-allow": True,
        "aps-environment": "development",
        "keychain-access-groups": [f"{team}.{bundle_id}"],
    }
    icons = {"CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}}
    add(zf, f"{root}/Info.plist", info(bundle_id, name, name, **icons))
    add(zf, f"{root}/{name}", macho(signature=entitlements), executable=True)
    add(zf, f"{root}/AppIcon60x60@2x.png", png(120, (237, 140, 51)))
    add(zf, f"{root}/embedded.mobileprovision", profile)
    add(zf, f"{root}/_CodeSignature/CodeResources", plistlib.dumps({"files": {}, "files2": {}}))
    add(zf, f"{root}/Frameworks/Core.framework/Info.plist", info(f"{bundle_id}.core", "Core", "Core"))
    add(zf, f"{root}/Frameworks/Core.framework/Core", macho(signature={}), executable=True)
    add(zf, f"{root}/PlugIns/Share.appex/Info.plist", info(f"{bundle_id}.share", "Share", "Share"))
    add(zf, f"{root}/PlugIns/Share.appex/Share",
        macho() if unsigned_extension else macho(signature={}), executable=True)


def write(name: str, build) -> None:
    path = OUT / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        build(zf)
    print(f"{path}  {path.stat().st_size} bytes")


OUT.mkdir(parents=True, exist_ok=True)

# 1. A well-formed build with a framework, an extension and an icon.
write("valid-sample.ipa", lambda zf: valid_app(zf, "TesseraSample.app", "TesseraSample", "com.example.tesserasample"))

# 2. FairPlay-encrypted main binary: must be flagged and refused for signing.
write("encrypted.ipa", lambda zf: valid_app(zf, "Encrypted.app", "Encrypted", "com.example.encrypted", encrypted=True, nested=False))

# 3. Simulator build: must be flagged as unusable on a device.
write("simulator.ipa", lambda zf: valid_app(zf, "Sim.app", "Sim", "com.example.sim", platforms=("iPhoneSimulator",), nested=False))

# 4. Not an IPA: no Payload folder.
write("no-payload.ipa", lambda zf: add(zf, "readme.txt", b"no payload here"))

# 5. Path traversal entry: must be rejected before anything is extracted.
def traversal(zf):
    valid_app(zf, "Evil.app", "Evil", "com.example.evil", nested=False)
    add(zf, "Payload/../../escaped.txt", b"should never be written")
write("traversal.ipa", traversal)

# 6. Symbolic link entry: must be rejected.
def symlink(zf):
    valid_app(zf, "Link.app", "Link", "com.example.link", nested=False)
    entry = zipfile.ZipInfo("Payload/Link.app/sneaky")
    entry.create_system = 3
    entry.external_attr = 0o120777 << 16
    zf.writestr(entry, "/etc/passwd")
write("symlink.ipa", symlink)

# 7. Two app bundles in one IPA: must be refused.
def two_apps(zf):
    valid_app(zf, "One.app", "One", "com.example.one", nested=False)
    valid_app(zf, "Two.app", "Two", "com.example.two", nested=False)
write("two-apps.ipa", two_apps)

# 8. Not a ZIP at all.
(OUT / "not-a-zip.ipa").write_bytes(b"this is plain text, not a zip archive\n")
print(f"{OUT / 'not-a-zip.ipa'}  written")

# 9. "Fake signed" build: has a (fake) code signature with entitlements, an embedded Development
#    profile that is valid until 2036, and signed nested code. Everything should read as signed.
write("signed-sample.ipa", lambda zf: signed_app(
    zf, "SignedSample.app", "SignedSample", "com.example.signedsample",
    mobileprovision("Tessera Sample Dev", "AAAAAAAA-1111-2222-3333-444444444444",
                    datetime.datetime(2036, 1, 1), "com.example.signedsample",
                    ["00008030-000A11223344002E", "00008110-000B55667788801E"], development=True)))

# 10. Signed, but the embedded Ad Hoc profile expired in 2021 and the extension is unsigned:
#     expect "profile expired" and "nested component unsigned" warnings (not errors).
write("signed-expired-profile.ipa", lambda zf: signed_app(
    zf, "OldBuild.app", "OldBuild", "com.example.oldbuild",
    mobileprovision("Tessera Old AdHoc", "BBBBBBBB-1111-2222-3333-444444444444",
                    datetime.datetime(2021, 1, 1), "com.example.oldbuild",
                    ["00008030-000A11223344002E"], development=False),
    unsigned_extension=True))

# 11. A binary laid out the way a linker emits it (__TEXT/__LINKEDIT, header padding), made fake-signed by
#     scripts/fake_sign_ipa.py. Mirrors what CI does to the real Tessera build, so the Swift tests can
#     check Tessera's Mach-O reader against it.
import os
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_sign_ipa
import test_fake_sign

with tempfile.TemporaryDirectory() as tmp:
    raw = os.path.join(tmp, "Tessera.ipa")
    test_fake_sign.make_ipa(raw, test_fake_sign.realistic_macho())
    print(fake_sign_ipa.fake_sign(raw, str(OUT / "tessera-like-fake-signed.ipa")))
