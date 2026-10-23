#!/usr/bin/env python3
"""Generates small sample IPAs for manually testing Tessera's import, inspection and safety checks.

Standard library only. Usage:  python3 scripts/make_test_ipas.py [output_dir]
None of these are real apps: the "executables" are minimal Mach-O headers.
"""
import plistlib
import struct
import sys
import zlib
import zipfile
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "TestAssets")


def macho(encrypted: bool = False) -> bytes:
    """A minimal 64-bit arm64 Mach-O header with an LC_UUID (and optionally FairPlay encryption)."""
    commands = struct.pack("<II16s", 0x1B, 24, bytes(range(16)))
    count = 1
    if encrypted:
        # LC_ENCRYPTION_INFO_64: cmd, size, cryptoff, cryptsize, cryptid, pad
        commands += struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x1000, 1, 0)
        count += 1
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, count, len(commands), 0, 0)
    return header + commands + bytes(64)


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
