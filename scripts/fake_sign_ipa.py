#!/usr/bin/env python3
"""Makes a *fake-signed* copy of an IPA, for testing Tessera's inspector and validation.

Usage:  python3 scripts/fake_sign_ipa.py INPUT.ipa OUTPUT.ipa [--expired] [--ldid[=PATH]]

What it does (standard library only):
  - reads the app's bundle identifier and executable name from its Info.plist,
  - fake-signs the main executable, carrying entitlements that match the profile. With --ldid this
    is done by `ldid -S` (the tool wrapped by "fakesigner" and used by TrollStore-style workflows),
    which writes a genuine ad-hoc signature structure. Without it, a built-in fallback appends a
    minimal fake signature instead: an LC_CODE_SIGNATURE load command plus a SuperBlob carrying
    only the entitlements, at the end of __LINKEDIT (an existing signature at the end is replaced),
  - adds an embedded.mobileprovision whose App ID matches the bundle ID (valid until 2036, or an
    Ad Hoc profile that expired in 2021 with --expired),
  - adds a _CodeSignature/CodeResources stub,
  - copies every other entry byte-for-byte.

The result is NOT validly signed and will not install or run anywhere: the blob has no CodeDirectory
or CMS signature and the profile is not signed by Apple. Use it only to test Tessera.
"""
import datetime
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

FAKE_CERTIFICATE = b"tessera-fake-certificate-bytes"   # same stand-in as scripts/make_test_ipas.py
TEAM = "TEAM123456"
PAGE = 0x4000   # arm64 page size


class FakeSignError(Exception):
    pass


# ---------------------------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------------------------

def superblob(entitlements: dict) -> bytes:
    """Fake embedded-signature SuperBlob; only the entitlements slot (5) is real."""
    if not entitlements:
        return struct.pack(">III", 0xFADE0CC0, 12, 0)
    xml = plistlib.dumps(entitlements)
    blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    return struct.pack(">IIIII", 0xFADE0CC0, 20 + len(blob), 1, 5, 20) + blob


def patch_macho(data: bytes, entitlements: dict) -> bytes:
    """Returns `data` (a thin little-endian 64-bit Mach-O) with a fake code signature added."""
    if len(data) < 32:
        raise FakeSignError("executable is too small to be a Mach-O file")
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        raise FakeSignError("fat (multi-architecture) binaries are not supported")
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise FakeSignError("executable is not a thin 64-bit little-endian Mach-O")

    buf = bytearray(data)
    ncmds, sizeofcmds = struct.unpack_from("<II", buf, 16)
    commands_end = 32 + sizeofcmds
    if commands_end > len(buf):
        raise FakeSignError("load commands run past the end of the file")

    linkedit = None      # (command offset, vmsize, fileoff, filesize)
    signature = None     # (command offset, dataoff, datasize)
    first_data = None    # lowest file offset of real section data
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", buf, offset)
        if size < 8 or offset + size > commands_end:
            raise FakeSignError("malformed load command")
        if cmd == 0x19:  # LC_SEGMENT_64
            name = bytes(buf[offset + 8:offset + 24]).split(b"\0")[0]
            _vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, offset + 24)
            nsects = struct.unpack_from("<I", buf, offset + 64)[0]
            if name == b"__LINKEDIT":
                linkedit = (offset, vmsize, fileoff, filesize)
            for i in range(nsects):
                section = offset + 72 + i * 80
                sect_size = struct.unpack_from("<Q", buf, section + 40)[0]
                sect_off = struct.unpack_from("<I", buf, section + 48)[0]
                if sect_off and sect_size:
                    first_data = sect_off if first_data is None else min(first_data, sect_off)
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from("<II", buf, offset + 8)
            signature = (offset, dataoff, datasize)
        offset += size

    if linkedit is None:
        raise FakeSignError("no __LINKEDIT segment found")
    link_cmd, link_vmsize, link_fileoff, link_filesize = linkedit
    if link_fileoff + link_filesize != len(buf):
        raise FakeSignError("__LINKEDIT is not the last thing in the file, so the signature can't be appended")

    if signature is not None:
        # Replace an existing signature, but only if it is the final blob in the file.
        command_offset, dataoff, datasize = signature
        if dataoff + datasize != len(buf):
            raise FakeSignError("the existing signature is not at the end of the file")
        del buf[dataoff:]
        new_command = False
    else:
        command_offset = commands_end
        limit = first_data if first_data is not None else link_fileoff
        if command_offset + 16 > limit:
            raise FakeSignError(
                f"no room for another load command (only {max(limit - command_offset, 0)} free bytes in the header)")
        if any(buf[command_offset:command_offset + 16]):
            raise FakeSignError("header padding after the load commands is not empty")
        new_command = True

    blob = superblob(entitlements)
    signature_offset = (len(buf) + 15) // 16 * 16
    buf += bytes(signature_offset - len(buf)) + blob

    new_filesize = len(buf) - link_fileoff
    new_vmsize = max(link_vmsize, (new_filesize + PAGE - 1) // PAGE * PAGE)
    struct.pack_into("<Q", buf, link_cmd + 32, new_vmsize)
    struct.pack_into("<Q", buf, link_cmd + 48, new_filesize)
    struct.pack_into("<IIII", buf, command_offset, 0x1D, 16, signature_offset, len(blob))
    if new_command:
        struct.pack_into("<II", buf, 16, ncmds + 1, sizeofcmds + 16)
    return bytes(buf)


def read_signature(data: bytes):
    """Independent reader: None if there is no signature, else the entitlements dict (maybe empty)."""
    if data[:4] != b"\xcf\xfa\xed\xfe":
        return None
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        if cmd == 0x1D:
            dataoff, datasize = struct.unpack_from("<II", data, offset + 8)
            blob = data[dataoff:dataoff + datasize]
            magic, length, count = struct.unpack_from(">III", blob, 0)
            # Real signers may pad the data region past the SuperBlob's own length.
            if magic != 0xFADE0CC0 or length > len(blob):
                raise FakeSignError("signature SuperBlob is malformed")
            blob = blob[:length]
            for i in range(count):
                slot, slot_off = struct.unpack_from(">II", blob, 12 + i * 8)
                if slot == 5:
                    entitlement_magic, entitlement_length = struct.unpack_from(">II", blob, slot_off)
                    if entitlement_magic != 0xFADE7171:
                        raise FakeSignError("entitlements blob has the wrong magic")
                    return plistlib.loads(blob[slot_off + 8:slot_off + entitlement_length])
            return {}
        offset += size
    return None


# ---------------------------------------------------------------------------------------------
# Profile and IPA
# ---------------------------------------------------------------------------------------------

def entitlements_for(bundle_id: str, expired: bool) -> dict:
    return {
        "application-identifier": f"{TEAM}.{bundle_id}",
        "com.apple.developer.team-identifier": TEAM,
        "get-task-allow": not expired,
        "keychain-access-groups": [f"{TEAM}.{bundle_id}"],
    }


def mobileprovision(bundle_id: str, expired: bool) -> bytes:
    profile_entitlements = entitlements_for(bundle_id, expired)
    profile_entitlements["keychain-access-groups"] = [f"{TEAM}.*"]
    data = {
        "UUID": "DDDDDDDD-1111-2222-3333-444444444444" if expired else "CCCCCCCC-1111-2222-3333-444444444444",
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
        "Entitlements": profile_entitlements,
    }
    # Stand-in bytes for the CMS envelope that wraps a real profile's plist.
    return b"\x30\x82\x01\x00" + plistlib.dumps(data) + b"\x00\x01"


def ldid_sign(data: bytes, entitlements: dict, ldid: str = "ldid") -> bytes:
    """Fake-signs a Mach-O with `ldid -S<entitlements.plist> <binary>` and returns the result."""
    tool = shutil.which(ldid)
    if tool is None:
        raise FakeSignError(f"{ldid!r} was not found. Install it (macOS: `brew install ldid`).")
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "binary")
        plist = os.path.join(tmp, "entitlements.plist")
        with open(binary, "wb") as handle:
            handle.write(data)
        with open(plist, "wb") as handle:
            handle.write(plistlib.dumps(entitlements))
        try:
            result = subprocess.run([tool, f"-S{plist}", binary], capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            raise FakeSignError(f"could not run ldid: {error}") from error
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise FakeSignError(f"ldid failed with exit code {result.returncode}: {detail}")
        with open(binary, "rb") as handle:
            return handle.read()


def fake_sign(source: str, target: str, expired: bool = False, ldid: "str | None" = None) -> str:
    """`ldid` is None for the built-in fake signature, or the name/path of an ldid executable."""
    with zipfile.ZipFile(source) as zin:
        names = zin.namelist()
        apps = sorted({n.split("/")[1] for n in names if n.startswith("Payload/") and n.count("/") >= 2
                       and n.split("/")[1].endswith(".app")})
        if len(apps) != 1:
            raise FakeSignError(f"expected exactly one Payload/*.app, found {apps}")
        app = f"Payload/{apps[0]}"
        info = plistlib.loads(zin.read(f"{app}/Info.plist"))
        bundle_id = info["CFBundleIdentifier"]
        executable = f"{app}/{info['CFBundleExecutable']}"
        if executable not in names:
            raise FakeSignError(f"{executable} not found in the archive")

        entitlements = entitlements_for(bundle_id, expired)
        original = zin.read(executable)
        if ldid is not None:
            patched = ldid_sign(original, entitlements, ldid)
            signer = "ldid"
        else:
            patched = patch_macho(original, entitlements)
            signer = "built-in"

        skipped = {f"{app}/embedded.mobileprovision"}
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zout:
            for entry in zin.infolist():
                if entry.filename in skipped or entry.filename.startswith(f"{app}/_CodeSignature"):
                    continue
                content = patched if entry.filename == executable else zin.read(entry)
                zout.writestr(entry, content, compress_type=entry.compress_type)
            for path, data in [
                (f"{app}/embedded.mobileprovision", mobileprovision(bundle_id, expired)),
                (f"{app}/_CodeSignature/CodeResources", plistlib.dumps({"files": {}, "files2": {}})),
            ]:
                entry = zipfile.ZipInfo(path)
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                zout.writestr(entry, data)

    # Verify the result with an independent reader, and that nothing else changed.
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(target) as zout:
        added = {f"{app}/embedded.mobileprovision", f"{app}/_CodeSignature/CodeResources"}
        for name in zin.namelist():
            if name == executable or name in added or name.startswith(f"{app}/_CodeSignature"):
                continue
            if zin.read(name) != zout.read(name):
                raise FakeSignError(f"{name} changed unexpectedly")
        if not added <= set(zout.namelist()):
            raise FakeSignError("profile or CodeResources missing from the output")
        read_back = read_signature(zout.read(executable))
        if read_back is None:
            raise FakeSignError("the output executable has no code signature")
        if read_back != entitlements:
            # Tessera reads entitlements from the XML slot, so a signer that omits it is worth flagging.
            raise FakeSignError(f"the entitlements in the output signature are {read_back!r}, expected {entitlements!r}")
    kind = "expired Ad Hoc" if expired else "valid Development"
    return (f"wrote {target}: {bundle_id}, {signer} fake signature with {len(entitlements)} entitlements in "
            f"{info['CFBundleExecutable']}, {kind} fake profile")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        return 2
    ldid = None
    for option in sys.argv[1:]:
        if option == "--ldid":
            ldid = "ldid"
        elif option.startswith("--ldid="):
            ldid = option.split("=", 1)[1]
    try:
        print(fake_sign(args[0], args[1], expired="--expired" in sys.argv[1:], ldid=ldid))
    except FakeSignError as error:
        print(f"error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
