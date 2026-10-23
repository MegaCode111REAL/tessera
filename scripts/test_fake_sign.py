#!/usr/bin/env python3
"""Tests for fake_sign_ipa.py. Run: python3 scripts/test_fake_sign.py"""
import os
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_sign_ipa as fs  # noqa: E402

TEXT_SIZE = 0x4000
LINKEDIT_SIZE = 0x120


def realistic_macho(room: int = 32, existing_signature: bool = False, linkedit_last: bool = True) -> bytes:
    """A thin arm64 Mach-O shaped like a linker's output: __TEXT (with a __text section placed after
    `room` spare header bytes), __LINKEDIT at the end, LC_UUID and LC_SYMTAB."""
    uuid = struct.pack("<II16s", 0x1B, 24, bytes(range(16)))
    symtab = struct.pack("<IIIIII", 0x02, 24, 0x4000, 4, 0x4040, 0x40)
    text_cmd_size = 72 + 80
    commands_size = text_cmd_size + 72 + len(uuid) + len(symtab) + (16 if existing_signature else 0)
    text_offset = 32 + commands_size + room

    text = struct.pack("<II16sQQQQiiII", 0x19, text_cmd_size, b"__TEXT", 0x100000000, TEXT_SIZE, 0, TEXT_SIZE, 5, 5, 1, 0)
    text += struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x100000000 + text_offset, 0x100,
                        text_offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    linkedit_data = bytes(range(256))[:LINKEDIT_SIZE - 0x20] + bytes(0x20)
    sig_blob = fs.superblob({"old": True}) if existing_signature else b""
    link_size = LINKEDIT_SIZE + (len(sig_blob) if existing_signature else 0)
    linkedit = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__LINKEDIT", 0x100004000, 0x4000, TEXT_SIZE, link_size, 1, 1, 0, 0)

    commands = text + linkedit + uuid + symtab
    count = 4
    if existing_signature:
        commands += struct.pack("<IIII", 0x1D, 16, TEXT_SIZE + LINKEDIT_SIZE, len(sig_blob))
        count += 1
    assert len(commands) == commands_size
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, count, len(commands), 0x200085, 0)
    body = header + commands
    body += bytes(TEXT_SIZE - len(body))
    data = body + linkedit_data + sig_blob
    if not linkedit_last:
        data += b"trailing junk"
    return data


ENTITLEMENTS = {
    "application-identifier": "TEAM123456.dev.tessera.app",
    "com.apple.developer.team-identifier": "TEAM123456",
    "get-task-allow": True,
}


class PatchMachOTests(unittest.TestCase):
    def test_adds_signature_and_keeps_structure_valid(self):
        original = realistic_macho()
        self.assertIsNone(fs.read_signature(original))
        patched = fs.patch_macho(original, ENTITLEMENTS)

        self.assertEqual(fs.read_signature(patched), ENTITLEMENTS)
        ncmds_old, size_old = struct.unpack_from("<II", original, 16)
        ncmds_new, size_new = struct.unpack_from("<II", patched, 16)
        self.assertEqual((ncmds_new, size_new), (ncmds_old + 1, size_old + 16))

        # Everything outside the header counters, the new command, and __LINKEDIT's size fields is unchanged.
        linkedit_cmd = 32 + 152
        keep = bytearray(patched[:len(original)])
        keep[16:24] = original[16:24]
        keep[32 + size_old:32 + size_old + 16] = original[32 + size_old:32 + size_old + 16]
        keep[linkedit_cmd + 32:linkedit_cmd + 40] = original[linkedit_cmd + 32:linkedit_cmd + 40]
        keep[linkedit_cmd + 48:linkedit_cmd + 56] = original[linkedit_cmd + 48:linkedit_cmd + 56]
        self.assertEqual(bytes(keep), original)

        # __LINKEDIT now ends exactly at the end of the file, page-aligned in memory.
        vmsize, fileoff, filesize = struct.unpack_from("<QQQ", patched, linkedit_cmd + 32)
        self.assertEqual(fileoff + filesize, len(patched))
        self.assertEqual(vmsize % fs.PAGE, 0)
        self.assertGreaterEqual(vmsize, filesize)

        # The signature data is 16-byte aligned and inside __LINKEDIT.
        command = 32 + size_old
        cmd, size, dataoff, datasize = struct.unpack_from("<IIII", patched, command)
        self.assertEqual((cmd, size), (0x1D, 16))
        self.assertEqual(dataoff % 16, 0)
        self.assertEqual(dataoff + datasize, len(patched))
        self.assertGreaterEqual(dataoff, fileoff)

    def test_replaces_an_existing_signature_at_the_end(self):
        original = realistic_macho(existing_signature=True)
        self.assertEqual(fs.read_signature(original), {"old": True})
        patched = fs.patch_macho(original, ENTITLEMENTS)
        self.assertEqual(fs.read_signature(patched), ENTITLEMENTS)
        self.assertEqual(struct.unpack_from("<II", patched, 16), struct.unpack_from("<II", original, 16))

    def test_empty_entitlements_give_a_signature_without_entitlements(self):
        patched = fs.patch_macho(realistic_macho(), {})
        self.assertEqual(fs.read_signature(patched), {})

    def test_refuses_when_the_header_has_no_room(self):
        with self.assertRaisesRegex(fs.FakeSignError, "no room"):
            fs.patch_macho(realistic_macho(room=8), ENTITLEMENTS)

    def test_exactly_enough_room_works(self):
        patched = fs.patch_macho(realistic_macho(room=16), ENTITLEMENTS)
        self.assertEqual(fs.read_signature(patched), ENTITLEMENTS)

    def test_refuses_fat_non_macho_and_odd_layouts(self):
        with self.assertRaisesRegex(fs.FakeSignError, "fat"):
            fs.patch_macho(b"\xca\xfe\xba\xbe" + bytes(100), ENTITLEMENTS)
        with self.assertRaisesRegex(fs.FakeSignError, "not a thin"):
            fs.patch_macho(b"hello world" * 10, ENTITLEMENTS)
        with self.assertRaisesRegex(fs.FakeSignError, "too small"):
            fs.patch_macho(b"\xcf\xfa", ENTITLEMENTS)
        with self.assertRaisesRegex(fs.FakeSignError, "not the last"):
            fs.patch_macho(realistic_macho(linkedit_last=False), ENTITLEMENTS)

    def test_truncated_input_never_crashes_unexpectedly(self):
        original = realistic_macho()
        for length in range(0, 400, 7):
            try:
                fs.patch_macho(original[:length], ENTITLEMENTS)
            except fs.FakeSignError:
                pass


class PaddedBlobTests(unittest.TestCase):
    def test_reader_accepts_a_signature_region_padded_past_the_blob(self):
        patched = bytearray(fs.patch_macho(realistic_macho(), ENTITLEMENTS))
        _, size = struct.unpack_from("<II", patched, 16)
        command = 32 + size - 16   # the LC_CODE_SIGNATURE command was appended last
        cmd, _, dataoff, datasize = struct.unpack_from("<IIII", patched, command)
        self.assertEqual(cmd, 0x1D)
        patched += bytes(32)
        struct.pack_into("<I", patched, command + 12, datasize + 32)
        self.assertEqual(fs.read_signature(bytes(patched)), ENTITLEMENTS)

    def test_reader_rejects_a_blob_that_claims_more_than_it_has(self):
        patched = bytearray(fs.patch_macho(realistic_macho(), ENTITLEMENTS))
        _, size = struct.unpack_from("<II", patched, 16)
        command = 32 + size - 16
        _, _, dataoff, datasize = struct.unpack_from("<IIII", patched, command)
        struct.pack_into(">I", patched, dataoff + 4, datasize + 100)
        with self.assertRaises(fs.FakeSignError):
            fs.read_signature(bytes(patched))


class LdidModeTests(unittest.TestCase):
    """Exercises the ldid plumbing with a stand-in executable (the real ldid needs macOS/Homebrew)."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.source = os.path.join(self.dir.name, "in.ipa")
        self.target = os.path.join(self.dir.name, "out.ipa")
        make_ipa(self.source, realistic_macho())

    def tearDown(self):
        self.dir.cleanup()

    def stub(self, body: str) -> str:
        path = os.path.join(self.dir.name, "ldid-stub")
        with open(path, "w") as handle:
            handle.write(body)
        os.chmod(path, 0o755)
        return path

    def test_ldid_is_called_with_dash_s_plist_and_the_binary(self):
        scripts = os.path.dirname(os.path.abspath(__file__))
        stub = self.stub(
            "#!/usr/bin/env python3\n"
            "import plistlib, sys\n"
            f"sys.path.insert(0, {scripts!r})\n"
            "import fake_sign_ipa as fs\n"
            "assert len(sys.argv) == 3 and sys.argv[1].startswith('-S'), sys.argv\n"
            "ents = plistlib.load(open(sys.argv[1][2:], 'rb'))\n"
            "data = open(sys.argv[2], 'rb').read()\n"
            "open(sys.argv[2], 'wb').write(fs.patch_macho(data, ents))\n")
        message = fs.fake_sign(self.source, self.target, ldid=stub)
        self.assertIn("ldid fake signature", message)
        with zipfile.ZipFile(self.target) as z:
            signature = fs.read_signature(z.read("Payload/Tessera.app/Tessera"))
        self.assertEqual(signature["application-identifier"], "TEAM123456.dev.tessera.app")

    def test_ldid_failure_is_reported(self):
        stub = self.stub("#!/bin/sh\necho boom >&2\nexit 3\n")
        with self.assertRaisesRegex(fs.FakeSignError, "exit code 3: boom"):
            fs.fake_sign(self.source, self.target, ldid=stub)

    def test_missing_ldid_is_reported(self):
        with self.assertRaisesRegex(fs.FakeSignError, "not found"):
            fs.fake_sign(self.source, self.target, ldid="definitely-not-installed-ldid")

    def test_a_signer_that_drops_the_entitlements_is_caught(self):
        stub = self.stub("#!/bin/sh\nexit 0\n")   # leaves the binary unsigned
        with self.assertRaisesRegex(fs.FakeSignError, "no code signature"):
            fs.fake_sign(self.source, self.target, ldid=stub)


def make_ipa(path: str, binary: bytes, bundle_id: str = "dev.tessera.app") -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo("Payload/Tessera.app/Info.plist")
        z.writestr(info, plistlib.dumps({"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "Tessera"}, fmt=plistlib.FMT_BINARY))
        exe = zipfile.ZipInfo("Payload/Tessera.app/Tessera")
        exe.create_system = 3
        exe.external_attr = 0o100755 << 16
        z.writestr(exe, binary)
        z.writestr("Payload/Tessera.app/Assets.car", b"assets-bytes")


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.source = os.path.join(self.dir.name, "in.ipa")
        self.target = os.path.join(self.dir.name, "out.ipa")

    def tearDown(self):
        self.dir.cleanup()

    def profile_of(self, z):
        raw = z.read("Payload/Tessera.app/embedded.mobileprovision")
        return plistlib.loads(raw[raw.index(b"<?xml"):raw.rindex(b"</plist>") + 8])

    def test_valid_variant(self):
        make_ipa(self.source, realistic_macho())
        message = fs.fake_sign(self.source, self.target)
        self.assertIn("valid Development", message)
        with zipfile.ZipFile(self.target) as z:
            signature = fs.read_signature(z.read("Payload/Tessera.app/Tessera"))
            self.assertEqual(signature["application-identifier"], "TEAM123456.dev.tessera.app")
            self.assertTrue(signature["get-task-allow"])
            profile = self.profile_of(z)
            self.assertEqual(profile["Entitlements"]["application-identifier"], "TEAM123456.dev.tessera.app")
            self.assertEqual(profile["ExpirationDate"].year, 2036)
            self.assertEqual(z.read("Payload/Tessera.app/Assets.car"), b"assets-bytes")
            self.assertEqual(z.getinfo("Payload/Tessera.app/Tessera").external_attr >> 16, 0o100755)
            self.assertIn("Payload/Tessera.app/_CodeSignature/CodeResources", z.namelist())

    def test_expired_variant(self):
        make_ipa(self.source, realistic_macho())
        fs.fake_sign(self.source, self.target, expired=True)
        with zipfile.ZipFile(self.target) as z:
            self.assertFalse(fs.read_signature(z.read("Payload/Tessera.app/Tessera"))["get-task-allow"])
            profile = self.profile_of(z)
            self.assertEqual(profile["ExpirationDate"].year, 2021)
            self.assertFalse(profile["Entitlements"]["get-task-allow"])

    def test_running_twice_does_not_duplicate_entries(self):
        make_ipa(self.source, realistic_macho())
        fs.fake_sign(self.source, self.target)
        again = os.path.join(self.dir.name, "again.ipa")
        fs.fake_sign(self.target, again)
        with zipfile.ZipFile(again) as z:
            names = z.namelist()
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(sum(n.endswith("embedded.mobileprovision") for n in names), 1)

    def test_bad_inputs_fail_cleanly(self):
        make_ipa(self.source, b"not a macho file at all, just text" * 4)
        with self.assertRaises(fs.FakeSignError):
            fs.fake_sign(self.source, self.target)
        with zipfile.ZipFile(self.source, "w") as z:
            z.writestr("readme.txt", "no payload")
        with self.assertRaisesRegex(fs.FakeSignError, "exactly one"):
            fs.fake_sign(self.source, self.target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
