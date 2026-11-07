"""Offline safety checks for the local pinned-nightly installer."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from protocol_rust.fuzzing import install_toolchain as installer


TARGET = "x86_64-unknown-linux-gnu"
ARCHIVE = f"rustc-nightly-{TARGET}.tar.xz"


class Response(io.BytesIO):
    def geturl(self):
        return installer.DIST_URL + ARCHIVE


class InstallerSafetyTests(unittest.TestCase):
    def test_artifacts_and_redirects_require_the_exact_official_dated_url(self):
        expected = installer.DIST_URL + ARCHIVE
        installer.require_official_url(expected, expected)
        for changed in (
            expected.replace("https:", "http:"),
            expected.replace("static.rust-lang.org", "example.org"),
            expected.replace("static.rust-lang.org", "user@static.rust-lang.org"),
            expected.replace("static.rust-lang.org", "static.rust-lang.org:443"),
            expected.replace(installer.DATE, "2026-11-06"),
            expected + "?download=1", expected + "#fragment",
            expected.replace("rustc-nightly", "cargo-nightly"),
        ):
            with self.subTest(url=changed), self.assertRaises(installer.InstallError):
                installer.require_official_url(changed, expected)
            handler = installer._OfficialRedirects(expected)
            with self.subTest(redirect=changed), self.assertRaises(installer.InstallError):
                handler.redirect_request(None, None, 302, "Found", {}, changed)

    def test_hash_mismatch_retains_failed_download_and_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, log = directory / ARCHIVE, directory / "download.log"
            opener = mock.Mock()
            opener.open.return_value = Response(b"a corrupt downloaded archive")
            with mock.patch.object(installer.urllib.request, "build_opener", return_value=opener):
                with redirect_stdout(io.StringIO()), self.assertRaisesRegex(installer.InstallError, "SHA256 mismatch"):
                    installer.download(installer.DIST_URL + ARCHIVE, archive, log, "0" * 64)
            self.assertEqual(archive.read_bytes(), b"a corrupt downloaded archive")
            self.assertIn("failed: SHA256 mismatch", log.read_text())
            self.assertNotIn("verified: yes", log.read_text())

    def test_existing_log_is_never_overwritten_or_downloaded(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / "download.log"
            log.write_text("previous attempt\n")
            opener = mock.Mock()
            with mock.patch.object(installer.urllib.request, "build_opener", return_value=opener):
                with redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
                    installer.download(installer.DIST_URL + ARCHIVE, directory / ARCHIVE, log)
            opener.open.assert_not_called()
            self.assertEqual(log.read_text(), "previous attempt\n")

    def make_archive(self, path, extra=None):
        root = ARCHIVE.removesuffix(".tar.xz")
        with tarfile.open(path, "w:xz") as archive:
            script = b"#!/bin/sh\nexit 0\n"
            member = tarfile.TarInfo(root + "/install.sh")
            member.size = len(script)
            archive.addfile(member, io.BytesIO(script))
            if extra is not None:
                archive.addfile(extra)

    def test_expected_package_root_extracts_a_local_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory / ARCHIVE
            self.make_archive(archive)
            root = installer.extract_package(archive, directory / "unpack")
            self.assertEqual((root / "install.sh").read_bytes(), b"#!/bin/sh\nexit 0\n")

    def test_archive_traversal_and_external_links_are_rejected(self):
        for attack in ("traversal", "symlink"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive = directory / ARCHIVE
                if attack == "traversal":
                    member = tarfile.TarInfo("../escaped")
                else:
                    member = tarfile.TarInfo(ARCHIVE.removesuffix(".tar.xz") + "/link")
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../../../escaped"
                self.make_archive(archive, member)
                with self.assertRaises((installer.InstallError, tarfile.FilterError)):
                    installer.extract_package(archive, directory / "unpack")
                self.assertFalse((directory / "escaped").exists())

    def test_existing_prefix_without_receipt_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "existing"
            prefix.mkdir()
            sentinel = prefix / "important"
            sentinel.write_text("keep this\n")
            with mock.patch.object(installer, "host_target", return_value=TARGET):
                with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    self.assertEqual(installer.main(["--prefix", str(prefix)]), 1)
            self.assertEqual(sentinel.read_text(), "keep this\n")
            self.assertFalse(prefix.with_name(prefix.name + ".downloads").exists())


if __name__ == "__main__":
    unittest.main()
