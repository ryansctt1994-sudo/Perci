"""Perci package manifest validation, offline and without Git LFS."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.verify_package import validate_manifest_entries

ROOT = Path(__file__).resolve().parents[1]
GOOD = {"path": "models/fixture.pwgt", "format": "PERCIW03",
        "bytes": 80, "sha256": "a" * 64}


class PackageManifestTests(unittest.TestCase):
    def validate(self, **changes):
        entry = {**GOOD, **changes}
        return validate_manifest_entries({"artifacts": [entry]})

    def test_valid_metadata(self):
        self.assertEqual(len(self.validate()), 1)

    def test_path_traversal_and_noncanonical_paths_rejected(self):
        for path in ("../outside.pwgt", "models/../../outside.pwgt",
                     "models/./file.pwgt", "models//file.pwgt",
                     "models\\file.pwgt", "/tmp/outside.pwgt",
                     "models/file.pwgt\x00suffix"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate(path=path)

    def test_manifest_duplicates_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_manifest_entries({"artifacts": [GOOD, copy.copy(GOOD)]})

    def test_hash_must_be_64_lowercase_hex(self):
        for digest in ("0" * 63, "z" * 64, "F" * 64, None):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.validate(sha256=digest)

    def test_reject_invalid_size_and_format(self):
        for value in (0, -1, True, "80"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(bytes=value)
        with self.assertRaises(ValueError):
            self.validate(format="PERCIW04")
        with self.assertRaises(ValueError):
            self.validate(path="models/fixture.bdlg")

    def test_malformed_manifest_fails_closed(self):
        for value in (None, {}, {"artifacts": []}, {"artifacts": [123]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_manifest_entries(value)

    def test_cli_rejects_corrupted_json_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "bad.json"
            bad.write_text('{"artifacts": [', encoding="utf-8")
            process = subprocess.run(
                [sys.executable, "scripts/verify_package.py", "--manifest", str(bad)],
                cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 1)
            self.assertFalse(json.loads(process.stdout)["ok"])
            self.assertEqual(process.stderr, "")


if __name__ == "__main__":
    unittest.main()
