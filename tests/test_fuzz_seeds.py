"""Small seed-contract checks; no Rust build or model download required."""
import struct
import tempfile
import unittest
from pathlib import Path

from fuzz.seed_corpus import generate, manifest_seeds, weight_seeds


class FuzzSeedContractTests(unittest.TestCase):
    def test_known_good_and_adversarial_binary_seeds(self):
        seeds = weight_seeds()
        self.assertEqual(seeds["valid-v3-minimal"][:8], b"PERCIW03")
        self.assertEqual(len(seeds["valid-v3-minimal"]), 80)
        self.assertEqual(seeds["valid-v3-one-label"][:8], b"PERCIW03")
        self.assertEqual(len(seeds["valid-v3-one-label"]), 1136)
        self.assertEqual(len(seeds["valid-v3-one-label-one-record"]), 1656)
        self.assertEqual(len(seeds["truncated-header-79"]), 79)
        self.assertEqual(
            struct.unpack_from("<I", seeds["regression-u32-max-label-count"], 20)[0],
            0xFFFFFFFF,
        )
        self.assertEqual(seeds["regression-magic-version-mismatch"][:8], b"PERCIW02")
        self.assertEqual(
            struct.unpack_from("<I", seeds["regression-magic-version-mismatch"], 8)[0], 3
        )

    def test_seed_generation_and_exact_bytes_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = generate(root)
            self.assertEqual(first, generate(root, check=True))
            self.assertEqual(len(first), len(weight_seeds()) + len(manifest_seeds()))
            target = root / "perciw03_loader" / "regression-u32-max-label-count"
            target.write_bytes(target.read_bytes() + b"!")
            with self.assertRaisesRegex(ValueError, "Seed differs"):
                generate(root, check=True)

    def test_manifest_seeds_are_structurally_distinct(self):
        seeds = manifest_seeds()
        self.assertIn(b'"promotion_status":"candidate"', seeds["candidate-valid-json"])
        self.assertFalse(seeds["candidate-truncated-json"].endswith(b"}"))
        self.assertEqual(seeds["candidate-invalid-utf8"], b"{\xff}")


if __name__ == "__main__":
    unittest.main()
