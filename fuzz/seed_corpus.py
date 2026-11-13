#!/usr/bin/env python3
"""Recreate bounded seed corpora for the real Perci binary and JSON parsers.

This script writes only under fuzz/corpus. Binary seeds are generated, not
checked into Git (the repository ignores unpromoted *.pwgt files).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

FIXED_HEADER = 80
SIGNED_LABEL_BYTES = 16 + 16 + (4096 // 64) * 8 * 2
RECORD_BYTES = 520
DEFAULT_ROOT = Path(__file__).resolve().parent / "corpus"


def weight_header(magic: bytes = b"PERCIW03", version: int = 3) -> bytearray:
    assert len(magic) == 8
    data = bytearray(FIXED_HEADER)
    data[:8] = magic
    struct.pack_into("<I", data, 8, version)
    struct.pack_into("<I", data, 12, 4096)
    struct.pack_into("<I", data, 16, 64)
    struct.pack_into("<Q", data, 32, len(data))
    struct.pack_into("<Q", data, 40, len(data))
    return data


def weight_seeds() -> dict[str, bytes]:
    v3 = weight_header()
    one_label = v3 + bytearray(SIGNED_LABEL_BYTES)
    one_label[80:87] = b"general"
    struct.pack_into("<I", one_label, 20, 1)  # one label
    struct.pack_into("<Q", one_label, 32, len(one_label))
    struct.pack_into("<Q", one_label, 40, len(one_label))
    with_record = one_label + bytearray(RECORD_BYTES)
    struct.pack_into("<Q", with_record, 24, 1)  # one record
    struct.pack_into("<Q", with_record, 40, len(with_record))
    struct.pack_into("<I", with_record, 80 + 16 + 8, 1)  # label's record count

    oversized_count = bytearray(v3)
    struct.pack_into("<I", oversized_count, 20, 0xFFFFFFFF)

    mismatched_magic_version = bytearray(v3)
    mismatched_magic_version[:8] = b"PERCIW02"

    two_labels_one_slot = bytearray(one_label)
    struct.pack_into("<I", two_labels_one_slot, 20, 2)

    bogus_size = bytearray(v3)
    struct.pack_into("<Q", bogus_size, 40, 999999999)

    bogus_records = bytearray(v3)
    struct.pack_into("<Q", bogus_records, 24, 0xFFFFFFFFFFFFFFFF)

    bogus_header_offset = bytearray(v3)
    struct.pack_into("<Q", bogus_header_offset, 32, 0xFFFFFFFFFFFFFFFF)

    concept_overflow = bytearray(one_label)
    struct.pack_into("<I", concept_overflow, 80 + 16 + 12, 0xFFFFFFFF)

    return {
        "valid-v1-minimal": bytes(weight_header(b"PERCIW01", 1)),
        "valid-v2-minimal": bytes(weight_header(b"PERCIW02", 2)),
        "valid-v3-minimal": bytes(v3),
        "valid-v3-one-label": bytes(one_label),
        "valid-v3-one-label-one-record": bytes(with_record),
        "truncated-magic-7": bytes(v3[:7]),
        "truncated-header-79": bytes(v3[:79]),
        "regression-u32-max-label-count": bytes(oversized_count),
        "regression-magic-version-mismatch": bytes(mismatched_magic_version),
        "labels-exceed-header": bytes(two_labels_one_slot),
        "declared-size-mismatch": bytes(bogus_size),
        "unbounded-record-count": bytes(bogus_records),
        "invalid-header-offset": bytes(bogus_header_offset),
        "unbounded-concept-count": bytes(concept_overflow),
    }


def manifest_seeds() -> dict[str, bytes]:
    good = {
        "schema": "perci.pack-manifest.v1",
        "magic": "PERCIW03",
        "format_version": 3,
        "pack_id": "fuzz-seed",
        "family": "PERCIW03",
        "capability_tags": ["cognitive"],
        "promotion_status": "candidate",
    }
    encoded = json.dumps(good, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {
        "candidate-valid-json": encoded,
        "candidate-truncated-json": encoded[:-1],
        "candidate-wrong-root": b"[]",
        "candidate-empty-object": b"{}",
        "candidate-invalid-utf8": b"{\xff}",
    }


def generate(root: Path, check: bool = False) -> dict[str, str]:
    files = {
        **{("perciw03_loader", name): body for name, body in weight_seeds().items()},
        **{("pack_manifest_json", name): body for name, body in manifest_seeds().items()},
    }
    hashes: dict[str, str] = {}
    for (target, name), body in sorted(files.items()):
        path = root / target / name
        if check:
            if not path.is_file() or path.read_bytes() != body:
                raise ValueError(f"Seed differs or is missing: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        hashes[f"{target}/{name}"] = hashlib.sha256(body).hexdigest()
    return hashes


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    cli.add_argument("--check", action="store_true",
                     help="Refuse missing/mutated seeds instead of writing them")
    args = cli.parse_args()
    print(json.dumps(generate(args.root, args.check), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
