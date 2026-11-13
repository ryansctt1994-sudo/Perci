#!/usr/bin/env python3
"""Verify that a complete Perci checkout has its LFS-backed runtime artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import re
from pathlib import PurePosixPath

FORMAT_SUFFIX = {
    "PERCIW01": ".pwgt", "PERCIW02": ".pwgt", "PERCIW03": ".pwgt",
    "PERCLNG1": ".blng", "PERCPHR1": ".bphr", "PERCDLG1": ".bdlg",
}

def validate_manifest_entries(manifest: object) -> list[dict]:
    """Reject invalid/malicious manifests before reading any weight payload."""
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest artifacts must be a nonempty list")
    if len(entries) > 128:
        raise ValueError("too many manifest artifacts")
    seen = set()
    for i, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"artifact {i}: entry must be an object")
        relative = item.get("path")
        if not isinstance(relative, str) or not relative.startswith("models/"):
            raise ValueError(f"artifact {i}: path must be relative to models/")
        if ("\\" in relative or "\x00" in relative or
                any(part in ("", ".", "..") for part in relative.split("/"))):
            raise ValueError(f"artifact {i}: unsafe path")
        parsed = PurePosixPath(relative)
        if parsed.is_absolute() or parsed.as_posix() != relative:
            raise ValueError(f"artifact {i}: noncanonical path")
        if relative in seen:
            raise ValueError(f"artifact {i}: duplicate path")
        seen.add(relative)
        fmt = item.get("format")
        if fmt not in FORMAT_SUFFIX or parsed.suffix != FORMAT_SUFFIX[fmt]:
            raise ValueError(f"artifact {i}: unsupported format or extension")
        size = item.get("bytes")
        if type(size) is not int or size < 8:
            raise ValueError(f"artifact {i}: invalid byte length")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ValueError(f"artifact {i}: invalid SHA-256")
    return entries



def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lfs_filter(path: str) -> str | None:
    result = subprocess.run(
        ["git", "check-attr", "filter", "--", path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    value = result.stdout.strip().rsplit(":", 1)[-1].strip()
    return value or None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "models" / "PACKAGE_MANIFEST.json",
    )
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        artifacts = validate_manifest_entries(manifest)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(json.dumps({"schema": "perci.package-verification.v1",
                          "ok": False, "error": str(error)}))
        return 1
    rows = []
    for artifact in artifacts:
        relative = artifact["path"]
        path = ROOT / relative
        exists = path.is_file() and not path.is_symlink()
        size = path.stat().st_size if exists else None
        actual_hash = sha256(path) if exists else None
        magic = None
        if exists:
            with path.open("rb") as stream:
                magic = stream.read(8).decode("ascii", errors="replace")
        row = {
            "path": relative,
            "format": artifact["format"],
            "exists": exists,
            "bytes": size,
            "sha256": actual_hash,
            "hash_matches": actual_hash == artifact["sha256"],
            "size_matches": size == artifact["bytes"],
            "magic": magic,
            "magic_matches": magic == artifact["format"],
            "lfs_filter": lfs_filter(relative),
        }
        row["ok"] = all(
            [
                row["exists"],
                row["hash_matches"],
                row["size_matches"],
                row["magic_matches"],
                row["lfs_filter"] == "lfs",
            ]
        )
        rows.append(row)
    payload = {
        "schema": "perci.package-verification.v1",
        "manifest": str(args.manifest),
        "artifact_count": len(rows),
        "ok": bool(rows) and all(row["ok"] for row in rows),
        "artifacts": rows,
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
