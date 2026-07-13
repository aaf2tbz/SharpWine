#!/usr/bin/env python3
"""Validate the reviewed, fail-closed v0.1.0 release activation record."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


SCRIPTS = {
    "tools/release/audit-runtime.py",
    "tools/release/build-integrated-wine.sh",
    "tools/release/build-release-candidate.sh",
    "tools/release/create-release-assets.py",
    "tools/release/stage-runtime.py",
    "tools/release/test-packaged-runtime.py",
    "tools/release/validate-release-assets.py",
    "tools/release/verify-published-release.py",
    ".github/workflows/release.yml",
}
CRITERIA = {
    "issues-21-through-24-integrated",
    "allowlisted-self-contained-runtime",
    "relocatable-arm64-only-macho-closure",
    "fresh-prefix-native-and-authentic-hybrid",
    "asan-ubsan-apple-leaks-stress-teardown",
    "two-clean-build-byte-reproducibility",
    "deterministic-assets-provenance-sbom-evidence",
    "least-privilege-protected-main-publication",
    "published-asset-redownload-and-smoke",
}


def fail(message: str) -> None:
    raise SystemExit(f"release readiness validation failed: {message}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--protected-main-parent", required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    try:
        value = json.loads((root / "release/v0.1.0-ready.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid activation record: {error}")
    if set(value) != {"schema", "version", "tag", "expectedProtectedMainParent",
                     "scripts", "readmeSha256", "acceptanceCriteria"}:
        fail("activation record fields differ from the schema")
    if value["schema"] != 1 or value["version"] != "0.1.0" or value["tag"] != "v0.1.0":
        fail("activation record release identity is invalid")
    parent = value["expectedProtectedMainParent"]
    if not isinstance(parent, str) or not re.fullmatch(r"[0-9a-f]{40}", parent) or \
            parent != args.protected_main_parent:
        fail("protected-main parent binding differs")
    scripts = value["scripts"]
    if not isinstance(scripts, dict) or set(scripts) != SCRIPTS:
        fail("release script allowlist differs")
    for relative, expected in scripts.items():
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or \
                digest(root / relative) != expected:
            fail(f"release script hash mismatch: {relative}")
    if value["readmeSha256"] != digest(root / "README.md"):
        fail("README status hash mismatch")
    criteria = value["acceptanceCriteria"]
    if not isinstance(criteria, dict) or set(criteria) != CRITERIA or any(item is not True for item in criteria.values()):
        fail("release acceptance criteria are incomplete")
    print("v0.1.0 release readiness record passed")


if __name__ == "__main__":
    main()
