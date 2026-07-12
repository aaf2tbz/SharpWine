#!/usr/bin/env python3
"""Validate the pinned, ordered Wine LGPL patch queue without mutating it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read canonical JSON {path}: {error}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(root: Path) -> None:
    patch_dir = root / "third_party/patches/wine"
    series_path = patch_dir / "series"
    provenance_path = patch_dir / "provenance.json"
    lock_path = root / "components.lock.json"

    if not patch_dir.is_dir() or patch_dir.is_symlink():
        fail("Wine patch directory must be a real directory")
    try:
        series_text = series_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read Wine series: {error}")
    if not series_text.endswith("\n") or "\r" in series_text:
        fail("Wine series must be LF-terminated ASCII")
    names = series_text.splitlines()
    if not names or len(names) != len(set(names)):
        fail("Wine series must be non-empty and duplicate-free")
    if names != sorted(names):
        fail("Wine series must use deterministic lexical order")
    for name in names:
        if Path(name).name != name or not re.fullmatch(r"[0-9]{4}-[a-z0-9-]+\.patch", name):
            fail(f"unsafe Wine patch name: {name!r}")

    actual_names = sorted(path.name for path in patch_dir.glob("*.patch"))
    if actual_names != names:
        fail("Wine series does not exactly enumerate patch files")

    provenance = load_json(provenance_path)
    lock = load_json(lock_path)
    if not isinstance(provenance, dict) or provenance.get("schema") != 1:
        fail("invalid Wine patch provenance schema")
    if provenance.get("license") != "LGPL-2.1-or-later":
        fail("Wine patch provenance must record LGPL-2.1-or-later")
    base = provenance.get("baseRevision")
    if not isinstance(base, str) or not HEX40.fullmatch(base):
        fail("Wine patch provenance requires a full lowercase base revision")
    records = provenance.get("patches")
    if not isinstance(records, list) or len(records) != len(names):
        fail("Wine patch provenance count does not match series")

    normalized: list[dict[str, object]] = []
    for index, (name, record) in enumerate(zip(names, records), 1):
        if not isinstance(record, dict) or record.get("order") != index:
            fail(f"Wine patch {index} has invalid provenance order")
        expected_path = f"third_party/patches/wine/{name}"
        if record.get("path") != expected_path:
            fail(f"Wine patch {index} provenance path mismatch")
        expected_hash = record.get("sha256")
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            fail(f"Wine patch {index} has invalid SHA-256")
        patch_path = patch_dir / name
        if patch_path.is_symlink() or not patch_path.is_file():
            fail(f"Wine patch {index} must be a regular file")
        if digest(patch_path) != expected_hash:
            fail(f"Wine patch hash mismatch: {name}")
        content = patch_path.read_text(encoding="utf-8")
        first = content.splitlines()[0] if content else ""
        if not re.fullmatch(r"From [0-9a-f]{40} Mon Sep 17 00:00:00 2001", first):
            fail(f"Wine patch {index} lacks an immutable format-patch header")
        if "\nFrom: " not in content or "\nSubject: [PATCH " not in content:
            fail(f"Wine patch {index} lacks author or ordered subject metadata")
        purpose = record.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            fail(f"Wine patch {index} lacks a recorded purpose")
        normalized.append({"path": expected_path, "sha256": expected_hash})

    if not isinstance(lock, dict):
        fail("components lock must be an object")
    wine = lock.get("components", {}).get("wine") if isinstance(lock.get("components"), dict) else None
    if not isinstance(wine, dict):
        fail("components lock lacks Wine")
    if wine.get("revision") != base or wine.get("license") != provenance.get("license"):
        fail("components lock Wine base or license disagrees with provenance")
    if wine.get("patch_series") != "third_party/patches/wine/series":
        fail("components lock has the wrong Wine series path")
    if wine.get("patch_provenance") != "third_party/patches/wine/provenance.json":
        fail("components lock has the wrong Wine provenance path")
    if wine.get("patches") != normalized:
        fail("components lock Wine patch list disagrees with provenance")

    readme = (patch_dir / "README.md").read_text(encoding="utf-8")
    if base not in readme or "LGPL-2.1-or-later" not in readme:
        fail("Wine patch README does not bind the base and license")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"wine patch validation failed: {error}", file=sys.stderr)
        return 1
    print("Wine patch queue validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
