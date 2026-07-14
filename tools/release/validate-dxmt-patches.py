#!/usr/bin/env python3
"""Validate the pinned, ordered DXMT MIT patch queue without mutating it."""

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
    patch_dir = root / "third_party/patches/dxmt"
    series_path = patch_dir / "series"
    provenance = load_json(patch_dir / "provenance.json")
    lock = load_json(root / "components.lock.json")
    if not patch_dir.is_dir() or patch_dir.is_symlink():
        fail("DXMT patch directory must be a real directory")
    try:
        series_text = series_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read DXMT series: {error}")
    if not series_text.endswith("\n") or "\r" in series_text:
        fail("DXMT series must be LF-terminated ASCII")
    names = series_text.splitlines()
    if not names or len(names) != len(set(names)) or names != sorted(names):
        fail("DXMT series must be non-empty, duplicate-free, and sorted")
    for name in names:
        if Path(name).name != name or not re.fullmatch(r"[0-9]{4}-[A-Za-z0-9-]+\.patch", name):
            fail(f"unsafe DXMT patch name: {name!r}")
    if sorted(path.name for path in patch_dir.glob("*.patch")) != names:
        fail("DXMT series does not exactly enumerate patch files")
    if not isinstance(provenance, dict) or provenance.get("schema") != 1:
        fail("invalid DXMT patch provenance schema")
    if provenance.get("component") != "dxmt" or provenance.get("license") != "MIT":
        fail("DXMT provenance must bind component and MIT license")
    base = provenance.get("baseRevision")
    if not isinstance(base, str) or not HEX40.fullmatch(base):
        fail("DXMT provenance requires a full lowercase base revision")
    for key in ("sourceArchiveSha256", "referenceBinaryArchiveSha256"):
        value = provenance.get(key)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            fail(f"DXMT provenance has invalid {key}")
    records = provenance.get("patches")
    if not isinstance(records, list) or len(records) != len(names):
        fail("DXMT patch provenance count does not match series")
    normalized: list[dict[str, str]] = []
    for index, (name, record) in enumerate(zip(names, records), 1):
        if not isinstance(record, dict) or record.get("order") != index:
            fail(f"DXMT patch {index} has invalid provenance order")
        expected_path = f"third_party/patches/dxmt/{name}"
        expected_hash = record.get("sha256")
        if record.get("path") != expected_path:
            fail(f"DXMT patch {index} provenance path mismatch")
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            fail(f"DXMT patch {index} has invalid SHA-256")
        patch_path = patch_dir / name
        if patch_path.is_symlink() or not patch_path.is_file() or digest(patch_path) != expected_hash:
            fail(f"DXMT patch hash mismatch: {name}")
        content = patch_path.read_text(encoding="utf-8")
        first = content.splitlines()[0] if content else ""
        if not re.fullmatch(r"From [0-9a-f]{40} Mon Sep 17 00:00:00 2001", first):
            fail(f"DXMT patch {index} lacks an immutable format-patch header")
        authoring = record.get("authoringCommit")
        if not isinstance(authoring, str) or not HEX40.fullmatch(authoring) or first.split()[1] != authoring:
            fail(f"DXMT patch {index} authoring commit mismatch")
        if "\nFrom: " not in content or "\nSubject: [PATCH" not in content:
            fail(f"DXMT patch {index} lacks author or ordered subject metadata")
        if not isinstance(record.get("purpose"), str) or not record["purpose"].strip():
            fail(f"DXMT patch {index} lacks a purpose")
        normalized.append({"path": expected_path, "sha256": expected_hash})
    submodules = provenance.get("submodules")
    if not isinstance(submodules, list) or len(submodules) != 2:
        fail("DXMT provenance requires both pinned submodules")
    for record in submodules:
        if not isinstance(record, dict) or set(record) != {
            "path", "repository", "revision", "sourceArchiveSha256"
        }:
            fail("invalid DXMT submodule provenance record")
        if not HEX40.fullmatch(str(record["revision"])) or not HEX64.fullmatch(
            str(record["sourceArchiveSha256"])
        ):
            fail("DXMT submodule revision or archive hash is invalid")
    if not isinstance(lock, dict) or not isinstance(lock.get("components"), dict):
        fail("components lock is invalid")
    dxmt = lock["components"].get("dxmt")
    if not isinstance(dxmt, dict):
        fail("components lock lacks DXMT")
    if dxmt.get("revision") != base or dxmt.get("license") != "MIT":
        fail("components lock DXMT base or license disagrees with provenance")
    if dxmt.get("source_archive_sha256") != provenance.get("sourceArchiveSha256"):
        fail("components lock DXMT source archive disagrees with provenance")
    if dxmt.get("patch_series") != "third_party/patches/dxmt/series" or dxmt.get(
        "patch_provenance"
    ) != "third_party/patches/dxmt/provenance.json":
        fail("components lock has the wrong DXMT queue paths")
    if dxmt.get("patches") != normalized or dxmt.get("submodules") != [
        {
            "path": record["path"],
            "repository": record["repository"],
            "revision": record["revision"],
            "source_archive_sha256": record["sourceArchiveSha256"],
        }
        for record in submodules
    ]:
        fail("components lock DXMT queue or submodules disagree with provenance")
    readme = (patch_dir / "README.md").read_text(encoding="utf-8")
    if base not in readme:
        fail("DXMT patch README does not bind the base revision")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"DXMT patch validation failed: {error}", file=sys.stderr)
        return 1
    print("DXMT patch queue validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
