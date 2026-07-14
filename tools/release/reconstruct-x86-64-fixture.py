#!/usr/bin/env python3
"""Reconstruct the hash-bound x86_64 release fixture from its BSDIFF40 patch."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


APPLIER_PATH = Path(__file__).with_name("apply-runtime-patches.py")
SPEC = importlib.util.spec_from_file_location("runtime_patch_applier", APPLIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load runtime patch applier")
APPLIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPLIER)


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 fixture reconstruction failed: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patch-set", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    patch_set_path = args.patch_set.resolve(strict=True)
    try:
        patch_set = json.loads(patch_set_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid patch set: {error}")
    fixture = patch_set.get("fixture")
    if not isinstance(fixture, dict):
        fail("patch set has no fixture record")
    patch = patch_set_path.parent / fixture.get("patch", "")
    if patch.is_symlink() or not patch.is_file() or \
            hashlib.sha256(patch.read_bytes()).hexdigest() != fixture.get("patchSha256"):
        fail("fixture patch is missing or has the wrong hash")
    output = APPLIER.apply_bsdiff(b"", patch.read_bytes())
    if len(output) != fixture.get("resultSize") or \
            hashlib.sha256(output).hexdigest() != fixture.get("resultSha256"):
        fail("reconstructed fixture identity mismatch")
    if args.output.exists():
        fail("output must be absent")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print("reconstructed exact x86_64 fixture")


if __name__ == "__main__":
    main()
