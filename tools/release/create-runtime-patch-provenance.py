#!/usr/bin/env python3
"""Create release provenance for a verified patch of the published runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"runtime patch provenance failed: {message}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", required=True, type=Path)
    parser.add_argument("--patch-set", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--components-lock", default="components.lock.json", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        fail("provenance must be produced on native Apple Silicon")
    if len(args.commit) != 40 or any(character not in "0123456789abcdef" for character in args.commit):
        fail("commit must be a lowercase full Git SHA")
    overlay = args.overlay.resolve(strict=True)
    patch_set = load(args.patch_set)
    policy = load(args.policy)
    base = load(args.base_manifest)
    lock = load(args.components_lock)
    if patch_set.get("release") != policy.get("release") or \
            patch_set.get("base") != policy.get("base"):
        fail("patch set does not match release policy")
    records = patch_set.get("runtimePatches")
    if not isinstance(records, list) or not records:
        fail("patch set contains no runtime patches")
    for record in records:
        path = overlay / record["path"]
        if not path.is_file() or digest(path) != record["resultSha256"]:
            fail(f"overlay output differs from patch record: {record.get('path')}")
    components = lock.get("components")
    if not isinstance(components, dict) or not {"wine", "dynarmic", "blink", "dxmt"}.issubset(components):
        fail("components lock is incomplete")
    patches = components["wine"].get("patches")
    if not isinstance(patches, list) or not patches:
        fail("components lock lacks the Wine patch queue")
    wine_patches = [{"path": item["path"], "sha256": item["sha256"],
                     "license": "LGPL-2.1-or-later"} for item in patches]
    bridge_path = overlay / "lib/libmetalsharp-gem-wine.0.1.0.dylib"
    exports = []
    for symbol in subprocess.check_output(["nm", "-gjU", str(bridge_path)], text=True).splitlines():
        symbol = symbol.removeprefix("_")
        if symbol.startswith("gem_wine_"):
            exports.append(symbol)
    required_exports = {"gem_wine_process_prepare_x86_64", "gem_wine_process_prepare_i386",
                        "gem_wine_i386_thread_create", "gem_wine_i386_thread_run"}
    if not required_exports.issubset(exports):
        fail("patched bridge lacks the required x86_64/i386 preparation exports")
    bridge = dict(base.get("bridge", {}))
    bridge["exports"] = sorted(exports)
    toolchain = dict(base.get("toolchain", {}))
    toolchain["runtimePatchApplication"] = {
        "format": "BSDIFF40",
        "baseTag": patch_set["release"]["previousTag"],
        "patchSetSha256": digest(args.patch_set),
        "appliedBy": "Python bz2 fail-closed patcher",
        "host": "aarch64-apple-darwin",
    }
    value = {
        "schema": 1,
        "kind": "published-runtime-patch-set",
        "repositoryCommit": args.commit,
        "fullWineRebuild": False,
        "base": patch_set["base"],
        "runtimePatches": records,
        "components": components,
        "winePatches": wine_patches,
        "bridge": bridge,
        "toolchain": toolchain,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    print("created fresh component, patch, bridge, and toolchain provenance")


if __name__ == "__main__":
    main()
