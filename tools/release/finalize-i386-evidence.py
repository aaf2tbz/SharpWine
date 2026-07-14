#!/usr/bin/env python3
"""Bind the bounded i386/WoW64 probe into packaged SharpWine evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"i386 acceptance evidence failed: {message}")


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
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--test-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build = load(args.build_manifest)
    summary = load(args.test_summary)
    if build.get("schema") != 1 or build.get("kind") != "published-runtime-patch-set" or \
            build.get("fullWineRebuild") is not False or "dxmt" not in build.get("components", {}):
        fail("focused build manifest lacks the paired DXMT component")
    tests = summary.get("tests")
    selected = [item for item in tests if isinstance(item, dict) and
                item.get("name") == "i386-gem-acceptance"] if isinstance(tests, list) else []
    if summary.get("passed") is not True or summary.get("freshPrefix") is not True or \
            summary.get("teardownClean") is not True or len(selected) != 1 or \
            selected[0].get("passed") is not True:
        fail("probe summary lacks the passing bounded i386 test")
    audit = summary.get("processAudit")
    if not isinstance(audit, dict) or audit.get("allNativeArm64") is not True or \
            audit.get("translatedProcesses") != []:
        fail("probe process audit is not native ARM64-only")
    result = {
        "schema": 1,
        "repositoryCommit": build.get("repositoryCommit"),
        "host": {"os": "macOS", "architecture": "arm64", "rosetta": False},
        "route": "PE32 i386 -> WoW64 -> GEM_i386/Blink",
        "scope": "source-built bounded acceptance fixture; corpus testing deferred",
        "pairedDxmt": True,
        "test": {"name": "i386-gem-acceptance", "passed": True, "bounded": True,
                 "logSha256": selected[0].get("logSha256")},
        "processAudit": {"allNativeArm64": True, "translatedProcesses": []},
        "inputs": {"buildManifestSha256": digest(args.build_manifest),
                   "probeSummarySha256": digest(args.test_summary)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    print("bound bounded i386/WoW64 acceptance evidence")


if __name__ == "__main__":
    main()
