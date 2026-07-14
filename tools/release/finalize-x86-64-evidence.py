#!/usr/bin/env python3
"""Bind focused build and probe results into the packaged x86_64 evidence file."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REQUIRED = {"x86_64-exception", "x86_64-cmd-exit"}


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 acceptance evidence failed: {message}")


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
    parser.add_argument("--fixture-manifest", required=True, type=Path)
    parser.add_argument("--test-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build = load(args.build_manifest)
    fixture = load(args.fixture_manifest)
    summary = load(args.test_summary)
    if build.get("schema") != 1 or build.get("kind") != "published-runtime-patch-set" or \
            build.get("fullWineRebuild") is not False:
        fail("focused build manifest is invalid")
    if fixture.get("schema") != 1 or fixture.get("byteIdentical") is not True or \
            fixture.get("host", {}).get("architecture") != "arm64":
        fail("fixture manifest is invalid")
    if summary.get("passed") is not True or summary.get("freshPrefix") is not True or \
            summary.get("teardownClean") is not True:
        fail("probe runtime did not pass lifecycle gates")
    tests = summary.get("tests")
    if not isinstance(tests, list):
        fail("probe summary tests are invalid")
    selected = {item.get("name"): item for item in tests if isinstance(item, dict) and
                item.get("name") in REQUIRED}
    if set(selected) != REQUIRED or any(item.get("passed") is not True for item in selected.values()):
        fail("probe summary lacks passing pure x86_64 tests")
    audit = summary.get("processAudit")
    if not isinstance(audit, dict) or audit.get("allNativeArm64") is not True or \
            audit.get("translatedProcesses") != []:
        fail("probe process audit is not native ARM64-only")
    result = {
        "schema": 1,
        "repositoryCommit": build.get("repositoryCommit"),
        "host": {"os": "macOS", "architecture": "arm64", "rosetta": False},
        "engine": "GEM_x86_64/Blink native AArch64 JIT",
        "fullWineRebuild": False,
        "runtimePatches": build.get("runtimePatches"),
        "fixture": fixture.get("fixture"),
        "tests": [
            {"name": name, "passed": True, "bounded": True,
             "logSha256": selected[name].get("logSha256")}
            for name in sorted(REQUIRED)
        ],
        "processAudit": {"allNativeArm64": True, "translatedProcesses": []},
        "inputs": {"buildManifestSha256": digest(args.build_manifest),
                   "fixtureManifestSha256": digest(args.fixture_manifest),
                   "probeSummarySha256": digest(args.test_summary)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("bound pure x86_64 exception and cmd acceptance evidence")


if __name__ == "__main__":
    main()
