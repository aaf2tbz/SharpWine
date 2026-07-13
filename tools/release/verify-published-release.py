#!/usr/bin/env python3
"""Verify draft GitHub release metadata and uploaded asset digests before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

UPLOADED_ASSETS = {
    "metalsharp-wine-v0.1.0-macos-arm64.tar.zst",
    "metalsharp-wine-v0.1.0-macos-arm64.tar.zst.sha256",
    "release-manifest.json",
    "wine-integration-evidence.json",
    "sbom.spdx.json",
    "evidence-index.json",
    "KNOWN-LIMITATIONS.md",
}


def fail(message: str) -> None:
    raise SystemExit(f"published release verification failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gh_release(repository: str, tag: str) -> dict[str, Any]:
    try:
        output = subprocess.check_output(
            ["gh", "release", "view", tag, "--repo", repository,
             "--json", "isDraft,tagName,targetCommitish,assets"], text=True)
        value = json.loads(output)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        fail(f"GitHub API request failed: {error}")
    if not isinstance(value, dict):
        fail("GitHub API response is not an object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--expect-draft", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        fail("GH_TOKEN is missing")
    release = gh_release(args.repository, args.tag)
    if release.get("isDraft") is not args.expect_draft or release.get("tagName") != args.tag:
        fail("release draft state or tag differs from expectation")
    if release.get("targetCommitish") != args.commit:
        fail("release target is not the tested commit")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("release assets are missing")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release contains an invalid asset record")
        if asset["name"] in by_name:
            fail(f"release contains duplicate asset {asset['name']}")
        by_name[asset["name"]] = asset
    if set(by_name) != UPLOADED_ASSETS:
        fail(f"release asset allowlist mismatch: {sorted(by_name)}")
    for name, asset in by_name.items():
        local = args.directory / name
        if not local.is_file() or local.is_symlink():
            fail(f"local asset {name} is missing or linked")
        if asset.get("size") != local.stat().st_size:
            fail(f"uploaded asset {name} size mismatch")
        digest = asset.get("digest")
        if digest != f"sha256:{sha256(local)}":
            fail(f"uploaded asset {name} digest mismatch")
    print("draft GitHub release assets match the tested candidate")


if __name__ == "__main__":
    main()
