#!/usr/bin/env python3
"""Download, validate, and unpack an immutable published release foundation."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"published foundation preparation failed: {message}")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def zstd() -> str:
    executable = shutil.which("zstd")
    if executable:
        return executable
    candidate = Path("/opt/homebrew/opt/zstd/bin/zstd")
    if candidate.is_file():
        return str(candidate)
    fail("zstd is unavailable")


def validate_policy(policy: dict[str, Any]) -> tuple[str, str, str, str]:
    if set(policy) != {"schema", "release", "base", "allowedChanges"} or policy["schema"] != 1:
        fail("overlay policy has an unsupported schema")
    release = policy["release"]
    base = policy["base"]
    if not isinstance(release, dict) or set(release) != {"version", "tag", "previousTag"}:
        fail("overlay policy release binding is invalid")
    if not isinstance(base, dict) or set(base) != {"archive", "sha256"}:
        fail("overlay policy base binding is invalid")
    version = release.get("version")
    tag = release.get("tag")
    previous = release.get("previousTag")
    archive = base.get("archive")
    digest = base.get("sha256")
    if tag != f"v{version}" or not isinstance(previous, str) or not previous.startswith("v"):
        fail("overlay policy release version/tag binding is invalid")
    if archive != f"metalsharp-wine-{previous}-macos-arm64.tar.zst":
        fail("overlay policy base archive does not match previousTag")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        fail("overlay policy base SHA-256 is invalid")
    if not isinstance(policy["allowedChanges"], list) or not policy["allowedChanges"]:
        fail("overlay policy has no allowed changes")
    return str(version), str(tag), str(previous), str(archive)


def copy_assets(source: Path, destination: Path) -> None:
    if not source.is_dir():
        fail("provided asset directory is missing")
    for path in source.iterdir():
        if path.is_symlink() or not path.is_file():
            fail(f"asset is not a regular file: {path.name}")
        shutil.copy2(path, destination / path.name)


def unpack(archive: Path, destination: Path, expected_top: str) -> Path:
    with tempfile.TemporaryDirectory(prefix="mswr-foundation-") as temporary:
        tar_path = Path(temporary) / "runtime.tar"
        with tar_path.open("wb") as output:
            result = subprocess.run(
                [zstd(), "-d", "--stdout", str(archive)],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode:
            fail(f"could not decompress foundation: {result.stderr.decode(errors='replace').strip()}")
        with tarfile.open(tar_path, "r:") as bundle:
            members = bundle.getmembers()
            if not members or members[0].name != expected_top or not members[0].isdir():
                fail("foundation archive has the wrong top-level directory")
            prefix = expected_top + "/"
            for member in members:
                if member.name != expected_top and not member.name.startswith(prefix):
                    fail(f"foundation member escapes top-level directory: {member.name}")
                if member.islnk() or member.isdev() or member.isfifo():
                    fail(f"foundation contains forbidden object: {member.name}")
            bundle.extractall(destination, filter="data")
    runtime = destination / expected_top
    if not runtime.is_dir():
        fail("foundation runtime was not extracted")
    return runtime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--policy", default="release/v0.1.2-overlay-policy.json", type=Path)
    parser.add_argument("--repository", default="aaf2tbz/SharpWine")
    parser.add_argument("--assets", type=Path,
                        help="copy already-downloaded assets instead of invoking gh")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    if workspace.exists():
        fail("workspace must be absent")
    policy = load_object(args.policy)
    _, _, previous_tag, archive_name = validate_policy(policy)
    workspace.mkdir(parents=True)
    assets = workspace / "assets"
    extracted = workspace / "extracted"
    assets.mkdir()
    extracted.mkdir()
    if args.assets:
        copy_assets(args.assets.resolve(), assets)
        if not (assets / "RELEASE-NOTES.md").is_file():
            notes = subprocess.run(
                ["gh", "release", "view", previous_tag, "--repo", args.repository,
                 "--json", "body", "--jq", ".body"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            (assets / "RELEASE-NOTES.md").write_text(notes, encoding="utf-8")
    else:
        subprocess.run(
            ["gh", "release", "download", previous_tag, "--repo", args.repository,
             "--dir", str(assets)],
            check=True,
        )
        notes = subprocess.run(
            ["gh", "release", "view", previous_tag, "--repo", args.repository,
             "--json", "body", "--jq", ".body"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        (assets / "RELEASE-NOTES.md").write_text(notes, encoding="utf-8")
    manifest = load_object(assets / "release-manifest.json")
    release = manifest.get("release")
    foundation_repository = release.get("repository") if isinstance(release, dict) else None
    accepted_repositories = {args.repository}
    if previous_tag == "v0.1.1" and args.repository == "aaf2tbz/SharpWine":
        accepted_repositories.add("aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64")
    if not isinstance(foundation_repository, str) or foundation_repository not in accepted_repositories:
        fail("foundation manifest repository binding is invalid")
    version = previous_tag.removeprefix("v")
    commit = release.get("commit")
    if release.get("tag") != previous_tag or release.get("version") != version or not isinstance(commit, str):
        fail("foundation manifest release binding is invalid")
    archive = assets / archive_name
    if sha256(archive) != policy["base"]["sha256"]:
        fail("foundation archive does not match overlay policy")
    validator = Path(__file__).with_name("validate-release-assets.py")
    subprocess.run(
        [sys.executable, str(validator), "--directory", str(assets),
         "--repository", foundation_repository, "--commit", commit, "--version", version],
        check=True,
    )
    runtime = unpack(archive, extracted, archive_name.removesuffix(".tar.zst"))
    summary = {
        "schema": 1,
        "repository": args.repository,
        "release": release,
        "archive": {"name": archive_name, "sha256": policy["base"]["sha256"]},
        "runtime": str(runtime),
        "packageFileCount": len(manifest.get("package", {}).get("files", [])),
        "peArchitectures": manifest.get("toolchain", {}).get("peArchitectures"),
        "bridge": manifest.get("bridge"),
        "components": manifest.get("components"),
    }
    (workspace / "foundation.json").write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(runtime)


if __name__ == "__main__":
    main()
