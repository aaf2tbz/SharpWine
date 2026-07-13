#!/usr/bin/env python3
"""Fail-closed validation for the complete integrated Wine release asset set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ARCHIVE = "metalsharp-wine-v0.1.0-macos-arm64.tar.zst"
ASSETS = {
    ARCHIVE,
    f"{ARCHIVE}.sha256",
    "release-manifest.json",
    "wine-integration-evidence.json",
    "sbom.spdx.json",
    "evidence-index.json",
    "KNOWN-LIMITATIONS.md",
    "RELEASE-NOTES.md",
}
REQUIRED_TESTS = {"wineboot-init", "arm64-cmd-exit", "arm64ec-x64-hybrid"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def fail(message: str) -> None:
    raise SystemExit(f"release asset validation failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} root is not an object")
    return value


def exact_keys(value: dict[str, Any], required: set[str], where: str) -> None:
    if set(value) != required:
        fail(f"{where} keys are {sorted(value)}, expected {sorted(required)}")


def binding(value: dict[str, Any], repository: str, commit: str, version: str, where: str) -> None:
    if value.get("repository") != repository:
        fail(f"{where} repository is not bound to {repository}")
    if value.get("commit") != commit:
        fail(f"{where} commit is not bound to {commit}")
    if value.get("version") != version:
        fail(f"{where} version is not {version}")


def validate_manifest(path: Path, repository: str, commit: str, version: str,
                      archive_hash: str, archive_size: int) -> None:
    value = load_json(path)
    exact_keys(value, {"schema", "release", "components", "winePatches", "bridge", "toolchain",
                       "package", "evidence"}, path.name)
    if value["schema"] != 1:
        fail("unsupported release manifest schema")
    release = value["release"]
    if not isinstance(release, dict):
        fail("release manifest release is not an object")
    exact_keys(release, {"version", "tag", "repository", "commit"}, "manifest release")
    binding(release, repository, commit, version, "manifest release")
    if release["tag"] != f"v{version}":
        fail("manifest tag mismatch")

    components = value["components"]
    if not isinstance(components, dict) or set(components) != {"wine", "dynarmic", "blink"}:
        fail("manifest must bind exactly Wine, Dynarmic, and Blink")
    for name, component in components.items():
        if not isinstance(component, dict):
            fail(f"manifest component {name} is not an object")
        for field in ("repository", "revision", "license"):
            if not isinstance(component.get(field), str) or not component[field]:
                fail(f"manifest component {name} lacks {field}")

    patches = value["winePatches"]
    if not isinstance(patches, list) or not patches:
        fail("manifest has no ordered Wine patch series")
    for index, patch in enumerate(patches):
        if not isinstance(patch, dict) or set(patch) != {"path", "sha256", "license"}:
            fail(f"Wine patch {index} has an invalid record")
        if (not isinstance(patch["path"], str) or patch["path"].startswith("/") or
                ".." in Path(patch["path"]).parts):
            fail(f"Wine patch {index} has an unsafe path")
        if not isinstance(patch["sha256"], str) or not HEX64.fullmatch(patch["sha256"]):
            fail(f"Wine patch {index} has an invalid hash")
        if patch["license"] != "LGPL-2.1-or-later":
            fail(f"Wine patch {index} has the wrong license")

    bridge = value["bridge"]
    if not isinstance(bridge, dict) or bridge.get("abiVersion") != 1 or \
            bridge.get("installName") != "@rpath/libmetalsharp-gem-wine.0.dylib" or \
            bridge.get("directWineBinding") != "lib/wine/aarch64-unix/ntdll.so" or \
            not isinstance(bridge.get("exports"), list) or not bridge["exports"]:
        fail("manifest bridge ABI binding is incomplete")

    toolchain = value["toolchain"]
    if not isinstance(toolchain, dict) or toolchain.get("host") != "aarch64-apple-darwin":
        fail("manifest does not bind the native ARM64 host")
    if toolchain.get("peArchitectures") != ["i386", "x86_64", "aarch64", "arm64ec"]:
        fail("manifest does not preserve the four PE architectures")

    package = value["package"]
    if not isinstance(package, dict):
        fail("manifest package is not an object")
    exact_keys(package, {"name", "sha256", "size", "sourceDateEpoch", "files"},
               "manifest package")
    if package["name"] != ARCHIVE or package["sha256"] != archive_hash:
        fail("manifest archive name/hash mismatch")
    if package["size"] != archive_size or not isinstance(package["sourceDateEpoch"], int):
        fail("manifest archive size/timestamp mismatch")
    if not isinstance(package["files"], list) or not package["files"]:
        fail("manifest package inventory is empty")

    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {
            "integration", "sbom", "index", "knownLimitations"}:
        fail("manifest evidence bindings are incomplete")
    for name, record in evidence.items():
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            fail(f"manifest evidence binding {name} is invalid")
        asset = path.parent / record["path"]
        if asset.name != record["path"] or asset.name not in ASSETS or not asset.is_file():
            fail(f"manifest evidence binding {name} has an unsafe path")
        if record["sha256"] != sha256(asset):
            fail(f"manifest evidence binding {name} hash mismatch")


def validate_archive(directory: Path, manifest: dict[str, Any]) -> None:
    archive = directory / ARCHIVE
    zstd = shutil.which("zstd")
    if not zstd and sys.platform == "darwin":
        candidate = Path("/opt/homebrew/opt/zstd/bin/zstd")
        if candidate.is_file():
            zstd = str(candidate)
    if not zstd:
        fail("zstd is unavailable for archive validation")
    with tempfile.TemporaryDirectory(prefix="mswr-release-validate-") as temporary:
        tar_path = Path(temporary) / "runtime.tar"
        with tar_path.open("wb") as output:
            result = subprocess.run([zstd, "-d", "--stdout", str(archive)], stdout=output,
                                    stderr=subprocess.PIPE, check=False)
        if result.returncode:
            fail(f"archive is not valid Zstandard: {result.stderr.decode(errors='replace').strip()}")
        expected_top = "metalsharp-wine-v0.1.0-macos-arm64"
        records = manifest["package"]["files"]
        by_path = {record.get("path"): record for record in records if isinstance(record, dict)}
        if len(by_path) != len(records) or None in by_path:
            fail("manifest package inventory contains duplicate or invalid paths")
        with tarfile.open(tar_path, "r:") as value:
            members = value.getmembers()
            names = [member.name for member in members]
            if not members or names[0] != expected_top or not members[0].isdir():
                fail("archive has the wrong top-level directory")
            if names[1:] != sorted(names[1:]) or len(names) != len(set(names)):
                fail("archive member order is not unique lexical order")
            seen: set[str] = set()
            epoch = manifest["package"]["sourceDateEpoch"]
            for member in members:
                if member.uid != 0 or member.gid != 0 or member.uname or member.gname or member.mtime != epoch:
                    fail(f"archive metadata is not normalized: {member.name}")
                if any(key.lower().startswith(("schily.xattr", "libarchive.xattr"))
                       for key in member.pax_headers):
                    fail(f"archive contains extended attributes: {member.name}")
                if member.islnk() or member.isdev() or member.isfifo():
                    fail(f"archive contains a forbidden object: {member.name}")
                if member.name == expected_top:
                    continue
                prefix = expected_top + "/"
                if not member.name.startswith(prefix):
                    fail(f"archive member escapes the top-level directory: {member.name}")
                relative = member.name[len(prefix):]
                record = by_path.get(relative)
                if record is None:
                    fail(f"archive member is absent from manifest: {relative}")
                if member.mode != record.get("mode"):
                    fail(f"archive mode mismatch: {relative}")
                if member.isdir():
                    if record.get("type") != "directory":
                        fail(f"archive directory type mismatch: {relative}")
                elif member.issym():
                    if record.get("type") != "symlink" or member.linkname != record.get("target") or \
                            os.path.isabs(member.linkname) or ".." in Path(member.linkname).parts:
                        fail(f"archive symlink mismatch or traversal: {relative}")
                elif member.isfile():
                    extracted = value.extractfile(member)
                    if extracted is None:
                        fail(f"archive file is unreadable: {relative}")
                    data = extracted.read()
                    if (record.get("type") != "file" or len(data) != record.get("size") or
                            hashlib.sha256(data).hexdigest() != record.get("sha256")):
                        fail(f"archive file hash/size mismatch: {relative}")
                else:
                    fail(f"archive member type is unsupported: {relative}")
                seen.add(relative)
            if seen != set(by_path):
                fail("manifest package inventory has members absent from archive")


def validate_integration(path: Path, repository: str, commit: str, version: str) -> None:
    value = load_json(path)
    exact_keys(value, {"schema", "repository", "commit", "version", "passed",
                       "wineEngineIntegrated", "zeroRosetta", "tests", "processAudit"}, path.name)
    if value["schema"] != 1:
        fail("unsupported integration evidence schema")
    binding(value, repository, commit, version, "integration evidence")
    if value["passed"] is not True or value["wineEngineIntegrated"] is not True or value["zeroRosetta"] is not True:
        fail("integration evidence did not pass every top-level gate")
    tests = value["tests"]
    if not isinstance(tests, list):
        fail("integration tests are not an array")
    seen: set[str] = set()
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"name", "passed", "bounded", "evidence"}:
            fail("integration test record is invalid")
        name = test["name"]
        if name in seen or name not in REQUIRED_TESTS:
            fail(f"unknown or duplicate integration test {name!r}")
        seen.add(name)
        if test["passed"] is not True or test["bounded"] is not True or not isinstance(test["evidence"], dict):
            fail(f"integration test {name} did not pass bounded execution")
    if seen != REQUIRED_TESTS:
        fail("required integration tests are missing")
    audit = value["processAudit"]
    if not isinstance(audit, dict) or audit.get("allNativeArm64") is not True or audit.get("translatedProcesses") != []:
        fail("process architecture audit is not clean")


def validate_sbom(path: Path) -> None:
    value = load_json(path)
    if value.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
        fail("SBOM is not SPDX 2.2 or 2.3")
    if not isinstance(value.get("documentNamespace"), str) or not value["documentNamespace"].startswith("https://"):
        fail("SBOM document namespace is invalid")
    if not isinstance(value.get("packages"), list) or not value["packages"]:
        fail("SBOM package inventory is empty")


def validate_index(path: Path, repository: str, commit: str, version: str) -> None:
    value = load_json(path)
    exact_keys(value, {"schema", "repository", "commit", "version", "criteria"}, path.name)
    if value["schema"] != 1:
        fail("unsupported evidence index schema")
    binding(value, repository, commit, version, "evidence index")
    criteria = value["criteria"]
    if not isinstance(criteria, list) or not criteria:
        fail("evidence index is empty")
    identifiers: set[str] = set()
    for criterion in criteria:
        if not isinstance(criterion, dict) or set(criterion) != {"id", "passed", "evidence"}:
            fail("evidence criterion is invalid")
        identifier = criterion["id"]
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            fail("evidence criterion identifier is invalid or duplicated")
        identifiers.add(identifier)
        if criterion["passed"] is not True or not isinstance(criterion["evidence"], list) or not criterion["evidence"]:
            fail(f"evidence criterion {identifier} did not pass")


def validate_text(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"invalid {path.name}: {error}")
    if len(text.strip()) < 32 or "TODO" in text or "TBD" in text:
        fail(f"{path.name} is empty or unfinished")
    if "/Users/" in text or "/home/runner/" in text or "/private/var/" in text:
        fail(f"{path.name} leaks an absolute build path")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not HEX40.fullmatch(args.commit):
        fail("commit is not a lowercase full Git SHA")
    directory = args.directory.resolve()
    if not directory.is_dir():
        fail("asset directory is missing")
    entries = list(directory.iterdir())
    names = {entry.name for entry in entries}
    if names != ASSETS:
        fail(f"asset names are {sorted(names)}, expected {sorted(ASSETS)}")
    for entry in entries:
        mode = entry.lstat().st_mode
        if not stat.S_ISREG(mode) or entry.is_symlink():
            fail(f"asset {entry.name} is not a regular file")
        if entry.name != ARCHIVE:
            data = entry.read_bytes()
            for forbidden in (b"/Users/", b"/home/runner/", b"/private/var/", b"/opt/homebrew/"):
                if forbidden in data:
                    fail(f"asset {entry.name} leaks a private or build path")

    archive = directory / ARCHIVE
    archive_hash = sha256(archive)
    checksum = (directory / f"{ARCHIVE}.sha256").read_text(encoding="ascii")
    if checksum != f"{archive_hash}  {ARCHIVE}\n":
        fail("archive checksum file is not exact")
    manifest = load_json(directory / "release-manifest.json")
    validate_integration(directory / "wine-integration-evidence.json", args.repository,
                         args.commit, args.version)
    validate_sbom(directory / "sbom.spdx.json")
    validate_index(directory / "evidence-index.json", args.repository, args.commit, args.version)
    validate_text(directory / "KNOWN-LIMITATIONS.md")
    validate_text(directory / "RELEASE-NOTES.md")
    validate_manifest(directory / "release-manifest.json", args.repository, args.commit,
                      args.version, archive_hash, archive.stat().st_size)
    validate_archive(directory, manifest)
    print("integrated Wine release asset validation passed")


if __name__ == "__main__":
    main()
