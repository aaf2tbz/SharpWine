#!/usr/bin/env python3
"""Create a new immutable release from a smoke-tested published runtime overlay."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"published runtime repackaging failed: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def archive_name(version: str) -> str:
    if not version or any(char not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.+-" for char in version):
        fail(f"invalid version: {version!r}")
    numeric = version.split("-", 1)[0].split("+", 1)[0]
    prefix = "metalsharp-wine" if tuple(map(int, numeric.split("."))) <= (0, 1, 1) else "sharpwine"
    return f"{prefix}-v{version}-macos-arm64.tar.zst"


def inventory(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            target = os.readlink(path)
            if os.path.isabs(target) or ".." in Path(target).parts:
                fail(f"unsafe runtime symlink: {relative}")
            result.append({"path": relative, "type": "symlink", "mode": mode, "target": target})
        elif path.is_dir():
            result.append({"path": relative, "type": "directory", "mode": mode})
        elif path.is_file():
            result.append({"path": relative, "type": "file", "mode": mode,
                           "size": path.stat().st_size, "sha256": digest(path)})
        else:
            fail(f"unsupported runtime object: {relative}")
    return result


def normalize(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        os.chmod(path, 0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def make_tar(runtime: Path, output: Path, top: str, epoch: int) -> None:
    with tempfile.TemporaryDirectory(prefix="mswr-repackage-") as temporary:
        uncompressed = Path(temporary) / "runtime.tar"
        with tarfile.open(uncompressed, "w", format=tarfile.PAX_FORMAT) as archive:
            paths = [runtime, *sorted(runtime.rglob("*"),
                                      key=lambda item: item.relative_to(runtime).as_posix())]
            for path in paths:
                relative = Path(top) if path == runtime else Path(top) / path.relative_to(runtime)
                info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = epoch
                info.pax_headers = {}
                if info.isfile():
                    with path.open("rb") as source:
                        archive.addfile(info, source)
                else:
                    archive.addfile(info)
        zstd = subprocess.run(["brew", "--prefix", "zstd"], text=True,
                              stdout=subprocess.PIPE, check=True).stdout.strip()
        subprocess.run([str(Path(zstd) / "bin/zstd"), "-19", "--threads=1", "--no-progress",
                        "--force", str(uncompressed), "-o", str(output)], check=True)


def integration_evidence(summary: dict[str, Any], repository: str, commit: str,
                         version: str) -> dict[str, Any]:
    required = {"wineboot-init", "arm64-cmd-exit", "arm64ec-x64-hybrid"}
    numeric = tuple(map(int, version.split("-", 1)[0].split("+", 1)[0].split(".")))
    if numeric <= (0, 1, 1):
        required |= {"x86_64-exception", "x86_64-cmd-exit"}
    else:
        required.add("i386-gem-acceptance")
    if (summary.get("passed") is not True or summary.get("freshPrefix") is not True or
            summary.get("teardownClean") is not True or not isinstance(summary.get("tests"), list)):
        fail("smoke-test summary did not pass required lifecycle gates")
    tests: list[dict[str, object]] = []
    for result in summary["tests"]:
        if not isinstance(result, dict) or result.get("name") not in required:
            continue
        if result.get("passed") is not True:
            fail(f"required smoke test failed: {result.get('name')}")
        tests.append({"name": result["name"], "passed": True, "bounded": True,
                      "evidence": {"timeoutSeconds": summary.get("timeoutSeconds"),
                                   "logSha256": result.get("logSha256")}})
    if {item["name"] for item in tests} != required:
        fail("smoke-test summary lacks a required release test")
    audit = summary.get("processAudit")
    if not isinstance(audit, dict) or audit.get("allNativeArm64") is not True or \
            audit.get("translatedProcesses") != []:
        fail("smoke-test process audit is not native ARM64-only")
    return {"schema": 1, "repository": repository, "commit": commit, "version": version,
            "passed": True, "wineEngineIntegrated": True, "zeroRosetta": True,
            "tests": sorted(tests, key=lambda item: str(item["name"])), "processAudit": audit}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--base-assets", required=True, type=Path)
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--test-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--previous-tag", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()
    if len(args.commit) != 40 or any(char not in "0123456789abcdef" for char in args.commit):
        fail("commit must be a lowercase full Git SHA")
    if not args.runtime.is_dir() or not args.base_assets.is_dir():
        fail("runtime or base assets are missing")
    if args.output.exists() and any(args.output.iterdir()):
        fail("output directory is not empty")
    archive = archive_name(args.version)
    top = archive.removesuffix(".tar.zst")
    summary = load_json(args.test_summary)
    build_manifest = load_json(args.build_manifest)
    base_sbom = load_json(args.base_assets / "sbom.spdx.json")
    base_index = load_json(args.base_assets / "evidence-index.json")
    args.output.mkdir(parents=True, exist_ok=True)

    if (build_manifest.get("schema") != 1 or
            build_manifest.get("kind") != "published-runtime-patch-set" or
            build_manifest.get("repositoryCommit") != args.commit or
            build_manifest.get("fullWineRebuild") is not False):
        fail("focused overlay build manifest is invalid")
    for field in ("components", "winePatches", "bridge", "toolchain"):
        if field not in build_manifest:
            fail(f"focused overlay build manifest lacks {field}")
    integration = integration_evidence(summary, args.repository, args.commit, args.version)
    canonical(args.output / "wine-integration-evidence.json", integration)
    sbom = dict(base_sbom)
    sbom["name"] = f"SharpWine-{args.version}"
    sbom["documentNamespace"] = (
        f"https://github.com/{args.repository}/releases/tag/v{args.version}/sbom/{args.commit}")
    creation = dict(sbom.get("creationInfo", {}))
    creation["created"] = datetime.datetime.fromtimestamp(
        args.source_date_epoch, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    sbom["creationInfo"] = creation
    packages = list(sbom.get("packages", []))
    if not any(isinstance(item, dict) and item.get("SPDXID") == "SPDXRef-dxmt"
               for item in packages):
        dxmt = build_manifest["components"].get("dxmt", {})
        packages.append({"SPDXID": "SPDXRef-dxmt",
                         "downloadLocation": dxmt.get("repository", "NOASSERTION"),
                         "filesAnalyzed": False,
                         "licenseConcluded": dxmt.get("license", "NOASSERTION"),
                         "licenseDeclared": dxmt.get("license", "NOASSERTION"),
                         "name": "dxmt", "versionInfo": dxmt.get("version", "NOASSERTION")})
    sbom["packages"] = packages
    canonical(args.output / "sbom.spdx.json", sbom)
    index = dict(base_index)
    index["repository"] = args.repository
    index["commit"] = args.commit
    index["version"] = args.version
    replacements = {
        "published-bundle-overlay-repackage": {
            "id": "published-bundle-overlay-repackage", "passed": True,
            "evidence": ["wine-integration-evidence.json", "release-manifest.json"]},
        "i386-wow64-gem-and-paired-dxmt": {
            "id": "i386-wow64-gem-and-paired-dxmt", "passed": True,
            "evidence": ["wine-integration-evidence.json", "release-manifest.json"]},
    }
    criteria = [item for item in index.get("criteria", [])
                if isinstance(item, dict) and item.get("id") not in replacements]
    criteria.extend(replacements.values())
    index["criteria"] = criteria
    canonical(args.output / "evidence-index.json", index)
    (args.output / "KNOWN-LIMITATIONS.md").write_text(
        f"# Known limitations for SharpWine v{args.version}\n\n"
        "This release validates a bounded source-built PE32 i386 fixture through WoW64 and the "
        "native ARM64 GEM/Blink bridge, plus the paired DXMT i386 PE/ARM64 Unix payload. It does "
        "not yet claim corpus-wide or arbitrary Windows application/game compatibility.\n\n"
        "The native AArch64, accepted ARM64EC/x64, and bounded pure x86_64 paths remain supported. "
        "Intel macOS hosting and Rosetta are not supported. Optional "
        f"host integrations not present in the {args.previous_tag} foundation remain outside "
        "the release. "
        "Apple frameworks and operating-system services remain external by design.\n",
        encoding="utf-8")
    notes = (f"# SharpWine v{args.version}\n\n"
             f"This immutable release is derived from {args.previous_tag}, with the reviewed "
             "hash-bound i386/WoW64 and paired DXMT runtime patch applied to the published bundle "
             "on native Apple Silicon. CI verifies every base, patch, and result digest, then "
             "runs the bounded i386 fixture alongside the retained AArch64 and ARM64EC/x64 "
             "gates without Rosetta, while carrying forward v0.1.1's pure x86_64 evidence.\n")
    (args.output / "RELEASE-NOTES.md").write_text(notes, encoding="utf-8")

    metadata = args.runtime / "share/metalsharp"
    runtime_manifest = load_json(metadata / "runtime-manifest.json")
    runtime_manifest["release"] = {"version": args.version, "tag": f"v{args.version}",
                                   "repository": args.repository, "commit": args.commit}
    runtime_manifest["components"] = build_manifest["components"]
    packaging = dict(runtime_manifest.get("packaging", {}))
    packaging["sourceDateEpoch"] = args.source_date_epoch
    runtime_manifest["packaging"] = packaging
    canonical(metadata / "runtime-manifest.json", runtime_manifest)
    for name in ("wine-integration-evidence.json", "sbom.spdx.json", "evidence-index.json",
                 "KNOWN-LIMITATIONS.md"):
        (metadata / name).write_bytes((args.output / name).read_bytes())

    normalize(args.runtime, args.source_date_epoch)
    archive_path = args.output / archive
    make_tar(args.runtime, archive_path, top, args.source_date_epoch)
    archive_hash = digest(archive_path)
    (args.output / f"{archive}.sha256").write_text(f"{archive_hash}  {archive}\n",
                                                     encoding="ascii")
    manifest = {"schema": 1,
                "release": {"version": args.version, "tag": f"v{args.version}",
                            "repository": args.repository, "commit": args.commit},
                "components": build_manifest["components"],
                "winePatches": build_manifest["winePatches"],
                "bridge": build_manifest["bridge"],
                "toolchain": build_manifest["toolchain"],
                "package": {"name": archive, "sha256": archive_hash,
                            "size": archive_path.stat().st_size,
                            "sourceDateEpoch": args.source_date_epoch,
                            "files": inventory(args.runtime)},
                "evidence": {
                    "integration": {"path": "wine-integration-evidence.json",
                                    "sha256": digest(args.output / "wine-integration-evidence.json")},
                    "sbom": {"path": "sbom.spdx.json",
                             "sha256": digest(args.output / "sbom.spdx.json")},
                    "index": {"path": "evidence-index.json",
                              "sha256": digest(args.output / "evidence-index.json")},
                    "knownLimitations": {"path": "KNOWN-LIMITATIONS.md",
                                         "sha256": digest(args.output / "KNOWN-LIMITATIONS.md")},
                }}
    canonical(args.output / "release-manifest.json", manifest)
    print(f"repackaged published runtime as {archive}")


if __name__ == "__main__":
    main()
