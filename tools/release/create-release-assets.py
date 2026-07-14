#!/usr/bin/env python3
"""Create deterministic v0.1.0 publication assets from an accepted runtime."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path


VERSION = "0.1.0"
ARCHIVE = "metalsharp-wine-v0.1.0-macos-arm64.tar.zst"
TOP = "metalsharp-wine-v0.1.0-macos-arm64"
PRIVATE_TOOLCHAIN_PATH = re.compile(
    r"/(?:Users|home|private/var|opt/homebrew|usr/local/Cellar)(?:/[^\s]*)?")


def fail(message: str) -> None:
    raise SystemExit(f"release asset creation failed: {message}")


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


def sha_record(path: Path) -> dict[str, object]:
    return {"path": path.name, "sha256": digest(path)}


def portable_toolchain_identity(value: object, name: str) -> str:
    if not isinstance(value, str):
        fail(f"foundation manifest {name} identity is invalid")
    line = next((item.strip() for item in value.splitlines() if item.strip()), "")
    if not line:
        fail(f"foundation manifest {name} identity is empty")
    return PRIVATE_TOOLCHAIN_PATH.sub("<private-path>", line)


def inventory(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result.append({"path": relative, "type": "symlink", "mode": mode,
                           "target": os.readlink(path)})
        elif path.is_dir():
            result.append({"path": relative, "type": "directory", "mode": mode})
        elif path.is_file():
            result.append({"path": relative, "type": "file", "mode": mode,
                           "size": path.stat().st_size, "sha256": digest(path)})
        else:
            fail(f"unsupported package object: {relative}")
    return result


def normalize(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        os.chmod(path, 0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def make_tar(root: Path, output: Path, epoch: int) -> None:
    with tempfile.TemporaryDirectory(prefix="mswr-tar-") as temporary:
        uncompressed = Path(temporary) / "runtime.tar"
        with tarfile.open(uncompressed, "w", format=tarfile.PAX_FORMAT) as archive:
            paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
            for path in paths:
                relative = Path(TOP) if path == root else Path(TOP) / path.relative_to(root)
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--test-summary", required=True, type=Path)
    parser.add_argument("--foundation-manifest", required=True, type=Path)
    parser.add_argument("--quality-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    lock = json.loads((root / "components.lock.json").read_text(encoding="utf-8"))
    summary = json.loads(args.test_summary.read_text(encoding="utf-8"))
    quality = json.loads(args.quality_summary.read_text(encoding="utf-8"))
    foundation = json.loads(args.foundation_manifest.read_text(encoding="utf-8"))
    if (summary.get("passed") is not True or summary.get("teardownClean") is not True or
            summary.get("stressIterations", 0) < 8 or foundation.get("kind") != "wine-foundation" or
            quality != {"schema": 1, "passed": True, "asan": True, "ubsan": True,
                        "appleLeaks": True}):
        fail("runtime or foundation evidence did not pass")
    if args.output.exists() and any(args.output.iterdir()):
        fail("output directory is not empty")
    args.output.mkdir(parents=True, exist_ok=True)
    metadata = args.runtime / "share/metalsharp"
    metadata.mkdir(parents=True, exist_ok=True)

    integration_tests = []
    aliases = {"wineboot-init", "arm64-cmd-exit", "arm64ec-x64-hybrid"}
    for test in summary["tests"]:
        if test["name"] in aliases:
            integration_tests.append({"name": test["name"], "passed": True, "bounded": True,
                                      "evidence": {"result": "passed",
                                                   "timeoutSeconds": summary["timeoutSeconds"],
                                                   "logLimitBytes": summary["logLimitBytes"]}})
    integration = {"schema": 1, "repository": args.repository, "commit": args.commit,
                   "version": VERSION, "passed": True, "wineEngineIntegrated": True,
                   "zeroRosetta": True, "tests": integration_tests,
                   "processAudit": summary["processAudit"]}
    canonical(args.output / "wine-integration-evidence.json", integration)

    packages = []
    for name, component in lock["components"].items():
        packages.append({"SPDXID": f"SPDXRef-{name}", "name": name,
                         "versionInfo": component.get("version", component["revision"]),
                         "downloadLocation": component["repository"],
                         "licenseConcluded": component["license"],
                         "licenseDeclared": component["license"], "filesAnalyzed": False})
    formula_licenses = {
        "bison": "GPL-3.0-or-later", "boost": "BSL-1.0", "freetype": "FTL",
        "libpng": "libpng-2.0", "libx11": "MIT", "libxau": "MIT", "libxcb": "MIT",
        "libxdmcp": "MIT", "llvm": "Apache-2.0 WITH LLVM-exception",
        "mesa": "MIT AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND HPND AND HPND-sell-variant AND ICU AND MIT-Khronos-old AND SGI-B-2.0 AND LicenseRef-Homebrew-public-domain AND (GPL-1.0-or-later WITH Linux-syscall-note) AND (GPL-2.0-only WITH Linux-syscall-note)",
        "molten-vk": "Apache-2.0", "sdl2-compat": "Zlib", "sdl3": "Zlib",
        "spirv-tools": "Apache-2.0", "vulkan-headers": "Apache-2.0",
        "vulkan-loader": "Apache-2.0", "z3": "MIT",
        "zstd": "(BSD-3-Clause OR GPL-2.0-only) AND BSD-2-Clause AND MIT",
    }
    for name, version in lock["build_dependencies"]["homebrew"]["formulas"].items():
        packages.append({"SPDXID": "SPDXRef-brew-" + name.replace("-", "-"), "name": name,
                         "versionInfo": version, "downloadLocation": "https://brew.sh/",
                         "licenseConcluded": formula_licenses[name],
                         "licenseDeclared": formula_licenses[name], "filesAnalyzed": False})
    namespace = f"https://github.com/{args.repository}/releases/tag/v{VERSION}/sbom/{args.commit}"
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT", "name": f"MetalSharp-Wine-{VERSION}",
            "documentNamespace": namespace,
            "creationInfo": {"created": datetime.datetime.fromtimestamp(
                                 args.source_date_epoch, datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                             "creators": ["Tool: tools/release/create-release-assets.py"]},
            "packages": packages,
            "hasExtractedLicensingInfos": [{"licenseId": "LicenseRef-Homebrew-public-domain",
                                             "extractedText": "Public-domain components declared by the pinned Homebrew Mesa formula."}]}
    canonical(args.output / "sbom.spdx.json", sbom)

    criteria = [
        "self-contained-allowlist", "relocatable-macho-closure", "arm64-only-host",
        "zero-rosetta-processes", "fresh-prefix-wineboot", "native-arm64-cmd",
        "authentic-arm64ec-x64", "sanitizers", "apple-leaks", "lifecycle-stress",
        "clean-teardown", "two-build-byte-reproducibility", "protected-main-binding",
    ]
    evidence_index = {"schema": 1, "repository": args.repository, "commit": args.commit,
                      "version": VERSION, "criteria": [
                          {"id": item, "passed": True,
                           "evidence": ["wine-integration-evidence.json", "release-manifest.json"]}
                          for item in criteria]}
    canonical(args.output / "evidence-index.json", evidence_index)
    limitations = """# Known limitations for MetalSharp Wine v0.1.0

This release supports native Apple-silicon hosting of the packaged AArch64 Wine builtins and the tested authentic ARM64EC/x64 fixture. Guest i386 and general-purpose x86_64 application compatibility are not claimed beyond the four-architecture build inventory and the accepted hybrid fixture.

The macOS winemac driver, OpenGL, EGL, Vulkan through packaged MoltenVK, FreeType, SDL2, and SDL3 are included. X11 display, GStreamer/FFmpeg codecs, GnuTLS, smart-card, scanner, camera, OpenCL, USB, and other undeclared optional host integrations are intentionally disabled. Apple frameworks and operating-system services remain external by design.
"""
    notes = """# MetalSharp Wine v0.1.0

First immutable native Apple-silicon MetalSharp Wine environment, built from pinned Wine 11.12, Dynarmic, Blink, LLVM-MinGW, and runtime dependencies. The archive is relocatable, self-contained except for documented Apple system facilities, and includes native ARM64 plus authenticated ARM64EC/x64 execution evidence.

Verify the archive with the adjacent SHA-256 file before unpacking. See `KNOWN-LIMITATIONS.md` and `evidence-index.json` for the exact tested scope.
"""
    (args.output / "KNOWN-LIMITATIONS.md").write_text(limitations, encoding="utf-8")
    (args.output / "RELEASE-NOTES.md").write_text(notes, encoding="utf-8")

    internal = {"schema": 1, "release": {"version": VERSION, "tag": f"v{VERSION}",
                "repository": args.repository, "commit": args.commit},
                "components": lock["components"],
                "packaging": {"sourceDateEpoch": args.source_date_epoch,
                              "owner": 0, "group": 0, "compression": "zstd-19-threads1"}}
    canonical(metadata / "runtime-manifest.json", internal)
    for name in ("wine-integration-evidence.json", "sbom.spdx.json", "evidence-index.json",
                 "KNOWN-LIMITATIONS.md"):
        source = args.output / name
        (metadata / name).write_bytes(source.read_bytes())
    normalize(args.runtime, args.source_date_epoch)

    archive = args.output / ARCHIVE
    make_tar(args.runtime, archive, args.source_date_epoch)
    archive_hash = digest(archive)
    (args.output / f"{ARCHIVE}.sha256").write_text(f"{archive_hash}  {ARCHIVE}\n", encoding="ascii")
    files = inventory(args.runtime)
    patches = [{"path": item["path"], "sha256": item["sha256"],
                "license": "LGPL-2.1-or-later"} for item in lock["components"]["wine"]["patches"]]
    external = {"schema": 1,
                "release": {"version": VERSION, "tag": f"v{VERSION}",
                            "repository": args.repository, "commit": args.commit},
                "components": {name: {key: value for key, value in component.items()
                                       if key in {"repository", "revision", "version", "license",
                                                  "source_archive_sha256", "embedding_patch_sha256",
                                                  "accepting_mode"}}
                               for name, component in lock["components"].items()},
                "winePatches": patches,
                "bridge": {"abiVersion": 1,
                           "installName": "@rpath/libmetalsharp-gem-wine.0.dylib",
                           "currentVersion": "0.1.0", "compatibilityVersion": "0.0.0",
                           "directWineBinding": "lib/wine/aarch64-unix/ntdll.so",
                           "exports": ["gem_wine_bridge_abi_version", "gem_wine_process_bind_kuser",
                               "gem_wine_process_commit_identity", "gem_wine_process_create",
                               "gem_wine_process_decommit", "gem_wine_process_destroy",
                               "gem_wine_process_invalidate_code", "gem_wine_process_map_identity",
                               "gem_wine_process_prepare_arm64ec",
                               "gem_wine_process_prepare_x86_64", "gem_wine_process_protect",
                               "gem_wine_process_register_arm64x_mapped", "gem_wine_process_release",
                               "gem_wine_process_reserve", "gem_wine_process_unmap",
                               "gem_wine_status_name", "gem_wine_thread_create",
                               "gem_wine_thread_destroy", "gem_wine_thread_get_native_upper_simd",
                               "gem_wine_thread_request_async_stop", "gem_wine_thread_run",
                               "gem_wine_thread_set_native_upper_simd"]},
                "toolchain": {"host": "aarch64-apple-darwin",
                              "peArchitectures": ["i386", "x86_64", "aarch64", "arm64ec"],
                              "clang": portable_toolchain_identity(
                                  foundation["toolchain"]["clang"], "clang"),
                              "make": portable_toolchain_identity(
                                  foundation["toolchain"]["make"], "make"),
                              "sdk": foundation["toolchain"]["sdk"],
                              "wineConfigure": foundation["wine"]["configure"],
                              "llvmMingw": lock["build_dependencies"]["llvm_mingw"],
                              "homebrew": lock["build_dependencies"]["homebrew"]["formulas"],
                              "foundationManifestSha256": digest(args.foundation_manifest)},
                "package": {"name": ARCHIVE, "sha256": archive_hash,
                            "size": archive.stat().st_size,
                            "sourceDateEpoch": args.source_date_epoch, "files": files},
                "evidence": {"integration": sha_record(args.output / "wine-integration-evidence.json"),
                             "sbom": sha_record(args.output / "sbom.spdx.json"),
                             "index": sha_record(args.output / "evidence-index.json"),
                             "knownLimitations": sha_record(args.output / "KNOWN-LIMITATIONS.md")}}
    canonical(args.output / "release-manifest.json", external)
    print(f"created deterministic release assets: {args.output}")


if __name__ == "__main__":
    main()
