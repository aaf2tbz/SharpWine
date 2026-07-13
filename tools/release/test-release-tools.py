#!/usr/bin/env python3
"""Unit tests for fail-closed integrated Wine release validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools/release/validate-release-assets.py"
VERIFIER = ROOT / "tools/release/verify-published-release.py"
REPOSITORY = "owner/project"
COMMIT = "1" * 40
VERSION = "0.1.0"
ARCHIVE = "metalsharp-wine-v0.1.0-macos-arm64.tar.zst"

STAGER_SPEC = importlib.util.spec_from_file_location(
    "stage_runtime", ROOT / "tools/release/stage-runtime.py")
if STAGER_SPEC is None or STAGER_SPEC.loader is None:
    raise RuntimeError("could not load runtime stager")
STAGER = importlib.util.module_from_spec(STAGER_SPEC)
STAGER_SPEC.loader.exec_module(STAGER)

PACKAGED_SPEC = importlib.util.spec_from_file_location(
    "test_packaged_runtime", ROOT / "tools/release/test-packaged-runtime.py")
if PACKAGED_SPEC is None or PACKAGED_SPEC.loader is None:
    raise RuntimeError("could not load packaged runtime tester")
PACKAGED = importlib.util.module_from_spec(PACKAGED_SPEC)
PACKAGED_SPEC.loader.exec_module(PACKAGED)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def make_candidate(directory: Path) -> None:
    package = directory / "package-tree"
    (package / "bin").mkdir(parents=True)
    (package / "bin/wine").write_bytes(b"test launcher\n")
    (package / "bin/wine").chmod(0o755)
    tar_path = directory / "candidate.tar"
    top = "metalsharp-wine-v0.1.0-macos-arm64"
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as value:
        for path, name in ((package, top), (package / "bin", f"{top}/bin"),
                           (package / "bin/wine", f"{top}/bin/wine")):
            info = value.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 1
            info.pax_headers = {}
            if path.is_file():
                with path.open("rb") as source:
                    value.addfile(info, source)
            else:
                value.addfile(info)
    zstd = shutil.which("zstd") or "/opt/homebrew/opt/zstd/bin/zstd"
    subprocess.run([zstd, "-1", "--threads=1", "--force", str(tar_path),
                    "-o", str(directory / ARCHIVE)], check=True, stdout=subprocess.DEVNULL)
    shutil.rmtree(package)
    tar_path.unlink()
    archive_hash = digest(directory / ARCHIVE)
    (directory / f"{ARCHIVE}.sha256").write_text(
        f"{archive_hash}  {ARCHIVE}\n", encoding="ascii")
    integration = {
        "schema": 1,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "version": VERSION,
        "passed": True,
        "wineEngineIntegrated": True,
        "zeroRosetta": True,
        "tests": [
            {"name": name, "passed": True, "bounded": True, "evidence": {"log": f"{name}.log"}}
            for name in ("wineboot-init", "arm64-cmd-exit", "arm64ec-x64-hybrid")
        ],
        "processAudit": {"allNativeArm64": True, "translatedProcesses": []},
    }
    write_json(directory / "wine-integration-evidence.json", integration)
    write_json(directory / "sbom.spdx.json", {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "https://example.invalid/spdx/test",
        "packages": [{"name": "metalsharp-wine"}],
    })
    write_json(directory / "evidence-index.json", {
        "schema": 1,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "version": VERSION,
        "criteria": [{"id": "integrated-wine", "passed": True, "evidence": ["wine-integration-evidence.json"]}],
    })
    (directory / "KNOWN-LIMITATIONS.md").write_text(
        "# Known limitations\n\nThis complete test fixture records an intentionally bounded limitation.\n",
        encoding="utf-8")
    (directory / "RELEASE-NOTES.md").write_text(
        "# MetalSharp Wine v0.1.0\n\nThis complete test fixture represents release notes.\n",
        encoding="utf-8")
    evidence = {
        "integration": "wine-integration-evidence.json",
        "sbom": "sbom.spdx.json",
        "index": "evidence-index.json",
        "knownLimitations": "KNOWN-LIMITATIONS.md",
    }
    manifest = {
        "schema": 1,
        "release": {"version": VERSION, "tag": f"v{VERSION}", "repository": REPOSITORY, "commit": COMMIT},
        "components": {
            "wine": {"repository": "https://example.invalid/wine", "revision": "a" * 40, "license": "LGPL-2.1-or-later"},
            "dynarmic": {"repository": "https://example.invalid/dynarmic", "revision": "b" * 40, "license": "ISC"},
            "blink": {"repository": "https://example.invalid/blink", "revision": "c" * 40, "license": "ISC"},
        },
        "winePatches": [{"path": "third_party/patches/wine/0001.patch", "sha256": "d" * 64,
                         "license": "LGPL-2.1-or-later"}],
        "bridge": {"abiVersion": 1, "installName": "@rpath/libmetalsharp-gem-wine.0.dylib",
                   "currentVersion": "0.1.0", "compatibilityVersion": "0.0.0",
                   "directWineBinding": "lib/wine/aarch64-unix/ntdll.so",
                   "exports": ["gem_wine_bridge_abi_version"]},
        "toolchain": {"host": "aarch64-apple-darwin",
                      "peArchitectures": ["i386", "x86_64", "aarch64", "arm64ec"]},
        "package": {"name": ARCHIVE, "sha256": archive_hash,
                    "size": (directory / ARCHIVE).stat().st_size,
                    "sourceDateEpoch": 1, "files": [
                        {"path": "bin", "type": "directory", "mode": 0o755},
                        {"path": "bin/wine", "type": "file", "mode": 0o755,
                         "size": 14, "sha256": hashlib.sha256(b"test launcher\n").hexdigest()},
                    ]},
        "evidence": {
            key: {"path": name, "sha256": digest(directory / name)} for key, name in evidence.items()
        },
    }
    write_json(directory / "release-manifest.json", manifest)


class ReleaseToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        make_candidate(self.directory)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def validate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), "--directory", str(self.directory),
             "--repository", REPOSITORY, "--commit", COMMIT, "--version", VERSION],
            text=True, capture_output=True, check=False)

    def test_valid_candidate(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_substituted_archive(self) -> None:
        (self.directory / ARCHIVE).write_bytes(b"substitution")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)

    def test_rejects_missing_integration_path(self) -> None:
        path = self.directory / "wine-integration-evidence.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["tests"] = value["tests"][:-1]
        write_json(path, value)
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required integration tests", result.stderr)

    def test_rejects_extra_asset(self) -> None:
        (self.directory / "unbound.bin").write_bytes(b"x")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("asset names", result.stderr)

    def test_scrubs_embedded_build_prefixes_without_resizing(self) -> None:
        payload = self.directory / "compiled-defaults.bin"
        original = (b"prefix\0/Users/builder/wine/stage/share/wine/nls\0"
                    b"/private/var/folders/aa/build/lib\0"
                    b"/Users/builder/opaque/object\0"
                    b"/opt/homebrew/opt/mesa/share:/usr/share\0suffix")
        payload.write_bytes(original)
        STAGER.scrub_embedded_prefixes(self.directory)
        scrubbed = payload.read_bytes()
        self.assertEqual(len(scrubbed), len(original))
        self.assertNotIn(b"/Users/", scrubbed)
        self.assertNotIn(b"/private/var/folders/", scrubbed)
        self.assertNotIn(b"/opt/homebrew", scrubbed)
        self.assertIn(b"/dev/null", scrubbed)
        self.assertIn(b"share/wine/nls", scrubbed)
        self.assertIn(b"lib", scrubbed)
        self.assertIn(b"/usr/share", scrubbed)

    def test_rebinds_chained_import_without_resizing(self) -> None:
        library = b"@rpath/libmetalsharp-gem-wine.0.dylib\0"
        dylib_size = (24 + len(library) + 7) & ~7
        dylib = (struct.pack("<6I", 0x0c, dylib_size, 24, 0, 0, 0) + library)
        dylib += bytes(dylib_size - len(dylib))
        command_size = dylib_size + 16
        data_offset = 32 + command_size
        fixups = struct.pack("<4I", 0x80000034, 16, data_offset, 39)
        header = struct.pack("<7I", 0, 0, 28, 32, 1, 1, 0)
        chained_import = struct.pack("<I", 2) + b"_pipe2\0"
        macho = (struct.pack("<8I", 0xfeedfacf, 0, 0, 0, 2, command_size, 0, 0) +
                 dylib + fixups + header + chained_import)
        rebound = STAGER.rebind_chained_import(
            macho, "_pipe2", "@rpath/libmetalsharp-gem-wine.0.dylib")
        self.assertEqual(len(rebound), len(macho))
        self.assertEqual(struct.unpack_from("<I", rebound, data_offset + 28)[0] & 0xff, 1)

    def test_prefix_readiness_requires_complete_nonempty_install(self) -> None:
        prefix = self.directory / "prefix"
        prefix.mkdir()
        missing, snapshot = PACKAGED.prefix_snapshot(prefix)
        self.assertEqual(set(missing), set(PACKAGED.PREFIX_READY_FILES))
        self.assertEqual(snapshot, {})
        for relative in PACKAGED.PREFIX_READY_FILES:
            path = prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode("utf-8"))
        missing, snapshot = PACKAGED.prefix_snapshot(prefix)
        self.assertEqual(missing, [])
        self.assertEqual(set(snapshot), set(PACKAGED.PREFIX_READY_FILES))

    def test_verifies_published_asset_digests(self) -> None:
        fake_bin = self.directory / "fake-bin"
        fake_bin.mkdir()
        response = self.directory / "release.json"
        uploaded = [name for name in sorted(p.name for p in self.directory.iterdir() if p.is_file())
                    if name != "RELEASE-NOTES.md" and name != "release.json"]
        write_json(response, {
            "isDraft": True,
            "tagName": "v0.1.0",
            "targetCommitish": COMMIT,
            "assets": [{"name": name, "size": (self.directory / name).stat().st_size,
                        "digest": f"sha256:{digest(self.directory / name)}"} for name in uploaded],
        })
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(f"#!/bin/sh\ncat '{response}'\n", encoding="utf-8")
        fake_gh.chmod(0o755)
        environment = os.environ.copy()
        environment["GH_TOKEN"] = "test"
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            ["python3", str(VERIFIER), "--directory", str(self.directory),
             "--repository", REPOSITORY, "--tag", "v0.1.0", "--commit", COMMIT],
            env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
