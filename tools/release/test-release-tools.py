#!/usr/bin/env python3
"""Unit tests for fail-closed integrated Wine release validation."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def make_candidate(directory: Path) -> None:
    (directory / ARCHIVE).write_bytes(b"deterministic-zstd-candidate")
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
        "toolchain": {"host": "aarch64-apple-darwin",
                      "peArchitectures": ["i386", "x86_64", "aarch64", "arm64ec"]},
        "package": {"name": ARCHIVE, "sha256": archive_hash,
                    "size": (directory / ARCHIVE).stat().st_size,
                    "sourceDateEpoch": 1, "files": [{"path": "bin/wine", "sha256": "e" * 64}]},
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

    def test_verifies_published_asset_digests(self) -> None:
        fake_bin = self.directory / "fake-bin"
        fake_bin.mkdir()
        response = self.directory / "release.json"
        uploaded = [name for name in sorted(p.name for p in self.directory.iterdir() if p.is_file())
                    if name != "RELEASE-NOTES.md" and name != "release.json"]
        write_json(response, {
            "draft": True,
            "tag_name": "v0.1.0",
            "target_commitish": COMMIT,
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
