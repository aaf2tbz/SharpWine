#!/usr/bin/env python3
"""Tests for the published-foundation and focused-overlay release tools."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import bz2
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPLY = ROOT / "tools/release/apply-focused-overlay.py"
CREATE = ROOT / "tools/release/create-focused-overlay.py"
FINALIZE = ROOT / "tools/release/finalize-x86-64-evidence.py"

PREPARE_SPEC = importlib.util.spec_from_file_location(
    "prepare_foundation", ROOT / "tools/release/prepare-published-foundation.py"
)
if PREPARE_SPEC is None or PREPARE_SPEC.loader is None:
    raise RuntimeError("could not load published foundation preparer")
PREPARE = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE)

PATCH_SPEC = importlib.util.spec_from_file_location(
    "runtime_patches", ROOT / "tools/release/apply-runtime-patches.py"
)
if PATCH_SPEC is None or PATCH_SPEC.loader is None:
    raise RuntimeError("could not load runtime patch applier")
PATCHES = importlib.util.module_from_spec(PATCH_SPEC)
PATCH_SPEC.loader.exec_module(PATCHES)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8")


def bsdiff_number(value: int) -> bytes:
    magnitude = abs(value)
    result = bytearray(8)
    for index in range(8):
        result[index] = magnitude & 0xff
        magnitude >>= 8
    if value < 0:
        result[7] |= 0x80
    return bytes(result)


class FocusedOverlayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "runtime"
        self.overlay = self.root / "overlay"
        self.runtime.mkdir()
        self.overlay.mkdir()
        (self.runtime / "bin").mkdir()
        (self.runtime / "share").mkdir()
        (self.runtime / "bin/base").write_bytes(b"base\n")
        (self.runtime / "bin/base").chmod(0o755)
        inventory = PREPARE.load_object  # retain a direct import smoke check
        self.assertTrue(callable(inventory))
        self.base_manifest = self.root / "release-manifest.json"
        write_json(self.base_manifest, {
            "package": {"files": [
                {"path": "bin", "type": "directory", "mode": 0o755},
                {"path": "bin/base", "type": "file", "mode": 0o755,
                 "size": 5, "sha256": sha256(b"base\n")},
                {"path": "share", "type": "directory", "mode": 0o755},
            ]},
        })
        self.binding = {
            "release": {"version": "0.1.1", "tag": "v0.1.1", "previousTag": "v0.1.0"},
            "base": {"archive": "metalsharp-wine-v0.1.0-macos-arm64.tar.zst",
                     "sha256": "1" * 64},
        }
        self.policy = self.root / "policy.json"
        write_json(self.policy, {
            "schema": 1,
            **self.binding,
            "allowedChanges": [
                {"path": "bin/base", "action": "replace", "reason": "test replacement"},
                {"path": "share/evidence.json", "action": "add", "reason": "test evidence"},
            ],
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_apply(self, changes: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
        manifest = self.root / "overlay.json"
        write_json(manifest, {"schema": 1, **self.binding, "changes": changes})
        return subprocess.run(
            [sys.executable, str(APPLY), "--runtime", str(self.runtime),
             "--base-manifest", str(self.base_manifest), "--policy", str(self.policy),
             "--overlay", str(self.overlay), "--overlay-manifest", str(manifest),
             "--evidence", str(self.root / "evidence.json")],
            text=True, capture_output=True, check=False,
        )

    def test_applies_only_hash_bound_changes(self) -> None:
        replacement = b"replacement\n"
        evidence = b"{}\n"
        (self.overlay / "bin").mkdir()
        (self.overlay / "bin/base").write_bytes(replacement)
        (self.overlay / "share").mkdir()
        (self.overlay / "share/evidence.json").write_bytes(evidence)
        result = self.run_apply([
            {"path": "bin/base", "action": "replace", "mode": 0o755,
             "size": len(replacement), "sha256": sha256(replacement)},
            {"path": "share/evidence.json", "action": "add", "mode": 0o644,
             "size": len(evidence), "sha256": sha256(evidence)},
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.runtime / "bin/base").read_bytes(), replacement)
        self.assertEqual((self.runtime / "share/evidence.json").read_bytes(), evidence)
        output = json.loads((self.root / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual([item["path"] for item in output["changes"]],
                         ["bin/base", "share/evidence.json"])

    def test_rejects_unlisted_payload(self) -> None:
        (self.overlay / "other").write_bytes(b"bad")
        result = self.run_apply([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted payloads", result.stderr)

    def test_rejects_base_runtime_drift(self) -> None:
        (self.runtime / "bin/base").write_bytes(b"changed\n")
        result = self.run_apply([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not exactly match", result.stderr)

    def test_policy_binding_is_exact(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        version, tag, previous, archive = PREPARE.validate_policy(policy)
        self.assertEqual((version, tag, previous, archive),
                         ("0.1.1", "v0.1.1", "v0.1.0",
                          "metalsharp-wine-v0.1.0-macos-arm64.tar.zst"))
        policy["unexpected"] = True
        with self.assertRaises(SystemExit):
            PREPARE.validate_policy(policy)

    def test_creator_binds_exact_policy_payloads(self) -> None:
        replacement = b"replacement\n"
        evidence = b"{}\n"
        (self.overlay / "bin").mkdir()
        (self.overlay / "bin/base").write_bytes(replacement)
        (self.overlay / "bin/base").chmod(0o755)
        (self.overlay / "share").mkdir()
        (self.overlay / "share/evidence.json").write_bytes(evidence)
        output = self.root / "created-overlay.json"
        result = subprocess.run(
            [sys.executable, str(CREATE), "--policy", str(self.policy),
             "--overlay", str(self.overlay), "--output", str(output)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([item["path"] for item in manifest["changes"]],
                         ["bin/base", "share/evidence.json"])
        self.assertEqual(manifest["changes"][0]["sha256"], sha256(replacement))

    def test_finalizer_requires_both_pure_x86_64_probes(self) -> None:
        build = self.root / "build.json"
        fixture = self.root / "fixture.json"
        summary = self.root / "summary.json"
        output = self.root / "acceptance.json"
        write_json(build, {"schema": 1, "kind": "published-runtime-patch-set",
                           "repositoryCommit": "a" * 40, "fullWineRebuild": False,
                           "runtimePatches": [{"path": "native"}, {"path": "guest"}]})
        write_json(fixture, {"schema": 1, "byteIdentical": True,
                             "host": {"architecture": "arm64"},
                             "fixture": {"sha256": "b" * 64}})
        write_json(summary, {"passed": True, "freshPrefix": True, "teardownClean": True,
                             "tests": [
                                 {"name": name, "passed": True, "logSha256": "c" * 64}
                                 for name in ("x86_64-exception", "x86_64-cmd-exit")
                             ],
                             "processAudit": {"allNativeArm64": True,
                                              "translatedProcesses": []}})
        result = subprocess.run(
            [sys.executable, str(FINALIZE), "--build-manifest", str(build),
             "--fixture-manifest", str(fixture), "--test-summary", str(summary),
             "--output", str(output)], text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([item["name"] for item in evidence["tests"]],
                         ["x86_64-cmd-exit", "x86_64-exception"])

    def test_bsdiff40_applier_checks_and_reconstructs_bytes(self) -> None:
        old = b"abc"
        differences = bytes((0, (ord("x") - ord("b")) & 0xff, 0))
        control = bsdiff_number(3) + bsdiff_number(1) + bsdiff_number(0)
        compressed_control = bz2.compress(control)
        compressed_diff = bz2.compress(differences)
        patch = (b"BSDIFF40" + bsdiff_number(len(compressed_control)) +
                 bsdiff_number(len(compressed_diff)) + bsdiff_number(4) +
                 compressed_control + compressed_diff + bz2.compress(b"!"))
        self.assertEqual(PATCHES.apply_bsdiff(old, patch), b"axc!")
        with self.assertRaises(SystemExit):
            PATCHES.apply_bsdiff(old, patch[:-1])

    def test_runtime_patch_parts_are_reassembled_in_order(self) -> None:
        (self.root / "patch.part00").write_bytes(b"BSDIFF")
        (self.root / "patch.part01").write_bytes(b"40")
        self.assertEqual(
            PATCHES.read_patch(
                self.root, ["patch.part00", "patch.part01"], "lib/example.so"
            ),
            b"BSDIFF40",
        )
        with self.assertRaises(SystemExit):
            PATCHES.read_patch(
                self.root, ["patch.part00", "patch.part00"], "lib/example.so"
            )

    def test_committed_fixture_patch_reconstructs_exact_fixture(self) -> None:
        patch_root = ROOT / "release/runtime-patches/v0.1.1"
        manifest = json.loads((patch_root / "manifest.json").read_text(encoding="utf-8"))
        fixture = manifest["fixture"]
        patch = (patch_root / fixture["patch"]).read_bytes()
        self.assertEqual(hashlib.sha256(patch).hexdigest(), fixture["patchSha256"])
        output = PATCHES.apply_bsdiff(b"", patch)
        self.assertEqual(len(output), fixture["resultSize"])
        self.assertEqual(hashlib.sha256(output).hexdigest(), fixture["resultSha256"])


if __name__ == "__main__":
    unittest.main()
