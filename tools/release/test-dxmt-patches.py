#!/usr/bin/env python3
"""Unit tests for the fail-closed DXMT patch queue validator."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools/release/validate-dxmt-patches.py"


class DxmtPatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "third_party/patches").mkdir(parents=True)
        shutil.copytree(
            ROOT / "third_party/patches/dxmt", self.root / "third_party/patches/dxmt"
        )
        shutil.copy2(ROOT / "components.lock.json", self.root / "components.lock.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def validate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), "--root", str(self.root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_valid_queue(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_patch_substitution(self) -> None:
        patch = next((self.root / "third_party/patches/dxmt").glob("*.patch"))
        patch.write_bytes(patch.read_bytes() + b"\nsubstitution\n")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hash mismatch", result.stderr)

    def test_rejects_unlisted_patch(self) -> None:
        (self.root / "third_party/patches/dxmt/9999-unlisted.patch").write_text(
            "not a patch\n", encoding="utf-8"
        )
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly enumerate", result.stderr)

    def test_rejects_lock_disagreement(self) -> None:
        lock_path = self.root / "components.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["components"]["dxmt"]["revision"] = "0" * 40
        lock_path.write_text(json.dumps(lock) + "\n", encoding="utf-8")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disagrees", result.stderr)


if __name__ == "__main__":
    unittest.main()
