#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


differential = load("phase4_differential", ROOT / "tools/i386/phase4_differential.py")
minimizer = load("minimize_phase4_case", ROOT / "tools/i386/minimize_phase4_case.py")


class Phase4ToolTests(unittest.TestCase):
    def test_phase5_golden_binding(self):
        evidence = json.loads(
            (ROOT / "docs/architecture/adr/i386-phase4-evidence.json").read_text()
        )
        golden = ROOT / "tests/fixtures/i386_phase5_golden.bin"
        data = golden.read_bytes()
        magic, schema, count, shard, ordinal, seed = struct.unpack("<8sIIIIQ", data[:32])
        self.assertEqual(magic, b"SWP5GLD1")
        self.assertEqual((schema, count, shard, ordinal, seed),
                         (1, 20313, 4, 3928, 0x534841525057494E))
        self.assertEqual(len(data), 32 + count * 8)
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         evidence["phase5CiCorpus"]["goldenSha256"])

    def test_worker_classification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = root / "good.py"
            good.write_text("print('{\"compatibilityHash\":\"x\",\"jitExecutions\":1,\"category\":\"scalar\"}')\n")
            result = differential.run_worker([sys.executable, str(good)], 1.0)
            self.assertEqual(result["classification"], "pass")
            bad = root / "bad.py"
            bad.write_text("print('{bad')\n")
            self.assertEqual(differential.run_worker([sys.executable, str(bad)], 1.0)["classification"],
                             "malformed-record")
            nonzero = root / "nonzero.py"
            nonzero.write_text("raise SystemExit(7)\n")
            self.assertEqual(
                differential.run_worker([sys.executable, str(nonzero)], 1.0)["classification"],
                "nonzero-exit",
            )
            crash = root / "crash.py"
            crash.write_text("import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
            self.assertEqual(
                differential.run_worker([sys.executable, str(crash)], 1.0)["classification"],
                "crash",
            )
            timeout = root / "timeout.py"
            timeout.write_text("import time\ntime.sleep(5)\n")
            self.assertEqual(
                differential.run_worker([sys.executable, str(timeout)], 0.02)["classification"],
                "timeout",
            )

    def test_triplet_mismatch_and_fallback(self):
        def result(value, executions=1):
            return {"classification": "pass", "record": {"compatibilityHash": value,
                    "jitExecutions": executions, "category": "scalar"}}
        self.assertEqual(differential.classify_triplet(result("a"), result("a"), result("a")), "pass")
        self.assertEqual(differential.classify_triplet(result("a"), result("b"), result("a")),
                         "semantic-mismatch")
        self.assertEqual(differential.classify_triplet(result("a"), result("a"), result("a", 0)),
                         "jit-fallback")
        unsupported = result("a")
        unsupported["record"]["resultClassification"] = "unsupported-advertised"
        self.assertEqual(
            differential.classify_triplet(unsupported, result("a"), result("a")),
            "unsupported-advertised",
        )

    def test_deterministic_minimizer(self):
        case = {"instruction": "909090", "prefixes": [1, 2], "optionalInstructions": [3],
                "registers": {"eax": 123}, "segments": {"fs": 44}, "memory": [8, 9, 10, 11]}
        predicate = lambda candidate: len(bytes.fromhex(candidate["instruction"])) >= 2
        first = minimizer.minimize(case, predicate)
        second = minimizer.minimize(case, predicate)
        self.assertEqual(first, second)
        self.assertEqual(first["instruction"], "9090")


if __name__ == "__main__":
    unittest.main()
