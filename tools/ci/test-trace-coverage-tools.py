#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
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


mapcov = load("map_handler_coverage", ROOT / "tools/i386/map_handler_coverage.py")

PROBE = os.environ.get("MSWR_I386_MAP_PROBE")


class TraceCoverageToolTests(unittest.TestCase):
    def test_phase4_template_parser(self):
        templates = mapcov.parse_phase4_templates(
            ROOT / "tests/fixtures/i386_phase4_generator.c")
        self.assertEqual(len(templates), 79)
        by_id = {template["templateId"]: template for template in templates}
        self.assertEqual(sorted(by_id), list(range(100, 138)) + list(range(200, 210)) +
                         [300, 301, 302, 303, 304, 305] +
                         list(range(400, 415)) +
                         [500, 501, 502, 503, 504, 505] + [600, 601, 602, 603])
        self.assertEqual(by_id[100]["bytes"], bytes([0x01, 0xd8]))
        self.assertEqual(by_id[108]["bytes"], bytes([0x0f, 0xb7, 0xc3]))
        self.assertEqual(by_id[131]["bytes"], bytes([0xff, 0xc0]))
        self.assertEqual(by_id[209]["bytes"], bytes([0x33, 0x06]))
        self.assertEqual(by_id[500]["bytes"], bytes([0xf3, 0xa4]))
        self.assertEqual(by_id[601]["bytes"], bytes([0xc5, 0xf8, 0x77]))
        self.assertFalse(by_id[100]["negative"])
        self.assertTrue(all(by_id[key]["negative"] for key in (600, 601, 602, 603)))

    def test_phase3_record_parser(self):
        records = mapcov.parse_phase3_records(
            ROOT / "tests/fixtures/i386_phase3_reference.bin")
        self.assertEqual(len(records), 1024)
        self.assertTrue(all(0 < len(record["bytes"]) <= 16 for record in records))
        self.assertEqual(len({record["caseId"] for record in records}), 1024)

    def test_histogram_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.out"
            path.write_text("gem_i386_handler_trace 1\ntotal_drained 7\n"
                            "overflow_events 0\nout_of_range 0\n"
                            "handler 1 OpNop 3\nhandler 4260 OpMovsb 4\n", encoding="utf-8")
            parsed = mapcov.parse_histogram(path)
        self.assertEqual(parsed["summary"],
                         {"totalDrained": 7, "overflowEvents": 0, "outOfRange": 0})
        self.assertEqual(parsed["handlers"],
                         {1: {"name": "OpNop", "count": 3},
                          4260: {"name": "OpMovsb", "count": 4}})

    def test_report_prioritization(self):
        with tempfile.TemporaryDirectory() as directory:
            aggregate = Path(directory) / "aggregate.out"
            aggregate.write_text("gem_i386_handler_trace 1\ntotal_drained 30\n"
                                 "overflow_events 0\nout_of_range 0\n"
                                 "handler 1 OpNop 20\nhandler 10 OpLeaGvqpM 9\n"
                                 "handler 4260 OpMovsb 1\n", encoding="utf-8")
            mapped = {
                1: {"name": "OpNop", "corpus": {"phase4": ["505"], "rosetta": ["nop"]}},
                2: {"name": "OpMovZvqpIvqp", "corpus": {"phase3": ["7"]}},
            }
            report = mapcov.build_report(ROOT, aggregate, [], mapped)
            uncovered = report["prioritized"]["uncoveredByTraceFrequency"]
            self.assertEqual([entry["handlerId"] for entry in uncovered], [10, 4260])
            hot = report["prioritized"]["coveredByTraceFrequency"]
            self.assertEqual([entry["handlerId"] for entry in hot], [1, 2])
            self.assertEqual(report["totals"]["tracedUncoveredHandlers"], 2)
            self.assertEqual(report["totals"]["corpusOnlyHandlers"], 1)
            finalized = mapcov.finalize(report)
            self.assertEqual(len(finalized["resultsSha256"]), 64)

    @unittest.skipUnless(PROBE, "MSWR_I386_MAP_PROBE not set; engine probe unavailable")
    def test_known_template_handlers_with_real_probe(self):
        probe = Path(PROBE)
        expectations = [
            (bytes([0x90]), [(1, "OpNop")]),
            (bytes([0xb8, 0x78, 0x56, 0x34, 0x12]), [(2, "OpMovZvqpIvqp")]),
            (bytes([0x83, 0xc0, 0x01]), [(6, "OpAlui")]),
            (bytes([0xf3, 0xa4]), [(4260, "OpMovsb")]),
            (bytes([0x01, 0xd8]), [(4097, "OpAluw")]),
            (bytes([0x0f, 0x0b]), []),
            (bytes([0x0f, 0xb7, 0xc3]), [(4535, "OpMovzwGvqpEw")]),
            (bytes([0x8d, 0x43, 0x40]), [(10, "OpLeaGvqpM")]),
            (bytes([0xff, 0xc0]), [(4351, "Op0ff")]),
        ]
        for code, expected in expectations:
            self.assertEqual(mapcov.run_probe(probe, code), expected, code.hex())


if __name__ == "__main__":
    unittest.main()
