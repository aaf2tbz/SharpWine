#!/usr/bin/env python3
"""Require byte-identical fixtures and semantic agreement across all three oracles."""

from __future__ import annotations

import argparse
import json
import pathlib


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 evidence comparison failed: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", nargs=3, type=pathlib.Path)
    args = parser.parse_args()
    records = [json.loads(path.read_text(encoding="utf-8")) for path in args.evidence]
    by_mode = {record.get("mode"): record for record in records}
    if set(by_mode) != {"intel-native", "jit", "interpreter"}:
        fail("exactly Intel-native, ARM64-JIT, and ARM64-interpreter evidence is required")
    if any(record.get("schema") != 1 or record.get("bounded") is not True or
           record.get("returnCode") != 0 or record.get("engineTraceObserved") is not True
           for record in records):
        fail("an evidence record is unaccepted")
    hashes = {record.get("fixtureSha256") for record in records}
    semantics = {json.dumps(record.get("semantic"), sort_keys=True, separators=(",", ":"))
                 for record in records}
    if len(hashes) != 1:
        fail("the three executions did not use identical fixture bytes")
    if len(semantics) != 1:
        fail("Intel, JIT, and interpreter semantic results disagree")
    print(f"x86_64 semantic evidence passed for fixture {hashes.pop()}")


if __name__ == "__main__":
    main()
