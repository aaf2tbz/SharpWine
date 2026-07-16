#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministically minimize a portable Phase 4 mismatch description."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
from typing import Any, Callable

EDGE_VALUES = (0, 1, -1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000)


def reproduces(candidate: dict[str, Any], command: str, classification: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="sharpwine-phase4-min-") as directory:
        path = Path(directory) / "candidate.json"
        path.write_text(json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8")
        argv = shlex.split(command.format(case=str(path)))
        for _ in range(3):
            run = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
            try:
                observed = json.loads(run.stdout.splitlines()[-1])["classification"]
            except (IndexError, KeyError, json.JSONDecodeError):
                return False
            if observed != classification:
                return False
    return True


def accept(current: dict[str, Any], candidate: dict[str, Any], predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    return candidate if predicate(candidate) else current


def minimize(case: dict[str, Any], predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    current = copy.deepcopy(case)
    instruction = bytes.fromhex(current.get("instruction", ""))
    for size in range(1, len(instruction)):
        candidate = copy.deepcopy(current)
        candidate["instruction"] = instruction[:size].hex()
        current = accept(current, candidate, predicate)
        instruction = bytes.fromhex(current.get("instruction", ""))
    for key in ("prefixes", "optionalInstructions"):
        while current.get(key):
            candidate = copy.deepcopy(current)
            candidate[key] = candidate[key][:-1]
            reduced = accept(current, candidate, predicate)
            if reduced is current:
                break
            current = reduced
    for section in ("registers", "segments"):
        for key in sorted(current.get(section, {})):
            for value in EDGE_VALUES:
                candidate = copy.deepcopy(current)
                candidate[section][key] = value & 0xffffffff
                current = accept(current, candidate, predicate)
    memory = list(current.get("memory", []))
    for index in range(len(memory)):
        for value in (0, 1, 0xff):
            candidate = copy.deepcopy(current)
            candidate["memory"][index] = value
            current = accept(current, candidate, predicate)
    while len(current.get("memory", [])) > 1:
        candidate = copy.deepcopy(current)
        candidate["memory"] = candidate["memory"][: len(candidate["memory"]) // 2]
        reduced = accept(current, candidate, predicate)
        if reduced is current:
            break
        current = reduced
    return current


def emit_regression(case: dict[str, Any], path: Path) -> None:
    encoding = bytes.fromhex(case.get("instruction", ""))
    values = ", ".join(f"0x{byte:02x}U" for byte in encoding)
    path.write_text(
        "// generated Phase 4 deterministic regression\n"
        "#include <stdint.h>\n"
        f"static const uint8_t phase4_regression[] = {{{values}}};\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--classification", required=True)
    parser.add_argument("--reproducer", required=True, help="command containing {case}")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    original = json.loads(args.case.read_text(encoding="utf-8"))
    predicate = lambda candidate: reproduces(candidate, args.reproducer, args.classification)
    if not predicate(original):
        raise SystemExit("original case does not reproduce three consecutive times")
    minimized = minimize(original, predicate)
    args.output.mkdir(parents=True, exist_ok=True)
    case_path = args.output / "minimized.case.json"
    case_path.write_text(json.dumps(minimized, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    emit_regression(minimized, args.output / "minimized-regression.c")
    print(case_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
