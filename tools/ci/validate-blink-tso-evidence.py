#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independently validate native Blink x86-TSO conformance evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

SHA256_RE = re.compile(r"[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_counts(record: dict[str, Any], lock_iterations: int, label: str) -> None:
    require(record.get("passed") is True, f"{label}: not passed")
    counts = record.get("counts")
    require(isinstance(counts, dict), f"{label}: counts missing")
    for name in ("lb11", "mp10", "iriw", "fence00", "smc"):
        require(counts.get(name) == 0, f"{label}: forbidden {name} outcome observed")
    require(counts.get("locked") == 4 * lock_iterations, f"{label}: locked count mismatch")
    require(isinstance(counts.get("sb00"), int) and counts["sb00"] >= 0, f"{label}: invalid SB count")
    run = record.get("run")
    require(isinstance(run, dict), f"{label}: run record missing")
    require(run.get("status") == "exited" and run.get("exitCode") == 0, f"{label}: run failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    with args.evidence.open("r", encoding="utf-8") as source:
        evidence = json.load(source)
    require(isinstance(evidence, dict), "evidence root must be an object")
    require(evidence.get("schemaVersion") == 1, "unsupported evidence schema")
    require(evidence.get("nativeMachine") == "arm64", "evidence was not produced on native ARM64")
    require(evidence.get("hardwareTso") == "not-requested; no supported per-thread API", "hardware TSO policy mismatch")
    require(evidence.get("roundsPerLitmus", 0) >= 20000, "insufficient litmus rounds")
    lock_iterations = evidence.get("lockIterationsPerWorker")
    require(isinstance(lock_iterations, int) and lock_iterations >= 10000, "insufficient locked iterations")
    for name in ("blinkSha256", "guestSourceSha256", "guestImageSha256"):
        value = evidence.get(name)
        require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{name} is invalid")

    interpreter = evidence.get("interpreter")
    require(isinstance(interpreter, list) and len(interpreter) >= 3, "interpreter repetitions missing")
    for index, record in enumerate(interpreter):
        require(isinstance(record, dict), f"interpreter[{index}] is invalid")
        validate_counts(record, lock_iterations, f"interpreter[{index}]")

    jit = evidence.get("jitCandidate")
    require(isinstance(jit, dict), "JIT candidate record missing")
    selected = evidence.get("selectedMode")
    fallback = evidence.get("fallback")
    if jit.get("passed") is True:
        require(selected == "jit", "passing JIT was not selected")
        require(fallback is None, "fallback must be absent when JIT passes")
        validate_counts(jit, lock_iterations, "jitCandidate")
    else:
        require(selected == "interpreter-fallback", "failed JIT did not select fallback")
        require(isinstance(fallback, dict), "interpreter fallback record missing")
        validate_counts(fallback, lock_iterations, "fallback")
    require(evidence.get("passed") is True, "aggregate evidence did not pass")
    print("Blink x86-TSO evidence validated")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"Blink x86-TSO evidence rejected: {error}") from error
