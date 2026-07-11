#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and run the bounded x86-TSO guest under pinned Blink modes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from typing import Any

RESULT_RE = re.compile(
    r"^MSWR_TSO_V1 sb00=(\d+) lb11=(\d+) mp10=(\d+) iriw=(\d+) "
    r"locked=(\d+) fence00=(\d+) smc=(\d+)$"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_bounded(command: list[str], timeout: float) -> dict[str, Any]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return {
            "status": "exited",
            "exitCode": process.returncode,
            "stdout": stdout[-4096:],
            "stderr": stderr[-4096:],
        }
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return {
            "status": "timeout",
            "exitCode": None,
            "stdout": stdout[-4096:],
            "stderr": stderr[-4096:],
        }


def parse_result(run: dict[str, Any], lock_iterations: int) -> dict[str, Any]:
    lines = [line.strip() for line in run["stdout"].splitlines() if line.strip()]
    match = RESULT_RE.fullmatch(lines[-1]) if lines else None
    if run["status"] != "exited" or run["exitCode"] != 0 or match is None:
        return {"passed": False, "run": run}
    keys = ("sb00", "lb11", "mp10", "iriw", "locked", "fence00", "smc")
    counts = {key: int(value) for key, value in zip(keys, match.groups())}
    passed = (
        counts["lb11"] == 0
        and counts["mp10"] == 0
        and counts["iriw"] == 0
        and counts["locked"] == 4 * lock_iterations
        and counts["fence00"] == 0
        and counts["smc"] == 0
    )
    return {"passed": passed, "counts": counts, "run": run}


def verify_elf(path: Path) -> None:
    header = path.read_bytes()[:20]
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError("guest output is not a little-endian ELF64 image")
    if int.from_bytes(header[18:20], "little") != 62:
        raise ValueError("guest output is not EM_X86_64")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blink", required=True, type=Path)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--linker", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=20000)
    parser.add_argument("--lock-iterations", type=int, default=10000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--interpreter-timeout", type=float, default=60.0)
    parser.add_argument("--jit-timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.rounds < 1 or args.lock_iterations < 1 or args.repetitions < 2:
        parser.error("rounds and lock iterations must be positive; repetitions must be at least two")

    args.build_dir.mkdir(parents=True, exist_ok=True)
    guest = args.build_dir / "x86_tso_litmus.elf"
    compile_command = [
        str(args.clang),
        "--target=x86_64-linux-gnu",
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-pic",
        "-nostdlib",
        "-static",
        f"--ld-path={args.linker}",
        "-Wl,-e,_start",
        "-Wl,-N",
        f"-DMSWR_TSO_ROUNDS={args.rounds}",
        f"-DMSWR_TSO_LOCK_ITERS={args.lock_iterations}",
        str(args.source),
        "-o",
        str(guest),
    ]
    subprocess.run(compile_command, check=True)
    verify_elf(guest)

    interpreter = []
    for _ in range(args.repetitions):
        interpreter.append(
            parse_result(
                run_bounded([str(args.blink), "-j", str(guest)], args.interpreter_timeout),
                args.lock_iterations,
            )
        )
    interpreter_passed = all(item["passed"] for item in interpreter)

    jit_candidate = parse_result(
        run_bounded([str(args.blink), str(guest)], args.jit_timeout), args.lock_iterations
    )
    selected_mode = "jit" if jit_candidate["passed"] else "interpreter-fallback"
    fallback = None
    if selected_mode == "interpreter-fallback":
        fallback = parse_result(
            run_bounded([str(args.blink), "-j", str(guest)], args.interpreter_timeout),
            args.lock_iterations,
        )

    passed = interpreter_passed and (
        jit_candidate["passed"] or (fallback is not None and fallback["passed"])
    )
    evidence = {
        "schemaVersion": 1,
        "nativeMachine": os.uname().machine,
        "hardwareTso": "not-requested; no supported per-thread API",
        "blinkSha256": sha256(args.blink),
        "guestSourceSha256": sha256(args.source),
        "guestImageSha256": sha256(guest),
        "roundsPerLitmus": args.rounds,
        "lockIterationsPerWorker": args.lock_iterations,
        "interpreter": interpreter,
        "jitCandidate": jit_candidate,
        "selectedMode": selected_mode,
        "fallback": fallback,
        "passed": passed,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Blink TSO conformance failed closed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
