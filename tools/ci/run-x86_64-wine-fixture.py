#!/usr/bin/env python3
"""Run one exact PE32+ fixture under a bounded Wine execution mode."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time


MARKER = "MSWR_X64_V1 "


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 Wine fixture failed: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wine", required=True, type=pathlib.Path)
    parser.add_argument("--wineserver", type=pathlib.Path)
    parser.add_argument("--fixture", required=True, type=pathlib.Path)
    parser.add_argument("--mode", required=True, choices=("intel-native", "jit", "interpreter"))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout < 10 or args.timeout > 300:
        fail("timeout is outside the accepted bound")
    host = platform.machine().lower()
    expected_host = "x86_64" if args.mode == "intel-native" else "arm64"
    if host != expected_host:
        fail(f"{args.mode} requires {expected_host}, observed {host}")
    prefix = pathlib.Path(tempfile.mkdtemp(prefix=f"mswr-x64-{args.mode}-"))
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix),
                "WINEDEBUG": "-all" if args.mode == "intel-native" else "+gem,-all",
                "WINEDLLOVERRIDES": "winemenubuilder.exe=d", "MVK_CONFIG_LOG_LEVEL": "0",
                "MSWR_X64_ENV": "oracle-value", "LC_ALL": "C", "LANG": "C"})
    if args.mode != "intel-native":
        env["METALSHARP_GEM_X64_ENGINE"] = args.mode
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as log:
        try:
            result = subprocess.run([str(args.wine.resolve()), str(args.fixture.resolve()),
                                     "mswr-argument"], env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=args.timeout, check=False)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if args.wineserver and args.wineserver.exists():
                subprocess.run([str(args.wineserver.resolve()), "-k"], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30, check=False)
            shutil.rmtree(prefix, ignore_errors=True)
        log.seek(0)
        raw_output = log.read(2 * 1024 * 1024 + 1)
    output = raw_output.decode(errors="replace")
    if len(raw_output) > 2 * 1024 * 1024:
        fail("execution exceeded the 2 MiB log bound")
    if timed_out:
        fail(f"execution timed out; partial output={output!r}")
    lines = [line for line in output.splitlines() if line.startswith(MARKER)]
    if result.returncode or len(lines) != 1:
        fail(f"rc={result.returncode}, semantic result count={len(lines)}\n{output}")
    semantic = json.loads(lines[0][len(MARKER):])
    if semantic.get("passed") is not True:
        fail(f"semantic fixture failure: {semantic}")
    required_trace = None if args.mode == "intel-native" else f"x64-engine={args.mode} host=aarch64"
    if required_trace and required_trace not in output:
        fail(f"selected engine was not evidenced: {required_trace}")
    evidence = {"schema": 1, "mode": args.mode, "hostArchitecture": host,
                "fixtureSha256": hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
                "returnCode": result.returncode, "durationSeconds": round(time.monotonic() - started, 3),
                "bounded": True, "engineTraceObserved": required_trace is None or required_trace in output,
                "semantic": semantic}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
