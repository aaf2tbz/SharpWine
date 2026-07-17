#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()
    source_root = Path(__file__).resolve().parents[2]
    fixture = source_root / "tests/fixtures"
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    executable = work / "rosetta-x64-oracle"
    subprocess.run([
        "/usr/bin/clang", "-arch", "x86_64", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", str(fixture), str(fixture / "rosetta_x64_oracle.c"),
        str(fixture / "rosetta_x64_oracle.s"), "-o", str(executable),
    ], check=True)
    started = time.monotonic()
    result = subprocess.run(
        ["/usr/bin/arch", "-x86_64", str(executable)], capture_output=True,
        text=True, timeout=args.timeout, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"direct Rosetta oracle exited {result.returncode}: {result.stderr}")
    records = [json.loads(line) for line in result.stdout.splitlines()
               if line.startswith('{"schemaVersion"')]
    if len(records) != 5:
        raise SystemExit(f"expected 5 direct records, found {len(records)}: {result.stdout}")
    evidence = {
        "schemaVersion": 1,
        "oracle": "Apple Rosetta 2 direct dynamic-code JIT",
        "translated": 1,
        "fixtureSha256": sha256(executable),
        "elapsedMilliseconds": int((time.monotonic() - started) * 1000),
        "records": records,
        "stderr": result.stderr,
    }
    output = work / "rosetta-x64-oracle.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
