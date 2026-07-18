#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run isolated Phase 4 baseline/interpreter/JIT workers."""
from __future__ import annotations

import argparse
from collections import deque
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
from typing import Any

SCHEMA = 1
SHARDS = 16
CASES_PER_SHARD = 4096
# Prism's x87 state is not SDM-exact for 300/301.  The qualification VM also
# exposes no BMI1 to its i386 process: it rejects the VEX forms in 132-136 and
# decodes TZCNT (137) as legacy BSF.  Those cases retain the attempted Windows
# result as evidence, but acceptance is the explicit SDM expectation plus
# exact interpreter/JIT parity.
NON_AUTHORITATIVE_BASELINE_TEMPLATES = frozenset({132, 133, 134, 135, 136, 137, 300, 301})
BASELINE_UNAVAILABLE_TEMPLATES = frozenset({132, 133, 134, 135, 136})
CLASSIFICATIONS = {
    "pass",
    "semantic-mismatch",
    "unsupported-advertised",
    "jit-fallback",
    "timeout",
    "crash",
    "nonzero-exit",
    "malformed-record",
    "infrastructure-failure",
}


def render(command: str, shard: int, case: int, lane: int) -> list[str]:
    return shlex.split(command.format(shard=shard, case=case, lane=lane))


def run_worker(command: list[str], timeout: float, environment: dict[str, str] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    with tempfile.TemporaryFile(mode="w+") as stdout_file, tempfile.TemporaryFile(mode="w+") as stderr_file:
        process = subprocess.Popen(
            command,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            start_new_session=True,
            env=environment,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except PermissionError:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            return {"classification": "timeout", "exitCode": None, "stdout": "",
                    "stderr": "worker exceeded watchdog", "elapsedMilliseconds":
                    int((time.monotonic() - started) * 1000)}
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
    elapsed = int((time.monotonic() - started) * 1000)
    if process.returncode is None:
        classification = "infrastructure-failure"
    elif process.returncode < 0:
        classification = "crash"
    elif process.returncode != 0:
        classification = "nonzero-exit"
    else:
        classification = "pass"
    rows = []
    for line in stdout.splitlines():
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                classification = "malformed-record"
    if classification == "pass" and len(rows) != 1:
        classification = "malformed-record"
    return {"classification": classification, "exitCode": process.returncode,
            "record": rows[0] if len(rows) == 1 else None, "stdout": stdout[-1000:],
            "stderr": stderr[-1000:], "elapsedMilliseconds": elapsed}


def classify_triplet(baseline: dict[str, Any], interpreter: dict[str, Any],
                     jit: dict[str, Any]) -> str:
    for result in (interpreter, jit):
        if result["classification"] != "pass":
            return str(result["classification"])
    i_record = interpreter["record"]
    j_record = jit["record"]
    if not i_record or not j_record:
        return "malformed-record"
    if any(record.get("resultClassification") == "unsupported-advertised"
           for record in (i_record, j_record)):
        return "unsupported-advertised"
    if int(j_record.get("jitExecutions", 0)) == 0 and j_record.get("category") != "negative":
        return "jit-fallback"
    template_ids = {record.get("templateId") for record in (i_record, j_record)}
    if None in template_ids or len(template_ids) != 1:
        return "semantic-mismatch"
    template_id = int(template_ids.pop())
    engine_hashes = {i_record.get("compatibilityHash"), j_record.get("compatibilityHash")}
    if None in engine_hashes or len(engine_hashes) != 1:
        return "semantic-mismatch"
    if template_id in NON_AUTHORITATIVE_BASELINE_TEMPLATES:
        if baseline["classification"] != "pass" and not (
            template_id in BASELINE_UNAVAILABLE_TEMPLATES and
            baseline["classification"] == "nonzero-exit"
        ):
            return str(baseline["classification"])
        if i_record.get("sdmExpectation") is not True or j_record.get("sdmExpectation") is not True:
            return "semantic-mismatch"
        return "pass"
    if baseline["classification"] != "pass":
        return str(baseline["classification"])
    b_record = baseline["record"]
    if not b_record:
        return "malformed-record"
    if b_record.get("resultClassification") == "unsupported-advertised":
        return "unsupported-advertised"
    if b_record.get("templateId") != template_id:
        return "semantic-mismatch"
    if b_record.get("compatibilityHash") not in engine_hashes:
        return "semantic-mismatch"
    return "pass"


def comparison_metadata(baseline: dict[str, Any], interpreter: dict[str, Any],
                        jit: dict[str, Any]) -> dict[str, Any]:
    records = [result.get("record") for result in (baseline, interpreter, jit)]
    engine_records = [interpreter.get("record"), jit.get("record")]
    template_ids = {record.get("templateId") for record in engine_records if record}
    template_id = next(iter(template_ids)) if len(template_ids) == 1 else None
    authoritative = template_id not in NON_AUTHORITATIVE_BASELINE_TEMPLATES
    hashes = [record.get("compatibilityHash") if record else None for record in records]
    return {
        "baselineAuthoritative": authoritative,
        "baselineMatched": None not in hashes and len(set(hashes)) == 1,
        "comparisonPolicy": "three-way-exact" if authoritative else "interpreter-jit-sdm",
    }


def run_case(args: argparse.Namespace, shard: int, case: int) -> dict[str, Any]:
    lane = (shard * CASES_PER_SHARD + case) % 4
    environment = os.environ.copy()
    environment["MSWR_PHASE4_LANE"] = str(lane)
    if args.baseline_results:
        baseline = args.saved_baselines[(shard, case)]
    else:
        baseline = run_worker(render(args.baseline_command, shard, case, lane), args.timeout,
                              environment)
    interpreter = run_worker(
        [str(args.worker), "--shard", str(shard), "--case", str(case), "--mode",
         "interpreter", "--json"], args.timeout, environment)
    jit = run_worker(
        [str(args.worker), "--shard", str(shard), "--case", str(case), "--mode", "jit",
         "--json"], args.timeout, environment)
    classification = classify_triplet(baseline, interpreter, jit)
    return {"shard": shard, "case": case, "lane": lane, "classification": classification,
            **comparison_metadata(baseline, interpreter, jit), "baseline": baseline,
            "interpreter": interpreter, "jit": jit}


def cleanup(args: argparse.Namespace) -> None:
    if not args.cleanup_command:
        return
    for lane in range(4):
        command = render(args.cleanup_command, 0, 0, lane)
        try:
            subprocess.run(command, timeout=10, check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass


def prepare_baselines(args: argparse.Namespace) -> None:
    if args.baseline_results:
        return
    cleanup(args)
    for lane in range(4):
        result = run_worker(render(args.baseline_command, 0, lane, lane), 10.0)
        if result["classification"] != "pass":
            raise RuntimeError(f"baseline lane {lane} failed initialization: {result}")


def load_saved_baselines(path: Path, shards: list[int], cases: int) -> dict[tuple[int, int], dict[str, Any]]:
    selected = set(shards)
    baselines: dict[tuple[int, int], dict[str, Any]] = {}
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            row = json.loads(line)
            shard = row.get("shard")
            case = row.get("case")
            if shard not in selected or not isinstance(case, int) or not 0 <= case < cases:
                continue
            identity = (int(shard), case)
            baseline = row.get("baseline")
            interpreter_record = row.get("interpreter", {}).get("record")
            template_id = interpreter_record.get("templateId") if interpreter_record else None
            reusable = isinstance(baseline, dict) and (
                (baseline.get("classification") == "pass" and baseline.get("record")) or
                (row.get("baselineAuthoritative") is False and
                 row.get("comparisonPolicy") == "interpreter-jit-sdm" and
                 baseline.get("classification") == "nonzero-exit" and
                 template_id in BASELINE_UNAVAILABLE_TEMPLATES))
            if identity in baselines or not reusable:
                raise ValueError(f"invalid saved baseline at line {line_number}")
            baselines[identity] = baseline
    expected = len(shards) * cases
    if len(baselines) != expected:
        raise ValueError(f"expected {expected} saved baselines, found {len(baselines)}")
    return baselines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", required=True, type=Path)
    baseline_source = parser.add_mutually_exclusive_group(required=True)
    baseline_source.add_argument("--baseline-command",
                                 help="command template with {shard}, {case}, and optional {lane}")
    baseline_source.add_argument("--baseline-results", type=Path,
                                 help="completed prior results whose passing baseline records are reused")
    parser.add_argument("--cleanup-command", help="four-lane cleanup command template")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--shards", default="0", help="comma list, range A-B, or 'all'")
    parser.add_argument("--cases", type=int, default=CASES_PER_SHARD,
                        help="ordinals per shard to run (default: full shard)")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    if not args.worker.is_file() or args.jobs < 1 or args.timeout <= 0:
        parser.error("invalid worker, jobs, or timeout")
    if not 1 <= args.cases <= CASES_PER_SHARD:
        parser.error("invalid case bound")
    if args.shards == "all":
        shards = list(range(SHARDS))
    elif "-" in args.shards:
        first, last = (int(value) for value in args.shards.split("-", 1))
        shards = list(range(first, last + 1))
    else:
        shards = [int(value) for value in args.shards.split(",")]
    if not shards or min(shards) < 0 or max(shards) >= SHARDS:
        parser.error("invalid shard selection")
    if args.baseline_results:
        if not args.baseline_results.is_file():
            parser.error("saved baseline results do not exist")
        if (args.output / "phase4-results.jsonl").resolve() == args.baseline_results.resolve():
            parser.error("saved baseline input and replay output must differ")
        args.saved_baselines = load_saved_baselines(args.baseline_results, shards, args.cases)
    args.output.mkdir(parents=True, exist_ok=True)
    prepare_baselines(args)
    rows_path = args.output / "phase4-results.jsonl"
    started = time.monotonic()
    totals = {name: 0 for name in sorted(CLASSIFICATIONS)}
    policy_totals = {"authoritative": 0, "nonAuthoritative": 0,
                     "nonAuthoritativeMismatches": 0}
    try:
        with rows_path.open("w", encoding="utf-8") as output:
            identities = ((shard, case) for shard in shards for case in range(args.cases))
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
                pending: deque[concurrent.futures.Future[dict[str, Any]]] = deque()
                for _ in range(args.jobs * 4):
                    identity = next(identities, None)
                    if identity is None:
                        break
                    pending.append(executor.submit(run_case, args, *identity))
                while pending:
                    row = pending.popleft().result()
                    totals[row["classification"]] += 1
                    if row["baselineAuthoritative"]:
                        policy_totals["authoritative"] += 1
                    else:
                        policy_totals["nonAuthoritative"] += 1
                        if not row["baselineMatched"]:
                            policy_totals["nonAuthoritativeMismatches"] += 1
                    output.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                    identity = next(identities, None)
                    if identity is not None:
                        pending.append(executor.submit(run_case, args, *identity))
    finally:
        cleanup(args)
    digest = hashlib.sha256(rows_path.read_bytes()).hexdigest()
    cases = len(shards) * args.cases
    baseline_records = sum(
        1 for line in rows_path.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["baseline"]["classification"] == "pass"
    )
    summary = {"schemaVersion": SCHEMA, "generatorVersion": 2, "templateRevision": 1,
               "masterSeed": "0x534841525057494e", "shards": shards, "cases": cases,
               "baselineRecords": baseline_records,
               "nativeComparisons": policy_totals["authoritative"] * 2,
               "parityComparisons": cases, "comparisonPolicies": policy_totals,
               "totals": totals, "resultsSha256": digest,
               "elapsedMilliseconds": int((time.monotonic() - started) * 1000)}
    if args.baseline_results:
        summary["baselineSourceSha256"] = hashlib.sha256(args.baseline_results.read_bytes()).hexdigest()
    summary_path = args.output / "phase4-summary.json"
    summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(summary_path)
    return 0 if totals["pass"] == cases else 1


if __name__ == "__main__":
    raise SystemExit(main())
