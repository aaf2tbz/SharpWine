#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Map SharpWine's i386 deterministic corpus onto Blink decoder handler ids
and join that map with a captured application handler-trace histogram.

The engine-backed mapping never hand-maintains a byte-to-handler table: every
unique instruction byte sequence found in the corpus is executed by
tools/i386/i386_handler_map_probe (the pinned Blink interpreter) and the
decoder-owned trace entries it retires become the handler ids that sequence
covers.

Corpus sources:
  * phase4: the raw-byte templates in tests/fixtures/i386_phase4_generator.c
    (template_id = category * 100 + index within its category array)
  * phase3: replay records in tests/fixtures/i386_phase3_reference.bin
  * rosetta: CASES in tools/rosetta/run-i386-matrix.py, assembled to bytes
    with the same clang + llvm-objcopy pipeline the matrix runner uses
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GENERATOR_VERSION = 1

PHASE4_CATEGORIES = {
    "scalar": 1,
    "memory": 2,
    "x87_mmx": 3,
    "simd": 4,
    "system": 5,
    "negative": 6,
}
PHASE3_RECORD_INSTRUCTION_OFFSET = 12
PHASE3_RECORD_INSTRUCTION_SIZE_OFFSET = 28
PHASE3_REFERENCE_MAGIC = 0x334D4547

CLANG = Path(os.environ.get("MSWR_I386_MATRIX_CLANG", "/opt/homebrew/opt/llvm/bin/clang"))
OBJCOPY = Path(
    os.environ.get("MSWR_I386_MATRIX_OBJCOPY", "/opt/homebrew/opt/llvm/bin/llvm-objcopy"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_phase4_templates(path: Path) -> list[dict]:
    """Comment/whitespace-tolerant parse of the template_entry arrays."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    templates = []
    for match in re.finditer(
            r"struct\s+template_entry\s+(\w+?)_templates\[\]\s*=\s*\{(.*?)\};", text,
            flags=re.DOTALL):
        category = PHASE4_CATEGORIES[match.group(1)]
        for index, row in enumerate(
                re.finditer(r"\{\{([^}]*)\}\s*,\s*(\d+)\s*,\s*(\d+)\s*,", match.group(2))):
            raw = [int(token, 16) for token in re.findall(r"0x([0-9a-fA-F]+)", row.group(1))]
            size = int(row.group(2))
            templates.append({
                "templateId": category * 100 + index,
                "bytes": bytes(raw[:size]),
                "negative": int(row.group(3)) != 0,
            })
    return templates


def parse_phase3_records(path: Path) -> list[dict]:
    data = path.read_bytes()
    magic, _schema, record_size, record_count = struct.unpack_from("<IIII", data, 0)
    if magic != PHASE3_REFERENCE_MAGIC:
        raise ValueError(f"{path}: bad phase3 reference magic 0x{magic:08x}")
    records = []
    for index in range(record_count):
        base = 16 + index * record_size
        case_id, category = struct.unpack_from("<II", data, base + 4)
        size = data[base + PHASE3_RECORD_INSTRUCTION_SIZE_OFFSET]
        start = base + PHASE3_RECORD_INSTRUCTION_OFFSET
        records.append({
            "caseId": case_id,
            "category": category,
            "bytes": data[start:start + size],
        })
    return records


def load_rosetta_module(root: Path):
    spec = importlib.util.spec_from_file_location(
        "run_i386_matrix", root / "tools/rosetta/run-i386-matrix.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_i386_matrix"] = module
    spec.loader.exec_module(module)
    return module


def assemble(asm: str, work: Path) -> bytes:
    source = work / "case.s"
    obj = work / "case.obj"
    raw = work / "case.bin"
    source.write_text(".text\n.globl _probe\n_probe:\n" + asm + "\n", encoding="utf-8")
    subprocess.run([str(CLANG), "-target", "i686-w64-windows-gnu", "-c", str(source),
                    "-o", str(obj)], check=True, capture_output=True)
    subprocess.run([str(OBJCOPY), "--dump-section", f".text={raw}", str(obj)], check=True,
                   capture_output=True)
    return raw.read_bytes()


def load_rosetta_cases(root: Path) -> list[dict]:
    module = load_rosetta_module(root)
    cases = []
    with tempfile.TemporaryDirectory(prefix="i386-map-asm-") as directory:
        work = Path(directory)
        for test in module.CASES:
            cases.append({"name": test["name"], "bytes": assemble(test["asm"], work)})
    return cases


def run_probe(probe: Path, code: bytes) -> list[tuple[int, str]]:
    """Handler (id, name) pairs for every instruction the sequence retires."""
    result = subprocess.run([str(probe), code.hex()], check=True, capture_output=True,
                            text=True)
    handlers = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "handler":
            handlers.append((int(fields[1]), fields[2]))
    return handlers


def parse_histogram(path: Path) -> dict[int, dict]:
    handlers: dict[int, dict] = {}
    summary = {"totalDrained": 0, "overflowEvents": 0, "outOfRange": 0}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[0] == "handler":
            handlers[int(fields[1])] = {"name": fields[2], "count": int(fields[3])}
        elif len(fields) == 2 and fields[0] == "total_drained":
            summary["totalDrained"] = int(fields[1])
        elif len(fields) == 2 and fields[0] == "overflow_events":
            summary["overflowEvents"] = int(fields[1])
        elif len(fields) == 2 and fields[0] == "out_of_range":
            summary["outOfRange"] = int(fields[1])
    return {"handlers": handlers, "summary": summary}


def map_corpus(probe: Path, sequences: list[dict]) -> dict[int, dict]:
    """Run every unique byte sequence through the engine once.

    sequences: [{"bytes": b, "source": {"kind": str, "id": str}}]
    Returns {handler_id: {"name": str, "corpus": {kind: [ids...]}}}."""
    by_bytes: dict[bytes, list[str]] = {}
    kinds: dict[str, str] = {}
    for entry in sequences:
        label = entry["source"]["id"]
        by_bytes.setdefault(entry["bytes"], []).append(label)
        kinds[label] = entry["source"]["kind"]
    mapped: dict[int, dict] = {}
    for code, labels in sorted(by_bytes.items()):
        for handler_id, name in run_probe(probe, code):
            slot = mapped.setdefault(handler_id, {"name": name, "corpus": {}})
            for label in labels:
                bucket = slot["corpus"].setdefault(kinds[label], [])
                if label not in bucket:
                    bucket.append(label)
    return mapped


def collect_sequences(root: Path, with_rosetta: bool) -> list[dict]:
    sequences = []
    for template in parse_phase4_templates(root / "tests/fixtures/i386_phase4_generator.c"):
        sequences.append({
            "bytes": template["bytes"],
            "source": {"kind": "phase4", "id": str(template["templateId"])},
        })
    for record in parse_phase3_records(root / "tests/fixtures/i386_phase3_reference.bin"):
        sequences.append({
            "bytes": record["bytes"],
            "source": {"kind": "phase3", "id": str(record["caseId"])},
        })
    if with_rosetta:
        for test in load_rosetta_cases(root):
            sequences.append({
                "bytes": test["bytes"],
                "source": {"kind": "rosetta", "id": test["name"]},
            })
    return sequences


def build_report(root: Path, aggregate_path: Path, run_paths: list[Path],
                 mapped: dict[int, dict]) -> dict:
    aggregate = parse_histogram(aggregate_path)
    runs = {path.stem: parse_histogram(path) for path in run_paths}
    handler_ids = sorted(set(aggregate["handlers"]) | set(mapped))
    entries = []
    for handler_id in handler_ids:
        traced = aggregate["handlers"].get(handler_id)
        covered = mapped.get(handler_id)
        traced_runs = sorted(name for name, run in runs.items()
                             if handler_id in run["handlers"])
        entries.append({
            "handlerId": handler_id,
            "name": (traced or covered)["name"],
            "tracedCount": traced["count"] if traced else 0,
            "tracedRuns": traced_runs,
            "corpusCoverage": {kind: sorted(ids)
                               for kind, ids in sorted(covered["corpus"].items())}
            if covered else {},
        })
    uncovered = sorted((entry for entry in entries if entry["tracedCount"] and
                        not entry["corpusCoverage"]),
                       key=lambda entry: (-entry["tracedCount"], entry["handlerId"]))
    hot = sorted((entry for entry in entries if entry["corpusCoverage"]),
                 key=lambda entry: (-entry["tracedCount"], entry["handlerId"]))
    return {
        "schemaVersion": 1,
        "generator": "tools/i386/map_handler_coverage.py",
        "generatorVersion": GENERATOR_VERSION,
        "inputSha256": {
            "aggregateHistogram": sha256_file(aggregate_path),
            "runHistograms": {path.stem: sha256_file(path) for path in run_paths},
            "phase4Generator": sha256_file(root / "tests/fixtures/i386_phase4_generator.c"),
            "phase3Records": sha256_file(root / "tests/fixtures/i386_phase3_records.h"),
            "phase3Reference": sha256_file(root / "tests/fixtures/i386_phase3_reference.bin"),
            "rosettaMatrix": sha256_file(root / "tools/rosetta/run-i386-matrix.py"),
        },
        "traceSummary": {
            "runs": {name: run["summary"] for name, run in sorted(runs.items())},
            "totalDrained": aggregate["summary"]["totalDrained"],
            "overflowEvents": aggregate["summary"]["overflowEvents"],
            "outOfRange": aggregate["summary"]["outOfRange"],
            "distinctHandlers": len(aggregate["handlers"]),
        },
        "totals": {
            "tracedHandlers": len(aggregate["handlers"]),
            "corpusCoveredHandlers": sum(1 for entry in entries if entry["corpusCoverage"]),
            "tracedUncoveredHandlers": len(uncovered),
            "corpusOnlyHandlers": sum(1 for entry in entries
                                      if entry["corpusCoverage"] and not entry["tracedCount"]),
        },
        "prioritized": {
            "uncoveredByTraceFrequency": [
                {"handlerId": entry["handlerId"], "name": entry["name"],
                 "tracedCount": entry["tracedCount"]} for entry in uncovered
            ],
            "coveredByTraceFrequency": [
                {"handlerId": entry["handlerId"], "name": entry["name"],
                 "tracedCount": entry["tracedCount"]} for entry in hot
            ],
        },
        "handlers": entries,
    }


def finalize(report: dict) -> dict:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["resultsSha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True,
                        help="built tools/i386/i386_handler_map_probe binary")
    parser.add_argument("--aggregate", type=Path, required=True,
                        help="merged application histogram (aggregate.out)")
    parser.add_argument("--runs", type=Path, nargs="*", default=[],
                        help="per-run histograms contributing to the aggregate")
    parser.add_argument("--no-rosetta", action="store_true",
                        help="skip assembling the rosetta matrix CASES")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = ROOT
    sequences = collect_sequences(root, not args.no_rosetta)
    mapped = map_corpus(args.probe, sequences)
    report = build_report(root, args.aggregate, args.runs, mapped)
    args.out.write_text(json.dumps(finalize(report), indent=1) + "\n", encoding="utf-8")
    totals = report["totals"]
    print(f"handlers: traced={totals['tracedHandlers']} "
          f"covered={totals['corpusCoveredHandlers']} "
          f"traced-uncovered={totals['tracedUncoveredHandlers']} "
          f"corpus-only={totals['corpusOnlyHandlers']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
