#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import json
from pathlib import Path
import subprocess

EXCEPTIONS = {"illegal-instruction": 0xC000001D, "integer-divide": 0xC0000094,
              "access-violation": 0xC0000005}


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-test", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    if evidence.get("schemaVersion") != 3 or evidence.get("caseCount") != 128:
        raise SystemExit("Phase 2 evidence schema/case count mismatch")
    failures = []
    for row in evidence["results"]:
        record = row.get("record")
        expected = EXCEPTIONS[row["expectedClass"]]
        if row.get("status") != "ok" or record is None:
            failures.append(f"{row['name']}: missing record")
        elif record.get("schemaVersion") != 3:
            failures.append(f"{row['name']}: record schema mismatch")
        elif number(record["exceptionCode"]) != expected:
            failures.append(f"{row['name']}: exception mismatch")
        elif number(record["retiredCount"]) != 0:
            failures.append(f"{row['name']}: fault retired an instruction")
        elif number(record["initialEip"]) != number(record["finalEip"]):
            failures.append(f"{row['name']}: EIP changed on fault")
        elif number(record["finalEip"]) != number(record["exceptionAddress"]):
            failures.append(f"{row['name']}: exception address/context mismatch")
        elif any(number(record[f"initial{name}"]) != number(record[f"final{name}"])
                 for name in ("Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp",
                              "Eflags")):
            failures.append(f"{row['name']}: architectural state changed on fault")
        elif row["expectedClass"] == "access-violation" and (
                number(record["beforeMemoryHash"]) != number(record["afterMemoryHash"])):
            failures.append(f"{row['name']}: partial write")
        elif row["expectedClass"] == "access-violation" and (
                number(record["parameterCount"]) != 2
                or number(record["accessType"]) != number(record["information0"])
                or number(record["faultAddress"]) != number(record["information1"])
                or number(record["faultAddress"]) == 0
                or number(record["gemMemoryError"]) != 7):
            failures.append(f"{row['name']}: access violation parameters mismatch")
    native = subprocess.run([str(args.native_test.resolve())], capture_output=True, text=True)
    if native.returncode != 0 or "110 deterministic scenarios, 220 interpreter/JIT comparisons passed" not in native.stdout:
        failures.append("native interpreter/JIT Phase 2 replay failed")
    result = {"schemaVersion": 1, "referenceCases": 128, "nativeScenarios": 110,
              "nativeComparisons": 220,
              "passed": not failures, "failures": failures, "nativeOutput": native.stdout.strip()}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    if failures:
        raise SystemExit("; ".join(failures))
    print("Phase 2 fault replay passed: 128 reference cases, 220 native comparisons")


if __name__ == "__main__":
    main()
