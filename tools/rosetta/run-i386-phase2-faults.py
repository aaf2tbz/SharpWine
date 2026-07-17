#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CLANG = Path("/opt/homebrew/opt/llvm/bin/clang")
LINK = Path("/opt/homebrew/bin/lld-link")


def cases():
    result = []
    for index in range(32):
        result.append({"name": f"phase2_ud2_{index}", "code": bytes.fromhex("0f0b"),
                       "regs": (index, index + 1, index + 2, index + 3), "offset": 0,
                       "class": "illegal-instruction"})
    divide = ("f6f3", "f6fb", "66f7f3", "66f7fb", "f7f3", "f7fb")
    for index in range(48):
        result.append({"name": f"phase2_divide_{index}",
                       "code": bytes.fromhex(divide[index % len(divide)]),
                       "regs": (0x80000000 ^ index, 0, index, 0xffffffff if index & 1 else 0),
                       "offset": 0, "class": "integer-divide"})
    memory = ("8b06", "8906", "f30f6f06", "f30f7f06")
    for index in range(48):
        result.append({"name": f"phase2_page_fault_{index}",
                       "code": bytes.fromhex(memory[index % len(memory)]),
                       "regs": (0x12340000 | index, index, index * 3, index * 7),
                       "offset": index % 3 + 1 if index % 4 < 2 else index % 12 + 1,
                       "class": "access-violation"})
    assert len(result) == 128 and len({case["name"] for case in result}) == 128
    return result


def write_header(work, matrix):
    lines = []
    for index, item in enumerate(matrix):
        lines.append(f"static const u8 phase2_code_{index}[] = "
                     f"{{{','.join(f'0x{byte:02x}U' for byte in item['code'])}}};")
    lines += ["#define PHASE2_FAULT_CASE_COUNT 128U",
              "static const struct fault_case phase2_fault_cases[PHASE2_FAULT_CASE_COUNT] = {"]
    for index, item in enumerate(matrix):
        regs = ",".join(f"0x{value & 0xffffffff:08x}U" for value in item["regs"])
        lines.append(f'{{"{item["name"]}",phase2_code_{index},sizeof(phase2_code_{index}),'
                     f'{regs},{item["offset"]}U}},')
    lines.append("};")
    (work / "i386_phase2_fault_cases.h").write_text("\n".join(lines) + "\n")


def build(root, runtime, work, matrix):
    write_header(work, matrix)
    fixture = root / "tests/fixtures"
    objects = []
    for source in (fixture / "i386_phase2_faults.c", fixture / "rosetta_i386_matrix.s"):
        obj = work / f"{source.name}.obj"
        flags = ["-I", str(work)]
        if source.suffix == ".c":
            flags += ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O2"]
        subprocess.run([str(CLANG), "-target", "i686-w64-windows-gnu", "-c", str(source),
                        *flags, "-o", str(obj)], check=True)
        objects.append(obj)
    output = work / "i386-phase2-faults.exe"
    subprocess.run([str(LINK), "/machine:x86", "/subsystem:console", "/entry:start",
                    "/nodefaultlib", "/brepro", "/dynamicbase:no", "/nxcompat",
                    "/safeseh:no", f"/out:{output}", *(str(obj) for obj in objects),
                    str(runtime / "lib/wine/i386-windows/libkernel32.a")], check=True)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--case-timeout", type=float, default=8.0)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    matrix = cases()
    executable = build(root, args.runtime.resolve(), work, matrix)
    env = os.environ.copy()
    env.update({"WINEARCH": "win64", "WINEPREFIX": str(args.prefix.resolve()),
                "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "winedbg.exe,winemenubuilder.exe=d"})
    results = []
    started = time.monotonic()
    try:
        for index, item in enumerate(matrix):
            stdout_path = work / f"case-{index}.stdout"
            stderr_path = work / f"case-{index}.stderr"
            with stdout_path.open("w+") as stdout_file, stderr_path.open("w+") as stderr_file:
                process = subprocess.Popen(["/usr/bin/arch", "-x86_64",
                                            str(args.runtime.resolve() / "bin/wine"),
                                            str(executable), str(index)], env=env,
                                           stdout=stdout_file, stderr=stderr_file,
                                           text=True, start_new_session=True)
                try:
                    process.wait(timeout=args.case_timeout)
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout, stderr = stdout_file.read(), stderr_file.read()
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    results.append({"name": item["name"], "expectedClass": item["class"],
                                    "status": "timeout", "record": None})
                    continue
                records = [json.loads(line) for line in stdout.splitlines()
                           if line.startswith('{"schemaVersion"')]
                results.append({"name": item["name"], "expectedClass": item["class"],
                                "status": "ok" if process.returncode == 0 and len(records) == 1
                                else "failed", "record": records[0] if len(records) == 1 else None,
                                "exitCode": process.returncode, "stderr": stderr[-1000:]})
    finally:
        subprocess.run(["/usr/bin/arch", "-x86_64",
                        str(args.runtime.resolve() / "bin/wineserver"), "-k"],
                       env=env, timeout=10, check=False)
    evidence = {"schemaVersion": 3, "corpus": "i386-phase2-faults",
                "fixtureSha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "caseCount": len(matrix),
                "elapsedMilliseconds": int((time.monotonic() - started) * 1000),
                "results": results}
    output = work / "i386-phase2-fault-evidence.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
