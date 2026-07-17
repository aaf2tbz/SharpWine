#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

EXPECTED_RUNTIME_SHA256 = "aaff5d0f9123a09613fa65c07b2d87ef09bd606dc6f0610df8be76eba7c9c02f"
REQUIRED_ENTITLEMENTS = (
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.disable-library-validation",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def build(source_root, runtime, work):
    clang = Path("/opt/homebrew/opt/llvm/bin/clang")
    linker = Path("/opt/homebrew/bin/lld-link")
    if not clang.is_file() or not linker.is_file():
        raise SystemExit("Homebrew LLVM clang and lld-link are required")
    fixture = source_root / "tests/fixtures"
    objects = []
    for name in ("rosetta_i386_oracle.c", "rosetta_i386_oracle.s"):
        output = work / (name + ".obj")
        flags = ["-I", str(fixture)]
        if name.endswith(".c"):
            flags += ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O2"]
        command([str(clang), "-target", "i686-w64-windows-gnu", "-c", str(fixture / name),
                 *flags, "-o", str(output)])
        objects.append(output)
    executable = work / "rosetta-i386-oracle.exe"
    kernel32 = runtime / "lib/wine/i386-windows/libkernel32.a"
    command([
        str(linker), "/machine:x86", "/subsystem:console", "/entry:start", "/nodefaultlib", "/brepro",
        "/dynamicbase:no", "/nxcompat", "/safeseh:no", f"/out:{executable}",
        *(str(path) for path in objects), str(kernel32),
    ])
    return executable


def translated_probe():
    result = command(
        ["/usr/bin/arch", "-x86_64", "/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
        capture_output=True,
    )
    if result.stdout.strip() != "1":
        raise SystemExit("Rosetta 2 translated-process proof failed")
    return 1


def preflight_runtime(runtime):
    hosts = (
        runtime / "bin/wine",
        runtime / "bin/wineserver",
        runtime / "lib/wine/x86_64-unix/wine",
    )
    for host in hosts:
        signature = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", str(host)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if signature.returncode != 0:
            raise SystemExit(f"unsigned or invalid Wine host: {host}: {signature.stderr.strip()}")
        quarantine = subprocess.run(
            ["/usr/bin/xattr", "-p", "com.apple.quarantine", str(host)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if quarantine.returncode == 0:
            raise SystemExit(
                f"quarantined Wine host: {host}; run tools/rosetta/prepare-metalsharp-runtime.sh"
            )
        entitlements = subprocess.run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(host)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        entitlement_text = entitlements.stdout + entitlements.stderr
        missing = [name for name in REQUIRED_ENTITLEMENTS if name not in entitlement_text]
        if missing:
            raise SystemExit(f"Wine host lacks oracle entitlements: {host}: {', '.join(missing)}")


def run_oracle(runtime, executable, prefix, timeout):
    wine = runtime / "bin/wine"
    wineserver = runtime / "bin/wineserver"
    env = os.environ.copy()
    env.update({
        "WINEARCH": "win64",
        "WINEPREFIX": str(prefix),
        "WINEDEBUG": "-all",
        "WINEDLLOVERRIDES": "winemenubuilder.exe,winevulkan=d;mscoree,mshtml=",
        "MVK_CONFIG_LOG_LEVEL": "0",
    })
    process = subprocess.Popen(
        ["/usr/bin/arch", "-x86_64", str(wine), str(executable)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        raise SystemExit(f"Rosetta oracle timed out after {timeout}s: {stderr[-2000:]}")
    finally:
        try:
            subprocess.run(
                ["/usr/bin/arch", "-x86_64", str(wineserver), "-k"], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["/usr/bin/pkill", "-9", "-f", str(runtime)], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    if process.returncode != 0:
        raise SystemExit(f"Rosetta oracle exited {process.returncode}: {stderr[-2000:]}")
    records = []
    for line in stdout.splitlines():
        if line.startswith('{"schemaVersion"'):
            records.append(json.loads(line))
    if len(records) != 5:
        raise SystemExit(f"expected 5 oracle records, found {len(records)}: {stdout[-2000:]}")
    return records, stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--runtime-archive", type=Path)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    source_root = Path(__file__).resolve().parents[2]
    runtime = args.runtime.resolve()
    work = args.work.resolve()
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    if args.runtime_archive and sha256(args.runtime_archive) != EXPECTED_RUNTIME_SHA256:
        raise SystemExit("MetalSharp runtime archive hash mismatch")
    for relative in ("bin/wine", "bin/wineserver", "lib/wine/i386-windows/libkernel32.a"):
        if not (runtime / relative).is_file():
            raise SystemExit(f"runtime input missing: {relative}")
    preflight_runtime(runtime)
    translated = translated_probe()
    executable = build(source_root, runtime, work)
    started = time.monotonic()
    records, stderr = run_oracle(runtime, executable, work / "prefix", args.timeout)
    evidence = {
        "schemaVersion": 1,
        "oracle": "Apple Rosetta 2",
        "translated": translated,
        "runtimeArchiveSha256": EXPECTED_RUNTIME_SHA256,
        "fixtureSha256": sha256(executable),
        "elapsedMilliseconds": int((time.monotonic() - started) * 1000),
        "records": records,
        "stderr": stderr[-2000:],
    }
    output = work / "rosetta-i386-oracle.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
