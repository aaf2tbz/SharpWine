#!/usr/bin/env python3
"""Bounded acceptance tests executed only through an unpacked release runtime."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import signal
import shutil
import subprocess
import tempfile
import threading
import time


def fail(message: str) -> None:
    raise SystemExit(f"packaged runtime test failed: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=pathlib.Path)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--stress-iterations", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    if args.stress_iterations < 1 or args.timeout < 30:
        fail("invalid stress or timeout bound")
    wine = runtime / "bin/wine"
    wineserver = runtime / "bin/wineserver"
    selftest = runtime / "share/metalsharp/selftest"
    for path in (wine, wineserver, selftest / "arm64x_fixture_host.exe",
                 selftest / "arm64x_fixture.dll"):
        if not path.exists():
            fail(f"missing packaged test input: {path.relative_to(runtime)}")
    args.evidence.mkdir(parents=True, exist_ok=True)
    prefix = pathlib.Path(tempfile.mkdtemp(prefix="mswr-v0.1-prefix-"))
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINE_GEM_LAUNCH_TRACE": "1",
                "LC_ALL": "C", "LANG": "C"})
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libproc.proc_pidpath.restype = ctypes.c_int
    observed: dict[str, str] = {}
    translated: list[str] = []
    sampler_stop = threading.Event()
    active_roots: set[int] = set()
    roots_lock = threading.Lock()

    def sample() -> None:
        while not sampler_stop.is_set():
            result = subprocess.run(["ps", "-axo", "pid=,ppid=,command="], text=True,
                                    stdout=subprocess.PIPE, check=False)
            rows = []
            for line in result.stdout.splitlines():
                fields = line.strip().split(None, 2)
                if len(fields) >= 2 and fields[0].isdigit() and fields[1].isdigit():
                    rows.append((int(fields[0]), int(fields[1]), fields[2] if len(fields) == 3 else ""))
            with roots_lock:
                selected = set(active_roots)
            changed = True
            while changed:
                changed = False
                for pid, ppid, _command in rows:
                    if ppid in selected and pid not in selected:
                        selected.add(pid)
                        changed = True
            for pid, _ppid, process_command in rows:
                buffer = ctypes.create_string_buffer(4096)
                if libproc.proc_pidpath(pid, buffer, len(buffer)) <= 0:
                    continue
                path = pathlib.Path(os.fsdecode(buffer.value))
                packaged = False
                try:
                    relative = path.resolve().relative_to(runtime)
                except (ValueError, OSError):
                    if pid not in selected:
                        continue
                    key = str(path) if str(path).startswith(("/System/", "/usr/", "/bin/", "/sbin/")) else path.name
                else:
                    packaged = True
                    key = relative.as_posix()
                if key not in observed:
                    kind = subprocess.run(["file", "-b", str(path)], text=True,
                                          stdout=subprocess.PIPE, check=False).stdout.strip()
                    observed[key] = kind
                    if "Mach-O" in kind and ("arm64" not in kind or
                                               (packaged and "x86_64" in kind)):
                        translated.append(f"{key}: {kind}")
                if "/usr/libexec/rosetta" in str(path) or "arch -x86_64" in process_command:
                    translated.append(f"pid={pid}: {path}: {process_command}")
            sampler_stop.wait(0.1)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    results: list[dict[str, object]] = []

    def run_test(name: str, command: list[str], expected: tuple[str, ...] = (),
                 timeout: int | None = None, trace_gem: bool = False) -> None:
        log = args.evidence / f"{name}.log"
        started = time.monotonic()
        timeout = args.timeout if timeout is None else min(args.timeout, timeout)
        run_env = env.copy()
        run_env["WINEDEBUG"] = "+gem,-all" if trace_gem else "-all"
        with log.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(command, cwd=selftest, env=run_env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            with roots_lock:
                active_roots.add(process.pid)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                fail(f"{name} exceeded {timeout} seconds")
            finally:
                with roots_lock:
                    active_roots.discard(process.pid)
        text = log.read_text(encoding="utf-8", errors="replace")
        if log.stat().st_size > 2 * 1024 * 1024:
            fail(f"{name} exceeded the 2 MiB log bound")
        missing = [marker for marker in expected if marker not in text]
        forbidden = [marker for marker in ("Unhandled EXC_BAD_ACCESS", "GEM execution failed",
                    "boot event wait timed out", "could not load", "status=c0000135",
                    "assertion failed", "Interpret should never be emitted") if marker in text]
        if returncode or missing or forbidden:
            fail(f"{name}: rc={returncode}, missing={missing}, forbidden={forbidden}; see {log}")
        results.append({"name": name, "passed": True, "bounded": True,
                        "durationSeconds": round(time.monotonic() - started, 3),
                        "timeoutSeconds": timeout,
                        "logSha256": __import__("hashlib").sha256(log.read_bytes()).hexdigest()})

    try:
        run_test("wineboot-init", [str(runtime / "bin/wineboot"), "--init"],
                 ("native ARM64 GEM launch image=",), timeout=60, trace_gem=True)
        run_test("arm64-gem-acceptance", [str(wine), "metalsharp-gem-acceptance.exe"],
                 ("metalsharp-gem-acceptance: passed", "boundary syscall"),
                 timeout=120, trace_gem=True)
        run_test("arm64-cmd-exit", [str(wine), "cmd.exe", "/c", "exit"],
                 ("native ARM64 GEM launch image=",), timeout=60)
        run_test("arm64ec-x64-hybrid", [str(wine), str(selftest / "arm64x_fixture_host.exe")],
                 ("ARM64X linked fixture native execution passed",), timeout=120)
        for index in range(args.stress_iterations):
            run_test(f"hybrid-stress-{index + 1:03d}",
                     [str(wine), str(selftest / "arm64x_fixture_host.exe")],
                     ("ARM64X linked fixture native execution passed",), timeout=120)
    finally:
        subprocess.run([str(wineserver), "-k"], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30, check=False)
        sampler_stop.set()
        sampler.join(timeout=5)
    if translated:
        fail("translated package process observed: " + "; ".join(translated))
    combined = "".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in sorted(args.evidence.glob("*.log")))
    for marker in ("boundary syscall", "boundary unix-call", "callback enter", "callback return"):
        if marker not in combined:
            fail(f"combined packaged evidence lacks {marker!r}")
    time.sleep(1)
    active = []
    for line in subprocess.run(["ps", "-axo", "command="], text=True,
                               stdout=subprocess.PIPE, check=False).stdout.splitlines():
        if str(runtime) in line and "test-packaged-runtime.py" not in line:
            active.append(line.strip())
    if active:
        fail(f"package processes survived teardown: {active}")
    shutil.rmtree(prefix)
    if prefix.exists():
        fail("fresh test prefix survived cleanup")
    summary = {"schema": 1, "passed": True, "freshPrefix": True,
               "stressIterations": args.stress_iterations, "timeoutSeconds": args.timeout,
               "logLimitBytes": 2 * 1024 * 1024, "tests": results,
               "processAudit": {"allNativeArm64": True, "translatedProcesses": [],
                                "executables": [{"path": key, "kind": observed[key]}
                                                for key in sorted(observed)]},
               "teardownClean": True}
    (args.evidence / "summary.json").write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("packaged Wine fresh-prefix, native ARM64, and authentic hybrid tests passed")


if __name__ == "__main__":
    main()
