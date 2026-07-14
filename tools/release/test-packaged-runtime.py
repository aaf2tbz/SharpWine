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


PREFIX_READY_FILES = (
    ".update-timestamp",
    "system.reg",
    "user.reg",
    "userdef.reg",
    "drive_c/windows/system32/kernel32.dll",
    "drive_c/windows/system32/ntdll.dll",
    "drive_c/windows/system32/services.exe",
)

RELEASE_OPERATION_TIMEOUT = 180


def fail(message: str) -> None:
    raise SystemExit(f"packaged runtime test failed: {message}")


def prefix_snapshot(prefix: pathlib.Path) -> tuple[list[str], dict[str, dict[str, int]]]:
    missing: list[str] = []
    snapshot: dict[str, dict[str, int]] = {}
    for relative in PREFIX_READY_FILES:
        path = prefix / relative
        try:
            stat = path.stat()
        except FileNotFoundError:
            missing.append(relative)
            continue
        if not path.is_file() or stat.st_size == 0:
            missing.append(relative)
            continue
        snapshot[relative] = {"size": stat.st_size, "mtimeNs": stat.st_mtime_ns}
    return missing, snapshot


def wait_for_prefix_ready(prefix: pathlib.Path, evidence: pathlib.Path, timeout: int) -> None:
    """Wait for wine.inf installation to finish, not merely wineboot's parent."""
    started = time.monotonic()
    deadline = started + timeout
    previous: dict[str, dict[str, int]] | None = None
    stable_since: float | None = None
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        missing, snapshot = prefix_snapshot(prefix)
        now = time.monotonic()
        if not missing and snapshot == previous:
            stable_since = now if stable_since is None else stable_since
        else:
            stable_since = None
        if len(observations) < 240:
            observations.append({"elapsedSeconds": round(now - started, 3),
                                 "missing": missing, "files": snapshot})
        if not missing and stable_since is not None and now - stable_since >= 5:
            (evidence / "wineboot-prefix-readiness.json").write_text(
                json.dumps({"ready": True, "requiredFiles": list(PREFIX_READY_FILES),
                            "durationSeconds": round(now - started, 3),
                            "observations": observations}, sort_keys=True,
                           separators=(",", ":")) + "\n", encoding="utf-8")
            return
        previous = snapshot
        time.sleep(0.5)
    missing, snapshot = prefix_snapshot(prefix)
    (evidence / "wineboot-prefix-readiness.json").write_text(
        json.dumps({"ready": False, "requiredFiles": list(PREFIX_READY_FILES),
                    "durationSeconds": round(time.monotonic() - started, 3),
                    "missing": missing, "files": snapshot, "observations": observations},
                   sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    fail(f"wineboot prefix did not become complete and stable within {timeout} seconds; "
         f"missing={missing}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=pathlib.Path)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--x86-64-fixture", type=pathlib.Path)
    parser.add_argument("--skip-retained-x86-64", action="store_true")
    parser.add_argument("--stress-iterations", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    x86_64_fixture = args.x86_64_fixture.resolve(strict=True) if args.x86_64_fixture else None
    if not args.skip_retained_x86_64 and x86_64_fixture is None:
        fail("the x86_64 fixture is required unless the v0.1.1 gate is retained")
    if args.stress_iterations < 1 or args.timeout < 30:
        fail("invalid stress or timeout bound")
    wine = runtime / "bin/wine"
    wineserver = runtime / "bin/wineserver"
    selftest = runtime / "share/metalsharp/selftest"
    i386_fixture = runtime / "lib/wine/i386-windows/sharpwine-i386-acceptance.exe"
    for path in (wine, wineserver, selftest / "arm64x_fixture_host.exe",
                 selftest / "arm64x_fixture.dll",
                 runtime / "lib/wine/x86_64-windows/cmd.exe", i386_fixture):
        if not path.exists():
            try:
                display = path.relative_to(runtime)
            except ValueError:
                display = path
            fail(f"missing packaged test input: {display}")
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
                 timeout: int | None = None, trace_gem: bool = False,
                 wine_debug: str | None = None) -> None:
        log = args.evidence / f"{name}.log"
        started = time.monotonic()
        timeout = args.timeout if timeout is None else min(args.timeout, timeout)
        run_env = env.copy()
        run_env["WINEDEBUG"] = (wine_debug if wine_debug is not None else
                                "+gem,-all" if trace_gem else "-all")
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
            tail = text[-16 * 1024:]
            fail(f"{name}: rc={returncode}, missing={missing}, forbidden={forbidden}; see {log}\n"
                 f"--- {name} log tail ---\n{tail}\n--- end log tail ---")
        results.append({"name": name, "passed": True, "bounded": True,
                        "durationSeconds": round(time.monotonic() - started, 3),
                        "timeoutSeconds": timeout,
                        "logSha256": __import__("hashlib").sha256(log.read_bytes()).hexdigest()})

    def quiesce_wineserver() -> None:
        stopped = subprocess.run([str(wineserver), "-k"], env=env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 timeout=min(args.timeout, RELEASE_OPERATION_TIMEOUT), check=False)
        waited = subprocess.run([str(wineserver), "-w"], env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=min(args.timeout, RELEASE_OPERATION_TIMEOUT), check=False)
        if stopped.returncode not in (0, 1) or waited.returncode:
            fail(f"wineboot server quiesce failed: kill={stopped.returncode}, "
                 f"wait={waited.returncode}")

    try:
        run_test("wineboot-init", [str(runtime / "bin/wineboot"), "--init"],
                 ("native ARM64 GEM launch image=",), timeout=RELEASE_OPERATION_TIMEOUT)
        wait_for_prefix_ready(prefix, args.evidence,
                              min(args.timeout, RELEASE_OPERATION_TIMEOUT))
        quiesce_wineserver()
        run_test("arm64-cmd-exit", [str(wine), "cmd.exe", "/c", "exit"],
                 ("native ARM64 GEM launch image=",), timeout=RELEASE_OPERATION_TIMEOUT)
        run_test("arm64-gem-acceptance", [str(wine), "metalsharp-gem-acceptance.exe"],
                 ("metalsharp-gem-acceptance: passed", "boundary syscall"),
                 timeout=RELEASE_OPERATION_TIMEOUT, trace_gem=True)
        quiesce_wineserver()
        run_test("arm64ec-x64-hybrid", [str(wine), str(selftest / "arm64x_fixture_host.exe")],
                 ("ARM64X linked fixture native execution passed",),
                 timeout=RELEASE_OPERATION_TIMEOUT, trace_gem=True)
        quiesce_wineserver()
        if not args.skip_retained_x86_64:
            run_test("x86_64-exception", [str(wine), str(x86_64_fixture)],
                     ("pure AMD64 routing enabled",), timeout=RELEASE_OPERATION_TIMEOUT,
                     wine_debug="-all,+gem,+module,+loaddll,+process,+seh")
            quiesce_wineserver()
            run_test("x86_64-cmd-exit",
                     [str(wine), str(runtime / "lib/wine/x86_64-windows/cmd.exe"),
                      "/d", "/c", "exit", "0"],
                     ("pure AMD64 routing enabled",), timeout=RELEASE_OPERATION_TIMEOUT,
                     trace_gem=True)
        quiesce_wineserver()
        run_test("i386-gem-acceptance", [str(wine), str(i386_fixture)],
                 timeout=RELEASE_OPERATION_TIMEOUT, trace_gem=True)
        marker = prefix / "drive_c/metalsharp-gem-i386-ok.txt"
        if not marker.is_file() or marker.read_bytes() != b"METALSHARP_GEM_I386_OK\r\n":
            fail("i386 GEM acceptance marker is missing or invalid")
        for index in range(args.stress_iterations):
            quiesce_wineserver()
            run_test(f"hybrid-stress-{index + 1:03d}",
                     [str(wine), str(selftest / "arm64x_fixture_host.exe")],
                     ("ARM64X linked fixture native execution passed",),
                     timeout=RELEASE_OPERATION_TIMEOUT)
    finally:
        subprocess.run([str(wineserver), "-k"], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       timeout=min(args.timeout, RELEASE_OPERATION_TIMEOUT), check=False)
        sampler_stop.set()
        sampler.join(timeout=5)
    if translated:
        fail("translated package process observed: " + "; ".join(translated))
    combined = "".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in sorted(args.evidence.glob("*.log")))
    for marker in ("boundary syscall", "boundary unix-call",
                   "metalsharp-gem-acceptance: access-violation=continued",
                   "metalsharp-gem-acceptance: guard=consumed",
                   "metalsharp-gem-acceptance: thread=create,suspend,resume,exit"):
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
               "retainedX86_64Foundation": args.skip_retained_x86_64,
               "stressIterations": args.stress_iterations, "timeoutSeconds": args.timeout,
               "logLimitBytes": 2 * 1024 * 1024, "tests": results,
               "processAudit": {"allNativeArm64": True, "translatedProcesses": [],
                                "executables": [{"path": key, "kind": observed[key]}
                                                for key in sorted(observed)]},
               "teardownClean": True}
    (args.evidence / "summary.json").write_text(
        json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    x86_status = "retained v0.1.1 x86_64" if args.skip_retained_x86_64 else "x86_64"
    print(f"packaged SharpWine AArch64, ARM64EC/x64, {x86_status}, and i386 gates passed")


if __name__ == "__main__":
    main()
