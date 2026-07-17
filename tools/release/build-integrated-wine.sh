#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build Wine only from a fresh checkout of the locked revision.  All source,
# build, and install trees are temporary/external; none may be this repository.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lock="$root/components.lock.json"
output=
llvm_mingw=${LLVM_MINGW:-}
deps_root=${MSWR_DEPS_ROOT:-}
commit=
jobs=${MSWR_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}

usage() {
    echo "usage: $0 --commit REPOSITORY_SHA --output DIRECTORY --llvm-mingw DIRECTORY --deps DIRECTORY [--jobs N]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --commit) commit=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --llvm-mingw) llvm_mingw=${2:-}; shift 2 ;;
        --deps) deps_root=${2:-}; shift 2 ;;
        --jobs) jobs=${2:-}; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "--commit must be a full lowercase repository SHA" >&2; exit 2; }
[[ -n "$output" && "$output" != / ]] || { echo "--output must be a non-root directory" >&2; exit 2; }
[[ -n "$llvm_mingw" ]] || { echo "--llvm-mingw is required" >&2; exit 2; }
[[ -n "$deps_root" ]] || { echo "--deps is required" >&2; exit 2; }
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "--jobs must be a positive integer" >&2; exit 2; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || {
    echo "Wine foundation builds require a native macOS ARM64 host" >&2; exit 1;
}

for tool in git python3 cmake make clang clang++ pkg-config bison flex file nm otool xcrun; do
    command -v "$tool" >/dev/null || { echo "missing required host tool: $tool" >&2; exit 1; }
done
[[ -d "$llvm_mingw/bin" ]] || { echo "invalid LLVM-MinGW root: $llvm_mingw" >&2; exit 1; }

for target in i686-w64-mingw32 x86_64-w64-mingw32 aarch64-w64-mingw32 arm64ec-w64-mingw32; do
    [[ -x "$llvm_mingw/bin/$target-clang" ]] || {
        echo "LLVM-MinGW is missing $target-clang" >&2; exit 1;
    }
done
[[ -x "$llvm_mingw/bin/llvm-objdump" ]] || {
    echo "LLVM-MinGW is missing llvm-objdump" >&2; exit 1;
}
[[ -f "$llvm_mingw/LICENSE.TXT" ]] || { echo "LLVM-MinGW license is missing" >&2; exit 1; }
for tool in "$llvm_mingw/bin/clang" "$llvm_mingw/bin/lld"; do
    file "$tool" | grep -Eq 'Mach-O.*arm64' || {
        echo "LLVM-MinGW host tool is not native ARM64: $tool" >&2; exit 1;
    }
done

brew_prefix=${HOMEBREW_PREFIX:-}
if [[ -z "$brew_prefix" ]] && command -v brew >/dev/null; then brew_prefix=$(brew --prefix); fi
[[ -n "$brew_prefix" && -d "$brew_prefix" ]] || {
    echo "Homebrew prefix is required for the pinned native dependency set" >&2; exit 1;
}
brew_opt="$brew_prefix/opt"
for required in bison boost freetype libpng libx11 libxau libxcb libxdmcp llvm llvm@15 mesa \
    meson molten-vk ninja sdl2-compat sdl3 spirv-tools vulkan-headers vulkan-loader z3 zstd; do
    [[ -d "$brew_opt/$required" ]] || { echo "missing Homebrew dependency: $required" >&2; exit 1; }
    expected=$(python3 - "$lock" "$required" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["build_dependencies"]["homebrew"]["formulas"].get(sys.argv[2], ""))
PY
)
    actual=$(brew list --versions "$required" | awk '{print $2}')
    [[ "$actual" == "$expected" ]] || {
        echo "Homebrew $required is $actual; locked version is $expected" >&2; exit 1;
    }
done
[[ -d /System/Library/Frameworks/OpenGL.framework/Versions/A ]] || {
    echo "macOS OpenGL framework is missing" >&2; exit 1;
}
[[ -f "$deps_root/vulkan/libvulkan.dylib" && -f "$deps_root/moltenvk/libMoltenVK.dylib" ]] || {
    echo "--deps must contain the external Vulkan/MoltenVK runtime libraries" >&2; exit 1;
}
vulkan_hash=$(shasum -a 256 "$deps_root/vulkan/libvulkan.dylib" | awk '{print $1}')
moltenvk_hash=$(shasum -a 256 "$deps_root/moltenvk/libMoltenVK.dylib" | awk '{print $1}')
expected_vulkan_hash=$(python3 - "$lock" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["build_dependencies"]["external_runtime"]["vulkan_loader_sha256"])
PY
)
expected_moltenvk_hash=$(python3 - "$lock" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["build_dependencies"]["external_runtime"]["moltenvk_sha256"])
PY
)
[[ "$vulkan_hash" == "$expected_vulkan_hash" && "$moltenvk_hash" == "$expected_moltenvk_hash" ]] || {
    echo "external Vulkan runtime hash does not match components.lock.json" >&2; exit 1;
}

pkg_config_path=()
for prefix in "$brew_opt/freetype" "$brew_opt/vulkan-headers" "$brew_opt/vulkan-loader" "$brew_opt/mesa" "$brew_opt/sdl2-compat" "$brew_opt/sdl3"; do
    [[ -d "$prefix/lib/pkgconfig" ]] && pkg_config_path+=("$prefix/lib/pkgconfig")
done
export PKG_CONFIG_PATH=$(IFS=:; echo "${pkg_config_path[*]}")
pkg-config --exists vulkan || { echo "pkg-config cannot resolve Vulkan" >&2; exit 1; }
pkg-config --exists freetype2 || { echo "pkg-config cannot resolve FreeType" >&2; exit 1; }
pkg-config --exists egl || { echo "pkg-config cannot resolve EGL" >&2; exit 1; }
pkg-config --exists sdl2 || { echo "pkg-config cannot resolve SDL2" >&2; exit 1; }
pkg-config --exists sdl3 || { echo "pkg-config cannot resolve SDL3" >&2; exit 1; }
[[ -f "$brew_opt/vulkan-headers/include/vulkan/vulkan.h" ]] || {
    echo "Vulkan headers are missing" >&2; exit 1;
}
[[ -f "$brew_opt/vulkan-loader/lib/libvulkan.dylib" || -f "$brew_prefix/lib/libvulkan.dylib" ]] || {
    echo "Vulkan loader library is missing" >&2; exit 1;
}

wine_repo=$(python3 - "$lock" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["components"]["wine"]["repository"])
PY
)
wine_revision=$(python3 - "$lock" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["components"]["wine"]["revision"])
PY
)
mkdir -p "$output"
[[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "output directory must be empty: $output" >&2; exit 1;
}
work=$(mktemp -d "${TMPDIR:-/tmp}/metalsharp-wine-foundation.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
source_dir="$work/wine"
build_dir="$work/build"
stage="$work/stage"
prefix="$stage"
gem_build="$work/gem-build"
gem_prefix="$work/gem-prefix"
[[ "$(git -C "$root" rev-parse HEAD)" == "$commit" ]] || {
    echo "repository commit mismatch: expected $commit" >&2; exit 1;
}
[[ -z "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "repository must be clean before the integrated Wine build" >&2; exit 1;
}
export MACOSX_DEPLOYMENT_TARGET=15.0
cmake -S "$root" -B "$gem_build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
    -DCMAKE_INSTALL_PREFIX="$gem_prefix" \
    -DMSWR_ENABLE_ARM64EC_ENGINE=ON -DMSWR_ENABLE_X64_ENGINE=ON \
    -DMSWR_ENABLE_I386_ENGINE=ON \
    -DMSWR_BUILD_WINE_BRIDGE=ON \
    -DMSWR_WARNINGS_AS_ERRORS=ON
cmake --build "$gem_build" --parallel "$jobs" --target metalsharp_gem_wine
cmake --install "$gem_build" --component metalsharp-gem-wine
bridge="$gem_prefix/lib/libmetalsharp-gem-wine.0.dylib"
[[ -f "$bridge" && -L "$bridge" ]] || { echo "versioned GEM bridge is missing" >&2; exit 1; }
file "$bridge" | grep -Eq 'Mach-O.*arm64' || { echo "GEM bridge is not ARM64 Mach-O" >&2; exit 1; }
file "$bridge" | grep -qv x86_64 || { echo "GEM bridge contains x86_64" >&2; exit 1; }
otool -D "$bridge" | grep -Fx '@rpath/libmetalsharp-gem-wine.0.dylib' >/dev/null || {
    echo "GEM bridge install name is not relocatable" >&2; exit 1;
}
git clone --filter=blob:none --no-checkout "$wine_repo" "$source_dir"
git -C "$source_dir" checkout --detach --quiet "$wine_revision"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$wine_revision" ]] || exit 1
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "fresh Wine checkout is dirty" >&2; exit 1;
}
"$root/tools/release/apply-wine-patches.sh" "$source_dir"
mkdir -p "$build_dir" "$stage"

export PATH="$llvm_mingw/bin:$brew_opt/bison/bin:$PATH"
export i386_CC="$llvm_mingw/bin/i686-w64-mingw32-clang"
export x86_64_CC="$llvm_mingw/bin/x86_64-w64-mingw32-clang"
export aarch64_CC="$llvm_mingw/bin/aarch64-w64-mingw32-clang"
export arm64ec_CC="$llvm_mingw/bin/arm64ec-w64-mingw32-clang"
configure=("$source_dir/configure" "--host=aarch64-apple-darwin"
    "--enable-archs=i386,x86_64,aarch64,arm64ec" "--with-mingw=xllvm-mingw" "--without-x"
    "--with-opengl" "--with-vulkan" "--with-sdl" "--with-metalsharp-gem=$gem_prefix"
    "--without-dbus" "--without-ffmpeg" "--without-fontconfig" "--without-gettext"
    "--without-gphoto" "--without-gnutls" "--without-gssapi" "--without-gstreamer"
    "--without-krb5" "--without-netapi" "--without-opencl" "--without-pcap"
    "--without-pcsclite" "--without-sane" "--without-usb" "--without-wayland"
    "--prefix=/"
    "BISON=$brew_opt/bison/bin/bison" "FLEX=$(command -v flex)"
    "i386_CC=$llvm_mingw/bin/i686-w64-mingw32-clang"
    "x86_64_CC=$llvm_mingw/bin/x86_64-w64-mingw32-clang"
    "aarch64_CC=$llvm_mingw/bin/aarch64-w64-mingw32-clang"
    "arm64ec_CC=$llvm_mingw/bin/arm64ec-w64-mingw32-clang"
    "CC=/usr/bin/clang" "CXX=/usr/bin/clang++"
    "CFLAGS=-O2 -g0 -arch arm64" "CXXFLAGS=-O2 -g0 -arch arm64"
    "LDFLAGS=-arch arm64 -L$brew_prefix/lib -framework OpenGL"
    "CPPFLAGS=-I$brew_prefix/include" "OPENGL_LIBS=-framework OpenGL" "OPENGL_CFLAGS=")
(
    cd "$build_dir"
    "${configure[@]}" 2>&1 | tee "$work/configure.log"
    make -j"$jobs" 2>&1 | tee "$work/build.log"
    make install DESTDIR="$stage" 2>&1 | tee "$work/install.log"
)

dxmt_output="$work/dxmt-pair"
"$root/tools/release/build-dxmt-pair.sh" --wine-build "$build_dir" \
    --output "$dxmt_output" --llvm-mingw "$llvm_mingw" \
    --llvm15 "$brew_opt/llvm@15" --jobs "$jobs"
for name in d3d10core.dll d3d11.dll dxgi.dll winemetal.dll; do
    install -m 644 "$dxmt_output/i386-windows/$name" "$prefix/lib/wine/i386-windows/$name"
done
install -m 755 "$dxmt_output/aarch64-unix/winemetal.so" \
    "$prefix/lib/wine/aarch64-unix/winemetal.so"

# The i386 ucrtbase delay imports are part of the WoW64 loader contract.  If
# advapi32 or user32 becomes an eager import, process attachment can recurse
# through secur32 into ucrtbase before its heap has been initialized.
i386_ucrt="$prefix/lib/wine/i386-windows/ucrtbase.dll"
i386_ucrt_imports="$work/i386-ucrt-imports.txt"
[[ -f "$i386_ucrt" ]] || { echo "staged i386 ucrtbase.dll is missing" >&2; exit 1; }
"$llvm_mingw/bin/llvm-objdump" -p "$i386_ucrt" | tee "$i386_ucrt_imports"
python3 - "$i386_ucrt_imports" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
imports = {name.lower() for name in re.findall(r"DLL Name:\s*([^\s]+)", text, re.I)}
required = {"kernel32.dll", "ntdll.dll"}
forbidden = {"advapi32.dll", "user32.dll"}
missing = sorted(required - imports)
eager = sorted(forbidden & imports)
if missing or eager:
    raise SystemExit(
        f"invalid i386 ucrtbase eager imports: missing={missing}, forbidden={eager}, "
        f"observed={sorted(imports)}"
    )
PY
cmake --install "$gem_build" --prefix "$prefix" --component metalsharp-gem-wine
runtime_dir="$prefix/lib/wine/aarch64-unix"
acceptance_exe="$prefix/lib/wine/aarch64-windows/metalsharp-gem-acceptance.exe"
i386_acceptance_exe="$prefix/lib/wine/i386-windows/sharpwine-i386-acceptance.exe"
"$llvm_mingw/bin/aarch64-w64-mingw32-clang" -O2 -Wall -Wextra -Werror \
    -Wl,--no-insert-timestamp -Wl,--subsystem,console \
    "$root/tests/fixtures/wine_arm64_gem_acceptance.c" -o "$acceptance_exe"
file "$acceptance_exe" | grep -Eq 'PE32\+ executable.*Aarch64' || {
    echo "native ARM64 GEM acceptance executable has the wrong architecture" >&2; exit 1;
}
"$llvm_mingw/bin/i686-w64-mingw32-clang" -O2 -msse2 -Wall -Wextra -Werror \
    -Wl,--no-insert-timestamp -Wl,--subsystem,console \
    "$root/tests/fixtures/wine_i386_gem_acceptance.c" -o "$i386_acceptance_exe"
file "$i386_acceptance_exe" | grep -Eq 'PE32 executable.*Intel 80386' || {
    echo "i386 GEM acceptance executable has the wrong architecture" >&2; exit 1;
}
install -m 755 "$deps_root/vulkan/libvulkan.dylib" "$runtime_dir/libvulkan.1.dylib"
ln -sfn libvulkan.1.dylib "$runtime_dir/libvulkan.dylib"
install -m 755 "$deps_root/moltenvk/libMoltenVK.dylib" "$runtime_dir/libMoltenVK.dylib"
install -m 755 "$brew_opt/mesa/lib/libEGL.1.dylib" "$runtime_dir/libEGL.1.dylib"
ln -sfn libEGL.1.dylib "$runtime_dir/libEGL.dylib"
install -m 755 "$brew_opt/freetype/lib/libfreetype.6.dylib" "$runtime_dir/libfreetype.6.dylib"
ln -sfn libfreetype.6.dylib "$runtime_dir/libfreetype.dylib"
install -m 755 "$brew_opt/sdl2-compat/lib/libSDL2-2.0.0.dylib" \
    "$runtime_dir/libSDL2-2.0.0.dylib"
ln -sfn libSDL2-2.0.0.dylib "$runtime_dir/libSDL2-2.0.dylib"
ln -sfn libSDL2-2.0.0.dylib "$runtime_dir/libSDL2.dylib"
install -m 755 "$brew_opt/sdl3/lib/libSDL3.0.dylib" "$runtime_dir/libSDL3.0.dylib"
ln -sfn libSDL3.0.dylib "$runtime_dir/libSDL3.dylib"
ntdll="$prefix/lib/wine/aarch64-unix/ntdll.so"
[[ -f "$ntdll" ]] || { echo "staged native ntdll.so is missing" >&2; exit 1; }
nm -gjU "$ntdll" | grep -Fx '___wine_main_gem' >/dev/null || {
    echo "ntdll.so lacks the native ARM64 GEM launch ABI" >&2; exit 1;
}
nm -gjU "$prefix/bin/wine" | grep -Fx '_wine_main_preload_info' >/dev/null || {
    echo "installed wrapper lacks the in-process loader marker" >&2; exit 1;
}
otool -L "$ntdll" | grep -F '@rpath/libmetalsharp-gem-wine.0.dylib' >/dev/null || {
    echo "ntdll.so lacks the direct versioned GEM dependency" >&2; exit 1;
}
otool -l "$ntdll" | grep -F '@loader_path/../..' >/dev/null || {
    echo "ntdll.so lacks the staged GEM runtime lookup path" >&2; exit 1;
}
probe_prefix="$work/probe-prefix"
probe_log="$work/gem-lifecycle-probe.log"
python3 - "$prefix" "$probe_prefix" "$probe_log" <<'PY'
import os, pathlib, subprocess, sys

prefix, wineprefix, log = map(pathlib.Path, sys.argv[1:])
wineprefix.mkdir()
env = os.environ.copy()
env.update({"METALSHARP_GEM_LIFECYCLE_PROBE": "1", "WINEDEBUG": "+gem",
            "WINEPREFIX": str(wineprefix)})
try:
    result = subprocess.run([str(prefix / "bin/wine"), "cmd.exe", "/c", "exit"],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=60, check=False)
except subprocess.TimeoutExpired as error:
    output = error.stdout or ""
    if isinstance(output, bytes): output = output.decode(errors="replace")
    log.write_text(output, encoding="utf-8")
    raise SystemExit("staged GEM lifecycle probe timed out")
finally:
    subprocess.run([str(prefix / "bin/wineserver"), "-k"], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
log.write_text(result.stdout, encoding="utf-8")
required = ("process created ABI=1", "thread created teb=", "KUSER bound host=",
            "lifecycle probe completed", "thread destroyed teb=", "process destroyed")
missing = [marker for marker in required if marker not in result.stdout]
if result.returncode or missing:
    print(result.stdout, file=sys.stderr, end="")
    raise SystemExit(f"staged GEM lifecycle probe failed: rc={result.returncode}, missing={missing}")
PY

acceptance_prefix="$work/acceptance-prefix"
acceptance_dir="$work/acceptance-evidence"
mkdir -p "$acceptance_dir"
cp "$i386_ucrt_imports" "$acceptance_dir/i386-ucrt-imports.txt"
cp "$dxmt_output/dxmt-build-manifest.json" "$acceptance_dir/dxmt-build-manifest.json"
python3 - "$prefix" "$acceptance_prefix" "$acceptance_dir" <<'PY'
import ctypes
import datetime
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time

prefix, wineprefix, evidence = map(pathlib.Path, sys.argv[1:])
wineprefix.mkdir()
env = os.environ.copy()
env.update({"WINE_GEM_LAUNCH_TRACE": "1", "WINEPREFIX": str(wineprefix)})
libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
libproc.proc_pidpath.restype = ctypes.c_int
descriptions = {}
audit_failure = []

def executable(pid):
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(pid, buffer, len(buffer))
    return pathlib.Path(os.fsdecode(buffer.value)) if length > 0 else None

def process_rows():
    output = subprocess.check_output(
        ["ps", "-axo", "pid=,ppid=,state=,etime=,command="], text=True,
        errors="replace")
    rows = []
    for line in output.splitlines():
        fields = line.strip().split(None, 4)
        if len(fields) == 5 and fields[0].isdigit() and fields[1].isdigit():
            rows.append((int(fields[0]), int(fields[1]), fields[2], fields[3], fields[4]))
    return rows

def sample(stop, root_pid, destination):
    with destination.open("w", encoding="utf-8") as stream:
        while not stop.is_set():
            rows = process_rows()
            selected = {root_pid}
            candidates = {
                pid for pid, _ppid, _state, _elapsed, command in rows
                if pid == root_pid or command.startswith(str(prefix)) or command.startswith("C:\\")
            }
            paths = {pid: executable(pid) for pid in candidates}
            for pid, path in tuple(paths.items()):
                if path:
                    try:
                        path.relative_to(prefix)
                    except ValueError:
                        pass
                    else:
                        selected.add(pid)
            changed = True
            while changed:
                changed = False
                for pid, ppid, _state, _elapsed, _command in rows:
                    if ppid in selected:
                        if pid not in selected:
                            selected.add(pid)
                            changed = True
            for pid in selected:
                paths.setdefault(pid, executable(pid))
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for pid, ppid, state, elapsed, command in rows:
                if pid not in selected:
                    continue
                path = paths[pid]
                description = "unresolved"
                if path and path.exists():
                    key = str(path)
                    if key not in descriptions:
                        descriptions[key] = subprocess.check_output(
                            ["file", "-b", key], text=True, errors="replace").strip()
                    description = descriptions[key]
                    if "Mach-O" in description and (
                            "arm64" not in description or "x86_64" in description):
                        audit_failure.append(f"pid={pid} path={path} file={description}")
                stream.write(
                    f"{stamp} pid={pid} ppid={ppid} state={state} elapsed={elapsed} "
                    f"path={path or 'unresolved'} file={description} command={command}\n")
            stream.flush()
            stop.wait(0.25)

def run(name, argv, timeout, trace_gem=False):
    log = evidence / f"{name}.log"
    tree = evidence / f"{name}-process-tree.log"
    run_env = env.copy()
    run_env["WINEDEBUG"] = "+gem,-all" if trace_gem else "-all"
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(argv, env=run_env, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True, text=True)
        stop = threading.Event()
        sampler = threading.Thread(target=sample, args=(stop, process.pid, tree), daemon=True)
        sampler.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise SystemExit(f"{name} timed out after {timeout} seconds")
        finally:
            stop.set()
            sampler.join(timeout=5)
    if log.stat().st_size > 2 * 1024 * 1024:
        raise SystemExit(f"{name} exceeded the 2 MiB log bound")
    if returncode:
        raise SystemExit(f"{name} failed with rc={returncode}; see {log}")
    return log

try:
    wineboot_log = run("wineboot", [str(prefix / "bin/wineboot"), "--init"], 60,
                       trace_gem=True)
    gem_acceptance_log = run(
        "gem-acceptance", [str(prefix / "bin/wine"), "metalsharp-gem-acceptance.exe"],
        120, trace_gem=True)
    i386_acceptance_log = run(
        "gem-i386-acceptance", [str(prefix / "bin/wine"),
                                 str(prefix / "lib/wine/i386-windows/sharpwine-i386-acceptance.exe")],
        180, trace_gem=True)
    cmd_log = run("cmd", [str(prefix / "bin/wine"), "cmd.exe", "/c", "exit"], 60)
finally:
    subprocess.run([str(prefix / "bin/wineserver"), "-k"], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                   timeout=30)

if audit_failure:
    raise SystemExit("translated or non-ARM64 process detected:\n" + "\n".join(audit_failure))
combined = wineboot_log.read_text(encoding="utf-8", errors="replace") + \
           gem_acceptance_log.read_text(encoding="utf-8", errors="replace") + \
           i386_acceptance_log.read_text(encoding="utf-8", errors="replace") + \
           cmd_log.read_text(encoding="utf-8", errors="replace")
marker = wineprefix / "drive_c/metalsharp-gem-i386-ok.txt"
expected_marker = b"METALSHARP_GEM_I386_OK\r\n"
if not marker.is_file() or marker.read_bytes() != expected_marker:
    raise SystemExit("authentic PE32 GEM acceptance marker is missing or invalid")
(evidence / "gem-i386-acceptance-marker.txt").write_bytes(marker.read_bytes())
resolved_prefix = prefix.resolve(strict=True)
required = ("gem_signal_run enter pc=", "boundary syscall", "boundary unix-call",
            "callback enter", "callback return",
            "metalsharp-gem-acceptance: access-violation=continued",
            "metalsharp-gem-acceptance: guard=consumed",
            "metalsharp-gem-acceptance: thread=create,suspend,resume,exit",
            "metalsharp-gem-acceptance: passed",
            f"wine: native ARM64 GEM launch image={resolved_prefix}/lib/wine/aarch64-windows/wineboot.exe",
            f"wine: native ARM64 GEM launch image={resolved_prefix}/lib/wine/aarch64-windows/metalsharp-gem-acceptance.exe",
            f"wine: native ARM64 GEM launch image={resolved_prefix}/lib/wine/aarch64-windows/cmd.exe")
missing = [marker for marker in required if marker not in combined]
forbidden = ("Unhandled EXC_BAD_ACCESS", "GEM execution failed", "boot event wait timed out",
             "could not load", "status=c0000135", "start.exe",
             "native ARM64 builtin launch ABI not found", "returned unexpectedly",
             "GEM thread destroy failed", "Interpret should never be emitted",
             "assertion failed")
found = [marker for marker in forbidden if marker in combined]
if missing or found:
    raise SystemExit(f"runtime evidence rejected: missing={missing}, forbidden={found}")
(evidence / "process-executables.txt").write_text(
    "".join(f"{path}\t{description}\n" for path, description in sorted(descriptions.items())),
    encoding="utf-8")
PY

find "$stage" \( -type f -o -type l \) | sort > "$work/install-files.txt"
find "$stage" -type f -print0 | xargs -0 file > "$work/macho-files.txt"
while IFS= read -r installed; do
    description=$(file -b "$installed")
    if [[ "$description" == *"Mach-O"* ]]; then
        [[ "$description" == *"arm64"* && "$description" != *"x86_64"* ]] || {
            echo "non-native Mach-O in staged Wine install: $installed ($description)" >&2; exit 1;
        }
    fi
done < <(find "$stage" -type f | sort)
"$root/tools/ci/audit-zero-rosetta.sh" "$stage" | tee "$work/zero-rosetta-audit.txt"
cp -R "$prefix" "$output/wine"
cp -R "$acceptance_dir" "$output/evidence"
mkdir -p "$output/licenses"
install -m 644 "$source_dir/COPYING.LIB" "$output/licenses/LGPL-2.1-or-later-Wine.txt"
install -m 644 "$gem_build/_deps/dynarmic-src/LICENSE.txt" "$output/licenses/ISC-Dynarmic.txt"
install -m 644 "$gem_build/_deps/blink_gem-src/LICENSE" "$output/licenses/ISC-Blink.txt"
install -m 644 "$gem_build/_deps/dynarmic-src/externals/mcl/LICENSE" "$output/licenses/MIT-mcl.txt"
install -m 644 "$gem_build/_deps/dynarmic-src/externals/fmt/LICENSE.rst" "$output/licenses/MIT-fmt.rst"
install -m 644 "$gem_build/_deps/dynarmic-src/externals/oaknut/LICENSE" "$output/licenses/MIT-oaknut.txt"
install -m 644 "$gem_build/_deps/dynarmic-src/externals/robin-map/LICENSE" "$output/licenses/MIT-robin-map.txt"
install -m 644 "$llvm_mingw/LICENSE.TXT" "$output/licenses/Apache-2.0-WITH-LLVM-exception-LLVM-MinGW.txt"
install -m 644 "$dxmt_output/licenses/MIT-DXMT.txt" "$output/licenses/MIT-DXMT.txt"
install -m 644 "$dxmt_output/licenses/License-NVAPI.txt" "$output/licenses/License-NVAPI.txt"
install -m 644 "$dxmt_output/licenses/COPYING-MinGW-w64-DirectX-Headers.txt" \
    "$output/licenses/COPYING-MinGW-w64-DirectX-Headers.txt"
install -m 644 "$brew_opt/boost/LICENSE_1_0.txt" "$output/licenses/BSL-1.0-Boost.txt"
clang --version > "$work/clang-version.txt"
make --version > "$work/make-version.txt"
xcrun --show-sdk-version > "$work/sdk-version.txt"
uname -a > "$work/uname.txt"
python3 - "$output/wine-build-manifest.json" "$lock" "$source_dir" "$prefix" "$work" "$jobs" "$llvm_mingw" "$brew_prefix" "$deps_root" "$commit" <<'PY'
import hashlib, json, os, pathlib, stat, subprocess, sys

manifest, lock_path, source, prefix, work = map(pathlib.Path, sys.argv[1:6])
jobs = sys.argv[6]
llvm, brew, deps = map(pathlib.Path, sys.argv[7:10])
repository_commit = sys.argv[10]
lock = json.loads(lock_path.read_text(encoding="utf-8")); wine = lock["components"]["wine"]
stage = pathlib.Path(prefix)
def text(name): return (pathlib.Path(work) / name).read_text(encoding="utf-8", errors="replace").strip()
files = []
for path in sorted(p for p in stage.rglob("*") if p.is_file() or p.is_symlink()):
    record = {"path": path.relative_to(stage).as_posix(), "type": "symlink" if path.is_symlink() else "file",
              "mode": stat.S_IMODE(path.lstat().st_mode)}
    if path.is_symlink(): record["target"] = os.readlink(path)
    else: record.update({"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    files.append(record)
evidence = pathlib.Path(work) / "acceptance-evidence"
evidence_files = {}
for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
    evidence_files[path.relative_to(evidence).as_posix()] = {
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
value = {"schema": 1, "kind": "wine-foundation", "repositoryCommit": repository_commit,
         "source": {"repository": wine["repository"], "revision": wine["revision"],
                     "patchedHead": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()},
         "wine": {"version": wine["version"], "configure": ["--host=aarch64-apple-darwin", "--enable-archs=i386,x86_64,aarch64,arm64ec", "--with-mingw=xllvm-mingw", "--without-x", "--with-opengl", "--with-vulkan", "--with-sdl", "--with-metalsharp-gem=<external-prefix>", "--prefix=/", "--without-dbus", "--without-ffmpeg", "--without-fontconfig", "--without-gettext", "--without-gphoto", "--without-gnutls", "--without-gssapi", "--without-gstreamer", "--without-krb5", "--without-netapi", "--without-opencl", "--without-pcap", "--without-pcsclite", "--without-sane", "--without-usb", "--without-wayland"]},
         "bridge": {"abi": 1, "dependency": "@rpath/libmetalsharp-gem-wine.0.dylib", "rpath": "@loader_path/../..", "linkage": "direct"},
         "dependencies": {"llvmMingw": str(llvm), "homebrewPrefix": str(brew), "externalRuntime": str(deps), "bison": "required", "freetype": "required+staged", "vulkan": "headers+loader+MoltenVK staged", "opengl": "macOS framework", "egl": "pkg-config/mesa+staged", "sdl2": "required+staged", "sdl3": "staged; Wine 11.12 consumes SDL2"},
         "toolchain": {"host": "aarch64-apple-darwin", "uname": text("uname.txt"), "clang": text("clang-version.txt"), "make": text("make-version.txt"), "sdk": text("sdk-version.txt")},
         "acceptance": {"lifecycleProbe": "passed before guest entry",
                        "nativeLaunchContract": "version 1; exact staged builtin PE selected in-process",
                        "winebootInit": "passed with a fresh prefix within 60 seconds",
                        "nativeArm64RuntimeProbe": "continued access violation; consumed guard; created, suspended, resumed, and cleanly terminated a guest thread",
                        "nativeArm64CmdExit": "passed within 60 seconds",
                        "processAudit": "all observed Mach-O executables are ARM64-only",
                        "evidence": evidence_files,
                        "lifecycleLog": text("gem-lifecycle-probe.log"),
                        "hostMachOClosure": text("zero-rosetta-audit.txt")},
         "build": {"jobs": int(jobs), "installRoot": "<DESTDIR>/", "files": files, "fileAudit": text("macho-files.txt")}}
manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
echo "Clean Wine foundation staged outside repository: $prefix"
echo "Manifest: $output/wine-build-manifest.json"
