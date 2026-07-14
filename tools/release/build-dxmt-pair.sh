#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build and compare two clean DXMT i386-PE/ARM64-Unix pairs from pinned source.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lock="$root/components.lock.json"
wine_build=
output=
llvm_mingw=${LLVM_MINGW:-}
llvm15=${DXMT_LLVM15:-}
jobs=${MSWR_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 1)}

usage() {
    echo "usage: $0 --wine-build DIRECTORY --output DIRECTORY --llvm-mingw DIRECTORY [--llvm15 DIRECTORY] [--jobs N]" >&2
    exit 2
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wine-build) wine_build=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --llvm-mingw) llvm_mingw=${2:-}; shift 2 ;;
        --llvm15) llvm15=${2:-}; shift 2 ;;
        --jobs) jobs=${2:-}; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done
[[ -n "$wine_build" && -d "$wine_build" ]] || { echo "--wine-build is required" >&2; exit 2; }
[[ -n "$output" && "$output" != / ]] || { echo "--output is required" >&2; exit 2; }
[[ -n "$llvm_mingw" && -d "$llvm_mingw/bin" ]] || { echo "--llvm-mingw is required" >&2; exit 2; }
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "--jobs must be a positive integer" >&2; exit 2; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || {
    echo "DXMT paired builds require native macOS ARM64" >&2; exit 1;
}
translated=$(sysctl -in sysctl.proc_translated 2>/dev/null || echo 0)
[[ "$translated" == 0 ]] || { echo "DXMT paired builds may not run under Rosetta" >&2; exit 1; }
for tool in git python3 meson ninja file lipo nm otool xcodebuild xcrun; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
if [[ -z "$llvm15" ]] && command -v brew >/dev/null; then llvm15=$(brew --prefix llvm@15); fi
[[ -n "$llvm15" && -x "$llvm15/bin/llvm-dis" && -x "$llvm15/bin/llvm-as" ]] || {
    echo "LLVM 15 with llvm-dis and llvm-as is required" >&2; exit 1;
}
for tool in i686-w64-mingw32-gcc i686-w64-mingw32-g++ i686-w64-mingw32-ar \
    i686-w64-mingw32-strip i686-w64-mingw32-windres llvm-nm; do
    [[ -x "$llvm_mingw/bin/$tool" ]] || { echo "LLVM-MinGW is missing $tool" >&2; exit 1; }
done
for module in dlls/ntdll/ntdll.so dlls/winemac.drv/winemac.so; do
    [[ -f "$wine_build/$module" ]] || { echo "Wine build is missing native $module" >&2; exit 1; }
    file "$wine_build/$module" | grep -Eq 'Mach-O.*arm64' || {
        echo "Wine native module is not ARM64: $module" >&2; exit 1;
    }
done

python3 "$root/tools/release/validate-dxmt-patches.py" --root "$root"
readarray_compat() { while IFS= read -r line; do values+=("$line"); done; }
values=()
readarray_compat < <(python3 - "$lock" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
dxmt = data["components"]["dxmt"]
xcode = data["build_dependencies"]["xcode"]
print(dxmt["repository"])
print(dxmt["revision"])
print(xcode["version"])
print(xcode["build"])
print(xcode["sdk"])
print(xcode["metal"])
for module in dxmt["submodules"]:
    print(f'{module["path"]}\t{module["revision"]}')
PY
)
dxmt_repo=${values[0]}
dxmt_revision=${values[1]}
expected_xcode=${values[2]}
expected_xcode_build=${values[3]}
expected_sdk=${values[4]}
expected_metal=${values[5]}
submodule_records=("${values[@]:6}")
xcode_version=$(xcodebuild -version)
grep -Fx "Xcode $expected_xcode" <<< "$xcode_version" >/dev/null || {
    echo "Xcode version does not match components.lock.json" >&2; exit 1;
}
grep -Fx "Build version $expected_xcode_build" <<< "$xcode_version" >/dev/null || {
    echo "Xcode build does not match components.lock.json" >&2; exit 1;
}
[[ "$(xcrun --show-sdk-version)" == "$expected_sdk" ]] || {
    echo "Xcode SDK does not match components.lock.json" >&2; exit 1;
}
metal_version=$(xcrun metal --version 2>&1)
grep -F "Apple metal version $expected_metal " <<< "$metal_version" >/dev/null || {
    echo "Xcode Metal toolchain does not match components.lock.json" >&2; exit 1;
}

mkdir -p "$output"
[[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "output directory must be empty: $output" >&2; exit 1;
}
work=$(mktemp -d "${TMPDIR:-/tmp}/metalsharp-dxmt-pair.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

build_one() {
    local label=$1 source="$work/source-$1" build="$work/build-$1" stage="$work/stage-$1"
    git clone --filter=blob:none --no-checkout "$dxmt_repo" "$source"
    git -C "$source" checkout --detach --quiet "$dxmt_revision"
    git -C "$source" submodule update --init --recursive
    [[ "$(git -C "$source" rev-parse HEAD)" == "$dxmt_revision" ]] || exit 1
    for record in "${submodule_records[@]}"; do
        local path=${record%%$'\t'*} expected=${record#*$'\t'} actual
        actual=$(git -C "$source/$path" rev-parse HEAD)
        [[ "$actual" == "$expected" ]] || {
            echo "DXMT submodule mismatch: $path expected $expected, got $actual" >&2; exit 1;
        }
    done
    [[ -z "$(git -C "$source" status --porcelain=v1 --untracked-files=all)" ]] || {
        echo "fresh DXMT checkout is dirty" >&2; exit 1;
    }
    "$root/tools/release/apply-dxmt-patches.sh" "$source"
    PATH="$llvm_mingw/bin:$PATH" meson setup "$build" "$source" \
        --cross-file "$source/build-win32.txt" --buildtype release --strip \
        --prefix "$stage" -Denable_tests=false -Dwine_builtin_dll=true \
        -Dnative_llvm_path="$llvm15" -Dwine_build_path="$wine_build"
    ZERO_AR_DATE=1 PATH="$llvm_mingw/bin:$PATH" ninja -C "$build" -j "$jobs"
    ZERO_AR_DATE=1 PATH="$llvm_mingw/bin:$PATH" meson install -C "$build"
    mkdir -p "$work/pair-$label/i386-windows" "$work/pair-$label/aarch64-unix"
    for name in d3d10core.dll d3d11.dll dxgi.dll winemetal.dll; do
        install -m 644 "$stage/i386-windows/$name" "$work/pair-$label/i386-windows/$name"
    done
    install -m 755 "$stage/aarch64-unix/winemetal.so" \
        "$work/pair-$label/aarch64-unix/winemetal.so"
    python3 "$root/tools/release/validate-dxmt-pair.py" --root "$work/pair-$label" \
        --llvm-nm "$llvm_mingw/bin/llvm-nm" --forbid-prefix "$root" \
        --forbid-prefix "$source" --forbid-prefix "$build"
}

build_one a
build_one b
for relative in i386-windows/d3d10core.dll i386-windows/d3d11.dll \
    i386-windows/dxgi.dll i386-windows/winemetal.dll aarch64-unix/winemetal.so; do
    cmp "$work/pair-a/$relative" "$work/pair-b/$relative" || {
        echo "DXMT clean builds differ: $relative" >&2; exit 1;
    }
done
cp -R "$work/pair-a/." "$output/"
python3 "$root/tools/release/validate-dxmt-pair.py" --root "$output" \
    --llvm-nm "$llvm_mingw/bin/llvm-nm" --forbid-prefix "$root" \
    --forbid-prefix "$work" --manifest "$work/pair-manifest.json"
python3 - "$work/pair-manifest.json" "$output/dxmt-build-manifest.json" "$lock" \
    "$xcode_version" "$metal_version" "$(meson --version)" "$(ninja --version)" <<'PY'
import json, pathlib, subprocess, sys
source, destination, lock_path = map(pathlib.Path, sys.argv[1:4])
manifest = json.loads(source.read_text(encoding="utf-8"))
lock = json.loads(lock_path.read_text(encoding="utf-8"))
dxmt = lock["components"]["dxmt"]
manifest.update({
    "source": {
        "repository": dxmt["repository"], "revision": dxmt["revision"],
        "version": dxmt["version"], "submodules": dxmt["submodules"],
        "patches": dxmt["patches"],
    },
    "toolchain": {
        "xcode": sys.argv[4].replace("\n", " / "),
        "metal": sys.argv[5].splitlines()[0],
        "meson": sys.argv[6], "ninja": sys.argv[7],
    },
    "reproducibility": {
        "cleanBuilds": 2, "byteIdentical": True,
        "archiveTimestamps": "ZERO_AR_DATE=1", "linkLayout": "-Wl,-reproducible",
    },
})
destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
mkdir -p "$output/licenses"
install -m 644 "$work/source-a/LICENSE" "$output/licenses/MIT-DXMT.txt"
install -m 644 "$work/source-a/external/nvapi/License.txt" "$output/licenses/License-NVAPI.txt"
install -m 644 "$work/source-a/include/native/directx/COPYING.MinGW-w64.txt" \
    "$output/licenses/COPYING-MinGW-w64-DirectX-Headers.txt"
echo "Accepted byte-reproducible DXMT pair: $output"
