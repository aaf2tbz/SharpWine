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

for tool in git python3 make clang clang++ pkg-config bison flex file xcrun; do
    command -v "$tool" >/dev/null || { echo "missing required host tool: $tool" >&2; exit 1; }
done
[[ -d "$llvm_mingw/bin" ]] || { echo "invalid LLVM-MinGW root: $llvm_mingw" >&2; exit 1; }

for target in i686-w64-mingw32 x86_64-w64-mingw32 aarch64-w64-mingw32 arm64ec-w64-mingw32; do
    [[ -x "$llvm_mingw/bin/$target-clang" ]] || {
        echo "LLVM-MinGW is missing $target-clang" >&2; exit 1;
    }
done
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
for required in bison vulkan-headers vulkan-loader mesa sdl2-compat sdl3; do
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
for prefix in "$brew_opt/vulkan-headers" "$brew_opt/vulkan-loader" "$brew_opt/mesa" "$brew_opt/sdl2-compat" "$brew_opt/sdl3"; do
    [[ -d "$prefix/lib/pkgconfig" ]] && pkg_config_path+=("$prefix/lib/pkgconfig")
done
export PKG_CONFIG_PATH=$(IFS=:; echo "${pkg_config_path[*]}")
pkg-config --exists vulkan || { echo "pkg-config cannot resolve Vulkan" >&2; exit 1; }
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
prefix="$stage/wine"
configure=("$source_dir/configure" "--host=aarch64-apple-darwin"
    "--enable-archs=i386,x86_64,aarch64,arm64ec" "--with-mingw=xllvm-mingw" "--with-x"
    "--with-opengl" "--with-vulkan" "--with-sdl" "--prefix=$prefix"
    "BISON=$brew_opt/bison/bin/bison" "FLEX=$(command -v flex)"
    "i386_CC=$llvm_mingw/bin/i686-w64-mingw32-clang"
    "x86_64_CC=$llvm_mingw/bin/x86_64-w64-mingw32-clang"
    "aarch64_CC=$llvm_mingw/bin/aarch64-w64-mingw32-clang"
    "arm64ec_CC=$llvm_mingw/bin/arm64ec-w64-mingw32-clang"
    "CC=/usr/bin/clang" "CXX=/usr/bin/clang++"
    "CFLAGS=-O2 -g -arch arm64" "CXXFLAGS=-O2 -g -arch arm64"
    "LDFLAGS=-arch arm64 -L$brew_prefix/lib -framework OpenGL"
    "CPPFLAGS=-I$brew_prefix/include" "OPENGL_LIBS=-framework OpenGL" "OPENGL_CFLAGS=")
(
    cd "$build_dir"
    "${configure[@]}" 2>&1 | tee "$work/configure.log"
    make -j"$jobs" 2>&1 | tee "$work/build.log"
    make install 2>&1 | tee "$work/install.log"
)

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
cp -R "$prefix" "$output/wine"
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
stage = pathlib.Path(prefix).parent
def text(name): return (pathlib.Path(work) / name).read_text(encoding="utf-8", errors="replace").strip()
files = []
for path in sorted(p for p in stage.rglob("*") if p.is_file() or p.is_symlink()):
    record = {"path": path.relative_to(stage).as_posix(), "type": "symlink" if path.is_symlink() else "file",
              "mode": stat.S_IMODE(path.lstat().st_mode)}
    if path.is_symlink(): record["target"] = os.readlink(path)
    else: record.update({"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    files.append(record)
value = {"schema": 1, "kind": "wine-foundation", "repositoryCommit": repository_commit,
         "source": {"repository": wine["repository"], "revision": wine["revision"],
                     "patchedHead": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()},
         "wine": {"version": wine["version"], "configure": ["--host=aarch64-apple-darwin", "--enable-archs=i386,x86_64,aarch64,arm64ec", "--with-mingw=xllvm-mingw", "--with-x", "--with-opengl", "--with-vulkan", "--with-sdl"]},
         "dependencies": {"llvmMingw": str(llvm), "homebrewPrefix": str(brew), "externalRuntime": str(deps), "bison": "required", "vulkan": "headers+loader+MoltenVK", "opengl": "macOS framework", "egl": "pkg-config/mesa", "sdl2": "required", "sdl3": "recorded; Wine 11.12 consumes SDL2"},
         "toolchain": {"host": "aarch64-apple-darwin", "uname": text("uname.txt"), "clang": text("clang-version.txt"), "make": text("make-version.txt"), "sdk": text("sdk-version.txt")},
         "build": {"jobs": int(jobs), "installRoot": "<external-stage>/wine", "files": files, "fileAudit": text("macho-files.txt")}}
manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
echo "Clean Wine foundation staged outside repository: $prefix"
echo "Manifest: $output/wine-build-manifest.json"
