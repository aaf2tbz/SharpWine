#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build two clean foundations and emit only a byte-reproducible accepted archive.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
commit=
output=
bundle=
llvm_mingw=${LLVM_MINGW:-}
deps=${MSWR_DEPS_ROOT:-}
jobs=${MSWR_JOBS:-$(sysctl -n hw.ncpu)}
repository=${GITHUB_REPOSITORY:-aaf2tbz/SharpWine}

usage() {
    echo "usage: $0 --commit SHA --output DIR --arm64x-bundle DIR --llvm-mingw DIR --deps DIR [--jobs N]" >&2
    exit 2
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --commit) commit=${2:-}; shift 2 ;;
        --output) output=${2:-}; shift 2 ;;
        --arm64x-bundle) bundle=${2:-}; shift 2 ;;
        --llvm-mingw) llvm_mingw=${2:-}; shift 2 ;;
        --deps) deps=${2:-}; shift 2 ;;
        --jobs) jobs=${2:-}; shift 2 ;;
        --repository) repository=${2:-}; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$commit" =~ ^[0-9a-f]{40}$ && -n "$output" && -n "$bundle" && -n "$llvm_mingw" && -n "$deps" ]] || usage
[[ "$(git -C "$root" rev-parse HEAD)" == "$commit" ]] || { echo "candidate commit mismatch" >&2; exit 1; }
[[ -z "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "candidate checkout must be clean" >&2; exit 1;
}
[[ ! -e "$output" ]] || { echo "candidate output must initially be absent" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" show -s --format=%ct "$commit")}
work=$(mktemp -d "${TMPDIR:-/tmp}/mswr-v0.1-candidate.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

# Re-run the supported Apple Clang sanitizer matrix against the pinned engines.
sanitizer="$work/sanitizer"
cmake -S "$root" -B "$sanitizer" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
    -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' \
    -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address,undefined' \
    -DMSWR_ENABLE_ARM64EC_ENGINE=ON -DMSWR_ENABLE_X64_ENGINE=ON \
    -DMSWR_ENABLE_I386_ENGINE=ON \
    -DMSWR_ENGINE_CONFORMANCE=ON -DMSWR_X64_ENGINE_CONFORMANCE=ON \
    -DMSWR_I386_ENGINE_CONFORMANCE=ON \
    -DMSWR_BUILD_WINE_BRIDGE=ON -DMSWR_WINE_BRIDGE_CONFORMANCE=ON \
    -DMSWR_WARNINGS_AS_ERRORS=ON -DBUILD_TESTING=ON
cmake --build "$sanitizer" --parallel "$jobs"
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    ctest --test-dir "$sanitizer" --output-on-failure --timeout 900

# Apple's heap inspector cannot inspect an AddressSanitizer allocator. Build the
# same assertion-enabled conformance target without an allocator replacement for
# the independent native leaks gate.
leakcheck="$work/leakcheck"
cmake -S "$root" -B "$leakcheck" -DCMAKE_BUILD_TYPE=Debug \
    -DMSWR_ENABLE_X64_ENGINE=ON -DMSWR_X64_ENGINE_CONFORMANCE=ON \
    -DMSWR_ENABLE_I386_ENGINE=ON -DMSWR_I386_ENGINE_CONFORMANCE=ON \
    -DMSWR_WARNINGS_AS_ERRORS=ON -DBUILD_TESTING=ON
cmake --build "$leakcheck" --target x64_engine_conformance i386_engine_conformance --parallel "$jobs"
/usr/bin/leaks --atExit -- "$leakcheck/x64_engine_conformance" 2>&1 | tee "$work/apple-x64-leaks.log"
grep -F '0 leaks for 0 total leaked bytes' "$work/apple-x64-leaks.log" >/dev/null
/usr/bin/leaks --atExit -- "$leakcheck/i386_engine_conformance" 2>&1 | tee "$work/apple-i386-leaks.log"
grep -F '0 leaks for 0 total leaked bytes' "$work/apple-i386-leaks.log" >/dev/null

foundation_a="$work/foundation-a"
foundation_b="$work/foundation-b"
"$root/tools/release/build-integrated-wine.sh" --commit "$commit" --output "$foundation_a" \
    --llvm-mingw "$llvm_mingw" --deps "$deps" --jobs "$jobs"
"$root/tools/release/build-integrated-wine.sh" --commit "$commit" --output "$foundation_b" \
    --llvm-mingw "$llvm_mingw" --deps "$deps" --jobs "$jobs"

runtime_a="$work/runtime-a"
runtime_b="$work/runtime-b"
fixture="$work/x86-64-fixture"
python3 "$root/tools/ci/build-x86-64-exit-fixture.py" --toolchain "$llvm_mingw" \
    --output "$fixture" --commit "$commit"
python3 "$root/tools/release/stage-runtime.py" --foundation "$foundation_a" --output "$runtime_a" \
    --arm64x-bundle "$bundle" --fixture-commit "$commit" --llvm-mingw "$llvm_mingw" \
    --deps "$deps" --source-date-epoch "$SOURCE_DATE_EPOCH"
python3 "$root/tools/release/stage-runtime.py" --foundation "$foundation_b" --output "$runtime_b" \
    --arm64x-bundle "$bundle" --fixture-commit "$commit" --llvm-mingw "$llvm_mingw" \
    --deps "$deps" --source-date-epoch "$SOURCE_DATE_EPOCH"
python3 "$root/tools/release/audit-runtime.py" --root "$runtime_a" --inventory "$work/inventory-a.json" \
    --forbid-prefix "$root" --forbid-prefix "$foundation_a" --forbid-prefix "$foundation_b"
python3 "$root/tools/release/audit-runtime.py" --root "$runtime_b" --inventory "$work/inventory-b.json" \
    --forbid-prefix "$root" --forbid-prefix "$foundation_a" --forbid-prefix "$foundation_b"

python3 "$root/tools/release/test-packaged-runtime.py" --runtime "$runtime_a" \
    --evidence "$work/package-evidence" --x86-64-fixture "$fixture/x86_64_exit.exe" \
    --stress-iterations 8 --timeout 300
python3 - "$work/quality.json" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps(
    {"schema": 1, "passed": True, "asan": True, "ubsan": True, "appleLeaks": True},
    sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

assets_a="$work/assets-a"
assets_b="$work/assets-b"
python3 "$root/tools/release/create-release-assets.py" --runtime "$runtime_a" \
    --test-summary "$work/package-evidence/summary.json" \
    --foundation-manifest "$foundation_a/wine-build-manifest.json" \
    --quality-summary "$work/quality.json" --output "$assets_a" --repository "$repository" \
    --commit "$commit" --source-date-epoch "$SOURCE_DATE_EPOCH"
python3 "$root/tools/release/create-release-assets.py" --runtime "$runtime_b" \
    --test-summary "$work/package-evidence/summary.json" \
    --foundation-manifest "$foundation_b/wine-build-manifest.json" \
    --quality-summary "$work/quality.json" --output "$assets_b" --repository "$repository" \
    --commit "$commit" --source-date-epoch "$SOURCE_DATE_EPOCH"
archive=metalsharp-wine-v0.1.0-macos-arm64.tar.zst
cmp "$assets_a/$archive" "$assets_b/$archive"
cmp "$work/inventory-a.json" "$work/inventory-b.json"

# Re-extract the exact archive and execute it while repository and build roots
# are denied. This proves the tested object is the publication object.
post="$work/post-release-location"
mkdir -p "$post"
"$(brew --prefix zstd)/bin/zstd" -d --stdout "$assets_a/$archive" | tar -xf - -C "$post"
tester="$work/package-smoke.py"
install -m 755 "$root/tools/release/test-packaged-runtime.py" "$tester"
profile="$work/no-build-access.sb"
python3 - "$profile" "$root" "$foundation_a" "$foundation_b" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text("(version 1)\n(allow default)\n" + "".join(
    f'(deny file-read* (subpath "{value}"))\n' for value in sys.argv[2:]), encoding="utf-8")
PY
sandbox-exec -f "$profile" python3 "$tester" \
    --runtime "$post/metalsharp-wine-v0.1.0-macos-arm64" \
    --evidence "$work/post-release-evidence" --x86-64-fixture "$fixture/x86_64_exit.exe" \
    --stress-iterations 1 --timeout 300

mkdir -p "$output"
cp "$assets_a"/* "$output"/
python3 "$root/tools/release/validate-release-assets.py" --directory "$output" \
    --repository "$repository" --commit "$commit" --version 0.1.0
echo "Accepted byte-reproducible release candidate: $output"
