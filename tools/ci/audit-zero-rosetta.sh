#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

build_dir=${1:-build-engine}
[[ "$(uname -s)" == Darwin ]] || { echo "zero-Rosetta audit requires macOS" >&2; exit 1; }
[[ "$(uname -m)" == arm64 ]] || { echo "zero-Rosetta audit requires arm64" >&2; exit 1; }
[[ "$(sysctl -in sysctl.proc_translated 2>/dev/null || echo 0)" == 0 ]] || {
    echo "process is running under Rosetta" >&2; exit 1;
}
[[ -d "$build_dir" ]] || { echo "build directory not found: $build_dir" >&2; exit 1; }

visited=$(mktemp)
trap 'rm -f "$visited"' EXIT
check_macho() {
    local path=$1 description dependency
    grep -Fqx -- "$path" "$visited" && return
    printf '%s\n' "$path" >> "$visited"
    [[ -f "$path" ]] || { echo "resolved Mach-O dependency missing: $path" >&2; exit 1; }
    description=$(file -b "$path")
    [[ "$description" == *Mach-O* && "$description" == *arm64* && "$description" != *x86_64* ]] || {
        echo "non-arm64 Mach-O artifact: $path: $description" >&2; exit 1;
    }
    while IFS= read -r dependency; do
        dependency=${dependency#*[[:space:]]}
        dependency=${dependency%% (*}
        [[ "$dependency" == @* || "$dependency" == /usr/lib/* || "$dependency" == /System/Library/* ]] && continue
        check_macho "$dependency"
    done < <(otool -L "$path" | tail -n +2)
}

while IFS= read -r -d '' file_path; do
    description=$(file -b "$file_path")
    case "$description" in
        *Mach-O*) check_macho "$file_path" ;;
        *ar\ archive*)
            archs=$(lipo -archs "$file_path" 2>/dev/null || true)
            [[ -z "$archs" || "$archs" == arm64 ]] || {
                echo "non-arm64 static archive: $file_path: $archs" >&2; exit 1;
            }
            ;;
    esac
done < <(find "$build_dir" -type f \( -perm -111 -o -name '*.a' -o -name '*.dylib' \) -print0)

echo "zero-Rosetta audit passed for $build_dir"
