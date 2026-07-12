#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
source_dir=${1:-}
[[ -n "$source_dir" ]] || { echo "usage: $0 CLEAN_WINE_SOURCE" >&2; exit 2; }
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || {
    echo "Wine source is not a Git worktree: $source_dir" >&2
    exit 1
}

python3 "$root/tools/release/validate-wine-patches.py" --root "$root"
base=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["components"]["wine"]["revision"])' \
    "$root/components.lock.json")
actual=$(git -C "$source_dir" rev-parse HEAD)
[[ "$actual" == "$base" ]] || {
    echo "Wine source revision mismatch: expected $base, got $actual" >&2
    exit 1
}
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "Wine source must be clean before patch application" >&2
    exit 1
}

applying=0
abort_am() {
    status=$?
    if ((applying)); then git -C "$source_dir" am --abort >/dev/null 2>&1 || true; fi
    exit "$status"
}
trap abort_am ERR INT TERM

while IFS= read -r patch; do
    [[ -n "$patch" ]] || continue
    applying=1
    if ! check_output=$(git -C "$source_dir" apply --check --verbose \
        "$root/third_party/patches/wine/$patch" 2>&1); then
        printf '%s\n' "$check_output" >&2
        exit 1
    fi
    if grep -Eiq \
        'Hunk #[0-9]+ succeeded at .*\(offset [0-9]+ lines?\)|with fuzz [0-9]+|falling back to 3-way' \
        <<< "$check_output"; then
        printf 'Wine patch application used an offset, fuzz, or three-way fallback: %s\n' "$patch" >&2
        printf '%s\n' "$check_output" >&2
        exit 1
    fi
    printf '%s\n' "$check_output"
    git -C "$source_dir" am --keep-cr --no-3way \
        "$root/third_party/patches/wine/$patch"
    applying=0
done < "$root/third_party/patches/wine/series"
trap - ERR INT TERM

[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || {
    echo "Wine source became dirty after patch application" >&2
    exit 1
}
printf 'Wine patch queue applied: %s -> %s\n' "$base" "$(git -C "$source_dir" rev-parse HEAD)"
