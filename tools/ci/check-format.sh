#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/../.."
mapfile_compat() {
    while IFS= read -r line; do files+=("$line"); done
}
files=()
mapfile_compat < <(find include src tests -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' \) | sort)
((${#files[@]})) || { echo 'no C sources found' >&2; exit 1; }
formatter=${CLANG_FORMAT:-clang-format}
if ! command -v "$formatter" >/dev/null 2>&1 && [[ -x /opt/homebrew/opt/llvm/bin/clang-format ]]; then
    formatter=/opt/homebrew/opt/llvm/bin/clang-format
fi
command -v "$formatter" >/dev/null 2>&1 || { echo 'clang-format not found' >&2; exit 1; }
"$formatter" --dry-run --Werror "${files[@]}"
