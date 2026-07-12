#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
build_dir=${MSWR_BUILD_DIR:-"$root/build/ci"}

python3 "$root/tools/ci/check-repository.py"
python3 "$root/tools/ci/test-check-repository.py"
python3 "$root/tools/release/validate-wine-patches.py"
python3 "$root/tools/release/test-wine-patches.py"
"$root/tools/ci/check-format.sh"
cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug -DMSWR_WARNINGS_AS_ERRORS=ON
cmake --build "$build_dir" --parallel
ctest --test-dir "$build_dir" --output-on-failure
