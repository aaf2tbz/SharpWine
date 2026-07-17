#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

usage() {
    echo "usage: $0 --runtime DIR --prefix-root DIR --fixture EXE --lane N --shard N --case N" >&2
    exit 2
}

runtime=
prefix_root=
fixture=
lane=
shard=
case_number=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime) runtime=$2; shift 2 ;;
        --prefix-root) prefix_root=$2; shift 2 ;;
        --fixture) fixture=$2; shift 2 ;;
        --lane) lane=$2; shift 2 ;;
        --shard) shard=$2; shift 2 ;;
        --case) case_number=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$runtime" ] && [ -n "$prefix_root" ] && [ -n "$fixture" ] || usage
[ -n "$lane" ] && [ -n "$shard" ] && [ -n "$case_number" ] || usage
runtime=$(CDPATH= cd -- "$runtime" && pwd)
prefix_root=$(CDPATH= cd -- "$prefix_root" && pwd)
fixture_directory=$(CDPATH= cd -- "$(dirname -- "$fixture")" && pwd)
fixture="$fixture_directory/$(basename -- "$fixture")"
prefix="$prefix_root/lane-$lane"
[ -d "$prefix" ] && [ -x "$runtime/bin/wine" ] && [ -f "$fixture" ] || usage
export WINEPREFIX=$prefix
export WINEDEBUG=-all
if mkdir "$prefix/.phase4-server-ready" 2>/dev/null; then
    "$runtime/bin/wineserver" -p </dev/null >/dev/null 2>&1 &
fi
exec "$runtime/bin/wine" "$fixture" "$shard" "$case_number"
