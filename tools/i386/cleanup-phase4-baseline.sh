#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

[ "$#" -eq 3 ] || {
    echo "usage: $0 RUNTIME PREFIX_ROOT LANE" >&2
    exit 2
}
prefix_root=$(CDPATH= cd -- "$2" && pwd)
export WINEPREFIX="$prefix_root/lane-$3"
export WINEDEBUG=-all
"$1/bin/wineserver" -k >/dev/null 2>&1 || true
rmdir "$prefix_root/lane-$3/.phase4-server-ready" >/dev/null 2>&1 || true
