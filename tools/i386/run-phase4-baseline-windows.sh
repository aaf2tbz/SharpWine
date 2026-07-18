#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run the i386 Phase 4 baseline fixture under the native Windows 11 ARM64 VM
# (guest WoW64) via prlctl exec.  This is the NO-ROSETTA exact-byte baseline
# lane for tools/i386/phase4_differential.py; it prints the worker record on
# stdout and propagates the guest exit code.
#
# The Parallels shared folders on this host do not cover the build tree, so
# the fixture is staged into the guest on first use (and whenever its sha256
# changes) by pushing base64 chunks through the exec channel.  Staging state
# lives under $MSWR_PHASE4_WINDOWS_GUEST_DIR and is refreshed automatically;
# nothing else in the guest is touched.
set -eu

usage() {
    echo "usage: $0 --fixture EXE --shard N --case N [--lane N]" >&2
    exit 2
}

vm=${MSWR_PHASE4_WINDOWS_VM:-Windows 11}
guest_dir=${MSWR_PHASE4_WINDOWS_GUEST_DIR:-'C:\sharpwine-phase4'}
fixture=
shard=
case_number=
lane=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --fixture) fixture=$2; shift 2 ;;
        --shard) shard=$2; shift 2 ;;
        --case) case_number=$2; shift 2 ;;
        --lane) lane=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$fixture" ] && [ -n "$shard" ] && [ -n "$case_number" ] || usage
[ -f "$fixture" ] || usage
: "$lane" # the VM lane is a single shared session; lanes need no isolation

base=$(basename -- "$fixture")
local_sha=$(shasum -a 256 "$fixture" | awk '{print $1}')
stamp="$guest_dir\\$base.sha256"
# The guest type/echo round-trip leaves a carriage return on the stamp;
# strip it or every call would restage.
guest_sha=$(prlctl exec "$vm" cmd.exe /c "type \"$stamp\"" 2>/dev/null | tr -d '\r' || true)

if [ "$guest_sha" != "$local_sha" ]; then
    lock=${TMPDIR:-/tmp}/phase4-windows-stage.lock
    while ! mkdir "$lock" 2>/dev/null; do sleep 1; done
    trap 'rmdir "$lock" 2>/dev/null || true' EXIT INT TERM
    guest_sha=$(prlctl exec "$vm" cmd.exe /c "type \"$stamp\"" 2>/dev/null | tr -d '\r' || true)
    if [ "$guest_sha" != "$local_sha" ]; then
        work=$(mktemp -d "${TMPDIR:-/tmp}/phase4-windows-stage.XXXXXX")
        trap 'rm -rf "$work"; rmdir "$lock" 2>/dev/null || true' EXIT INT TERM
        base64 -i "$fixture" | tr -d '\n' >"$work/fixture.b64"
        (cd "$work" && split -b 2000 fixture.b64 chunk-)
        prlctl exec "$vm" cmd.exe /c "mkdir $guest_dir 2>nul & del $guest_dir\\$base.b64 $guest_dir\\$base 2>nul" >/dev/null
        for chunk in "$work"/chunk-*; do
            data=$(cat "$chunk")
            prlctl exec "$vm" cmd.exe /c "echo $data>> $guest_dir\\$base.b64" >/dev/null
        done
        prlctl exec "$vm" cmd.exe /c "certutil -decode $guest_dir\\$base.b64 $guest_dir\\$base >nul & del $guest_dir\\$base.b64" >/dev/null
        prlctl exec "$vm" cmd.exe /c "echo $local_sha> \"$stamp\"" >/dev/null
    fi
    rm -rf "${work:-}" 2>/dev/null || true
    rmdir "$lock" 2>/dev/null || true
    trap - EXIT INT TERM
fi

exec prlctl exec "$vm" cmd.exe /c "$guest_dir\\$base $shard $case_number"
