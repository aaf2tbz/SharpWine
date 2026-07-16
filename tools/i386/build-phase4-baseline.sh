#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

usage() {
    echo "usage: $0 --runtime DIR --output DIR [--clang PATH] [--lld-link PATH]" >&2
    exit 2
}

runtime=
output=
clang=${CLANG:-clang}
lld_link=${LLD_LINK:-lld-link}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime) runtime=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --clang) clang=$2; shift 2 ;;
        --lld-link) lld_link=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$runtime" ] && [ -n "$output" ] || usage
[ -f "$runtime/lib/wine/i386-windows/libkernel32.a" ] || usage
mkdir -p "$output"
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
common="-target i686-w64-windows-gnu -DI386_PHASE4_FREESTANDING=1 -ffreestanding -fno-builtin -fno-stack-protector -O2"
"$clang" $common -I"$root/include" -I"$root/tests/fixtures" \
    -c "$root/tests/fixtures/i386_phase4_generator.c" -o "$output/generator.o"
"$clang" $common -I"$root/include" -I"$root/tests/fixtures" \
    -c "$root/tests/fixtures/i386_phase4_baseline.c" -o "$output/baseline_c.o"
"$clang" -target i686-w64-windows-gnu -c \
    "$root/tests/fixtures/i386_phase4_baseline.s" -o "$output/baseline_s.o"
"$lld_link" /subsystem:console /entry:start /nodefaultlib /machine:x86 /safeseh:no \
    "/out:$output/i386-phase4-baseline.exe" "$output/baseline_c.o" \
    "$output/baseline_s.o" "$output/generator.o" \
    "$runtime/lib/wine/i386-windows/libkernel32.a"
shasum -a 256 "$output/i386-phase4-baseline.exe"
