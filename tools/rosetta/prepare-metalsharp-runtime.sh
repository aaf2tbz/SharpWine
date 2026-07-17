#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

if test "$#" -lt 1 || test "$#" -gt 2; then
    echo "usage: $0 EXTRACTED_RUNTIME_ROOT [WRITABLE_METALSHARP_APP]" >&2
    exit 2
fi

runtime=$1
app=${2-}
entitlements=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/wine-oracle-entitlements.plist
list=$(mktemp -t metalsharp-macho.XXXXXX)
trap 'rm -f "$list"' EXIT HUP INT TERM

if test ! -d "$runtime/wine"; then
    echo "runtime root must contain wine/: $runtime" >&2
    exit 2
fi

if test -n "$app"; then
    if test ! -d "$app/Contents"; then
        echo "not a writable app bundle: $app" >&2
        exit 2
    fi
    /usr/bin/xattr -dr com.apple.quarantine "$app" 2>/dev/null || true
    /usr/bin/codesign --force --deep --sign - --timestamp=none "$app"
    /usr/bin/codesign --verify --deep --strict "$app"
fi

/usr/bin/xattr -dr com.apple.quarantine "$runtime" 2>/dev/null || true
: > "$list"
find "$runtime" -type f -print0 | while IFS= read -r -d '' file_path; do
    if /usr/bin/file -b "$file_path" | /usr/bin/grep -q 'Mach-O'; then
        echo "$file_path"
    fi
done > "$list"

while IFS= read -r file_path; do
    /usr/bin/codesign --force --sign - --timestamp=none "$file_path"
done < "$list"

while IFS= read -r file_path; do
    if /usr/bin/file -b "$file_path" | /usr/bin/grep -q 'Mach-O .* executable'; then
        /usr/bin/codesign --force --sign - --timestamp=none \
            --entitlements "$entitlements" "$file_path"
    fi
done < "$list"

while IFS= read -r file_path; do
    /usr/bin/codesign --verify --strict "$file_path"
    if /usr/bin/xattr -p com.apple.quarantine "$file_path" >/dev/null 2>&1; then
        echo "quarantine remains on $file_path" >&2
        exit 1
    fi
done < "$list"

echo "prepared and verified $(wc -l < "$list" | tr -d ' ') Mach-O files"
