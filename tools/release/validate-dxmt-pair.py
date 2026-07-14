#!/usr/bin/env python3
"""Audit the exact source-built DXMT i386-PE/ARM64-Unix runtime pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PE_NAMES = ("d3d10core.dll", "d3d11.dll", "dxgi.dll", "winemetal.dll")
MACH_NAME = "winemetal.so"


def run(*argv: str) -> str:
    return subprocess.check_output(argv, text=True, errors="replace")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_header(path: Path) -> tuple[int, int, int]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"not a DOS/PE image: {path}")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 26 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ValueError(f"invalid PE header: {path}")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    timestamp = struct.unpack_from("<I", data, offset + 8)[0]
    optional_magic = struct.unpack_from("<H", data, offset + 24)[0]
    return machine, timestamp, optional_magic


def otool_values(text: str, command: str, field: str) -> list[str]:
    values: list[str] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != f"cmd {command}":
            continue
        for candidate in lines[index + 1 : index + 8]:
            stripped = candidate.strip()
            if stripped.startswith(f"{field} "):
                values.append(stripped.split()[1])
                break
    return values


def validate(root: Path, llvm_nm: Path, forbidden: list[str]) -> dict[str, object]:
    expected = {*(f"i386-windows/{name}" for name in PE_NAMES), f"aarch64-unix/{MACH_NAME}"}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != expected:
        raise ValueError(f"DXMT pair inventory mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    records: list[dict[str, object]] = []
    for name in PE_NAMES:
        path = root / "i386-windows" / name
        machine, timestamp, optional_magic = pe_header(path)
        if (machine, timestamp, optional_magic) != (0x14C, 0, 0x10B):
            raise ValueError(
                f"{name} is not deterministic PE32 i386: "
                f"machine={machine:#x}, timestamp={timestamp}, magic={optional_magic:#x}"
            )
        description = run("file", "-b", str(path)).strip()
        if "PE32 executable" not in description or "Intel 80386" not in description:
            raise ValueError(f"unexpected PE architecture for {name}: {description}")
        symbols = run(str(llvm_nm), "--defined-only", "--extern-only", str(path))
        if not symbols.strip():
            raise ValueError(f"{name} has no externally defined symbols")
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256(path),
                "size": path.stat().st_size,
                "format": "PE32-i386",
                "coffTimestamp": timestamp,
                "symbolsSha256": hashlib.sha256(symbols.encode()).hexdigest(),
            }
        )
    native = root / "aarch64-unix" / MACH_NAME
    description = run("file", "-b", str(native)).strip()
    if "Mach-O 64-bit" not in description or "arm64" not in description or "x86_64" in description:
        raise ValueError(f"native DXMT bridge is not ARM64-only: {description}")
    if run("lipo", "-archs", str(native)).strip() != "arm64":
        raise ValueError("native DXMT bridge has an unexpected architecture slice")
    load_commands = run("otool", "-l", str(native))
    if "LC_UUID" in load_commands:
        raise ValueError("native DXMT bridge contains a nondeterministic LC_UUID")
    ids = otool_values(load_commands, "LC_ID_DYLIB", "name")
    rpaths = otool_values(load_commands, "LC_RPATH", "path")
    if ids != ["@rpath/winemetal.so"]:
        raise ValueError(f"unexpected winemetal.so install name: {ids}")
    if sorted(rpaths) != ["@loader_path/", "@loader_path/../../"]:
        raise ValueError(f"unexpected winemetal.so rpaths: {rpaths}")
    dependencies = []
    for line in run("otool", "-L", str(native)).splitlines()[1:]:
        value = line.strip().split(" (", 1)[0]
        if value:
            dependencies.append(value)
    expected_rpath = {"@rpath/winemetal.so", "@rpath/winemac.so", "@rpath/ntdll.so"}
    if not expected_rpath.issubset(dependencies):
        raise ValueError(f"native DXMT bridge lacks paired Wine dependencies: {dependencies}")
    unexpected = [
        value
        for value in dependencies
        if value not in expected_rpath and not value.startswith(("/System/Library/", "/usr/lib/"))
    ]
    if unexpected:
        raise ValueError(f"native DXMT bridge has non-system absolute dependencies: {unexpected}")
    symbols = run("nm", "-gjU", str(native))
    if not symbols.strip():
        raise ValueError("native DXMT bridge has no exported symbols")
    data = native.read_bytes()
    markers = [b"/Users/", b"/private/tmp/", b"x86_64-unix/"]
    markers.extend(value.encode() for value in forbidden if value)
    leaked = [marker.decode(errors="replace") for marker in markers if marker in data]
    if leaked:
        raise ValueError(f"native DXMT bridge leaks forbidden build paths: {leaked}")
    records.append(
        {
            "path": native.relative_to(root).as_posix(),
            "sha256": sha256(native),
            "size": native.stat().st_size,
            "format": "Mach-O-arm64",
            "installName": ids[0],
            "rpaths": rpaths,
            "dependencies": dependencies,
            "symbolsSha256": hashlib.sha256(symbols.encode()).hexdigest(),
        }
    )
    return {"schema": 1, "kind": "dxmt-paired-runtime", "passed": True, "files": records}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--llvm-nm", type=Path, required=True)
    parser.add_argument("--forbid-prefix", action="append", default=[])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.root.resolve(), args.llvm_nm.resolve(), args.forbid_prefix)
        if args.manifest:
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"DXMT pair validation failed: {error}", file=sys.stderr)
        return 1
    print("DXMT paired runtime validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
