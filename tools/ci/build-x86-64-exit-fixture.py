#!/usr/bin/env python3
"""Build the minimal AMD64 PE32+ acceptance fixture twice and bind its identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 fixture build failed: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def inspect_pe(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        fail("fixture is not a DOS/PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe > len(data) - 0x78 or data[pe:pe + 4] != b"PE\0\0":
        fail("fixture has an invalid PE header")
    machine, sections, timestamp = struct.unpack_from("<HHI", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    entry = struct.unpack_from("<I", data, pe + 40)[0]
    if machine != 0x8664 or sections == 0 or optional_size < 0xF0 or magic != 0x20B:
        fail("fixture is not an AMD64 PE32+ image")
    if timestamp != 0 or entry == 0:
        fail("fixture timestamp or entry point is not deterministic")
    return {"machine": machine, "sections": sections, "timestamp": timestamp,
            "entryPointRva": entry, "size": len(data)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", required=True, type=Path)
    parser.add_argument("--source", default="tests/fixtures/x86_64_exit.c", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        fail("fixture producer must run natively on Apple Silicon")
    if len(args.commit) != 40 or any(c not in "0123456789abcdef" for c in args.commit):
        fail("commit must be a full lowercase Git SHA")
    compiler = args.toolchain.resolve() / "bin/x86_64-w64-mingw32-clang"
    source = args.source.resolve()
    output = args.output.resolve()
    if not compiler.is_file() or not os.access(compiler, os.X_OK) or not source.is_file():
        fail("pinned compiler or fixture source is missing")
    if output.exists():
        fail("output directory must be absent")
    output.mkdir(parents=True)
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = "0"
    binaries: list[Path] = []
    for name in ("a", "b"):
        directory = output / name
        directory.mkdir()
        binary = directory / "x86_64_exit.exe"
        subprocess.run(
            [str(compiler), "-nostdlib", "-Wl,--entry,mainCRTStartup",
             "-Wl,--subsystem,console", str(source), "-lntdll", "-o", str(binary)],
            check=True, env=environment,
        )
        binaries.append(binary)
    if binaries[0].read_bytes() != binaries[1].read_bytes():
        fail("two clean fixture builds are not byte-identical")
    pe = inspect_pe(binaries[0])
    manifest = {
        "schema": 1,
        "commit": args.commit,
        "source": {"path": args.source.as_posix(), "sha256": digest(source)},
        "toolchain": {"compiler": compiler.name, "sha256": digest(compiler)},
        "fixture": {"path": "x86_64_exit.exe", "sha256": digest(binaries[0]), **pe},
        "builds": 2,
        "byteIdentical": True,
        "host": {"os": "macOS", "architecture": "arm64", "rosetta": False},
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    shutil.copyfile(binaries[0], output / "x86_64_exit.exe")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
