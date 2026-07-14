#!/usr/bin/env python3
"""Build the redistributable PE32+ fixture twice and bind its exact bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import subprocess


def fail(message: str) -> None:
    raise SystemExit(f"x86_64 fixture build failed: {message}")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_pe(path: pathlib.Path) -> None:
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        fail("output is not a DOS/PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 26 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        fail("output lacks a bounded PE signature")
    machine, magic = struct.unpack_from("<H18xH", data, pe + 4)
    if machine != 0x8664 or magic != 0x20B:
        fail(f"output is not PE32+ AMD64: machine={machine:#x} magic={magic:#x}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", required=True, type=pathlib.Path)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.compiler.is_file() or not args.source.is_file():
        fail("compiler or source is absent")
    args.output.mkdir(parents=True, exist_ok=False)
    # LLVM-MinGW target drivers are basename-sensitive symlinks to one wrapper;
    # resolving the symlink would erase the selected target triple. Native
    # Windows CI instead uses MSVC so its SEH oracle has Microsoft's complete
    # asynchronous exception implementation.
    compiler = str(args.compiler.absolute())
    is_msvc = args.compiler.name.lower() in {"cl", "cl.exe"}
    outputs = []
    for name in ("a", "b"):
        path = args.output / f"wine_x86_64_acceptance-{name}.exe"
        if is_msvc:
            command = [compiler, "/nologo", "/O2", "/W4", "/WX", "/Brepro",
                       "/D_CRT_SECURE_NO_WARNINGS", str(args.source.resolve()), "advapi32.lib",
                       "/link", "/SUBSYSTEM:CONSOLE", f"/OUT:{path}"]
        else:
            command = [compiler, "-O2", "-g0", "-Wall", "-Wextra", "-Werror",
                       "-fms-extensions", "-Wl,--no-insert-timestamp", "-Wl,--subsystem,console",
                       str(args.source.resolve()), "-ladvapi32", "-o", str(path)]
        subprocess.run(command, check=True)
        check_pe(path)
        outputs.append(path)
    if outputs[0].read_bytes() != outputs[1].read_bytes():
        fail("two clean builds produced different fixture bytes")
    identity_result = subprocess.run([compiler] if is_msvc else [compiler, "--version"],
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     check=False)
    identity = next(line for line in identity_result.stdout.splitlines() if line.strip()).strip()
    manifest = {"schema": 1, "kind": "mswr-x86_64-windows-fixture",
                "source": args.source.name, "sourceSha256": digest(args.source),
                "binary": outputs[0].name, "binarySha256": digest(outputs[0]),
                "size": outputs[0].stat().st_size, "peMachine": "AMD64",
                "peMagic": "PE32+", "compiler": identity, "reproducible": True}
    args.manifest.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                             encoding="utf-8")


if __name__ == "__main__":
    main()
