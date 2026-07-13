#!/usr/bin/env python3
"""Fail-closed audit of an unpacked MetalSharp Wine runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path


SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")
FORBIDDEN_NAMES = {".DS_Store", ".git", "__MACOSX", "drive_c", "dosdevices", "system.reg",
                   "user.reg", "userdef.reg"}
FORBIDDEN_SUFFIXES = (".dSYM", ".pdb", ".ilk", ".exp", ".lib", ".a", ".la", ".pc")
HEX = re.compile(r"[0-9a-f]{64}\Z")
BRIDGE_EXPORTS = {
    "_gem_wine_bridge_abi_version", "_gem_wine_process_bind_kuser",
    "_gem_wine_process_commit_identity", "_gem_wine_process_create",
    "_gem_wine_process_decommit", "_gem_wine_process_destroy",
    "_gem_wine_process_invalidate_code", "_gem_wine_process_map_identity",
    "_gem_wine_process_prepare_arm64ec", "_gem_wine_process_protect",
    "_gem_wine_process_register_arm64x_mapped", "_gem_wine_process_release",
    "_gem_wine_process_reserve", "_gem_wine_process_unmap", "_gem_wine_status_name",
    "_gem_wine_thread_create", "_gem_wine_thread_destroy",
    "_gem_wine_thread_get_native_upper_simd", "_gem_wine_thread_request_async_stop",
    "_gem_wine_thread_run", "_gem_wine_thread_set_native_upper_simd",
}


def fail(message: str) -> None:
    raise SystemExit(f"runtime audit failed: {message}")


def command(*argv: str, check: bool = True) -> str:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        fail(f"{' '.join(argv)}: {result.stderr.strip()}")
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_macho(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and "Mach-O" in command("file", "-b", str(path))


def rpaths(path: Path) -> list[str]:
    lines = command("otool", "-l", str(path)).splitlines()
    result: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH" and index + 2 < len(lines):
            value = lines[index + 2].strip()
            if value.startswith("path "):
                result.append(value[5:].split(" (offset", 1)[0])
    return result


def dependencies(path: Path) -> list[str]:
    return [line.strip().split(" (", 1)[0]
            for line in command("otool", "-L", str(path)).splitlines()[1:] if line.strip()]


def resolve_dependency(root: Path, origin: Path, name: str) -> Path | None:
    if name.startswith(SYSTEM_PREFIXES):
        return None
    candidates: list[Path] = []
    if name.startswith("@loader_path/"):
        candidates.append(origin.parent / name.removeprefix("@loader_path/"))
    elif name.startswith("@executable_path/"):
        candidates.append(root / "bin" / name.removeprefix("@executable_path/"))
    elif name.startswith("@rpath/"):
        suffix = name.removeprefix("@rpath/")
        for value in rpaths(origin):
            if value.startswith("@loader_path/"):
                candidates.append(origin.parent / value.removeprefix("@loader_path/") / suffix)
            elif value.startswith("@executable_path/"):
                candidates.append(root / "bin" / value.removeprefix("@executable_path/") / suffix)
        candidates.extend([root / "lib" / suffix, root / "lib/wine/aarch64-unix" / suffix])
    elif name.startswith("/"):
        fail(f"absolute non-system load command in {origin.relative_to(root)}: {name}")
    else:
        fail(f"unrecognized load command in {origin.relative_to(root)}: {name}")
    for candidate in candidates:
        normalized = candidate.resolve(strict=False)
        try:
            normalized.relative_to(root)
        except ValueError:
            continue
        if normalized.is_file():
            return normalized
    fail(f"unresolved packaged dependency in {origin.relative_to(root)}: {name}")


def audit(root: Path, forbidden: list[str]) -> list[dict[str, object]]:
    root = root.resolve(strict=True)
    required = (
        "bin/wine", "bin/wineserver", "lib/libmetalsharp-gem-wine.0.1.0.dylib",
        "lib/wine/aarch64-unix/ntdll.so", "lib/wine/aarch64-windows/cmd.exe",
        "lib/wine/i386-windows/ntdll.dll", "lib/wine/x86_64-windows/ntdll.dll",
        "share/wine/wine.inf", "share/metalsharp/selftest/arm64x_fixture.dll",
        "share/metalsharp/selftest/arm64x_fixture_host.exe",
    )
    for relative in required:
        if not (root / relative).is_file():
            fail(f"required runtime file is missing: {relative}")
    # Filesystem provenance/quarantine attributes are applied by macOS itself
    # and are not package members. The deterministic tar validator rejects all
    # PAX/SCHILY xattr records in the publication archive.
    records: list[dict[str, object]] = []
    machos: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if any(part in FORBIDDEN_NAMES for part in relative.parts):
            fail(f"forbidden package path: {relative}")
        if path.name.endswith(FORBIDDEN_SUFFIXES):
            fail(f"debug/development product is packaged: {relative}")
        mode = path.lstat().st_mode
        record: dict[str, object] = {"path": relative.as_posix()}
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if os.path.isabs(target):
                fail(f"absolute symlink: {relative} -> {target}")
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(root)
            except ValueError:
                fail(f"escaping symlink: {relative} -> {target}")
            if not resolved.exists():
                fail(f"dangling symlink: {relative} -> {target}")
            record.update({"type": "symlink", "mode": stat.S_IMODE(mode), "target": target})
        elif stat.S_ISDIR(mode):
            record.update({"type": "directory", "mode": stat.S_IMODE(mode)})
        elif stat.S_ISREG(mode):
            kind = command("file", "-b", str(path)).strip()
            record.update({"type": "file", "mode": stat.S_IMODE(mode),
                           "size": path.stat().st_size, "sha256": sha256(path), "kind": kind})
            if "Mach-O" in kind:
                if "arm64" not in kind or "x86_64" in kind:
                    fail(f"non-ARM64-only host Mach-O: {relative}: {kind}")
                machos.append(path)
        else:
            fail(f"unsupported filesystem object: {relative}")
        records.append(record)
    for macho in machos:
        for value in rpaths(macho):
            if value.startswith("/"):
                fail(f"absolute rpath in {macho.relative_to(root)}: {value}")
        for name in dependencies(macho):
            resolve_dependency(root, macho, name)
    ntdll = root / "lib/wine/aarch64-unix/ntdll.so"
    if "@rpath/libmetalsharp-gem-wine.0.dylib" not in dependencies(ntdll):
        fail("native ntdll lacks the direct versioned GEM dependency")
    bridge = root / "lib/libmetalsharp-gem-wine.0.1.0.dylib"
    ids = [line.strip() for line in command("otool", "-D", str(bridge)).splitlines()[1:] if line.strip()]
    if ids != ["@rpath/libmetalsharp-gem-wine.0.dylib"]:
        fail("GEM bridge install name is not the versioned relocatable ABI name")
    exports = set(command("nm", "-gjU", str(bridge)).splitlines())
    if exports != BRIDGE_EXPORTS:
        fail(f"GEM bridge export allowlist differs: {sorted(exports ^ BRIDGE_EXPORTS)}")
    scan_terms = [term for term in forbidden if term]
    scan_terms.extend(["/Users/", "/home/runner/", "/opt/homebrew/",
                       "/usr/local/Cellar/", "/private/var/folders/"])
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        output = command("strings", "-a", str(path), check=False)
        for term in scan_terms:
            if term in output:
                fail(f"forbidden source/build/runtime path embedded in {path.relative_to(root)}: {term}")
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--forbid-prefix", action="append", default=[])
    args = parser.parse_args()
    records = audit(args.root, args.forbid_prefix)
    if args.inventory:
        args.inventory.parent.mkdir(parents=True, exist_ok=True)
        args.inventory.write_text(json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n",
                                  encoding="utf-8")
    print(f"runtime audit passed: {len(records)} allowlisted objects")


if __name__ == "__main__":
    main()
