#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject accidental artifacts, secrets, local paths, and basic text hygiene failures."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_FILE = 2 * 1024 * 1024
TEXT_SUFFIXES = {
    ".c",
    ".cpp",
    ".h",
    ".md",
    ".json",
    ".yml",
    ".yaml",
    ".txt",
    ".cmake",
    ".sh",
    ".py",
}
TEXT_FILENAMES = {"CMakeLists.txt", "LICENSE", ".gitignore", ".editorconfig", ".clang-format"}
FORBIDDEN_PARTS = {"build", ".cache", "__pycache__", ".wine"}
FORBIDDEN_TEXT = ("/Users/averyfelts", "/Volumes/AverySSD", "gho_", "github_pat_")
BINARY_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
FORBIDDEN_BINARY_SUFFIXES = {
    ".a",
    ".cab",
    ".dll",
    ".dmp",
    ".dylib",
    ".exe",
    ".lib",
    ".msi",
    ".o",
    ".obj",
    ".pdb",
    ".so",
    ".sys",
}
FORBIDDEN_ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".bzip2",
    ".dmg",
    ".gz",
    ".gzip",
    ".ipa",
    ".pkg",
    ".rar",
    ".tar",
    ".tbz",
    ".tbz2",
    ".tgz",
    ".txz",
    ".xar",
    ".xip",
    ".xz",
    ".zip",
}
ARCHIVE_MAGIC_PREFIXES = (
    ("ZIP", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ("gzip", (b"\x1f\x8b",)),
    ("bzip2", (b"BZh",)),
    ("xz", (b"\xfd7zXZ\x00",)),
    ("7z", (b"7z\xbc\xaf'\x1c",)),
    ("RAR", (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")),
    ("Apple xar/pkg", (b"xar!",)),
)


def tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / os.fsdecode(name) for name in output.split(b"\0") if name]


def archive_magic_label(data: bytes) -> str | None:
    for label, signatures in ARCHIVE_MAGIC_PREFIXES:
        if data.startswith(signatures):
            return label
    if len(data) >= 512 and data[-512:-508] == b"koly":
        return "Apple UDIF/dmg"
    return None


def has_forbidden_dsym_part(relative: Path) -> bool:
    return any(part.lower().endswith(".dsym") for part in relative.parts)


def classify_tracked_file(relative: Path, data: bytes) -> list[str]:
    errors: list[str] = []
    if FORBIDDEN_PARTS.intersection(relative.parts):
        errors.append(f"forbidden artifact path: {relative}")
        return errors
    if has_forbidden_dsym_part(relative):
        errors.append(f"tracked debug-symbol bundle path: {relative}")
    if len(data) > MAX_FILE:
        errors.append(f"file exceeds 2 MiB: {relative}")
    if data.startswith(BINARY_MAGIC):
        errors.append(f"tracked executable/binary: {relative}")
    suffix = relative.suffix.lower()
    if suffix in FORBIDDEN_BINARY_SUFFIXES:
        errors.append(f"tracked executable/debug artifact suffix: {relative}")
    if suffix in FORBIDDEN_ARCHIVE_SUFFIXES:
        errors.append(f"tracked opaque archive/container suffix: {relative}")
    magic_label = archive_magic_label(data)
    if magic_label is not None:
        errors.append(f"tracked opaque archive/container magic ({magic_label}): {relative}")
    if suffix in TEXT_SUFFIXES or relative.name in TEXT_FILENAMES:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-UTF-8 text file: {relative}")
            return errors
        if data and not data.endswith(b"\n"):
            errors.append(f"missing final newline: {relative}")
        for number, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line:
                errors.append(f"trailing whitespace: {relative}:{number}")
        if relative != Path("tools/ci/check-repository.py"):
            for marker in FORBIDDEN_TEXT:
                if marker in text:
                    errors.append(f"forbidden local/secret marker {marker!r}: {relative}")
    return errors


def main() -> int:
    errors: list[str] = []
    paths = tracked_files()
    for path in paths:
        relative = path.relative_to(ROOT)
        errors.extend(classify_tracked_file(relative, path.read_bytes()))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"repository hygiene passed ({len(paths)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
