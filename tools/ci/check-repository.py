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
TEXT_SUFFIXES = {".c", ".h", ".md", ".json", ".yml", ".yaml", ".txt", ".cmake", ".sh", ".py"}
FORBIDDEN_PARTS = {"build", ".cache", "__pycache__", ".wine"}
FORBIDDEN_TEXT = ("/Users/averyfelts", "/Volumes/AverySSD", "gho_", "github_pat_")
BINARY_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")


def tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / os.fsdecode(name) for name in output.split(b"\0") if name]


def main() -> int:
    errors: list[str] = []
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if FORBIDDEN_PARTS.intersection(relative.parts):
            errors.append(f"forbidden artifact path: {relative}")
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE:
            errors.append(f"file exceeds 2 MiB: {relative}")
        if data.startswith(BINARY_MAGIC):
            errors.append(f"tracked executable/binary: {relative}")
        if path.suffix in TEXT_SUFFIXES or path.name in {"CMakeLists.txt", "LICENSE", ".gitignore", ".editorconfig", ".clang-format"}:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"non-UTF-8 text file: {relative}")
                continue
            if data and not data.endswith(b"\n"):
                errors.append(f"missing final newline: {relative}")
            for number, line in enumerate(text.splitlines(), 1):
                if line.rstrip() != line:
                    errors.append(f"trailing whitespace: {relative}:{number}")
            if relative != Path("tools/ci/check-repository.py"):
                for marker in FORBIDDEN_TEXT:
                    if marker in text:
                        errors.append(f"forbidden local/secret marker {marker!r}: {relative}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"repository hygiene passed ({len(tracked_files())} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
