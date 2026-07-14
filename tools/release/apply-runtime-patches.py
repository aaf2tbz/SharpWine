#!/usr/bin/env python3
"""Apply a hash-bound BSDIFF40 patch set to an extracted published runtime."""

from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"runtime patch application failed: {message}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def read_patch(patch_root: Path, value: object, runtime_path: str) -> bytes:
    names = value if isinstance(value, list) else [value]
    if not names:
        fail(f"runtime patch has no parts: {runtime_path}")
    parts: list[bytes] = []
    seen: set[str] = set()
    for value_part in names:
        patch_name = safe_relative(value_part)
        flat_name = patch_name.as_posix()
        if len(patch_name.parts) != 1 or flat_name in seen:
            fail(f"patch filename is not unique and flat: {patch_name}")
        seen.add(flat_name)
        patch = patch_root / patch_name
        if patch.is_symlink() or not patch.is_file():
            fail(f"runtime patch is missing: {runtime_path}")
        parts.append(patch.read_bytes())
    return b"".join(parts)


def number(value: bytes) -> int:
    if len(value) != 8:
        fail("truncated BSDIFF40 integer")
    result = value[7] & 0x7F
    for index in range(6, -1, -1):
        result = result * 256 + value[index]
    return -result if value[7] & 0x80 else result


def apply_bsdiff(old: bytes, patch: bytes) -> bytes:
    if len(patch) < 32 or patch[:8] != b"BSDIFF40":
        fail("patch is not BSDIFF40")
    control_size = number(patch[8:16])
    diff_size = number(patch[16:24])
    new_size = number(patch[24:32])
    if min(control_size, diff_size, new_size) < 0 or 32 + control_size + diff_size > len(patch):
        fail("BSDIFF40 header sizes are invalid")
    try:
        control = bz2.decompress(patch[32:32 + control_size])
        differences = bz2.decompress(patch[32 + control_size:32 + control_size + diff_size])
        extra = bz2.decompress(patch[32 + control_size + diff_size:])
    except (OSError, ValueError) as error:
        fail(f"BSDIFF40 stream is invalid: {error}")
    output = bytearray(new_size)
    old_position = new_position = control_position = diff_position = extra_position = 0
    while new_position < new_size:
        if control_position + 24 > len(control):
            fail("BSDIFF40 control stream is truncated")
        add_size = number(control[control_position:control_position + 8])
        copy_size = number(control[control_position + 8:control_position + 16])
        seek = number(control[control_position + 16:control_position + 24])
        control_position += 24
        if add_size < 0 or copy_size < 0 or new_position + add_size + copy_size > new_size or \
                diff_position + add_size > len(differences) or extra_position + copy_size > len(extra):
            fail("BSDIFF40 control tuple exceeds a stream bound")
        for index in range(add_size):
            value = differences[diff_position + index]
            source = old_position + index
            if 0 <= source < len(old):
                value = (value + old[source]) & 0xFF
            output[new_position + index] = value
        new_position += add_size
        old_position += add_size
        diff_position += add_size
        output[new_position:new_position + copy_size] = extra[extra_position:extra_position + copy_size]
        new_position += copy_size
        extra_position += copy_size
        old_position += seek
    if control_position != len(control) or diff_position != len(differences) or \
            extra_position != len(extra):
        fail("BSDIFF40 contains trailing decompressed data")
    return bytes(output)


def safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or value.startswith("/"):
        fail(f"unsafe runtime path: {value!r}")
    result = Path(value)
    if ".." in result.parts or result.as_posix() != value:
        fail(f"unsafe runtime path: {value!r}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--patch-set", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture-output", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    patch_set_path = args.patch_set.resolve(strict=True)
    patch_root = patch_set_path.parent
    patch_set = load(patch_set_path)
    policy = load(args.policy)
    if set(patch_set) != {"schema", "format", "release", "base", "runtimePatches", "fixture"} or \
            patch_set.get("schema") != 1 or patch_set.get("format") != "BSDIFF40":
        fail("unsupported patch-set schema")
    if patch_set.get("release") != policy.get("release") or patch_set.get("base") != policy.get("base"):
        fail("patch-set release/base binding does not match policy")
    if len(args.commit) != 40 or any(character not in "0123456789abcdef" for character in args.commit):
        fail("commit must be a lowercase full Git SHA")
    if args.output.exists() or args.fixture_output.exists():
        fail("output paths must be absent")
    allowed = {record.get("path"): record.get("action") for record in policy.get("allowedChanges", [])
               if isinstance(record, dict)}
    patches = patch_set.get("runtimePatches")
    if not isinstance(patches, list) or not patches:
        fail("patch set must contain at least one runtime binary patch")
    args.output.mkdir(parents=True)
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    required_fields = {"path", "action", "patch", "patchSha256", "baseSha256",
                       "resultSha256", "resultSize", "mode"}
    for record in patches:
        if not isinstance(record, dict) or set(record) != required_fields:
            fail("runtime patch record has invalid fields")
        relative = safe_relative(record["path"])
        name = relative.as_posix()
        action = record["action"]
        if name in seen or action not in {"add", "replace"} or allowed.get(name) != action:
            fail(f"runtime patch is duplicated or not policy-approved: {name}")
        seen.add(name)
        source = runtime / relative
        patch_bytes = read_patch(patch_root, record["patch"], name)
        if action == "replace":
            if source.is_symlink() or not source.is_file():
                fail(f"runtime source is missing: {name}")
            source_bytes = source.read_bytes()
        else:
            if source.exists() or record["baseSha256"] != digest_bytes(b""):
                fail(f"added runtime path exists in the foundation: {name}")
            source_bytes = b""
        if digest_bytes(source_bytes) != record["baseSha256"] or \
                digest_bytes(patch_bytes) != record["patchSha256"]:
            fail(f"base or patch hash mismatch: {name}")
        patched = apply_bsdiff(source_bytes, patch_bytes)
        if len(patched) != record["resultSize"] or digest_bytes(patched) != record["resultSha256"]:
            fail(f"patched output identity mismatch: {name}")
        destination = args.output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(patched)
        os.chmod(destination, record["mode"])
        results.append({"path": name, "action": action, "baseSha256": record["baseSha256"],
                        "patchSha256": record["patchSha256"],
                        "resultSha256": record["resultSha256"],
                        "resultSize": record["resultSize"], "mode": record["mode"]})
    evidence_paths = {"share/metalsharp/x86_64-acceptance-evidence.json",
                      "share/metalsharp/i386-acceptance-evidence.json"}
    expected = {name for name, action in allowed.items()
                if action in {"add", "replace"} and name not in evidence_paths}
    if seen != expected:
        fail("runtime patch set does not cover every policy payload")
    fixture = patch_set.get("fixture")
    fixture_fields = {"patch", "patchSha256", "baseSha256", "resultSha256", "resultSize"}
    if not isinstance(fixture, dict) or set(fixture) != fixture_fields or \
            fixture.get("baseSha256") != digest_bytes(b""):
        fail("fixture patch record is invalid")
    fixture_patch = patch_root / safe_relative(fixture["patch"])
    if not fixture_patch.is_file() or digest(fixture_patch) != fixture["patchSha256"]:
        fail("fixture patch is missing or has the wrong hash")
    fixture_bytes = apply_bsdiff(b"", fixture_patch.read_bytes())
    if len(fixture_bytes) != fixture["resultSize"] or \
            digest_bytes(fixture_bytes) != fixture["resultSha256"]:
        fail("fixture output identity mismatch")
    args.fixture_output.parent.mkdir(parents=True, exist_ok=True)
    args.fixture_output.write_bytes(fixture_bytes)
    if "share/metalsharp/x86_64-acceptance-evidence.json" in allowed:
        evidence_path = args.output / "share/metalsharp/x86_64-acceptance-evidence.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence = {"schema": 1, "repositoryCommit": args.commit,
                    "release": patch_set["release"], "base": patch_set["base"],
                    "patchSetSha256": digest(patch_set_path), "runtimePatches": results,
                    "fixture": {"sha256": fixture["resultSha256"],
                                "size": fixture["resultSize"]},
                    "status": "awaiting packaged-runtime probe"}
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8")
        os.chmod(evidence_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    if "share/metalsharp/i386-acceptance-evidence.json" in allowed:
        i386_evidence = args.output / "share/metalsharp/i386-acceptance-evidence.json"
        i386_evidence.parent.mkdir(parents=True, exist_ok=True)
        i386_evidence.write_text(json.dumps({"schema": 1, "repositoryCommit": args.commit,
                                             "release": patch_set["release"],
                                             "status": "awaiting packaged-runtime probe"},
                                            sort_keys=True, separators=(",", ":")) + "\n",
                                 encoding="utf-8")
        os.chmod(i386_evidence, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    print(f"applied {len(results)} exact runtime patches and reconstructed the x86_64 fixture")


if __name__ == "__main__":
    main()
