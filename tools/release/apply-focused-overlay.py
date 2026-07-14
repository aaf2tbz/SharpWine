#!/usr/bin/env python3
"""Apply a hash-bound runtime overlay under an exact release policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"focused runtime overlay failed: {message}")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or value.startswith("/"):
        fail(f"unsafe overlay path: {value!r}")
    path = Path(value)
    if ".." in path.parts or path.as_posix() != value:
        fail(f"unsafe overlay path: {value!r}")
    return path


def runtime_inventory(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            record: dict[str, object] = {
                "path": relative, "type": "symlink", "mode": mode, "target": os.readlink(path)
            }
        elif path.is_dir():
            record = {"path": relative, "type": "directory", "mode": mode}
        elif path.is_file():
            record = {"path": relative, "type": "file", "mode": mode,
                      "size": path.stat().st_size, "sha256": digest(path)}
        else:
            fail(f"unsupported runtime object: {relative}")
        result[relative] = record
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--overlay", required=True, type=Path)
    parser.add_argument("--overlay-manifest", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    overlay = args.overlay.resolve()
    if not runtime.is_dir() or not overlay.is_dir():
        fail("runtime or overlay directory is missing")
    base = load_object(args.base_manifest)
    policy = load_object(args.policy)
    manifest = load_object(args.overlay_manifest)
    if policy.get("schema") != 1 or manifest.get("schema") != 1:
        fail("unsupported policy or overlay manifest schema")
    if manifest.get("base") != policy.get("base") or manifest.get("release") != policy.get("release"):
        fail("overlay release/base binding does not match policy")
    allowed_records = policy.get("allowedChanges")
    changes = manifest.get("changes")
    if not isinstance(allowed_records, list) or not isinstance(changes, list):
        fail("policy or overlay changes are not arrays")
    allowed: dict[str, str] = {}
    for record in allowed_records:
        if not isinstance(record, dict) or set(record) != {"path", "action", "reason"}:
            fail("invalid allowed change record")
        path = safe_relative(record["path"]).as_posix()
        if path in allowed or record["action"] not in {"add", "replace", "remove", "symlink"}:
            fail(f"duplicate or invalid policy change: {path}")
        allowed[path] = str(record["action"])
    base_files = base.get("package", {}).get("files")
    if not isinstance(base_files, list):
        fail("base release manifest has no package inventory")
    expected = {record.get("path"): record for record in base_files if isinstance(record, dict)}
    current = runtime_inventory(runtime)
    if current != expected:
        fail("runtime does not exactly match the base release manifest")
    seen: set[str] = set()
    payload_paths = {
        path.relative_to(overlay).as_posix()
        for path in overlay.rglob("*") if not path.is_dir()
    }
    expected_payloads: set[str] = set()
    for change in changes:
        if not isinstance(change, dict) or "path" not in change or "action" not in change:
            fail("invalid overlay change record")
        relative = safe_relative(change["path"])
        name = relative.as_posix()
        action = change["action"]
        if name in seen or allowed.get(name) != action:
            fail(f"unlisted, duplicate, or wrong-action overlay change: {name}")
        seen.add(name)
        destination = runtime / relative
        existed = name in expected
        if action == "add" and existed:
            fail(f"add target already exists: {name}")
        if action in {"replace", "remove", "symlink"} and not existed:
            fail(f"overlay target is absent from base: {name}")
        if action == "remove":
            if set(change) != {"path", "action"}:
                fail(f"remove record has extra fields: {name}")
            destination.unlink()
            continue
        source = overlay / relative
        expected_payloads.add(name)
        if action == "symlink":
            if set(change) != {"path", "action", "target", "mode"} or not source.is_symlink():
                fail(f"invalid symlink overlay record: {name}")
            target = os.readlink(source)
            if target != change["target"] or os.path.isabs(target) or ".." in Path(target).parts:
                fail(f"unsafe or mismatched overlay symlink: {name}")
            if destination.exists() or destination.is_symlink():
                destination.unlink()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(target)
            continue
        if set(change) != {"path", "action", "sha256", "size", "mode"}:
            fail(f"invalid file overlay record: {name}")
        if source.is_symlink() or not source.is_file():
            fail(f"overlay payload is not a regular file: {name}")
        if digest(source) != change["sha256"] or source.stat().st_size != change["size"]:
            fail(f"overlay payload hash/size mismatch: {name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        os.chmod(destination, change["mode"])
    if payload_paths != expected_payloads:
        fail("overlay directory contains missing or unlisted payloads")
    after = runtime_inventory(runtime)
    changed = sorted(name for name in set(current) | set(after) if current.get(name) != after.get(name))
    if changed != sorted(seen):
        fail("observed runtime changes do not match overlay manifest")
    evidence = {
        "schema": 1,
        "base": policy["base"],
        "release": policy["release"],
        "changes": [after.get(name, {"path": name, "type": "removed"}) for name in changed],
        "unchangedFileCount": len(set(current) & set(after)) - len([name for name in changed if name in current and name in after]),
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(f"applied {len(changed)} focused runtime changes")


if __name__ == "__main__":
    main()
