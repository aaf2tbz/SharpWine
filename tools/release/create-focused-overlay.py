#!/usr/bin/env python3
"""Create the exact hash-bound overlay manifest allowed by a release policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"focused overlay manifest creation failed: {message}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--overlay", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    policy = load(args.policy)
    if set(policy) != {"schema", "release", "base", "allowedChanges"} or \
            policy.get("schema") != 1:
        fail("unsupported policy schema")
    allowed = policy.get("allowedChanges")
    if not isinstance(allowed, list) or not allowed:
        fail("policy contains no allowed changes")
    overlay = args.overlay.resolve(strict=True)
    changes: list[dict[str, object]] = []
    expected: set[str] = set()
    for record in allowed:
        if not isinstance(record, dict) or set(record) != {"path", "action", "reason"}:
            fail("invalid policy change record")
        relative = record["path"]
        action = record["action"]
        if not isinstance(relative, str) or not relative or relative.startswith("/") or \
                ".." in Path(relative).parts or relative in expected:
            fail(f"unsafe or duplicate policy path: {relative!r}")
        if action not in {"add", "replace"}:
            fail(f"release builder does not produce policy action {action!r}")
        expected.add(relative)
        payload = overlay / relative
        if payload.is_symlink() or not payload.is_file():
            fail(f"missing regular overlay payload: {relative}")
        changes.append({"path": relative, "action": action,
                        "mode": stat.S_IMODE(payload.stat().st_mode),
                        "size": payload.stat().st_size, "sha256": digest(payload)})
    actual = {
        path.relative_to(overlay).as_posix()
        for path in overlay.rglob("*") if not path.is_dir()
    }
    if actual != expected:
        fail(f"overlay payloads differ from policy: extra={sorted(actual - expected)}, "
             f"missing={sorted(expected - actual)}")
    manifest = {"schema": 1, "release": policy["release"], "base": policy["base"],
                "changes": changes}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"bound {len(changes)} focused overlay payloads")


if __name__ == "__main__":
    main()
