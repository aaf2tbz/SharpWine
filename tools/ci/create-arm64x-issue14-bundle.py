#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create the allowlisted, run-scoped Issue #14 CI handoff."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

PAYLOADS = {
    "arm64x_fixture.dll": "arm64ec/Release/arm64x_fixture.dll",
    "arm64x_fixture_host.exe": "arm64ec/Release/arm64x_fixture_host.exe",
    "arm64ec-entry-map.txt": "arm64ec-entry-map.txt",
    "build-manifest.json": "arm64x-fixture-build.manifest.json",
    "inspection.json": "arm64x-fixture-inspection.json",
    "execution.json": "arm64x-issue11-execution.json",
    "native-evidence.json": "arm64x-native-evidence.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path: Path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON property {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-a", type=Path, required=True)
    parser.add_argument("--build-b", type=Path, required=True)
    parser.add_argument("--reproducibility", type=Path, required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.git_commit) != 40 or any(c not in "0123456789abcdef" for c in args.git_commit):
        raise SystemExit("git commit must be a lowercase 40-digit SHA")
    if args.output.exists():
        raise SystemExit("bundle output must initially be absent")
    args.output.mkdir(parents=True)
    files = []
    for label, root in (("a", args.build_a), ("b", args.build_b)):
        destination = args.output / label
        destination.mkdir()
        manifest = strict_json(root / PAYLOADS["build-manifest.json"])
        if manifest.get("schemaVersion") != 3 or manifest.get("gitCommit") != args.git_commit:
            raise SystemExit(f"build {label} is not bound to the requested commit")
        for output_name, relative in PAYLOADS.items():
            source = root / relative
            if not source.is_file() or source.is_symlink():
                raise SystemExit(f"missing or linked producer payload: {source}")
            target = destination / output_name
            shutil.copyfile(source, target)
            files.append(
                {
                    "path": target.relative_to(args.output).as_posix(),
                    "size": target.stat().st_size,
                    "sha256": sha256(target),
                }
            )
    repro_target = args.output / "reproducibility.json"
    if not args.reproducibility.is_file() or args.reproducibility.is_symlink():
        raise SystemExit("reproducibility evidence is missing or linked")
    shutil.copyfile(args.reproducibility, repro_target)
    files.append(
        {
            "path": repro_target.name,
            "size": repro_target.stat().st_size,
            "sha256": sha256(repro_target),
        }
    )
    files.sort(key=lambda item: item["path"])
    manifest = {
        "schemaVersion": 1,
        "distribution": "run-scoped-ci-only",
        "gitCommit": args.git_commit,
        "files": files,
    }
    (args.output / "bundle.manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
