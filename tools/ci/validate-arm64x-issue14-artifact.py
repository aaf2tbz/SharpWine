#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed validation for the run-scoped Issue #14 handoff."""

import argparse
import hashlib
import json
import re
from pathlib import Path

HASH = re.compile(r"^[0-9a-f]{64}$")
GIT = re.compile(r"^[0-9a-f]{40}$")
SOURCES = {
    "CMakeLists.txt",
    "arm64x.cmake",
    "fixture.c",
    "fixture_x64.c",
    "fixture_x64_roundtrip.asm",
    "fixture_api.h",
    "host.c",
    "fixture.def",
}
PAYLOAD_NAMES = {
    "arm64x_fixture.dll",
    "arm64x_fixture_host.exe",
    "arm64ec-entry-map.txt",
    "build-manifest.json",
    "inspection.json",
    "execution.json",
    "native-evidence.json",
}


def fail(message):
    raise ValueError(message)


def exact(value, names, context):
    if not isinstance(value, dict) or set(value) != set(names):
        fail(f"{context} properties differ: {sorted(value) if isinstance(value, dict) else value}")


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail(f"duplicate property {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def canonical_text_digest(path):
    text = path.read_text(encoding="utf-8", errors="strict")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def checked_file(root, relative):
    if not isinstance(relative, str) or not relative or relative.startswith(("/", "\\")):
        fail("artifact path is not relative")
    parts = Path(relative).parts
    if ".." in parts or "" in parts or "\\" in relative:
        fail("artifact path is not normalized")
    path = root.joinpath(*parts)
    if path.is_symlink() or not path.is_file() or root.resolve() not in path.resolve().parents:
        fail(f"artifact path is missing, linked, or escaped: {relative}")
    return path


def validate_entry_map(path):
    lines = path.read_text(encoding="ascii").splitlines()
    names = ["integer", "floating", "aggregate", "variadic", "roundtrip", "finish",
             "direct", "callbackResume", "tailTransfer", "boundedNested", "armCallback",
             "armNestedCallback", "checkerSlot", "dispatchCallSlot", "dispatchRetSlot"]
    if len(lines) != 16 or lines[0] != "MSWR_ARM64EC_ENTRY_MAP_V3":
        fail("entry map header or line count is invalid")
    for line, name in zip(lines[1:], names):
        if not re.fullmatch(name + r" [0-9a-f]{8}", line):
            fail(f"entry map record is invalid: {line!r}")


def validate_build(path, expected_git, dll_hash, source_root):
    value = read_json(path)
    exact(value, ["schemaVersion", "gitCommit", "producerLock", "source", "outputs", "distribution"],
          "build manifest")
    if value["schemaVersion"] != 3 or value["gitCommit"] != expected_git or \
            value["distribution"] != "build-tree-only" or not HASH.fullmatch(value["producerLock"]):
        fail("build manifest contract is invalid")
    exact(value["source"], SOURCES, "build manifest source")
    if any(not isinstance(item, str) or not HASH.fullmatch(item) for item in value["source"].values()):
        fail("build manifest source hash is invalid")
    fixture_root = source_root / "tests" / "fixtures" / "arm64x_linked"
    for name, expected_hash in value["source"].items():
        source = checked_file(fixture_root, name)
        if canonical_text_digest(source) != expected_hash:
            fail(f"build manifest source does not match checkout: {name}")
    lock = checked_file(source_root, "docs/architecture/adr/microsoft-arm64x-fixture.provenance.json")
    if canonical_text_digest(lock) != value["producerLock"]:
        fail("build manifest producer lock does not match checkout")
    exact(value["outputs"], ["dll", "host"], "build manifest outputs")
    for name in ("dll", "host"):
        exact(value["outputs"][name], ["type", "path", "sha256"], f"build output {name}")
        if value["outputs"][name]["type"] != name or not HASH.fullmatch(value["outputs"][name]["sha256"]):
            fail(f"build output {name} is invalid")
    if value["outputs"]["dll"]["path"] != "arm64ec/Release/arm64x_fixture.dll" or \
            value["outputs"]["dll"]["sha256"] != dll_hash:
        fail("build manifest DLL link is invalid")
    if value["outputs"]["host"]["path"] != "arm64ec/Release/arm64x_fixture_host.exe":
        fail("build manifest host path is invalid")
    return value["producerLock"], value["source"], value["outputs"]["host"]["sha256"]


def validate_set(root, label, expected_git, source_root):
    directory = root / label
    actual = {item.name for item in directory.iterdir()} if directory.is_dir() else set()
    if actual != PAYLOAD_NAMES or any(item.is_symlink() for item in directory.iterdir()):
        fail(f"payload set {label} differs from the allowlist")
    dll = directory / "arm64x_fixture.dll"
    dll_hash = digest(dll)
    producer_lock, sources, host_hash = validate_build(
        directory / "build-manifest.json", expected_git, dll_hash, source_root)
    if digest(directory / "arm64x_fixture_host.exe") != host_hash:
        fail("packaged validation host does not match its build manifest")
    validate_entry_map(directory / "arm64ec-entry-map.txt")
    native = read_json(directory / "native-evidence.json")
    exact(native, ["schemaVersion", "nativeMachine", "roundtripInput", "roundtripResult",
                   "directResult", "callbackResumeResult", "tailTransferResult", "nestedResult",
                   "passed"], "native evidence")
    if native != {"schemaVersion": 2, "nativeMachine": "arm64", "roundtripInput": 12,
                  "roundtripResult": 30, "directResult": 47, "callbackResumeResult": 82,
                  "tailTransferResult": 23120, "nestedResult": 85, "passed": True}:
        fail("native round-trip oracle is invalid")
    inspection = read_json(directory / "inspection.json")
    exact(inspection, ["schemaVersion", "distribution", "manifestSha256", "dllSha256", "parser"],
          "inspection evidence")
    if inspection["schemaVersion"] != 1 or inspection["distribution"] != "build-tree-only" or \
            inspection["dllSha256"] != dll_hash or not isinstance(inspection["parser"], dict):
        fail("inspection evidence is invalid")
    execution = read_json(directory / "execution.json")
    exact(execution, ["schemaVersion", "distribution", "producer", "dynarmicCommit", "dllSha256",
                      "inspectionSha256", "nativeMachine", "contextSize", "imageBase", "loadedBase",
                      "blinkLoaded", "x64InstructionsFetched", "passed", "stages"],
          "Issue #11 execution evidence")
    if execution["schemaVersion"] != 1 or execution["distribution"] != "build-tree-only" or \
            execution["dllSha256"] != dll_hash or execution["contextSize"] != 720 or \
            execution["blinkLoaded"] is not False or execution["x64InstructionsFetched"] != 0 or \
            execution["passed"] is not True:
        fail("Issue #11 execution prerequisite is invalid")
    if execution["inspectionSha256"] != digest(directory / "inspection.json"):
        fail("execution-to-inspection hash link is invalid")
    if inspection["manifestSha256"] != digest(directory / "build-manifest.json"):
        fail("inspection-to-build-manifest hash link is invalid")
    return dll_hash, producer_lock, sources, host_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    if not GIT.fullmatch(args.git_commit):
        fail("expected Git commit is invalid")
    root = args.bundle
    source_root = args.source_root.resolve()
    if not source_root.is_dir():
        fail("source root is not a directory")
    manifest_path = checked_file(root, "bundle.manifest.json")
    manifest = read_json(manifest_path)
    exact(manifest, ["schemaVersion", "distribution", "gitCommit", "files"], "bundle manifest")
    if manifest["schemaVersion"] != 1 or manifest["distribution"] != "run-scoped-ci-only" or \
            manifest["gitCommit"] != args.git_commit or not isinstance(manifest["files"], list):
        fail("bundle manifest contract is invalid")
    expected_paths = {f"{label}/{name}" for label in ("a", "b") for name in PAYLOAD_NAMES}
    expected_paths.add("reproducibility.json")
    records = {}
    for record in manifest["files"]:
        exact(record, ["path", "size", "sha256"], "bundle file record")
        if record["path"] in records or not isinstance(record["size"], int) or record["size"] < 0 or \
                not isinstance(record["sha256"], str) or not HASH.fullmatch(record["sha256"]):
            fail("bundle file record is invalid or duplicated")
        path = checked_file(root, record["path"])
        if path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            fail(f"bundle file hash/size mismatch: {record['path']}")
        records[record["path"]] = record
    if set(records) != expected_paths:
        fail("bundle inner file set differs from the allowlist")
    disk_files = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if disk_files != expected_paths | {"bundle.manifest.json"}:
        fail("bundle contains an unmanifested file")
    hash_a, lock_a, source_a, host_a = validate_set(root, "a", args.git_commit, source_root)
    hash_b, lock_b, source_b, host_b = validate_set(root, "b", args.git_commit, source_root)
    if hash_a != hash_b or lock_a != lock_b or source_a != source_b or host_a != host_b:
        fail("clean-build producer identities differ")
    repro = read_json(root / "reproducibility.json")
    exact(repro, ["schemaVersion", "distribution", "equal", "producerLock", "source", "outputs", "parser"],
          "reproducibility evidence")
    if repro["schemaVersion"] != 1 or repro["distribution"] != "build-tree-only" or \
            repro["equal"] is not True or repro["outputs"]["dll"]["sha256"] != hash_a or \
            repro["outputs"]["host"]["sha256"] != host_a or \
            repro["producerLock"] != lock_a or repro["source"] != source_a:
        fail("reproducibility evidence is invalid")
    print("Issue #14 artifact bundle validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
