#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed source inventory for the pinned Blink memory-order implementation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REQUIRED_SNIPPETS = {
    "blink/bus.c": [
        "memory_order_acquire",
        "memory_order_release",
        "void LockBus(const u8 *locality)",
        "z = Read64(p);",
        "Write64(p, x);",
    ],
    "blink/uop.c": [
        "MICRO_OP static i64 NativeLoad64(const u8 *p)",
        "return *(const u64 *)p;",
        "MICRO_OP static void NativeStore64(u8 *p, u64 x)",
        "*(u64 *)p = x;",
    ],
    "blink/machine.c": [
        "static void OpMfence(P)",
        "atomic_thread_fence(memory_order_seq_cst);",
        "static void OpLfence(P)",
        "static void OpSfence(P)",
    ],
    "blink/smc.c": [
        "atomic_store_explicit(&m->attention, true, memory_order_release);",
        "ResetJitPage(&m->system->jit, page);",
    ],
    "blink/xchg.c": ["atomic_exchange_explicit", "LockBus(p);", "UnlockBus(p);"],
    "blink/alui.c": ["atomic_compare_exchange_weak_explicit", "LockBus(p);"],
    "blink/string.c": ["atomic_thread_fence(memory_order_acquire);", "atomic_thread_fence(memory_order_release);"],
    "blink/jit.c": ["pthread_jit_write_protect_np", "memory_order_acquire", "memory_order_release"],
    "blink/memory.c": [
        "AddPageToSmcQueue(m, virt);",
        "FindPageTableEntry",
        "ThrowSegmentationFault(m, v);",
        "u8 *BeginStore(",
        "void EndStore(",
    ],
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    provenance = load_json(args.provenance)
    blink = provenance.get("blink")
    if not isinstance(blink, dict):
        raise ValueError("provenance blink record is missing")
    revision = blink.get("revision")
    reviewed = blink.get("reviewedFiles")
    if not isinstance(revision, str) or len(revision) != 40:
        raise ValueError("provenance Blink revision is invalid")
    if not isinstance(reviewed, dict) or set(reviewed) != set(REQUIRED_SNIPPETS):
        raise ValueError("provenance reviewed-file set does not match the inventory")

    verified: dict[str, str] = {}
    for relative, snippets in REQUIRED_SNIPPETS.items():
        path = args.source / relative
        data = path.read_bytes()
        digest = sha256(data)
        if digest != reviewed[relative]:
            raise ValueError(f"{relative}: expected sha256 {reviewed[relative]}, got {digest}")
        text = data.decode("utf-8")
        for snippet in snippets:
            if snippet not in text:
                raise ValueError(f"{relative}: reviewed construct disappeared: {snippet!r}")
        verified[relative] = digest

    result = {
        "schemaVersion": 1,
        "blinkRevision": revision,
        "verifiedFiles": verified,
        "facts": {
            "interpreterAlignedLoads": "C acquire atomics on non-x86 hosts",
            "interpreterAlignedStores": "C release atomics on non-x86 hosts",
            "interpreterUnalignedAccesses": "byte-copy helpers",
            "jitScalarLoadsAndStores": "plain native pointer accesses",
            "guestFences": "C sequentially-consistent fence",
            "lockedOperations": "C atomics and hashed bus-lock fallback",
            "selfModifyingCode": "release attention flag and JIT-page reset",
            "faultOrdering": "checked translation with BeginStore/EndStore staging",
            "hostCompilerAssumptions": "C atomics in the interpreter and plain typed JIT accesses",
        },
        "acceptance": "inventory-only; concurrent interpreter and JIT remain unproven",
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
