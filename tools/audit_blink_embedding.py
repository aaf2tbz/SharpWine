#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
import re
from pathlib import Path

PINNED_REVISION = "f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580"
UNRESTRICTED_HANDLERS = (
    "OpNop",
    "OpMovZvqpIvqp",
    "OpMovEvqpGvqp",
    "OpMovGvqpEvqp",
    "OpBsuwiImm",
    "OpAlui",
    "OpJcc",
    "OpJmp",
    "OpRet",
    "OpLeaGvqpM",
    "OpCallJvds",
)
APPROVED_HANDLER_DEFINITIONS = UNRESTRICTED_HANDLERS + (
    "OpAluFlip",
    "Op0ff",
    "OpAddpsd",
    "OpSubpsd",
    "OpAluTest",
    "OpMovslGdqpEd",
    "OpNopEv",
)
TRACE_IDENTITIES = UNRESTRICTED_HANDLERS + (
    "OpAluFlip",
    "OpCallEq",
    "OpJmpEq",
    "OpAddpsd",
    "OpSubpsd",
    "OpAluTest",
    "OpMovslGdqpEd",
    "OpNopEv",
)
DENIED_HANDLERS = (
    "OpUd",
    "OpSyscall",
    "OpHlt",
    "OpCli",
    "OpSti",
    "OpInterrupt1",
    "OpInterrupt3",
    "OpInterruptImm",
    "OpInto",
)


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return digest_bytes(path.read_bytes())


def need(value, message):
    if not value:
        raise ValueError(message)


def definition_bytes(path, start_line, end_line, name):
    lines = path.read_bytes().splitlines(keepends=True)
    need(1 <= start_line <= end_line <= len(lines), f"invalid definition range {name}")
    data = b"".join(lines[start_line - 1 : end_line])
    text = data.decode("utf-8")
    need(
        re.match(rf"^(?:static )?void {re.escape(name)}\(P\) \{{", text) is not None,
        f"definition start drift {name}",
    )
    depth = 0
    saw_open = False
    closing_line = None
    for line_number, line in enumerate(text.splitlines(), start=start_line):
        for character in line:
            if character == "{":
                depth += 1
                saw_open = True
            elif character == "}":
                depth -= 1
                need(depth >= 0, f"definition brace drift {name}")
        if saw_open and depth == 0:
            closing_line = line_number
            break
    need(closing_line == end_line, f"definition end drift {name}")
    return data


def audit_handlers(source_root, provenance, machine_text):
    manifest = provenance["handlerManifest"]
    names = tuple(entry["name"] for entry in manifest)
    need(
        names == APPROVED_HANDLER_DEFINITIONS,
        "handler manifest addition, removal, or ordering drift",
    )
    need(len(names) == len(set(names)), "duplicate handler manifest entry")

    compared = tuple(re.findall(r"handler == (Op[A-Za-z0-9_]+)", machine_text))
    need(
        compared == APPROVED_HANDLER_DEFINITIONS + DENIED_HANDLERS,
        "compiled handler admission/denylist drift",
    )

    for entry in manifest:
        name = entry["name"]
        path = source_root / entry["file"]
        need(digest(path) == entry["sourceSha256"], f"defining source hash drift {name}")
        definition = definition_bytes(path, entry["startLine"], entry["endLine"], name)
        need(
            digest_bytes(definition) == entry["definitionSha256"],
            f"handler definition drift {name}",
        )

    for entry in provenance.get("reviewedHelperSources", ()):
        need(
            digest(source_root / entry["file"]) == entry["sourceSha256"],
            f"reviewed helper source hash drift {entry['file']}",
        )


def audit_trace(provenance, machine_text, embedding_text, embedding_header):
    # The decoder-owned handler identity is the single authority for both the
    # admission decision and diagnostic trace id. GemHandlerId retains stable
    # 1..19 ids for the accepted corpus, denies host/system boundaries by exact
    # handler identity, and assigns all other decoded safe instructions a
    # deterministic 0x1000+mopcode id. No second byte decoder is added.
    mapped = tuple(
        (name, int(value))
        for name, value in re.findall(
            r"if \(handler == (Op[A-Za-z0-9_]+)\) return (\d+);", machine_text
        )
    )
    need(
        tuple(name for name, _ in mapped) == UNRESTRICTED_HANDLERS,
        "unrestricted GemHandlerId ordering drift",
    )
    need(
        tuple(value for _, value in mapped) == tuple(range(1, len(UNRESTRICTED_HANDLERS) + 1)),
        "unrestricted GemHandlerId numbering drift",
    )
    gem_handler_id = re.search(
        r"int GemHandlerId\(nexgen32e_f handler, long rde, bool legacy32\) \{(.*?)\n\}",
        machine_text,
        re.S,
    )
    need(gem_handler_id is not None, "GemHandlerId definition missing")
    returned_ids = tuple(
        int(value)
        for value in re.findall(r"return (\d+);", gem_handler_id.group(1))
        if value != "0"
    )
    need(returned_ids == tuple(range(1, 20)), "GemHandlerId numbering/coverage drift")
    need(
        "return 0x1000 + Mopcode(rde);" in machine_text,
        "decoded-handler identity fallback missing",
    )
    need(
        "BLINK_GEM_HANDLER_DECODED_BASE" in embedding_header
        and "DescribeMopcode(id - BLINK_GEM_HANDLER_DECODED_BASE)" in embedding_text,
        "decoded-handler diagnostic mapping missing",
    )
    restricted = provenance["handlerTrace"]["restrictions"]
    need(
        restricted
        == [
            {
                "id": 12,
                "handler": "OpAluFlip",
                "forms": "ADD r32/r64, OR r64, XOR r32; register-register only",
            },
            {"id": 13, "handler": "Op0ff", "forms": "near indirect CALL, 0xff /2"},
            {"id": 14, "handler": "Op0ff", "forms": "near indirect JMP, 0xff /4"},
            {"id": 15, "handler": "OpAddpsd", "forms": "ADDSD xmm,xmm"},
            {"id": 16, "handler": "OpSubpsd", "forms": "SUBSD xmm,[rip+disp32]"},
            {"id": 17, "handler": "OpAluTest", "forms": "TEST r32,r32"},
            {"id": 18, "handler": "OpMovslGdqpEd", "forms": "MOVSXD r64,m32"},
            {"id": 19, "handler": "OpNopEv", "forms": "0x0f 0x1f alignment NOP"},
        ],
        "handler restriction provenance drift",
    )
    need(
        "return GemHandlerId(handler, rde, legacy32) != 0;" in machine_text,
        "GemIsAllowedHandler not derived from GemHandlerId",
    )
    need(
        "m->gemembed ||\n        (opclass != kOpPrecious && opclass != kOpSerializing)"
        in machine_text
        and machine_text.count(
            "unassert(m->gemembed || opclass == kOpNormal || opclass == kOpBranching);"
        )
        == 2,
        "GEM serializing-instruction JIT admission drift",
    )
    jit_policy = provenance.get("jitPolicy", {})
    need(
        jit_policy.get("pathBound") == "exactly one decoded instruction per GEM path"
        and jit_policy.get("productionFallback")
        == "a newly compiled aligned SIMD memory store retires once through Blink's native dispatcher; legacy REP string stores commit their complete destination range; compile rollback scans only the exact architectural write and guarded stack ranges; installed JIT hooks execute subsequent iterations; no CPUID family is masked",
        "bounded JIT policy provenance drift",
    )

    # Identity must originate at Blink's own selected decode/dispatch handler.
    need(
        re.search(
            r"GemHandlerId\(GetOpForRde\(m, m->xedd->op.rde\),\s*"
            r"m->xedd->op.rde,\s*"
            r"g->guest_mode == BLINK_GEM_GUEST_LEGACY_32\)",
            embedding_text,
        ),
        "trace identity not sourced from Blink decode dispatch",
    )
    need("blink_gem_machine_trace_reset" in embedding_text, "trace reset missing")
    need("BLINK_GEM_MAX_TRACE_ENTRIES" in embedding_header, "trace capacity missing")
    need(
        "g->trace_count < BLINK_GEM_MAX_TRACE_ENTRIES" in embedding_text
        and "g->trace_overflowed = 1;" in embedding_text,
        "trace overflow guard missing",
    )
    for forbidden in ("% BLINK_GEM_MAX_TRACE_ENTRIES",):
        need(forbidden not in embedding_text, f"trace storage must not wrap ({forbidden})")

    trace = provenance["handlerTrace"]
    need(trace["capacity"] == 256 and trace["abiVersion"] == 1, "trace provenance drift")
    identity = tuple((e["id"], e["name"]) for e in trace["identityMap"])
    need(
        identity == tuple((i + 1, name) for i, name in enumerate(TRACE_IDENTITIES)),
        "trace identity manifest drift",
    )


def audit_decode_attempt(provenance, machine_text, embedding_text, embedding_header):
    # The "last decode attempt" record captures Blink's own decode dispatch
    # result for every LoadInstruction, including denied handlers. It is reset
    # on every step, populated
    # immediately after a successful LoadInstruction using Blink's own
    # Mopcode()/DescribeMopcode() helpers, and never influences execution,
    # admission, or committed architectural state.
    need(
        "BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION" in embedding_header,
        "decode attempt ABI version missing",
    )
    need("struct blink_gem_decode_attempt" in embedding_header, "decode attempt struct missing")
    need(
        "blink_gem_machine_decode_attempt_info" in embedding_header,
        "decode attempt query missing",
    )
    need(
        "blink_gem_machine_decode_attempt_info" in embedding_text,
        "decode attempt query not defined",
    )
    need(
        "memset(&g->last_decode, 0, sizeof(g->last_decode));" in embedding_text,
        "decode attempt reset missing",
    )
    need(
        "g->last_decode.valid = 1u;" in embedding_text,
        "decode attempt valid flag not set on successful LoadInstruction",
    )
    need("Mopcode(m->xedd->op.rde)" in embedding_text,
         "decode attempt identity not sourced from Blink mopcode")
    need("DescribeMopcode((int)out->mopcode)" in embedding_text,
         "decode attempt name not sourced from Blink DescribeMopcode")
    need('#include "blink/debug.h"' in embedding_text,
         "decode attempt name source header missing")
    need(
        re.search(
            r"GemHandlerId\(GetOpForRde\(m, m->xedd->op.rde\),\s*"
            r"m->xedd->op.rde,\s*"
            r"g->guest_mode == BLINK_GEM_GUEST_LEGACY_32\)", embedding_text,
        ) and "g->last_decode.handler_id" in embedding_text,
        "decode attempt handler_id not sourced from GemHandlerId",
    )
    need(
        "name[BLINK_GEM_DECODE_ATTEMPT_NAME_BYTES]" in embedding_header
        and "uint8_t  valid;" in embedding_header,
        "decode attempt record fields missing",
    )
    decode_attempt = provenance["decodeAttempt"]
    need(decode_attempt["abiVersion"] == 1 and decode_attempt["nameBytes"] == 32
         and decode_attempt["resetPerStep"], "decode attempt provenance drift")
    need(
        decode_attempt["identitySource"]
        == "Mopcode(m->xedd->op.rde) + DescribeMopcode() in blink/gem_embed.c",
        "decode attempt identity source drift",
    )
    need(decode_attempt["nameSource"] == "blink/name.c DescribeMopcode()",
         "decode attempt name source drift")


def audit_phase3_capabilities(source_root, manifest_path, corpus_path):
    manifest = json.loads(manifest_path.read_text())
    need(manifest["schemaVersion"] == 1, "Phase 3 capability schema")
    need(manifest["hostIndependent"], "Phase 3 CPUID profile must be host independent")
    need(manifest["corpus"]["cases"] == 1024, "Phase 3 case total")
    need(manifest["corpus"]["comparisons"] == 2048, "Phase 3 comparison total")
    reference = manifest_path.parents[3] / manifest["corpus"]["reference"]
    need(reference.is_file(), "Phase 3 versioned reference corpus missing")
    need(digest(reference) == manifest["corpus"]["referenceSha256"],
         "Phase 3 reference corpus hash")
    need(
        manifest["corpus"]["categories"]
        == {"x87": 256, "mmx": 128, "simd": 384,
            "repAndSegmentation": 160, "cpuidAndContext": 96},
        "Phase 3 category totals",
    )
    expected = {
        ("FPU", "0x00000001", "edx", 0), ("CX8", "0x00000001", "edx", 8),
        ("CMOV", "0x00000001", "edx", 15), ("MMX", "0x00000001", "edx", 23),
        ("FXSR", "0x00000001", "edx", 24), ("SSE", "0x00000001", "edx", 25),
        ("SSE2", "0x00000001", "edx", 26), ("SSE3", "0x00000001", "ecx", 0),
        ("PCLMUL", "0x00000001", "ecx", 1), ("SSSE3", "0x00000001", "ecx", 9),
        ("SSE4.1", "0x00000001", "ecx", 19), ("SSE4.2", "0x00000001", "ecx", 20),
        ("POPCNT", "0x00000001", "ecx", 23), ("AES", "0x00000001", "ecx", 25),
        ("XSAVE", "0x00000001", "ecx", 26), ("OSXSAVE", "0x00000001", "ecx", 27),
        ("AVX", "0x00000001", "ecx", 28),
        ("FMA", "0x00000001", "ecx", 12),
        ("RDRAND", "0x00000001", "ecx", 30),
        ("AVX2", "0x00000007", "ebx", 5),
        ("ADX", "0x00000007", "ebx", 19),
        ("RDPID", "0x00000007", "ecx", 22),
        ("RDSEED", "0x00000007", "ebx", 18),
        ("ERMS", "0x00000007", "ebx", 9),
        ("BMI1", "0x00000007", "ebx", 3),
        ("BMI2", "0x00000007", "ebx", 8),
        ("RDTSCP", "0x80000001", "edx", 27),
    }
    actual = {(item["name"], item["leaf"], item["register"], item["bit"])
              for item in manifest["advertised"]}
    need(actual == expected, "advertised CPUID capability drift")
    need(
        set(manifest["masked"])
        == {"FSGSBASE", "CX16",
            "LONG_MODE", "SYSCALL"},
        "masked CPUID capability drift",
    )
    sources = "\n".join(path.read_text() for path in (source_root / "blink").glob("*.c"))
    corpus = corpus_path.read_text()
    for item in manifest["advertised"]:
        need(item["handlers"], f"missing handlers for {item['name']}")
        for handler in item["handlers"]:
            need(f"{handler}(" in sources, f"missing advertised handler {handler}")
        witness_source = corpus
        if "witnessSource" in item:
            witness_path = manifest_path.parents[3] / item["witnessSource"]
            need(witness_path.is_file(), f"missing witness source for {item['name']}")
            witness_source = witness_path.read_text()
        need(item["witness"] in witness_source, f"missing corpus witness for {item['name']}")
        if "cpuidWitness" in item:
            need(item["cpuidWitness"] in witness_source,
                 f"missing CPUID witness for {item['name']}")
        if "programWitness" in item:
            need(item["programWitness"] in corpus,
                 f"missing program-loading witness for {item['name']}")
        for witness in item.get("opcodeWitnesses", ()):
            need(witness in corpus, f"missing opcode witness {item['name']} {witness}")
    sse41 = next(item for item in manifest["advertised"] if item["name"] == "SSE4.1")
    sse42 = next(item for item in manifest["advertised"] if item["name"] == "SSE4.2")
    need(len(sse41["opcodeWitnesses"]) >= 38, "incomplete SSE4.1 opcode witnesses")
    need(len(sse42["opcodeWitnesses"]) >= 6, "incomplete SSE4.2 opcode witnesses")
    need("void OpSse4(P)" in sources and "PackedStringCompare(A" in sources,
         "portable SSE4 family handler missing")
    need("Phase 3 corpus passed" in corpus, "Phase 3 corpus completion oracle missing")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--jit-patch", type=Path, required=True)
    parser.add_argument("--i386-patch", type=Path, required=True)
    parser.add_argument("--sync-patch", type=Path, required=True)
    parser.add_argument("--rosetta-patch", type=Path, required=True)
    parser.add_argument("--rosetta-sse41-patch", type=Path, required=True)
    parser.add_argument("--phase1-patch", type=Path, required=True)
    parser.add_argument("--phase2-patch", type=Path, required=True)
    parser.add_argument("--phase3-patch", type=Path, required=True)
    parser.add_argument("--phase4-patch", type=Path, required=True)
    parser.add_argument("--phase6-patch", type=Path, required=True)
    parser.add_argument("--phase55-patch", type=Path, required=True)
    parser.add_argument("--phase55-optimization-patch", type=Path, required=True)
    parser.add_argument("--phase55-concurrency-patch", type=Path, required=True)
    parser.add_argument("--cmpxchg-patch", type=Path, required=True)
    parser.add_argument("--state-abi-patch", type=Path, required=True)
    parser.add_argument("--xsave-foundation-patch", type=Path, required=True)
    parser.add_argument("--virtual-tsc-patch", type=Path, required=True)
    parser.add_argument("--bmi1-patch", type=Path, required=True)
    parser.add_argument("--bmi2-patch", type=Path, required=True)
    parser.add_argument("--rdtscp-patch", type=Path, required=True)
    parser.add_argument("--avx-foundation-patch", type=Path, required=True)
    parser.add_argument("--avx-packed-patch", type=Path, required=True)
    parser.add_argument("--avx-promoted-patch", type=Path, required=True)
    parser.add_argument("--avx-store-patch", type=Path, required=True)
    parser.add_argument("--avx-cross-lane-patch", type=Path, required=True)
    parser.add_argument("--avx-shift-patch", type=Path, required=True)
    parser.add_argument("--avx-misc-patch", type=Path, required=True)
    parser.add_argument("--avx-mask-patch", type=Path, required=True)
    parser.add_argument("--avx-conversion-patch", type=Path, required=True)
    parser.add_argument("--avx-inventory-patch", type=Path, required=True)
    parser.add_argument("--avx-cpuid-patch", type=Path, required=True)
    parser.add_argument("--avx2-packed-patch", type=Path, required=True)
    parser.add_argument("--avx2-data-patch", type=Path, required=True)
    parser.add_argument("--avx2-memory-patch", type=Path, required=True)
    parser.add_argument("--avx2-cpuid-patch", type=Path, required=True)
    parser.add_argument("--fma-patch", type=Path, required=True)
    parser.add_argument("--fma-cpuid-patch", type=Path, required=True)
    parser.add_argument("--adx-patch", type=Path, required=True)
    parser.add_argument("--adx-cpuid-patch", type=Path, required=True)
    parser.add_argument("--rdpid-patch", type=Path, required=True)
    parser.add_argument("--rdpid-cpuid-patch", type=Path, required=True)
    parser.add_argument("--random-patch", type=Path, required=True)
    parser.add_argument("--random-cpuid-patch", type=Path, required=True)
    parser.add_argument("--resident-state-patch", type=Path, required=True)
    parser.add_argument("--block-linking-patch", type=Path, required=True)
    parser.add_argument("--aligned-simd-store-patch", type=Path, required=True)
    parser.add_argument("--precise-host-dirty-patch", type=Path, required=True)
    parser.add_argument("--tiered-resident-fastpath-patch", type=Path, required=True)
    parser.add_argument("--capability-manifest", type=Path, required=True)
    parser.add_argument("--phase3-corpus", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()

    provenance = json.loads(args.provenance.read_text())
    need(provenance["schemaVersion"] == 46, "provenance schema")
    need(provenance["revision"] == PINNED_REVISION, "revision")
    need(digest(args.patch) == provenance["patchSha256"], "patch hash")
    need(digest(args.jit_patch) == provenance["jitPatchSha256"], "JIT patch hash")
    need(digest(args.i386_patch) == provenance["i386PatchSha256"], "i386 patch hash")
    need(digest(args.sync_patch) == provenance["syncPatchSha256"], "sync patch hash")
    need(
        digest(args.rosetta_patch) == provenance["rosettaPatchSha256"],
        "Rosetta conformance patch hash",
    )
    need(
        digest(args.rosetta_sse41_patch) == provenance["rosettaSse41PatchSha256"],
        "Rosetta SSE4.1 patch hash",
    )
    need(digest(args.phase1_patch) == provenance["phase1PatchSha256"], "phase 1 patch hash")
    need(digest(args.phase2_patch) == provenance["phase2PatchSha256"], "phase 2 patch hash")
    need(digest(args.phase3_patch) == provenance["phase3PatchSha256"], "phase 3 patch hash")
    need(digest(args.phase4_patch) == provenance["phase4PatchSha256"], "phase 4 patch hash")
    need(digest(args.phase6_patch) == provenance["phase6PatchSha256"], "phase 6 patch hash")
    need(digest(args.phase55_patch) == provenance["phase55PatchSha256"], "phase 5.5 patch hash")
    need(
        digest(args.phase55_optimization_patch)
        == provenance["phase55OptimizationPatchSha256"],
        "phase 5.5 optimization patch hash",
    )
    need(
        digest(args.phase55_concurrency_patch) == provenance["phase55ConcurrencyPatchSha256"],
        "phase 5.5 concurrency patch hash",
    )
    need(
        digest(args.cmpxchg_patch) == provenance["cmpxchgPatchSha256"],
        "cmpxchg flag-order patch hash",
    )
    need(
        digest(args.state_abi_patch) == provenance["stateAbiPatchSha256"],
        "state ABI ymm/xcr0 patch hash",
    )
    need(
        digest(args.xsave_foundation_patch) == provenance["xsaveFoundationPatchSha256"],
        "VEX/XSAVE foundation patch hash",
    )
    need(
        digest(args.virtual_tsc_patch) == provenance["virtualTscPatchSha256"],
        "virtual TSC admission patch hash",
    )
    need(digest(args.bmi1_patch) == provenance["bmi1PatchSha256"], "BMI1 patch hash")
    need(digest(args.bmi2_patch) == provenance["bmi2PatchSha256"], "BMI2 patch hash")
    need(digest(args.rdtscp_patch) == provenance["rdtscpPatchSha256"], "RDTSCP patch hash")
    need(
        digest(args.avx_foundation_patch) == provenance["avxFoundationPatchSha256"],
        "AVX foundation patch hash",
    )
    need(
        digest(args.avx_packed_patch) == provenance["avxPackedPatchSha256"],
        "AVX packed-lane patch hash",
    )
    need(
        digest(args.avx_promoted_patch) == provenance["avxPromotedPatchSha256"],
        "AVX promoted-128 patch hash",
    )
    need(
        digest(args.avx_store_patch) == provenance["avxStorePatchSha256"],
        "AVX store patch hash",
    )
    need(
        digest(args.avx_cross_lane_patch) == provenance["avxCrossLanePatchSha256"],
        "AVX cross-lane patch hash",
    )
    need(
        digest(args.avx_shift_patch) == provenance["avxShiftPatchSha256"],
        "AVX immediate-shift patch hash",
    )
    need(
        digest(args.avx_misc_patch) == provenance["avxMiscPatchSha256"],
        "AVX miscellaneous-destination patch hash",
    )
    need(
        digest(args.avx_mask_patch) == provenance["avxMaskPatchSha256"],
        "AVX mask-move patch hash",
    )
    need(
        digest(args.avx_conversion_patch) == provenance["avxConversionPatchSha256"],
        "AVX conversion patch hash",
    )
    need(
        digest(args.avx_inventory_patch) == provenance["avxInventoryPatchSha256"],
        "AVX inventory-closure patch hash",
    )
    need(
        digest(args.avx_cpuid_patch) == provenance["avxCpuidPatchSha256"],
        "AVX CPUID patch hash",
    )
    need(
        digest(args.avx2_packed_patch) == provenance["avx2PackedPatchSha256"],
        "AVX2 packed-lane patch hash",
    )
    need(
        digest(args.avx2_data_patch) == provenance["avx2DataPatchSha256"],
        "AVX2 data-movement patch hash",
    )
    need(
        digest(args.avx2_memory_patch) == provenance["avx2MemoryPatchSha256"],
        "AVX2 memory/gather patch hash",
    )
    need(
        digest(args.avx2_cpuid_patch) == provenance["avx2CpuidPatchSha256"],
        "AVX2 CPUID patch hash",
    )
    need(digest(args.fma_patch) == provenance["fmaPatchSha256"], "FMA patch hash")
    need(
        digest(args.fma_cpuid_patch) == provenance["fmaCpuidPatchSha256"],
        "FMA CPUID patch hash",
    )
    need(digest(args.adx_patch) == provenance["adxPatchSha256"], "ADX patch hash")
    need(
        digest(args.adx_cpuid_patch) == provenance["adxCpuidPatchSha256"],
        "ADX CPUID patch hash",
    )
    need(digest(args.rdpid_patch) == provenance["rdpidPatchSha256"], "RDPID patch hash")
    need(
        digest(args.rdpid_cpuid_patch) == provenance["rdpidCpuidPatchSha256"],
        "RDPID CPUID patch hash",
    )
    need(digest(args.random_patch) == provenance["randomPatchSha256"], "random patch hash")
    need(
        digest(args.random_cpuid_patch) == provenance["randomCpuidPatchSha256"],
        "random CPUID patch hash",
    )
    need(
        digest(args.resident_state_patch) == provenance["residentStatePatchSha256"],
        "resident quantum-state patch hash",
    )
    need(
        digest(args.block_linking_patch) == provenance["blockLinkingPatchSha256"],
        "block-linking patch hash",
    )
    need(
        digest(args.aligned_simd_store_patch)
        == provenance["alignedSimdStorePatchSha256"],
        "aligned SIMD store patch hash",
    )
    need(
        digest(args.precise_host_dirty_patch)
        == provenance["preciseHostDirtyPatchSha256"],
        "precise host-dirty patch hash",
    )
    need(
        digest(args.tiered_resident_fastpath_patch)
        == provenance["tieredResidentFastpathPatchSha256"],
        "tiered resident fast-path patch hash",
    )
    for relative, expected_hash in provenance["postPatch"].items():
        need(digest(args.source / relative) == expected_hash, f"hash {relative}")

    embedding = (args.source / "blink/gem_embed.c").read_text()
    embedding_header = (args.source / "blink/gem_embed.h").read_text()
    machine = (args.source / "blink/machine.c").read_text()
    need("Mopcode(rde) == 0x131" in machine, "legacy32 RDTSC host-handler exclusion missing")
    need(
        "last_decode.instruction_length = (uint8_t)Oplength" in embedding,
        "decode-attempt instruction length missing",
    )
    fusion = (args.source / "blink/fusion.c").read_text()
    jit = (args.source / "blink/jit.c").read_text()
    jit_header = (args.source / "blink/jit.h").read_text()
    instruction = (args.source / "blink/instruction.c").read_text()
    legacy = (args.source / "blink/legacy.c").read_text()
    stack = (args.source / "blink/stack.c").read_text()
    string = (args.source / "blink/string.c").read_text()
    throw = (args.source / "blink/throw.c").read_text()
    for symbol in (
        "NewSystem(",
        "NewMachine(",
        "LoadInstruction(",
        "GetOpForRde(",
        "GemCompileInstruction(",
        "ExecuteInstruction(",
        "ReserveVirtual(",
        "ProtectVirtual(",
        "sigsetjmp(",
    ):
        need(symbol in embedding, f"missing real Blink call {symbol}")
    for forbidden in (
        "static int Byte(",
        "Immediate(",
        "DecodeInstruction(",
        "switch (op",
    ):
        need(forbidden not in embedding, f"forbidden {forbidden}")

    for required in (
        "blink_gem_machine_create_with_config(",
        "BLINK_GEM_ENGINE_JIT",
        "pthread_once_(&g_blink_gem_init_once, blink_gem_init_runtime)",
        "InitMap();",
        "jit_compilations",
        "write_xor_execute",
        "drop_page(g, 0)",
        "BLINK_GEM_GUEST_LEGACY_32",
        "XED_MACHINE_MODE_LEGACY_32",
        "guest_address(g, in->rip)",
        "m->fs.base = s->fs_base ? s->fs_base : s->segments[4].base",
        "DeserializeLdbl(s->x87[i])",
        "SerializeLdbl(out->x87[i], m->fpu.st[i])",
        "m->seg[i].limit = s->segments[i].limit",
        "m->fpu.ip = s->fip",
        "blink_gem_machine_sync(",
        "BLINK_GEM_EXCEPTION_DIVIDE",
        "BLINK_GEM_EXCEPTION_ILLEGAL_INSTRUCTION",
        "BLINK_GEM_EXCEPTION_OVERFLOW",
        "block_linked_successor(",
        "return_prediction_hits",
        "invalidate_blocks(g, address, size)",
        "blink_gem_machine_invalidate_memory(",
    ):
        need(required in embedding, f"missing bounded JIT embedding invariant {required}")
    need("m->gemembed || opclass == kOpBranching" in machine, "JIT path is not one instruction")
    need(
        "(m->gemembed || !op_overlaps_page_boundary)" in machine
        and "page - 4096" in embedding,
        "GEM cross-page instruction JIT/invalidation contract missing",
    )
    need(
        "m->faultaddr = ip + i;" in instruction
        and "if (!m->gemembed || !m->faultaddr) m->faultaddr = pc;" in instruction,
        "GEM cross-page decode fault address missing",
    )
    need(
        "SetWriteAddr(m, v, osz);" in stack
        and "SetReadAddr(m, v, osz);" in stack
        and legacy.count("memcpy(b, Load(m, addr, n, b), n);") == 2,
        "GEM precise stack access/fault tracking missing",
    )
    need(
        string.count("m->gemembed && m->mode.omode == XED_MODE_LEGACY") == 2,
        "legacy GEM REP byte operations can bypass restartable iteration state",
    )
    need(
        fusion.count("if (m->gemembed) return false;") == 2,
        "GEM branch fusion can consume more than one decoded instruction",
    )
    need(
        "GeneralDispatch(DISPATCH_NOTHING);" in machine
        and "hook && hook != JitlessDispatch" in machine
        and "if (!GemCompileInstruction(m))" in embedding,
        "GEM compile path may accept an interpreter staging hook",
    )
    need("#ifdef BLINK_GEM_EMBEDDING" in jit_header, "bounded JIT sizing missing")
    need("#define kJitMemorySize   1048576" in jit_header, "bounded JIT arena drift")
    need("pthread_jit_write_protect_np(enabled);" in jit, "Apple JIT W^X control missing")
    need("__builtin_add_overflow" in jit, "64-bit JIT arena alignment guard missing")

    audit_handlers(args.source, provenance, machine)
    audit_trace(provenance, machine, embedding, embedding_header)
    audit_decode_attempt(provenance, machine, embedding, embedding_header)
    audit_phase3_capabilities(args.source, args.capability_manifest, args.phase3_corpus)
    need(
        "if (m->gemembed)" in throw and "siglongjmp(m->onhalt, code)" in throw,
        "structured halt missing",
    )
    print("real Blink bounded interpreter/JIT embedding audit passed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"Blink embedding audit rejected: {error}")
