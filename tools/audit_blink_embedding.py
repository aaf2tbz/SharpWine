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
        r"int GemHandlerId\(nexgen32e_f handler, long rde\) \{(.*?)\n\}",
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
        "return GemHandlerId(handler, rde) != 0;" in machine_text,
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
        == "none; interpreter mode is an explicit test oracle only",
        "bounded JIT policy provenance drift",
    )

    # Identity must originate at Blink's own selected decode/dispatch handler.
    need(
        re.search(
            r"GemHandlerId\(GetOp\(Mopcode\(m->xedd->op.rde\)\),\s*"
            r"m->xedd->op.rde\)",
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
    # Identity must be sourced from Blink's own already-decoded mopcode; no
    # second decoder, byte scanner, or external lookup may be introduced.
    need(
        "Mopcode(m->xedd->op.rde)" in embedding_text,
        "decode attempt identity not sourced from Blink mopcode",
    )
    need(
        "DescribeMopcode((int)g->last_decode.mopcode)" in embedding_text,
        "decode attempt name not sourced from Blink DescribeMopcode",
    )
    need(
        '#include "blink/debug.h"' in embedding_text,
        "decode attempt name source header missing",
    )
    need(
        re.search(
            r"GemHandlerId\(GetOp\(Mopcode\(m->xedd->op.rde\)\),\s*"
            r"m->xedd->op.rde\)",
            embedding_text,
        )
        and "g->last_decode.handler_id" in embedding_text,
        "decode attempt handler_id not sourced from GemHandlerId",
    )
    # The struct must carry an explicit Blink-provided name (length bounded)
    # and a valid flag; the machine-owned struct is the single authority.
    need(
        "name[BLINK_GEM_DECODE_ATTEMPT_NAME_BYTES]" in embedding_header
        and "uint8_t  valid;" in embedding_header,
        "decode attempt record fields missing",
    )
    decode_attempt = provenance["decodeAttempt"]
    need(
        decode_attempt["abiVersion"] == 1
        and decode_attempt["nameBytes"] == 32
        and decode_attempt["resetPerStep"],
        "decode attempt provenance drift",
    )
    need(
        decode_attempt["identitySource"]
        == "Mopcode(m->xedd->op.rde) + DescribeMopcode() in blink/gem_embed.c",
        "decode attempt identity source drift",
    )
    need(
        decode_attempt["nameSource"] == "blink/name.c DescribeMopcode()",
        "decode attempt name source drift",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--jit-patch", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()

    provenance = json.loads(args.provenance.read_text())
    need(provenance["schemaVersion"] == 3, "provenance schema")
    need(provenance["revision"] == PINNED_REVISION, "revision")
    need(digest(args.patch) == provenance["patchSha256"], "patch hash")
    need(digest(args.jit_patch) == provenance["jitPatchSha256"], "JIT patch hash")
    for relative, expected_hash in provenance["postPatch"].items():
        need(digest(args.source / relative) == expected_hash, f"hash {relative}")

    embedding = (args.source / "blink/gem_embed.c").read_text()
    embedding_header = (args.source / "blink/gem_embed.h").read_text()
    machine = (args.source / "blink/machine.c").read_text()
    fusion = (args.source / "blink/fusion.c").read_text()
    jit = (args.source / "blink/jit.c").read_text()
    jit_header = (args.source / "blink/jit.h").read_text()
    instruction = (args.source / "blink/instruction.c").read_text()
    throw = (args.source / "blink/throw.c").read_text()
    for symbol in (
        "NewSystem(",
        "NewMachine(",
        "LoadInstruction(",
        "GetOp(",
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
