#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
import re
from pathlib import Path

PINNED_REVISION = "f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580"
APPROVED_HANDLERS = (
    "OpNop",
    "OpMovZvqpIvqp",
    "OpMovEvqpGvqp",
    "OpMovGvqpEvqp",
    "OpBsuwiImm",
    "OpAlui",
    "OpJcc",
    "OpJmp",
    "OpRet",
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
    need(names == APPROVED_HANDLERS, "handler manifest addition, removal, or ordering drift")
    need(len(names) == len(set(names)), "duplicate handler manifest entry")

    compared = tuple(re.findall(r"handler == (Op[A-Za-z0-9_]+)", machine_text))
    need(compared == APPROVED_HANDLERS, "compiled handler allowlist drift")

    for entry in manifest:
        name = entry["name"]
        path = source_root / entry["file"]
        need(digest(path) == entry["sourceSha256"], f"defining source hash drift {name}")
        definition = definition_bytes(path, entry["startLine"], entry["endLine"], name)
        need(
            digest_bytes(definition) == entry["definitionSha256"],
            f"handler definition drift {name}",
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()

    provenance = json.loads(args.provenance.read_text())
    need(provenance["schemaVersion"] == 2, "provenance schema")
    need(provenance["revision"] == PINNED_REVISION, "revision")
    need(digest(args.patch) == provenance["patchSha256"], "patch hash")
    for relative, expected_hash in provenance["postPatch"].items():
        need(digest(args.source / relative) == expected_hash, f"hash {relative}")

    embedding = (args.source / "blink/gem_embed.c").read_text()
    machine = (args.source / "blink/machine.c").read_text()
    throw = (args.source / "blink/throw.c").read_text()
    for symbol in (
        "NewSystem(",
        "NewMachine(",
        "LoadInstruction(",
        "GetOp(",
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
        "pthread_jit",
        "MAP_JIT",
        "APRR",
    ):
        need(forbidden not in embedding, f"forbidden {forbidden}")

    audit_handlers(args.source, provenance, machine)
    need(
        "if (m->gemembed)" in throw and "siglongjmp(m->onhalt, code)" in throw,
        "structured halt missing",
    )
    print("real Blink interpreter embedding audit passed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"Blink embedding audit rejected: {error}")
