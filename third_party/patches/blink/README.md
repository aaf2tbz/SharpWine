# Blink real-interpreter GEM embedding patch

This ISC patch applies only to Blink `f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580` from the
SHA-256 verified upstream archive. The zero-context patch SHA-256 is
`03acc9bc848338e7614a1f487054cc6995e5826c94c4ddbf17365d6a7ae1891a`. It adds an opaque
bounded step API around Blink's existing `NewSystem`/`NewMachine`, `LoadInstruction`, decoded `GetOp` handler selection, and
`ExecuteInstruction`/`JitlessDispatch`. It does not contain a decoder or opcode parser.

The initial handler-function allowlist is source-reviewed and intentionally excludes every x87,
MMX, SIMD, syscall, string, and atomic handler. Provenance records the exact approved names,
defining-file hashes, definition ranges, and definition hashes; the audit rejects additions or
drift. This is not a semantic claim about any handler outside that manifest. Raw canonical x87/MM
slots remain an untouched
sidecar. Missing pages are bounded adapter-owned Blink mappings. Every instruction refreshes those
shadows from a GEM transaction, validates tracked fetch/read/write ranges, compares bounded full
pages, and atomically commits staged pages before CPU export. `HaltMachine` has an explicit
embedding-only longjmp path that does not deliver Linux guest signals.

Blink's own decode dispatch also feeds a diagnostic, machine-owned, bounded (`256`-entry,
sticky-overflow, non-wrapping) handler-identity trace. `GemHandlerId(GetOp(Mopcode(rde)))` maps the
exact selected handler pointer to a stable id and is the single authority for both the allowlist
decision and the trace; one entry is appended per retired instruction, and unsupported/faulted/
pre-decode outcomes append nothing. The trace never affects execution, allowlisting, or committed
architectural state.

The same decode dispatch exposes a separate, machine-owned "last decode attempt" record that
captures the exact `Mopcode(rde)`, the `DescribeMopcode()` mnemonic Blink's own
decoder assigned, and the `GemHandlerId()` allowlist id (or `0` outside the reviewed set).
Reviewed LEA and relative-CALL handlers carry ids 10 and 11. ID 12 admits only
the register-register REX.W form of mopcode `0x003` from the shared `OpAluFlip`
handler; other widths, memory forms, and operations remain rejected.
The record is reset on every step, populated only after
a successful `LoadInstruction`, and is diagnostic-only — it never influences execution,
allowlisting, or committed architectural state.

Exact build:

```sh
./configure --disable-jit
$MAKE clean
$MAKE -j2 o//blink/blink.a
```

CMake resolves `$MAKE` by searching for `gmake` and then `make`, performs those commands in the
verified FetchContent tree, and links the actual full static interpreter archive. `HAVE_JIT` is absent; JIT code is not referenced by the accepting target.
The embedding API consists only of `blink_gem_machine_create`, `blink_gem_machine_destroy`,
`blink_gem_machine_step`, `blink_gem_embedding_version`, the diagnostic trace queries
`blink_gem_machine_trace_reset`, `blink_gem_machine_trace_info`, `blink_gem_machine_trace_read`,
`blink_gem_handler_name`, and the diagnostic decode-attempt queries
`blink_gem_machine_decode_attempt_info` and `blink_gem_decode_attempt_name`. See
`docs/architecture/adr/0008-blink-embedding.provenance.json` and `LICENSES/Blink-ISC.txt`.
