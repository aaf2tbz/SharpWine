# Blink real-interpreter GEM embedding patch

This ISC patch applies only to Blink `f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580` from the
SHA-256 verified upstream archive. The zero-context patch SHA-256 is
`36774371e862c7a44775b19d16b130c23ab0beccf223d755b0321225c7fbfd03`. It adds an opaque
bounded step API around Blink's existing `NewSystem`/`NewMachine`, `LoadInstruction`, decoded `GetOp` handler selection, and
`ExecuteInstruction`/`JitlessDispatch`. It does not contain a decoder or opcode parser.

The handler-function allowlist is source-reviewed and intentionally excludes every x87, MMX,
syscall, string, and atomic handler plus every SIMD form outside the two scalar-double operations
required by the authentic fixture. Provenance records the exact approved names,
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
Reviewed LEA and relative-CALL handlers carry ids 10 and 11. IDs 12–19 narrowly admit the
authentic fixture's register ALU forms, near indirect CALL/JMP, scalar-double ADD/SUB,
32-bit register TEST, memory-source MOVSXD, and multi-byte alignment NOP. Each operand-width and
addressing restriction is enforced after Blink's own decode; neighboring forms remain rejected.
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
`blink_gem_machine_sync`, `blink_gem_machine_trace_reset`, `blink_gem_machine_trace_info`, `blink_gem_machine_trace_read`,
`blink_gem_handler_name`, and the diagnostic decode-attempt queries
`blink_gem_machine_decode_attempt_info` and `blink_gem_decode_attempt_name`. See
`docs/architecture/adr/0008-blink-embedding.provenance.json` and `LICENSES/Blink-ISC.txt`.

`0003-gem-i386-legacy-mode.patch` (SHA-256
`50499a434838be5620fb86d4a6e214e6a9545eeac0dd059b1f56385a78b6cbeb`)
adds an explicit legacy-32 decoder/executor mode without changing the accepted long-mode default.
It binds FS-based TEB and x87 state, rejects addresses outside `[0, 2^32)`, and keeps Blink's
reviewed long-mode page-table system underneath the adapter because Blink's virtual-memory helper
requires that system mode. The thread-confined machine itself executes with
`XED_MACHINE_MODE_LEGACY_32`; all mappings remain disposable GEM transaction snapshots.

`0005-gem-rosetta-i386-conformance.patch` (SHA-256
`6c704396c72f739b5e5bd1cf22dc0f85ddb3cb69160fbcc965fcb44cba0c708a`)
captures semantics established by differential execution against Rosetta 2. It corrects auxiliary
carry for INC and NEG, computes CMPXCHG flags from destination minus accumulator for every operand
width and memory path, corrects nonzero LZCNT results, and implements the SSE4.1 PMINSD opcode in
Blink's existing static instruction runtime. PMINSD is core interpreter support, not a dynamically
loaded compatibility shim; its legacy MMX encoding remains an invalid-opcode fault.

`0006-gem-rosetta-sse41-minmax.patch` (SHA-256
`7aca01d50c670da77df8c8366806b2de7d42c3a21ba47532c1e21b00d00aa9be`)
completes the SSE4.1 packed integer min/max family exposed by the expanded Rosetta corpus:
PMINSB, PMINSD, PMINUW, PMINUD, PMAXSB, PMAXSD, PMAXUW, and PMAXUD.

`0007-gem-i386-stack-cmpxchg8b.patch` (SHA-256
`d7104347dead5681aad60876b04889de19f4cadea6bedc1c7a4ae5d4bcd03eee`)
routes PUSHA stack frames and CMPXCHG8B replacements through Blink's tracked
write paths, and gives legacy PUSHF/POPF the Windows user-mode IF/IOPL view.

`0008-gem-i386-normalized-exceptions.patch` (SHA-256
`df5b9d33a5945df0fa53ac6a412d7df0d416d936c0a9b5ae7b01e6dadc27e354`)
converts Blink-private divide, overflow, decode, and undefined-instruction halt
values into stable embedding exception classes. The GEM i386 boundary maps
only those reviewed values into Windows-visible exceptions; private halt codes
never escape the embedding ABI. Stack reads and writes now preserve their
precise access type and failing cross-page address. Guest writes to executable
shadow pages also invalidate that page and its possible cross-page predecessor
before the next JIT execution.

`0011-gem-preserve-shadow-snapshot-fault.patch` (SHA-256
`c3ccbbee11adb765bb80d54560e1e3240668136f0a6f03c8c06fcd961d8a05b0`)
preserves the exact memory error when a legacy i386 shadow snapshot fails.
This prevents a freed external Wine mapping from reaching either execution
engine and keeps the fault address, access class, and memory status available
to the compatibility boundary.

`0012-gem-bounded-multi-instruction-run.patch` (SHA-256
`ac718a33b9f8920b39a9746d6515ab2c79feafbd0aed7b96e094577a1f1867c9`)
adds the versioned bounded run request, stop-PC and asynchronous boundaries,
and reuses Blink's decode cache within a run while retaining one-instruction
step semantics.

`0013-gem-concurrent-quantum-optimization.patch` (SHA-256
`d9ab44fbd1e67c791a4f0d0960d308122471aa23fa4e034dbba998f1c2f37980`)
keeps reviewed NOP and branch sequences resident under one recovery frame,
defers non-guard dependency validation to the GEM quantum boundary, and uses
a lightweight integer-state export between safe resident instructions.

`0014-gem-concurrent-host-page-registry.patch` (SHA-256
`cd4894556b28691082307bb23d74a83d51073e63dee329cd8f66384734e49c4f`)
preallocates and serializes the embedding-only host-page registry so separate
Blink machines can fault in shadow pages concurrently without racing a global
registry reallocation.

`0017-gem-i386-vex-xsave-foundation.patch` (SHA-256
`6599e93fc0dd951e45eb124a24677f28d482871f133bbaf5f4d3cf6ff9b267e0`)
adds protected-mode VEX disambiguation while retaining the per-family gate,
implements standard-format XSAVE/XRSTOR and XGETBV over the ABI-v3 YMM/XCR0
state, maps protection faults into a stable embedding exception, and rejects
XSAVEOPT instead of inheriting Blink's incorrect fence dispatch. CPUID remains
masked until the corresponding Phase 6 family gates pass.

`0018-gem-i386-virtual-tsc-admission.patch` (SHA-256
`a780c433970b9fb7b2b07f1a3f58fb8055117bc39a527c53e4ccd6d2977eb5b9`)
keeps legacy-32 RDTSC out of Blink's host-backed handler. The GEM adapter
supplies an epoch-zero, one-tick-per-retired-instruction virtual counter only
after a transaction commits, so interpreter and JIT execution are identical
and memory-conflict retries reproduce the same timestamp. Blink's decoded
instruction length crosses in the reserved decode-attempt sidecar byte so
prefixed encodings advance EIP without a second decoder.

`0019-gem-i386-bmi1.patch` (SHA-256
`2258dcb91a84b534a4cf2d9efd9845b892e323bc5dfba692a0d33dc82e1ba88f`)
implements portable legacy-32 ANDN, BEXTR, BLSI, BLSMSK, and BLSR handlers,
admits only their exact VEX map/prefix forms while later VEX families remain
masked, and adds BMI1 to the deterministic legacy CPUID profile. The native
Windows ARM64 qualification VM does not expose BMI1 to its i386 process, so
semantic authority comes from the SDM checks and exact interpreter/JIT parity.
TZCNT reuses Blink's existing reviewed scalar handler.

`0020-gem-i386-bmi2.patch` (SHA-256
`18910ef86f5031d8f244061d5e713c211d7a3b655a2df10f5d7b57712d2fa465`)
admits the portable BZHI, PDEP, PEXT, MULX, SHLX, SHRX, SARX, and RORX
implementations in the legacy-32 interpreter and JIT. Exact VEX map/prefix
checks keep ADX, 256-bit encodings, and legacy aliases fail-closed. BMI2 is
advertised from SharpWine's deterministic CPUID profile after native semantic,
state, fault, corpus, and program-loading qualification; an external runtime
that lacks BMI2 is retained only as non-authoritative comparison evidence.

`0021-gem-i386-rdtscp.patch` (SHA-256
`b85442976c2b6cc12e0ba3674793822d9e0791da8b7dfe60154517d61eb8fd87`)
advertises RDTSCP after the GEM adapter qualifies its deterministic virtual
timestamp implementation. The host-backed Blink handler remains excluded;
SharpWine returns the committed retired-instruction counter in EDX:EAX and a
fixed guest TSC_AUX of zero in ECX in both interpreter and JIT modes.

`0022-gem-i386-avx-foundation.patch` (SHA-256
`edbe07e90ab3648311d09a5eef2789a94b98dc1b10ef0917bf7006013b6166ec`)
starts the deliberate native AVX implementation without advertising AVX yet.
It corrects C5 `vvvv` decoding, adds VZEROUPPER/VZEROALL and reviewed
VEX.128 floating-point/scalar three-operand forms, enforces architectural
upper-lane zeroing, and emits the portable semantic helper through Blink's
real JIT hook. The complete AVX CPUID gate remains closed until 256-bit and
cross-lane coverage is implemented and qualified.

`0023-gem-i386-avx-packed-lanes.patch` (SHA-256
`b785875a9d54f3d0953cd37e173922ebad16da4c1520e49db728dca540d6932f`)
extends the native implementation across promoted 256-bit AVX floating-point
operations. It executes both architectural 128-bit lanes in one checked GEM
transaction, snapshots the complete memory source before changing destination
state, preserves precise cross-page faults, and commits both YMM halves
together through the same interpreter/JIT semantic helper.

`0024-gem-i386-avx-promoted-128.patch` (SHA-256
`859f5cd44ae2a4224c353589c13b2eaaf83a0b525bccd36c6a0a2c7a1bb2c9c9`)
executes the native VEX.128 forms promoted from Blink's portable SSE handlers,
including integer, shuffle, conversion, rounding, AES, and carry-less multiply
families. It supplies the non-destructive VEX source, preserves exact narrow
memory access widths, zeros the architectural YMM upper half, and rejects
256-bit integer forms that belong to AVX2.

`0025-gem-i386-avx-stores.patch` (SHA-256
`071e91230f038175b30d81d3056de8fb91149bc45de8fc1f9bb1dca2cf3e83e6`)
implements scalar, packed, aligned, unaligned, low/high-lane, and non-temporal
AVX stores. Full source snapshots and explicit cross-page stash commits keep
interpreter and JIT stores atomic and restartable; exact scalar widths avoid
touching an adjacent uncommitted page, and aligned forms retain their fault
contract.

`0026-gem-i386-avx-cross-lane.patch` (SHA-256
`7d996a9f1b2db4c7975340f82c9ec0a659478516e3d1e1f7cdd84cec2b4a9b9c`)
implements broadcast, immediate and variable in-lane permutation,
VPERM2F128, VINSERTF128/VEXTRACTF128, VTEST/VPTEST, and four-operand variable
blend semantics. Sources are snapshotted before overlapping destinations,
memory widths remain exact at page boundaries, and every form shares the
portable interpreter/JIT transaction helper.

`0027-gem-i386-avx-immediate-shifts.patch` (SHA-256
`6a11c3380635dab199df279235854fe484baee4a1970401ceb73409bd8a8324a`)
implements VEX.128 packed logical, arithmetic, and byte-lane immediate shifts.
The opcode-extension and VEX destination fields are handled independently,
over-wide counts follow the architectural zero/sign-fill rules, and every
result clears its YMM upper half in both execution engines.

`0028-gem-i386-avx-misc-destinations.patch` (SHA-256
`e84cbf65f831d902f79e5ee4869203dbcd8ec7bb2390626cbb8adb1540952df1`)
implements AVX compare flags, movemasks, MOVD/MOVQ, scalar insert/extract,
packed-string comparisons, and LDMXCSR/STMXCSR across their GPR, flags, MXCSR,
memory, and implicit-vector destination shapes. Exact VEX admission precedes
reviewed legacy semantics; new portable handlers retain width and upper-lane
contracts in interpreter and JIT modes.

`0029-gem-i386-avx-mask-moves.patch` (SHA-256
`ba601314d5f62d4bc4d0ecca51f2ce468bffa4beda2b36a7a4a179af986eb201`)
implements VMASKMOVPS/PD and VMASKMOVDQU with inactive-element fault
suppression, zero-filled masked loads, and preflighted restartable stores.
Selected lanes are coalesced into one GEM transaction span so every write is
retained, while inactive trailing pages remain untouched; the overlap stash
is also widened to the 32-byte maximum used by native AVX moves.

`0030-gem-i386-avx-conversions.patch` (SHA-256
`e0d6cf89d9d494edeb2459a91a68992cdcf473dd2db4283067e449395a0c185b`)
implements 256-bit packed float/integer conversions, asymmetric widening and
narrowing forms, and scalar VCVTSI2SS/SD merge semantics. It preserves exact
source widths, destination/upper-lane contracts, and MXCSR rounding versus
truncation behavior while rejecting reserved VEX source fields.
