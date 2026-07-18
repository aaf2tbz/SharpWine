# ADR 0012: FEX coverage inventory for i386 phase 6

Date: 2026-07-17
Status: Accepted for phase 6 implementation work

## Context

The native ARM64 compatibility roadmap's Phase 6 requires importing FEX-proven
CPU coverage without replacing GEM/Blink ownership: GEM stays authoritative for
i386 context, 4 KiB guest memory, faults, Windows boundaries, budgets, and
teardown; Blink remains the selected decoder/JIT and interpreter oracle. The
phase requires an inventory of FEX's stable x86 implementations, tests, ARM64
lowering strategies, and licenses by exact upstream revision, recording which
ideas are adapted, independently implemented, or rejected. FEX is used as
implementation evidence only. SharpWine's own architecture assertions,
hash-bound interpreter/JIT corpus, precise state/fault tests, and application
compatibility are the semantic acceptance authority. Native Windows supplies
exact comparison results for families it exposes, but is only an oracle and
does not define SharpWine's capability ceiling.

This ADR is that inventory. It is the document later phase 6 commits cite when
unmasking a CPUID family or adapting a DBT technique.

## Pinned upstream revision and licenses

- Repository: `https://github.com/FEX-Emu/FEX.git`
- Release: `FEX-2607`
- Revision: `1cc4b93e7a71c883ec021b71359f136394dc1f3c` (2026-07-03)
- License: MIT (`LICENSE`, `FEXCore/LICENSE`; all FEXCore sources carry
  `SPDX-License-Identifier: MIT`)
- Vendored-external nuances, recorded for completeness: `External/cephes` and
  `External/tiny-json` carry their own permissive licenses; `CodeEmitter/` is
  vixl-derived (BSD-3-Clause family). No FEX source, tables, or generated
  artifacts are vendored into this repository, so none of these bind; they are
  recorded so the inventory is complete.
- Reviewed file hashes are pinned in
  [`0012-fex-coverage-inventory.provenance.json`](0012-fex-coverage-inventory.provenance.json).
  All line numbers below are cited against the pinned revision and drift
  across releases.

## Evidence map per family

- BMI1/BMI2: implementations `ANDNBMIOp`, `BEXTRBMIOp`, `BLSIBMIOp`,
  `BLSMSKBMIOp`, `BLSRBMIOp`, `BMI2Shift` (SARX/SHLX/SHRX), `RORX`, `MULX`,
  `PDEP`, `PEXT`, `TZCNT`, `LZCNT` in
  `FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp:1691-1926,4897-4917`;
  tabled in `FEXCore/Source/Interface/Core/X86Tables/VEXTables.cpp`
  (VEX map 2 `:1267-1284`, map 3 RORX `:1359`, group 17 `:1393-1395`).
- CMPXCHG16B: tabled as Group 9 `CMPXCHG8B/16B` in
  `X86Tables/SecondaryGroupTables.cpp:176-209`; implementation
  `OpDispatchBuilder::CMPXCHGPairOp` at `OpcodeDispatcher.cpp:3933`.
  ARM64 lowering: `ldaxp/stlxp` pair on ARMv8.0, `caspal` on FEAT_LSE128
  (`FEXCore/Source/Interface/Core/JIT/AtomicOps.cpp:48`).
- RDTSCP: tabled at `X86Tables/SecondaryModRMTables.cpp:50` (`0F 01 F9`);
  implementation `RDTSCPOp` at `OpcodeDispatcher.cpp:5033` uses the raw host
  cycle counter plus `_ProcessorID()` for `IA32_TSC_AUX`; the source comments
  explicitly document that FEX does not enforce fence semantics.
- XSAVE/XRSTOR/XGETBV: Group 15 (`0F AE`) decode; `LoadFenceOrXRSTOR` at
  `OpcodeDispatcher.cpp:4963`, `MemFenceOrXSAVEOPT` at `:4972`; bulk
  XSAVE/XRSTOR state logic with `XSTATE_BV` header handling in
  `OpcodeDispatcher/Vector.cpp:~3018-3287`; XGETBV tabled at
  `SecondaryModRMTables.cpp:29`; tests in `unittests/ASM/Secondary/xsave/`
  with `unittests/ASM/Includes/xsave_macros.mac`.
- VEX/AVX decode and lowering: VEX prefix decode and `MapVEXToReg` in
  `FEXCore/Source/Interface/Core/Frontend.cpp` (dual table selection
  `VEXTableOps` vs `VEXTableOps_AVX128` at `:83-87`); AVX implemented as
  128-bit halves in `OpcodeDispatcher/AVX_128.cpp`, chosen by host SVE-256
  support.
- Deferred flags: flags stored as raw values via `SetRFLAG` and flushed by
  `CalculateDeferredFlags()` (`OpcodeDispatcher.h:2288`, called before any
  flag consumer); PF stored inverted and AF handled specially
  (`OpcodeDispatcher/Flags.cpp:26-40`); redundancy eliminated by
  `FEXCore/Source/Interface/IR/Passes/RedundantFlagCalculationElimination.cpp`.
- Register caching, block linking, SMC: static guest-register allocation
  (`Dispatcher.cpp:106`, `JIT/JITClass.h`) plus
  `IR/Passes/RegisterAllocationPass.cpp`; backpatchable exit-link stubs and
  guest-PC lookup cache in `JIT/BranchOps.cpp` (`ExitFunctionLink`,
  `BindOrRestart`, `LookupCache`); call/return cache invalidation at
  `Core.cpp:991`; inline per-block SMC detection with
  `InvalidateGuestCodeRange` at `Core.cpp:639-700` and buffer invalidation at
  `:968`.
- x86-TSO/atomics on ARM64: canonical write-up
  `FEXCore/docs/MemoryModelEmulation.md` (ARMv8.0 -> LSE -> LRCPC -> LSE128
  tiering; LOCK'd ops as `ldaxr/stlxr` loops or single LSE atomics; unaligned
  RMWs finished in a signal handler).
- Tests: per-instruction asm corpus `unittests/ASM/` (`Primary/`, `TwoByte/`,
  `VEX/`, `H0F38/`, `H0F3A/`, `Atomics/`, `FEX_bugs/` including
  `cmpxchg16b.asm`, `Secondary/xsave/`; 32-bit mirror `unittests/32Bit_ASM/`);
  codegen-regression ratchet `unittests/InstructionCountCI/` (JSON golden
  host-instruction counts per guest opcode, partitioned by host feature set,
  gated by `.github/workflows/instcountci.yml`).

## Register: adapt, independently implement, or reject

Adapted as design evidence (idea studied, SharpWine implementation our own):

1. Deferred flag materialization with a redundancy-elimination pass — the
   `CalculateDeferredFlags` contract (flags fully materialized before any
   consumer) maps directly onto ADR 0010's quantum-terminator rules.
2. The `X86Tables/*.cpp` `X86InstInfo` checklist style as a machine-readable
   coverage inventory for BMI/VEX/AVX families.
3. The `unittests/ASM` corpus organization and the InstructionCountCI
   golden-count ratchet as CI ideas.
4. CMPXCHG-pair ARM64 lowering evidence (`ldaxp/stlxp`, `caspal`/FEAT_LSE128)
   and the tiered TSO lowering documented in `MemoryModelEmulation.md`, where
   applicable to the x64 engine.

Independently implemented (FEX evidence unsuitable; designed fresh):

1. VEX/AVX lowering — FEX's AVX-as-two-128-bit-halves is coupled to its IR and
   SVE tiering and is the wrong fit for GEM's fixed context ABI.
2. XSAVE region semantics — Windows/WoW64 `XSAVE_FORMAT` obligations differ
   from FEX's Linux assumptions.
3. RDTSCP/RDTSC — FEX uses the raw host cycle counter with no deterministic
   policy; SharpWine's deterministic-timestamp policy is GEM-owned and
   designed fresh (phase 6 workstream W4).

Rejected (out of scope or contradictory to GEM/Blink ownership):

1. FEX's `Frontend` decoder — Blink is the authoritative decoder.
2. FEX's IR, AOT cache, Linux syscall/thunk layers.
3. Signal-handler-based unaligned-atomic emulation — incompatible with the
   macOS/Wine boundary model.

## Applicability determinations

Phase 6 scopes coverage "where applicable to the selected guest architecture".
The selected guest is i386 legacy32 (Windows WoW64):

- BMI1, BMI2, AVX, AVX2, FMA, XSAVE/XRSTOR/XGETBV, and RDTSCP are all
  architecturally encodable in 32-bit protected mode and are in scope for the
  i386 engine, each behind its reviewed per-family gate.
- CMPXCHG16B is a long-mode instruction and is not encodable in legacy32;
  CX16 is already masked in `i386-phase3-capabilities.json`. CMPXCHG16B
  coverage is therefore recorded as not applicable to the i386 guest. Whether
  the x86_64 engine adopts it (its corpus tooling and the FEX lowering
  evidence above apply there) is a separate, later decision and is not phase 6
  scope creep.
- Every CPUID unmask is atomic across three artifacts: the Blink `cpuid.c`
  patch (with its new SHA-256 in `cmake/patch-blink-gem.cmake`),
  `i386-phase3-capabilities.json`, and the expected sets in
  `tools/audit_blink_embedding.py` — and happens only after the family's
  corpus, interpreter/JIT parity, architecture-semantics checks, and
  native-Windows comparison attempt are reviewed. An exact Windows match is
  required when the qualification VM exposes the instruction family; when it
  does not, the unavailable capability is recorded and independent SDM tests
  are the semantic authority.
  A family is not left masked merely because the current Blink/GEM snapshot or
  an external oracle lacks it. Phase 6 first makes a deliberate native
  implementation attempt in SharpWine's Blink patch series, then advertises
  every family that passes the complete gate. Only functionality SharpWine
  itself cannot yet implement completely or qualify honestly stays masked.
- The native Windows ARM64 qualification VM does not expose BMI1 to its i386
  process: ANDN, BEXTR, BLSR, BLSMSK, and BLSI terminate as illegal
  instructions, while the TZCNT encoding executes with legacy BSF semantics.
  SharpWine's BMI1 handlers have deterministic SDM checks, exact
  interpreter/JIT coverage, precise fault tests, and a full-corpus replay.
  BMI1 is therefore advertised by SharpWine even though Prism cannot serve as
  its result oracle; the compatibility target is the x86 architecture and the
  programs that use it, not Prism's smaller instruction subset.

## Acceptance authority

FEX contributes evidence and checklists only. Semantic acceptance remains, in
order: the native-Windows exact-byte oracle where the VM exposes the family
(phase 4 baseline flow in `tools/i386/`), independent SDM assertions, the
hash-bound interpreter/JIT golden corpus
(`tests/fixtures/i386_phase5_golden.bin`), and deterministic conformance
suites. A capability-unavailable Windows attempt is evidence about Prism, not
a ceiling on SharpWine's macOS ARM64 compatibility. No Rosetta lane is used.
No FEX source enters the repository; only this inventory, its provenance
record, and SharpWine's own implementations do.

## Consequences

- Phase 6 workstreams cite this ADR per family and per DBT technique; a
  technique not registered here is not adapted.
- If a later review promotes an idea from "independently implement" to
  "adapt" (or the reverse), this ADR and its provenance record are amended in
  the same commit as the work that relies on the change.
