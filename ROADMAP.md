# Roadmap

## First completion target: v0.1 — Deterministic Hybrid Execution Proof

The first roadmap ends with a standalone, repeatable ARM64EC → x86_64/Blink → ARM64EC round trip whose canonical state never depends on Darwin x18. It deliberately stops before modifying Wine startup. This gives the Wine integration a proven execution substrate instead of another speculative runtime path.

The evidence-corrected assessment in
[`docs/architecture/arm64ec-arm64x-research-assessment.md`](docs/architecture/arm64ec-arm64x-research-assessment.md)
is a cross-cutting planning input. It preserves useful PE/CHPE, memory-order, and 4 KiB guest-page research goals while explicitly rejecting guessed metadata, unverified TSO controls, ad-hoc x86 decoding, and unsafe signal-handler page emulation.

### Release acceptance criteria

v0.1 is complete only when all of the following are demonstrated in CI-compatible tests:

- An ARM64X fixture is parsed into validated ARM64, ARM64EC, and x64 code ranges.
- A selected AArch64 correctness engine executes ARM64EC instructions on native ARM64 macOS.
- Guest x18 remains equal to the configured TEB through every instruction and transition boundary.
- Canonical low addresses, including `0x7ffe0000`, are accessible through GEM without requiring a host mapping below 4 GiB.
- ARM64EC mandatory indirect-call checker behavior is covered by fixtures.
- A compiler-generated exit thunk transfers to Blink, executes x86_64 code, and returns through an entry thunk.
- GPRs, SP, PC, NZCV/RFLAGS, v0-v15/XMM0-XMM15, FP state, and stack bytes match expected results after the round trip.
- Direct call, indirect call, callback, normal return, tail-call, memory fault, and unsupported-instruction stop reasons are deterministic.
- Every optimized execution path used in the demonstration has a correctness fallback.
- The x64 engine passes an explicit x86 memory-order conformance suite; hardware TSO is optional and never assumed.
- Four 4 KiB guest pages sharing one 16 KiB host page retain distinct logical permissions and deterministic checked faults without transiently exposing neighboring guest pages.
- The macOS process and every Mach-O dependency are ARM64, with no Rosetta invocation.
- CI, formatting, repository-policy, licensing, and test gates pass.

## Milestone 0 — Repository and specification foundation

Status: substantially complete.

- [x] Establish public integration repository and mixed-license boundaries.
- [x] Add protected `main`, pinned CI actions, formatting, warnings-as-errors, and repository hygiene gates.
- [x] Publish the deterministic virtual-CPU architecture.
- [x] Define the initial canonical GEM context.
- [x] Add compile-time layout assertions and context serialization versioning.
- [x] Add contribution rules for legal, redistributable binary fixtures.
- [x] Add architecture decision records for engine ownership, memory ownership, and transition ownership.

**Exit gate:** ABI and ownership rules are reviewable and machine-tested before an execution engine is introduced.

## Milestone 1 — ARM64X metadata and ABI fixture layer

- [x] Implement a bounds-checked PE32+/ARM64X reader for only the metadata GEM needs.
- [x] Parse load configuration, CHPE metadata, code maps, entry-point ranges, and redirections.
- [x] Represent target ISA as ARM64, ARM64EC, x64, thunk, fast-forward, data, or invalid.
- [x] Add a legal synthetic ARM64X fixture generated from source during tests.
- [x] Add sanitized metadata expectations from the current Wine ARM64X ntdll without committing the binary.
- [x] Reject overlaps, integer overflow, truncated records, unsorted ranges, and out-of-image pointers.
- [x] Add corpus/fuzz entry points for metadata parsing.

**Exit gate:** every executable target in the synthetic fixture is classified from metadata without inspecting instruction bytes.

## Milestone 2 — Canonical context and memory subsystem

- [x] Finalize `gem_thread_context` with fixed-width layout and explicit version.
- [x] Implement pure ARM64EC ↔ x64 register conversion routines.
- [x] Implement NZCV/RFLAGS and FPCR/FPSR/MXCSR conversion with exhaustive table tests.
- [x] Implement a logical guest page table independent of host page size.
- [x] Implement checked read, write, execute, protect, map, unmap, and alias operations.
- [x] Support high-address identity fast paths only after validation.
- [x] Support low aliases including KUSER shared data at `0x7ffe0000`.
- [x] Model Windows write-copy, guard, reserve, commit, and execute protections needed by the standalone fixture.
- [x] Add 4 KiB guest-page tests on a 16 KiB host.

**Exit gate:** canonical state and memory behavior pass without executing guest instructions.

## Milestone 3 — Correctness-engine selection

Status: complete; corrected native ARM64 conformance gate passed on 2026-07-10.

Evaluate established engines with one shared conformance harness. A candidate is not selected by convenience or benchmark alone.

- [x] Document candidate versions, build provenance, licenses, and distribution implications.
- [x] Test AArch64 GPR, SIMD, flags, atomics, exclusive operations, FP control, faults, and single-step behavior.
- [x] Test explicit x18 get/set without relying on host x18.
- [x] Test low-address callbacks and 4 KiB guest protections.
- [x] Test deterministic instruction budgets and stop reasons.
- [x] Test self-modifying code and cache invalidation behavior.
- [x] Select the correctness engine through an architecture decision record.
- [x] Wrap it behind `gem_run_arm64ec(context, budget)` so it cannot own canonical state.

Preferred evaluation order:

1. A QEMU-TCG-derived library/runtime suitable as a correctness oracle.
2. Another established full AArch64 virtual CPU if licensing or embedding blocks the first.
3. Frida Gum Stalker and QBDI only as accelerated engines after the oracle exists.

**Exit gate:** passed — pinned FetchContent Debug build, all 11 CTest tests, and the zero-Rosetta audit passed on native ARM64 macOS on 2026-07-10.

## Milestone 4 — ARM64EC checker and thunk execution

**Status: complete.** Issues #10 and #11 are closed. Native Windows ARM64 CI run
`29168212337` produced and independently inspected two clean Microsoft-linked ARM64X builds, then
executed their authentic checker, entry-thunk, and signature-specific exit paths through pinned
Dynarmic. Every exit stopped at its distinct metadata-classified x64 boundary with Blink unloaded
and zero x64 instructions fetched. Generated Microsoft artifacts remained build-tree-only; raw
COFF and synthetic metadata remain non-accepting substitutes.

- [x] Generate authentic Microsoft-linked ARM64X fixtures from source in runner-temporary build trees.
- [x] Implement target classification against the Milestone 1 code map.
- [x] Implement `__os_arm64x_check_icall` behavior for ARM64EC and x64 targets.
- [x] Add CFG-form checker interfaces while keeping policy separate from architecture dispatch.
- [x] Preserve x0-x8, x15, and q0-q7 exactly as required.
- [x] Resolve the four-byte ARM64EC entry-thunk descriptor safely.
- [x] Execute signature-specific integer, floating-point, structure, and variadic thunk fixtures.
- [x] Validate disallowed ARM64EC register use as a deterministic failure.
- [x] Inspect linked load-config and CHPE records with checked file-offset/RVA/VA conversion; do not infer linked semantics from raw COFF sections.
- [x] Prove relocation, import, alias, and local-exit-thunk resolution to a real metadata-classified x64 target.

**Exit gate:** passed — run `29168212337` validated the forced-nonpreferred-base linked images,
checked descriptor and checker evidence, executed all generated paths through pinned Dynarmic,
preserved the fixed 720-byte canonical context and x18/TEB contract, and stopped before each x64
boundary without Blink. Repository policy, formatting, native macOS ARM64 conformance,
zero-Rosetta auditing, clean-build reproducibility, and generated-artifact leakage checks passed in
the same run.

## Cross-cutting correctness track — x86 memory ordering and host-page isolation

Milestone 4 is complete. This track now supplies the memory-order and guest-page correctness
prerequisites for the Milestone 5 hybrid round trip and cannot be bypassed by later integration.

- [x] Specify the observable x86-TSO contract from authoritative architecture documentation, including permitted Store→Load behavior.
- [x] Inventory Blink interpreter/JIT loads, stores, locked operations, fences, self-modifying-code handling, fault ordering, and host-compiler assumptions.
- [x] Add bounded Store Buffering, Load Buffering, Message Passing, IRIW, locked-operation, and self-modifying-code litmus tests under contention.
- [x] Compare interpreter and JIT behavior; reject the timed-out concurrent JIT and retain the passing bounded interpreter fallback.
- [ ] Prove atomic and transactional behavior for misaligned and cross-4-KiB-page guest accesses.
- [x] Keep hardware TSO optional; the native probe found no supported, queryable, per-thread API.
- [x] Do not depend on private TSO symbols, kernel extensions, Rosetta process state, or an unverified Virtualization.framework control.
- [ ] Preserve distinct logical permissions for 4 KiB guest pages sharing a 16 KiB host page through checked GEM translation.
- [ ] Reject temporary host-page permission widening, guessed `ucontext_t` debug-state mutation, and process-global signal single-stepping as correctness mechanisms.
- [ ] Evaluate Mach exceptions or direct mappings only as optional accelerations after race, reentrancy, fault, and multithreaded conformance tests pass.

**Exit gate:** memory-order litmus tests and 4 KiB protection/fault tests pass repeatedly on native
ARM64 macOS with hardware TSO disabled or unavailable, and every acceleration has a deterministic
GEM-owned fallback.

## Milestone 5 — Blink integration and hybrid round trip

- [ ] Define a stable GEM x64-engine interface around Blink.
- [ ] Move existing Blink memory alias and per-thread Machine behavior behind that interface.
- [ ] Implement pure GEM ↔ Blink state synchronization.
- [ ] Preserve XMM6-XMM15 and x87/MM state required by ARM64EC mappings.
- [ ] Implement transition frames for ARM64EC return LR, x64 return address, aligned SP, and original x64 SP.
- [ ] Implement documented dispatch-call and dispatch-ret stop handling.
- [ ] Execute ARM64EC → exit thunk → Blink x64 → entry thunk → ARM64EC.
- [ ] Add callbacks, tail calls, nested transitions, memory faults, and unsupported-instruction cases.
- [ ] Compare every final register, flag, SIMD lane, stack byte, and guest memory mutation.
- [ ] Keep Blink JIT generation process-serialized until concurrency is proven safe.
- [ ] Route all x64 memory effects through the proven memory-order and guest-page contracts; a byte-prefix scanner is not an acceptable decoder.
- [ ] Perform native instruction-cache maintenance only when host executable code is created or modified; do not add architecture-transition `ISB` instructions without a demonstrated requirement.

**Exit gate:** the v0.1 hybrid round-trip acceptance suite and the cross-cutting memory-order/page-isolation gates pass repeatedly and under sanitizers where supported.

## Milestone 6 — Release hardening

- [ ] Add deterministic trace format with versioning and redaction.
- [ ] Add bounded stress tests and randomized state round trips.
- [ ] Add ASan/UBSan Linux jobs and supported macOS sanitizer coverage.
- [ ] Add dependency license/SBOM generation.
- [ ] Add reproducible toolchain and fixture-generation documentation.
- [ ] Audit all Mach-O files and launched processes for ARM64-only execution.
- [ ] Publish v0.1.0 with evidence, known limitations, and the Wine-integration plan.

**Exit gate:** all release acceptance criteria have links to CI runs, fixtures, test names, and architecture records.

## After v0.1

The second roadmap integrates GEM into Wine ntdll without changing the v0.1 state contracts:

1. route initial PE thread entry through GEM;
2. connect Wine virtual-memory operations to GEM;
3. implement syscall and Unix-call stop reasons;
4. convert exceptions, APCs, suspend/resume, and new threads;
5. pass `wineboot --init` and ARM64 `cmd.exe`;
6. reach x64 naturally through `xtajit64` and pass hybrid application tests;
7. introduce a validated accelerated ARM64EC engine;
8. build and stage DXMT and Winemetal;
9. address i386 only through a complete translated 32-bit address space.

## Working rules

- One milestone exit gate at a time; no integration work may bypass a failed lower-level gate.
- Every ABI behavior requires published documentation or a legal, reproducible fixture.
- Research notes and sample code are hypotheses until reproduced against pinned public specifications, tool output, and native tests.
- PE machine identifiers, CHPE layouts, load-config offsets, and thunk-table meanings must come from pinned definitions or verified legal fixtures; no guessed structures are accepted.
- No proprietary Windows binaries or private diagnostics enter the repository.
- No direct native PE execution is required for correctness.
- No optimized path ships without a deterministic fallback.
- Every runtime test is bounded by time, log size, process-group cleanup, and zero-Rosetta auditing.
