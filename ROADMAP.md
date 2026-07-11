# Roadmap

## First completion target: v0.1 — Deterministic Hybrid Execution Proof

The first roadmap ends with a standalone, repeatable ARM64EC → x86_64/Blink → ARM64EC round trip whose canonical state never depends on Darwin x18. It deliberately stops before modifying Wine startup. This gives the Wine integration a proven execution substrate instead of another speculative runtime path.

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

- [ ] Generate small ARM64EC fixtures with LLVM rather than hand-writing production thunk bytes.
- [ ] Implement target classification against the Milestone 1 code map.
- [ ] Implement `__os_arm64x_check_icall` behavior for ARM64EC and x64 targets.
- [ ] Add CFG-form checker interfaces while keeping policy separate from architecture dispatch.
- [ ] Preserve x0-x8, x15, and q0-q7 exactly as required.
- [ ] Resolve the four-byte ARM64EC entry-thunk descriptor safely.
- [ ] Execute signature-specific integer, floating-point, structure, and variadic thunk fixtures.
- [ ] Validate disallowed ARM64EC register use as a deterministic failure.

**Exit gate:** generated entry and exit thunks execute correctly without Blink and produce expected canonical states.

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

**Exit gate:** the v0.1 hybrid round-trip acceptance suite passes repeatedly and under sanitizers where supported.

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
- No proprietary Windows binaries or private diagnostics enter the repository.
- No direct native PE execution is required for correctness.
- No optimized path ships without a deterministic fallback.
- Every runtime test is bounded by time, log size, process-group cleanup, and zero-Rosetta auditing.
