# ADR 0004: AArch64 correctness engine selection

## Status

Accepted.

## Context

Milestone 3 requires an established AArch64 correctness engine selected by shared conformance tests, not by convenience or benchmark alone. ADR 0001 keeps `gem_thread_context` as canonical CPU state, ADR 0002 keeps `gem_memory` as canonical memory, and ADR 0003 keeps transition policy outside the engine. The selected engine must run on native ARM64 macOS without Rosetta and must not introduce incompatible code into the Apache-2.0 runtime.

## Decision

Select **Dynarmic 6.7.0** at commit `a41c380246d3d9f9874f0f792d234dc0cc17c180` as the Milestone 3 AArch64 correctness engine backend.

Dynarmic is fetched at configure time only when `MSWR_ENABLE_ARM64EC_ENGINE=ON`; no Dynarmic source or binary artifact is vendored in the repository. The adapter links the permissively licensed Dynarmic backend into the optional GEM engine build and exposes only the C API in `include/metalsharp/gem/arm64ec_engine.h`:

- `gem_arm64ec_runtime_create(memory, config)` owns backend/runtime state outside the fixed 720-byte context;
- `gem_arm64ec_runtime_run(runtime, context, budget)` imports and exports all canonical state through `gem_thread_context`;
- `gem_run_arm64ec(context, budget)` is the required issue-facing wrapper backed by an explicitly installed current runtime;
- `gem_arm64ec_runtime_last_stop_info()` reports fault address, access class, retired-instruction count, and backend status without changing the context ABI.

The adapter configures Dynarmic conservatively: no fastmem, no direct page-table fast path, unsafe optimizations disabled, and execution through `Jit::Step()` so each budget unit is one guest instruction. All code/data/fetch accesses are mediated by GEM callbacks. Guest `x18` is imported/exported explicitly from `context->x[18]`; Darwin host x18 is never used as guest state.

## Provenance

Structured provenance is recorded in [`0004-aarch64-correctness-engine.provenance.json`](0004-aarch64-correctness-engine.provenance.json).

Summary:

- Upstream: <https://github.com/lioncash/dynarmic.git>
- Version: `6.7.0`
- Revision: `a41c380246d3d9f9874f0f792d234dc0cc17c180`
- License: `ISC` (`LICENSE.txt` upstream); bundled `mcl` and `fmt` are MIT-licensed.
- Source archive SHA-256: `cc0dfec19b7cfb80a649bd994bd0569c0482de1f49448773d2899f30b6a180c3`
- Distribution: optional fetched source/build under ignored build directories; no vendored engine code.

## Conformance evidence

The corrected implementation passed a clean native ARM64/no-Rosetta FetchContent Debug build on 2026-07-10: all 11 CTest tests passed and `tools/ci/audit-zero-rosetta.sh` passed. Exact commands and recorded results are in the provenance JSON. System-package Dynarmic is explicitly a non-conformance developer mode because a package version cannot establish the pinned revision and archive provenance.

The shared test executable `tests/arm64ec_engine_conformance.cpp` exercises the public API, not Dynarmic internals. Covered cases include:

- public runtime creation, `gem_run_arm64ec(context,budget)`, invalid-context rejection, and exact budget-zero behavior;
- single-step budget slices and deterministic loop budgets with retired-instruction accounting;
- GPR import/export, SP/PC/LR host-return handling, NZCV arithmetic flags;
- SIMD v0-v15 lane operations;
- FPCR-controlled rounding and FPSR divide-by-zero status;
- LDXR/STXR exclusive success and deterministic STXR failure without an active monitor;
- explicit guest x18/TEB import on repeated runs with different TEB values, with native AArch64 host x18 observed as a separate value;
- low KUSER data access at `0x7ffe0000` and low-address code execution without a host low mapping;
- 4 KiB protection split faults, fetch faults, guard fetch fault reporting, and fault atomicity for a cross-page store;
- stop reasons for syscall, Windows exception/BRK, unsupported/UDF, host return, architecture transition, memory fault, budget, and invariant violation;
- self-modifying code through explicit invalidation and guest writes, plus IC/DC/DSB/ISB cache-maintenance instructions;
- deterministic pre-`Step()` rejection of every documented disallowed GPR (`x13`, `x14`, `x23`, `x24`, `x28`) and SIMD (`v16`-`v31`) encoding through the pinned decoder operand schema, including source/destination, accumulator, branch, scalar FP, and SIMD load/store forms; rejection has no guest-state or memory side effect, preserves PC and retired budget, and reports unsupported with the fetched word;
- checked-fetch priority over forbidden-register rejection, forbidden-before-data-fault priority after a valid fetch, and allowed-to-forbidden explicit invalidation.

`tests/arm64ec_engine_zero_rosetta.cpp` verifies the test process is native arm64 and not Rosetta-translated on macOS. `tools/ci/audit-zero-rosetta.sh` performs the corresponding shell-level process and Mach-O audit in CI.

## Rejected alternatives

- **QEMU TCG in-process linkage**: technically strong but GPL linkage is not acceptable for the Apache-2.0 runtime. A separately obtained, process-isolated QEMU oracle remains a possible future fallback if Dynarmic stops satisfying the contract.
- **Unicorn Engine in-process linkage**: QEMU-derived GPL library linkage has the same Apache runtime distribution problem.
- **Frida Gum Stalker**: kept for future fast-engine work. It is DBI/host execution, not the selected correctness oracle with GEM-owned architectural state.
- **QBDI**: license-compatible but likewise deferred to future fast-engine work rather than the Milestone 3 correctness oracle.
- **VIXL simulator**: permissive and established, but not selected after Dynarmic passed the required harness with a direct A64 frontend, native ARM64 backend, and GEM callback integration.

## Consequences

- The project keeps Apache-2.0 licensing for project code and avoids GPL runtime linkage.
- Engine state is a synchronized view only; GEM remains canonical owner of CPU state and memory.
- The fixed 720-byte `gem_thread_context` ABI is preserved.
- The correctness engine is intentionally slow and deterministic: one Dynarmic `Step()` per GEM budget unit.
- Any future enablement of fastmem, block execution, LSE-specific expansion, or optimized code-cache behavior must pass the same public conformance harness before becoming accepted.
- The decision returns to Proposed if Dynarmic changes license, loses native ARM64 macOS support, fails the harness, or if a mandatory ARM64EC semantic expands beyond the adapter's proven cases.
