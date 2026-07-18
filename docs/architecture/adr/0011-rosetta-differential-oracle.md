# ADR 0011: Rosetta differential development oracle

Date: 2026-07-15
Status: Accepted for development and conformance work

## Context

The native ARM64 GEM/Blink runtime needs broad, reproducible x86 semantic
coverage before the i386 Notepad and Steam Setup milestones can be treated as
hardened. Rosetta 2 is available on the development host and provides a mature
x86_64-to-ARM64 implementation. It does not directly execute i386 Mach-O code,
so it cannot alone characterize the legacy-only IA-32 environment required by
Windows WoW64.

ProjectChampollion documents useful observable Rosetta internals: a direct
x86_64-to-ARM64 register mapping, JIT translation of dynamically generated
code reached by indirect branches, legacy-prefix decoding, optional translation
IR/segment diagnostics, and an ARM64 `execve` runner that keeps LLDB attached
through the x86_64-to-Rosetta transition. Its analysis targets an earlier
Rosetta build and is supporting research, not a normative compatibility table.

## Decision

Conformance uses two separate Rosetta-backed lanes:

1. A direct x86_64 Mach-O corpus executes generated code under Rosetta. This is
   the primary oracle for shared x86 semantics and Rosetta's supported x86_64
   envelope. Every run proves translation with `sysctl.proc_translated == 1`.
2. A freestanding PE32 console corpus runs through a pinned, x86_64 MetalSharp
   Wine WoW64 carrier under Rosetta. This covers IA-32 register width,
   addressing, x87, segmentation, PE32 transitions, and other legacy-only
   behavior. Carrier behavior is identified separately from Rosetta behavior.

Both lanes emit normalized, versioned architectural records containing only
defined outputs: registers, defined flag masks, memory, SIMD/x87 state, fault
class and address, and instruction bytes. Inputs, executables, carrier archive,
host OS/Rosetta identity, and results are hash-bound. Native ARM64 GEM/Blink
replays the exact instruction bytes and compares records field by field.

The initial PE32 runner is console-only, uses a fresh isolated prefix, disables
installer/UI helpers, imposes a process-group watchdog, and always kills its
scoped wineserver. It refuses quarantined, unsigned, or improperly entitled
Wine hosts. Runtime preparation ad-hoc signs every extracted Mach-O and grants
the Wine host executables only the JIT/executable-memory allowances needed for
this local oracle.

ProjectChampollion's tracing techniques are used only after a mismatch is
minimized. Architectural state is the acceptance oracle; Rosetta IR, AOT code,
and ARM64 register mapping are diagnostic evidence that helps locate a bad
decode, lowering, flag, memory, or transition decision.

## Coverage order

Coverage expands by encoding family rather than attempting an unbounded cross
product: one-byte, `0F`, `0F 38`, and `0F 3A` maps; legacy/REX/VEX prefixes;
ModR/M, SIB, displacement and immediate edges; arithmetic flags; branches and
stack; faults and page boundaries; string operations; atomics and ordering;
x87, MMX, SSE through AVX2; self-modifying code; and i386 segmentation/WoW64
transitions. Randomized differential cases supplement, but never replace,
deterministic boundary cases.

## Current verified corpus

The expanded PE32 matrix contains 1,458 fully defined cases and completed in a
single 4.575-second carrier batch on macOS 27.0 (26A5378j). It covers 8-, 16-,
and 32-bit arithmetic and flags; shifts, rotates and double shifts at masked
count boundaries; bit scans and bit manipulation; aligned and unaligned locked
memory operations; ModR/M and SIB addressing; branches, calls, returns, and
stack frames; multiply and divide; scalar moves; packed integer SSE2, SSSE3,
and SSE4.1; and POPCNT/LZCNT/TZCNT. Rosetta produced a record for every case.

A freshly extracted Blink tree with patches 0001 through 0007 replayed every
record in both the ARM64 interpreter and ARM64 JIT modes: 2,916 comparisons,
2,916 matches, zero unsupported instructions, zero crashes, and zero semantic
mismatches. The expanded run found and froze fixes for INC/NEG auxiliary carry,
CMPXCHG subtraction direction, LZCNT, Blink embedding bus initialization for
unaligned atomics, the SSE4.1 packed integer min/max family, transactional
PUSHA/POPA stack frames, Windows user-mode PUSHF/POPF state, and CMPXCHG8B
writeback.

The Phase 2 fault/coherency corpus adds 128 deterministic PE32 records: 32
illegal-instruction exceptions, 48 integer divide exceptions, and 48 access
violations. Each record binds the instruction bytes, initial and final context,
exception code and parameters, fault address and access type, retirement state,
and before/after memory hashes. All 128 records replay successfully alongside
110 native boundary, rollback, exception-delivery, guard-page, and invalidation
scenarios replay in both interpreter and JIT modes for 220 comparisons. The
original 2,916 Phase 1 interpreter/JIT
comparisons remain 2,916/2,916 after the Phase 2 embedding changes.

Phase 2 exposed a stale translated block after guest self-modification. The
embedding now invalidates the written executable page and its predecessor so
same-address rewrites, overlapping instructions, and instructions crossing a
page boundary observe new code in both execution modes. The corpus also proves
that unsuccessful multi-page operations preserve register, flag, stack,
memory, and instruction-pointer state; guard consumption is the only permitted
protection-state side effect before retry.

The expanded boundary matrix additionally found that INTO was being reported
as an illegal instruction and that cross-page PUSH/POP and PUSHA/POPA failures
could lose their write/read identity or exact second-page address. The ordered
embedding patch admits INTO only through its architectural overflow behavior
and records stack access intent before any lazy page resolution, including the
multi-register POPA load. Those exception and stack-address changes are gated
to the legacy-32 guest mode so the established x86_64 embedding contract and
fault metadata remain unchanged.

The Phase 3 legacy-state corpus adds 1,024 deterministic PE32 cases: 256 x87,
128 MMX, 384 SIMD, 160 REP/segmentation, and 96 CPUID/context-transition cases.
All records replay in both native ARM64 execution modes for 2,048/2,048 Phase 3
comparisons. Together with the retained 2,916 Phase 1 and 220 Phase 2
comparisons, the native deterministic total is 5,184/5,184.

The fixed legacy CPU profile now reports FPU, CX8, CMOV, MMX, FXSR, SSE through
SSE4.2, POPCNT, PCLMUL, AES, and ERMS independently of host CPU features. Its
capability manifest binds those bits to reviewed handlers and corpus witnesses,
including the complete SSE4.1/SSE4.2 and AES opcode groups used by the profile.
AVX, AVX2, FMA, OSXSAVE, BMI/ADX, FSGSBASE, hardware-random, CX16, long mode,
and legacy-inapplicable syscall features remain masked until a future context
ABI can preserve their architectural state.

Raw 80-bit x87 values and the x87 environment round-trip exactly. Common x87
arithmetic deliberately uses host-double compatibility precision; full software
extended-precision arithmetic is outside this phase. MMX retains physical x87
aliasing without destroying the independent XMM register file, REP faults
preserve completed iterations and restart at the string instruction, and all
six segment descriptors enforce complete access widths and permissions. A
packaged PE32 context/exception fixture also completed with its exact success
marker and no residual Wine processes.

The Phase 4 generator defines 16 independently addressable 4,096-case shards
using schema v1, template revision 1, master seed `0x534841525057494e`, and
SplitMix64 derivation. The shared integer-only generator is compiled into both
the PE32 compatibility worker and native GEM worker. Canonical records carry
the complete initial and final i386 context, defined-state masks, memory hashes,
exception state, retirement state, and JIT counters. Every case runs in an
isolated process under a two-second watchdog, with four independent prefixes
and scoped ten-second cleanup.

The accepted Phase 4 qualification stops at shard 4 ordinal 3928: 20,313
baseline records, 40,626/40,626 native-to-baseline comparisons, and
20,313/20,313 interpreter/JIT parity checks. All 20,313 cases passed with zero
mismatches, unsupported advertised instructions, JIT fallback, crashes,
timeouts, malformed records, infrastructure failures, or residual processes.
The proportional 4,096-case smoke shard also passed independently. Together
with the retained 5,184 deterministic comparisons, this records 45,810 native
compatibility comparisons. The unexecuted suffix of the generated 65,536-case
space is explicitly not claimed; Phase 5 may select or bind additional cases
when establishing the permanent CI corpus.

Qualification promoted two minimized deterministic regressions. A full x87
stack push now commits the indefinite value and special tag after masked stack
overflow, and SCAS now computes accumulator-minus-memory flags while retaining
load-before-update fault behavior. The PE32 capture path also normalizes x87
arithmetic at the documented binary64 boundary and explicitly reconstructs MMX
alias state where the carrier FXSAVE view is insufficient. Complete category
totals, precision policy, source hashes, fixture hash, patch hash, and evidence
hash are recorded in `i386-phase4-evidence.json`.

The Phase 6 full-space requalification uses the native Windows 11 ARM64 WoW64
baseline. Its Prism x87 carrier is observational rather than authoritative for
templates 300 (`FLD1`) and 301 (`FLDZ`): on a full masked stack it omits Intel's
stack-overflow result, exposes the FXSAVE register file in logical order, and
does not retain FOP. Those two template families therefore retain the Windows
records as explicit non-authoritative observations while acceptance requires
bit-identical interpreter/JIT results plus the in-process Intel-SDM assertions
for status, TOP, tag, indefinite value, and FOP. No defined-state mask changes;
all other templates remain exact three-way comparisons, and only those exact
cases contribute to the native-comparison count.

Phase 5 promotes the accepted prefix into a 162,536-byte golden corpus containing
one compatibility hash for every accepted identity. Normal CI replays all 20,313
cases independently through the native interpreter and JIT without an external
runtime, verifies every hash, and rejects JIT fallback. The golden file's schema,
seed, final identity, length, and SHA-256 are checked by the repository-policy
job. Existing capability and Blink provenance audits continue to reject CPUID
features without handlers and tests, or unreviewed embedded-source drift.

## Boundaries

- Rosetta and the MetalSharp carrier are development oracles only. Neither is
  linked, packaged, invoked, or silently selected by the shipped no-Rosetta
  runtime.
- A Rosetta match is evidence of compatibility, not permission to diverge from
  Intel architectural requirements.
- Rosetta's x86_64 coverage does not prove i386 segmentation or Windows WoW64;
  those claims require the separately identified PE32 carrier lane and native
  Windows evidence where available.
- GUI workloads are recorded separately from console semantic collection. They
  do not replace field-by-field architectural conformance.

## Relationship to ADR 0010

ADR 0010's rejection of Rosetta as an implementation path remains unchanged.
This ADR permits Rosetta only as an offline differential development oracle.
