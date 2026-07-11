# ADR 0006: x86-TSO correctness contract and Blink acceptance

Date: 2026-07-11

## Status

Accepted contract; implementation and conformance pending.

## Decision

GEM's x64 engine must expose behavior allowed by the Intel 64 memory-order model without relying
on the host CPU to provide x86 ordering. The normative architecture source is Intel® 64 and IA-32
Architectures Software Developer's Manual, Volume 3A, sections 10.2 and 10.3, order number 325384.
The reviewed edition is linked by the provenance record beside this ADR.

For ordinary write-back memory, the accepted contract is:

- loads are not reordered with older loads;
- stores are not reordered with older loads or older stores;
- a load may be observed before an older store to a different location;
- a load is not reordered with an older store to the same location;
- stores by one logical processor are observed in a consistent order by other processors;
- locked operations are atomic and totally ordered with other locked operations;
- `MFENCE`, `LFENCE`, and `SFENCE` enforce their documented ordering domains;
- instruction fetch after self-modifying writes follows the documented synchronization protocol;
- faults do not commit a partially completed GEM-owned memory transaction.

Store Buffering's `0/0` result is architecturally permitted, not required. A serialized fallback
may therefore be stronger than x86-TSO, but it must never admit an x86-forbidden result. Tests must
reject forbidden outcomes and must not require a permitted weak outcome to occur.

The pinned Blink source is `f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580`. Its unmodified concurrent
interpreter and JIT are **not yet accepted** as the correctness path:

- aligned interpreter loads and stores use C acquire and release atomics on non-x86 hosts;
- unaligned interpreter accesses use byte-copy helpers;
- the AArch64-capable JIT's `NativeLoad*` and `NativeStore*` helpers use plain pointer accesses;
- guest fences use a sequentially consistent C fence;
- locked read/modify/write paths use C atomics where available and hashed bus locks otherwise; and
- self-modifying-code invalidation uses an attention flag and JIT-page reset protocol.

These are source facts, not proof that ARM64 execution satisfies x86-TSO. In particular, C
acquire/release does not by itself establish x86's single observed store order, and concurrent
plain JIT accesses create an unaccepted host-language data-race assumption. The checked inventory
tool fails if any reviewed source changes before this analysis is updated.

Until interpreter and JIT litmus suites pass, GEM must select the bounded interpreter as its
deterministic fallback for concurrent x64 execution. JIT execution remains an optimization
candidate, not the oracle. If the JIT times out, crashes, or admits a forbidden result, mode
selection must fail over to a separately passing interpreter run. No hardware-TSO path is enabled:
current evidence provides no supported, queryable, per-thread macOS API suitable for this runtime.

## Required conformance

Both the serialized interpreter and every candidate optimized mode must run bounded, repeated
x86_64 guest tests for:

1. Store Buffering (the only listed test where `0/0` is permitted);
2. Load Buffering;
3. Message Passing;
4. IRIW;
5. locked read/modify/write total order and atomicity;
6. fence ordering; and
7. self-modifying-code publication and instruction-cache invalidation.

Interpreter and JIT results must be reported separately. Timeouts, crashes, unavailable modes,
or malformed output fail closed. Passing empirical runs do not broaden the contract or justify
selective barrier substitutions without a source-level proof.

## Consequences

Blink is pinned as an ISC-licensed build dependency but is not copied into this repository.
Generated executables and x86_64 guest images remain build-tree-only. Issue #12 remains open until
native ARM64 macOS repeatedly passes the suite with hardware TSO disabled or unavailable and the
runtime exposes deterministic fallback selection for every unproven optimized case.
