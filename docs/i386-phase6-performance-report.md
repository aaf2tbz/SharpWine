# i386 Phase 6 performance report

Status: W9 engine measurements complete; final interactive Notepad distribution pending the
remaining Wine callback/exception fix.

## Acceptance policy

SharpWine's native macOS ARM64 execution evidence decides whether an i386 capability is retained.
Interpreter/JIT equality, checked state and fault behavior, deterministic corpus coverage, and real
guest program loading are positive capability evidence. External implementations and native-Windows
results are comparison oracles, not ceilings. A CPUID family is masked only while its native GEM/Blink
implementation is genuinely incomplete.

## Method

Five independent Release runs used the Phase 5.5 performance fixture on native Apple ARM64. Each run
compares one-instruction stepping with the checked multi-instruction path and verifies one-step,
bounded-interpreter, and JIT equality at every tested budget boundary. The optimized path retains
transaction validation, precise stops and faults, async stops, and full state export at observable
boundaries.

Host: macOS 27.0 (26A5378n), arm64, Apple clang 21.0.0. Build:
`sharpwine-phase-6-w9-final`. Machine-readable samples and counters are in
`docs/architecture/adr/i386-phase6-performance-evidence.json`.

## Results

| Sample | Step median (ns) | Run median (ns) | Speedup | Throughput (instructions/s) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 39,781,000 | 3,816,000 | 10.425× | 17,174,004 |
| 2 | 37,782,000 | 4,004,000 | 9.436× | 16,367,632 |
| 3 | 37,393,000 | 3,848,000 | 9.718× | 17,031,185 |
| 4 | 39,021,000 | 3,857,000 | 10.117× | 16,991,444 |
| 5 | 38,922,000 | 3,779,000 | 10.300× | 17,342,154 |
| **Median** | **38,922,000** | **3,848,000** | **10.117×** | **17,031,185** |

The required floor is 3.000×. The adaptive checked quantum reaches 4,096 instructions and reduces
the fixture from 1,536 quanta at the former 256-instruction ceiling to 336. A representative run
retired 360,576 instructions with 336 snapshots/imports/exports, zero retries, 1,376,256 bytes copied,
zero committed write bytes, and 43 µs lock wait.

The JIT/block equality lane retired 32,896 instructions with 8 compilations, 32,896 executions,
32,888 JIT cache hits, zero failures, 8 blocks created, 32,633 block-cache/direct-link hits, and zero
code invalidations. The CALL/RET probe recorded 64 calls, 64 returns, 64 correct predictions, zero
misses, and four precise block invalidations.

## Loader relevance

Writable, non-executable host-backed pages are now lazily refreshed at Wine boundaries while
executable pages retain reviewed decode/JIT state. A dedicated conformance test mutates host-backed
data between guest runs and proves the next run observes it without discarding cached code. Internal
data reconciliation likewise avoids code-cache eviction unless the old or new page is executable.

With this synchronization policy, the real 32-bit Notepad path progressed from an unbounded,
snapshot-dominated loader stall to DLL/NLS initialization and window-creation code in about 33
seconds. That is substantive native program-loading evidence. The remaining failure is a reproducible
callback/exception unwind fault after a truncated window-data pointer; enlarging the guest stack would
only hide that defect, so the Phase 6 exit checkbox remains open until the native callback/state path
is fixed and visible launch distributions are captured.

## Verification

- Fresh locked Blink patch application produced `blink/gem_embed.c` SHA-256
  `4590a5fb149a95d9f7f0a928686c0e0b7cd6c704773a4e6ba0f720d81b395b61`.
- All 35 tests enabled in the fresh W9 build passed, including both authentic ARM64X tests and all
  enabled i386 conformance, golden, randomized, performance, page, and concurrency gates.
- The broader build passed all 42 configured tests, including both authentic ARM64X lanes. The
  roundtrip CI regression was fixed by removing a stale expectation that Blink's private lazy-parity
  byte appear in architectural RFLAGS.
