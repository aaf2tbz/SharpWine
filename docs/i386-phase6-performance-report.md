# i386 Phase 6 performance report

Status: W10 complete; W11 active. Engine measurements, 32-bit Notepad, and the complete persistent
32-bit Notepad++ native-window loading gate pass on macOS ARM64. W11 retains startup latency,
input latency, and overlay repaint as the final performance gate.

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
`sharpwine-phase-6-w9-refresh-final2`. Machine-readable samples and counters are in
`docs/architecture/adr/i386-phase6-performance-evidence.json`.

## Results

| Sample | Step median (ns) | Run median (ns) | Speedup | Throughput (instructions/s) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 40,181,000 | 4,004,000 | 10.035× | 16,367,632 |
| 2 | 37,388,000 | 3,871,000 | 9.658× | 16,929,992 |
| 3 | 36,850,000 | 3,829,000 | 9.624× | 17,115,696 |
| 4 | 37,148,000 | 3,751,000 | 9.903× | 17,471,608 |
| 5 | 37,413,000 | 3,880,000 | 9.643× | 16,890,722 |
| **Median** | **37,388,000** | **3,871,000** | **9.658×** | **16,929,992** |

The required floor is 3.000×. The adaptive checked quantum reaches 4,096 instructions and reduces
the fixture from 1,536 quanta at the former 256-instruction ceiling to 336. A representative run
retired 360,576 instructions with 261 page snapshots, 336 state imports/exports, zero retries,
1,069,056 bytes copied, zero committed write bytes, and 41 µs lock wait.

The JIT/block equality lane retired 32,896 instructions with 8 compilations, 32,896 executions,
32,888 JIT cache hits, zero failures, 8 blocks created, 32,633 block-cache/direct-link hits, and zero
code invalidations. The CALL/RET probe recorded 64 calls, 64 returns, 64 correct predictions, zero
misses, and four precise block invalidations.

## Loader relevance

Writable, non-executable host-backed pages are lazily refreshed at Wine boundaries, read-only
executable pages retain reviewed decode/JIT state, and writable executable pages are reconciled once
per public run. Dedicated production-JIT and interpreter gates prove guest writes reach an external
RWX page and a later host mutation is observed on the next run. A transaction conflict forces a
resynchronization before retry.

With this synchronization policy, the real 32-bit Notepad path no longer consumes a stale
`RtlGetLocaleFileMappingAddress` output pointer or takes the compiler's deliberate null trap. Wine
patch 0022 then closes the later native Darwin ARM64 reentry defect: a native Wine service entering
the guest-resident GEM syscall or Unix-call PE boundary is serviced and resumed instead of being
converted into an access violation and recursive exception dispatch.

With matching PE and Unix `win32u` artifacts, a clean production `WINEDEBUG=-all` execution remained
alive beyond the former crash window and produced a visible, frontmost macOS window titled
`Untitled - Notepad`. This is direct real-program loading and native-window evidence. It is also the
reason the implementation is retained: external comparison runtimes are useful oracles, but are not
capability ceilings or vetoes for behavior SharpWine proves on macOS ARM64.

The W10 application gate extends that proof to the official Notepad++ 8.9.7 32-bit portable
distribution (archive SHA-256
`ce0690fac91c1fc5d61dcdf5b09733ff0d143a61d0a27c6cb9f4003ea92765bb`). Both the interpreter and
production JIT loaded `C:\\npp-8.9.7\\notepad++.exe` into a visible 1016×705 native macOS window
titled `new 1 - Notepad++ [Administrator]`. The JIT window appeared within 267 seconds in the
instrumented run. Correcting aligned cold SIMD-store retirement and preserving the full destination
range of cross-page legacy REP operations kept the generated `stylers.xml` and `langs.xml` files
valid and eliminated the prior partial-buffer failure without masking SSE2 or another CPUID family.

This is a program-loading acceptance result, not a claim that interactive performance is finished.
User-observed typing can take about five seconds to appear, and menus or other overlay pages can
remain blank until pointer hover causes repaint. Those are the explicit W11 startup, input-latency,
and invalidation targets.

### Persistent-window checkpoint

The window gate was reconfirmed on 2026-07-18 with the official Notepad++ 8.9.7 32-bit minimalist
portable archive (SHA-256
`6700cafa0ade7d79f0c51edc881d3af83f79110c3cb4a1b54cb1248454aa501e`). The PE32 editor itself
has SHA-256 `f54d67663a6356f69c1be302f2dfb82c6b7a66f72e4d86c1e3fe3a6ac413d6e9`. A native ARM64
SharpWine/GEM-Blink JIT runtime with deployed dylib SHA-256
`5ee0d37d4f075b3562587765aecb9d006a02ff5932e5f3c20eb8fad5223959b3` launched the editor with
`-noPlugin -nosession`, zero Rosetta, and `WINEDEBUG=-all`.

Computer Use captured and then independently recaptured a persistent window titled
`new 1 - Notepad++ [Administrator]`. Both captures visibly contained the complete application
frame: title bar, File/Edit menu row, toolbar, document tab, editor surface, and status bar. This is
the application-window proof; a typed glyph is not used as a substitute. The first qualifying
capture occurred 139.752 seconds after the recorded launch epoch, so this checkpoint closes only
the real-window/no-window-regression sub-gate. It does not close W11's 15-second startup, input, or
menu-overlay requirements.

## Verification

- Fresh locked Blink patch application produced `blink/gem_embed.c` SHA-256
  `5880d08128b08aac307ac03678030d51a697f08be8f274f7b4d8d1a759c132ca`.
- All 37 tests enabled in the fresh W9 refresh build passed, including the production-JIT and
  interpreter external executable-page refresh gates plus all enabled i386 conformance, golden,
  randomized, performance, page, and concurrency gates.
- The broader build passed all 42 configured tests, including both authentic ARM64X lanes. The
  roundtrip CI regression was fixed by removing a stale expectation that Blink's private lazy-parity
  byte appear in architectural RFLAGS.
- Wine patch 0022 applies cleanly with `git am`; the Wine patch validator and five patch-policy unit
  tests pass. Formatting, repository hygiene, the zero-Rosetta audit, and all 37 tests in the fresh
  configured W9 build pass.
