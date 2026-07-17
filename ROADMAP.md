# Roadmap

## First completion target: v0.1 — Integrated deterministic Wine runtime

Milestones 0–5 established a standalone, repeatable ARM64EC → x86_64/Blink → ARM64EC round trip whose canonical state never depends on Darwin x18. Issue #15 is the v0.1 release epic: the first official release must integrate that substrate into a clean, pinned Wine 11.12 build and publish an audited, self-contained native ARM64 runtime archive. PR #20 establishes the versioned Wine/GEM bridge and inert release contracts; Issues #21–#25 divide clean Wine construction, ntdll lifecycle/memory integration, native ARM64 execution, authentic hybrid execution, and final packaging/publication into separately accepted PRs. A standalone engine or vanilla Wine build with an adjacent unused engine is not a v0.1 release. See proposed [ADR 0009](docs/architecture/adr/0009-integrated-wine-v0.1-release.md).

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
- Pinned Wine 11.12 is reproducibly built with `--enable-archs=i386,x86_64,aarch64,arm64ec` from an ordered, reviewed LGPL patch series.
- Wine routes initial execution, virtual-memory events, required syscall/Unix-call boundaries, exceptions, and thread state through GEM without weakening its ownership contracts.
- Bounded fresh-prefix `wineboot --init`, ARM64 `cmd.exe /c exit`, and accepted ARM64EC/x64 integration probes pass.
- A deterministic `metalsharp-wine-v0.1.0-macos-arm64.tar.zst` and its checksum, SBOM, provenance, limitations, and evidence assets are published from the protected final `main` commit.
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
- [x] Prove atomic and transactional behavior for misaligned and cross-4-KiB-page guest accesses.
- [x] Keep hardware TSO optional; the native probe found no supported, queryable, per-thread API.
- [x] Do not depend on private TSO symbols, kernel extensions, Rosetta process state, or an unverified Virtualization.framework control.
- [x] Preserve distinct logical permissions for 4 KiB guest pages sharing a 16 KiB host page through checked GEM translation.
- [x] Reject temporary host-page permission widening, guessed `ucontext_t` debug-state mutation, and process-global signal single-stepping as correctness mechanisms.
- [ ] Evaluate Mach exceptions or direct mappings only as optional accelerations after race, reentrancy, fault, and multithreaded conformance tests pass.

**Exit gate:** memory-order litmus tests and 4 KiB protection/fault tests pass repeatedly on native
ARM64 macOS with hardware TSO disabled or unavailable, and every acceleration has a deterministic
GEM-owned fallback.

## Milestone 5 — Blink integration and hybrid round trip

- [x] Define a stable GEM x64-engine interface around Blink.
- [x] Move existing Blink memory alias and per-thread Machine behavior behind that interface.
- [x] Implement pure GEM ↔ Blink state synchronization.
- [x] Preserve XMM6-XMM15 and x87/MM state required by the accepted integer path.
- [x] Implement a bounded transition frame for ARM64EC return LR, x64 return address, aligned SP, and original x64 SP.
- [x] Implement the evidenced dispatch-call and dispatch-ret stops used by the accepted integer path.
- [x] Execute ARM64EC → exit thunk → Blink x64 → entry thunk → ARM64EC.
- [x] Add callbacks, tail calls, nested transitions, memory faults, and unsupported-instruction cases.
- [x] Compare every final canonical field and touched stack byte across repeated accepted-path runs.
- [x] Keep Blink JIT disabled; any future generation remains process-serialized until concurrency is proven safe.
- [x] Route all x64 memory effects through the proven memory-order and guest-page contracts; a byte-prefix scanner is not an acceptable decoder.
- [x] Perform native instruction-cache maintenance only when host executable code is created or modified; the interpreter creates none and adds no transition `ISB`.

**Exit gate:** complete — final implementation CI run
[`29187287010`](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/actions/runs/29187287010)
passed two reproducible native Windows ARM64 fixture builds, the strict one-day artifact handoff,
the complete authentic transition/failure/oracle matrix on native macOS ARM64, Linux GCC/Clang and
Apple Clang, x86 TSO, 4 KiB-on-16 KiB page isolation, policy/format/provenance/leakage checks, and
zero-Rosetta audits. Local Apple Clang ASan+UBSan passed the complete 15-test matrix, and Apple
`leaks` reported zero leaks. ADR 0008 is Accepted; Milestone 5 is complete.

## Milestone 6 — Wine integration and release hardening

- [x] Define and test the versioned native Wine/GEM bridge ABI, component install, exported-symbol allowlist, lifecycle conflicts, checked mapping surface, bounded callbacks, and native ARM64 execution profile in PR #20.
- [x] Define fail-closed integrated-release asset, evidence, readiness, permission, and publication contracts while leaving publication inert in PR #20.
- [x] Complete #21: clean pinned Wine patch queue, Darwin ARM64 loader foundation, and reproducible four-architecture build.
- [x] Complete #22: direct ntdll linkage plus GEM process, memory, thread, KUSER, protection, and invalidation integration.
- [x] Complete #23: native ARM64 PE execution through GEM with syscall/Unix-call/exception boundaries, bounded `wineboot`, and ARM64 `cmd.exe`.
- [x] Complete #24: authentic ARM64EC/x64 execution through the integrated Wine path.
- [x] Complete #25: self-contained relocatable package, hardening, reproducibility, evidence, protected-main publication, and post-release verification.
- [ ] Add deterministic trace format with versioning and redaction.
- [ ] Add bounded stress tests and randomized state round trips.
- [ ] Add ASan/UBSan Linux jobs and supported macOS sanitizer coverage.
- [x] Import required Wine 11.12 changes as an ordered, reviewed LGPL-2.1-or-later patch series; reject local dirty worktrees as build inputs.
- [x] Reproduce the native host plus `i386,x86_64,aarch64,arm64ec` PE build from pinned clean sources and toolchains.
- [ ] Route initial PE thread entry and Wine virtual-memory events through GEM.
- [ ] Implement the required syscall, Unix-call, exception, APC, suspend/resume, and thread boundaries without transferring canonical authority from GEM.
- [ ] Reach x64 naturally through Wine's selected ARM64EC emulation interface and the accepted Blink adapter.
- [ ] Pass bounded fresh-prefix `wineboot --init`, ARM64 `cmd.exe /c exit`, and accepted hybrid probes.
- [ ] Add dependency license/SBOM generation.
- [ ] Add reproducible toolchain and fixture-generation documentation.
- [ ] Audit all packaged Mach-O files and launched processes for ARM64-only execution.
- [ ] Produce and independently validate the deterministic package and publication assets defined in [`docs/release/integrated-wine-package.md`](docs/release/integrated-wine-package.md).
- [x] Publish immutable v0.1.0 assets from the protected final `main` commit through a least-privilege release job.
- [x] Replace README's development-status notice in the final merge with an accurate v0.1.0 status, supported scope, known-limitations link, release link, and evidence link; do not claim unaccepted acceleration, graphics, i386, or application support.

**Exit gate:** all release acceptance criteria have links to CI runs, fixtures, test names, and architecture records; the accepted native ARM64 Wine build is packaged and uploaded by the release operator, then the protected-main workflow redownloads, validates, exercises, and publishes the hash-bound `.tar.zst`, checksum, SBOM, provenance, limitations, and evidence assets. The README on `main` reports the final supported v0.1.0 status and links to those published records rather than retaining the architecture-foundation notice.

## Native ARM64 compatibility roadmap

Each phase ends with a dedicated, reviewed commit after its phase-specific tests pass. A phase checkbox is marked complete only after that commit is pushed and its evidence is recorded.

- [x] **Phase 0 — Freeze the initial i386 semantic baseline**
  - preserve the current 514-case deterministic corpus
  - replay every case through the native ARM64 interpreter and JIT paths
  - retain the verified 1,028/1,028 comparison result
  - freeze arithmetic flags, CMPXCHG, LZCNT, unaligned atomics, and SSE4.1 packed min/max regressions in CI

- [x] **Phase 1 — Expand deterministic core instruction coverage**
  - cover 8-, 16-, and 32-bit arithmetic, flag boundaries, branches, calls, returns, and stack behavior
  - cover ModR/M, SIB, displacement, immediate, register, and memory forms
  - expand multiply/divide, shifts/rotates, bit operations, and aligned/unaligned atomic families
  - require identical interpreter/JIT state with no crashes or unsupported decoded instructions
  - completed in `2e8bacb`: 1,458 cases captured and 2,916/2,916 native interpreter/JIT comparisons passed

- [x] **Phase 2 — Add faults, memory boundaries, and code invalidation**
  - normalize invalid-opcode, divide, access, protection, fetch, and stack faults
  - cover instructions and operands crossing 4 KiB pages
  - verify partial-write and rollback behavior
  - cover self-modifying code and JIT invalidation
  - verify GEM fault results map into the correct Windows exception path

- [x] **Phase 3 — Complete legacy and Steam-relevant instruction state**
  - add x87 control, status, tag, and 80-bit value coverage
  - add MMX aliasing and transition coverage
  - extend packed/vector coverage through every feature advertised by CPUID
  - cover REP string instructions, direction-flag behavior, segmentation, and WoW64 context restoration
  - prevent CPUID from advertising any instruction family the runtime cannot execute

- [x] **Phase 4 — Add seeded randomized differential coverage**
  - generate valid cases from reviewed instruction templates
  - record seeds and defined-state masks for exact reproduction
  - isolate each case with watchdog and crash classification
  - automatically minimize mismatches
  - promote every discovered defect into a deterministic CI regression
  - completed in `739fdd3`: 20,313 pinned compatibility baseline records, 40,626/40,626 native comparisons, and 20,313/20,313 interpreter/JIT parity checks passed with zero failures; 45,810 native compatibility comparisons overall; evidence SHA-256 `799de284a2aebc46a4745d403742af968169ba737cfffe3ea4b7556ad0d5c36b`

- [x] **Phase 5 — Integrate the compatibility corpus into SharpWine CI**
  - maintain a hash-bound golden corpus that normal CI can replay without external runtime dependencies
  - run both native ARM64 interpreter and JIT replay jobs
  - track coverage by handler, width, operand form, addressing form, and fault class
  - reject untested CPUID additions and unreviewed Blink source drift
  - use real application traces to prioritize uncovered handlers
  - completed in `739fdd3`: the accepted 20,313-case corpus is permanently bound by golden SHA-256 `179ed278a8382fa4b3066b73b2aecf5c791880492505c1b93ba6e6922d67755b`; separate native ARM64 interpreter and JIT replays pass in normal CI without external runtime dependencies

- [x] **Phase 5.5 — Harden concurrent execution and remove prototype bottlenecks**
  - replace process-wide serialized guest-memory execution with conflict-safe concurrent reads and atomic staged writes
  - add deterministic page generations and retry behavior for write conflicts, mapping changes, and external host-backed memory
  - add a true multi-instruction Blink execution path that amortizes state import/export, page synchronization, and decode/JIT setup
  - preserve precise exits for syscalls, callbacks, faults, restartable REP operations, atomics, invalidation, and self-modifying code
  - add multi-threaded read, write, RMW, mapping, teardown, race, and deadlock stress coverage
  - retain every deterministic compatibility gate and require a measured improvement in visible 32-bit Notepad startup and interaction before resuming installer testing
  - completed in `489a522` after the reviewed Phase 6 checkpoint `b77f7b8`: five-sample Release microbenchmark median is 9.003× locally and the hosted Release gate passed the required 3× floor; Linux ThreadSanitizer and native 4 KiB page-isolation/concurrency suites each passed 100 consecutive repetitions; all 45,810 compatibility comparisons remain retained; both visible Notepad launches were user-confirmed dramatically faster than the prototype, with zero perceived typing lag on the best sample

- [ ] **Phase 6 — Import FEX-proven CPU coverage without replacing GEM/Blink ownership**
  - keep GEM authoritative for i386 context, 4 KiB guest memory, faults, Windows boundaries, budgets, and teardown; keep Blink as the selected decoder/JIT and interpreter oracle
  - add a private versioned `gem_i386_engine_ops` seam so execution backends can be compared without changing the Wine/GEM bridge ABI or silently falling back inside a process
  - inventory FEX's stable x86 implementations, tests, ARM64 lowering strategies, and licenses by exact upstream revision; record which ideas are adapted, independently implemented, or rejected
  - use FEX as implementation evidence only; retain the native-Windows exact-byte oracle and SharpWine's hash-bound interpreter/JIT corpus as the semantic acceptance authority
  - expand the deterministic corpus around real Notepad, installer, and Steam traces before enabling any new CPUID bit
  - add complete `CMPXCHG16B`, BMI1, BMI2, RDTSCP, and deterministic timestamp-policy coverage where applicable to the selected guest architecture
  - add VEX decode and full XSAVE/XRSTOR/XGETBV state foundations before advertising OSXSAVE, AVX, AVX2, or FMA
  - add AVX/AVX2/FMA instruction families incrementally with defined-state masks, interpreter/JIT parity, native-Windows comparison, cross-page operands, faults, and context-switch preservation
  - retain explicit masking for every incomplete family, including AVX/AVX2/FMA, BMI, ADX, FSGSBASE, RDRAND/RDSEED, RDPID, and RDTSCP until its reviewed gate passes
  - adapt proven DBT techniques where they fit Blink: multi-instruction basic blocks, deferred flag materialization, guest-register caching, direct block linking, call/return prediction, SIMD register caching, and precise self-modifying-code invalidation
  - preserve exact exits for `sysenter`, WoW64 Unix calls, callbacks, exceptions, APCs, suspend/resume, atomics, restartable REP, executable writes, and asynchronous stop requests
  - compare one-step, bounded-quantum, and optimized-block execution at every budget boundary used by CI; a faster path must produce the same complete context, touched bytes, stop reason, and retired count
  - add explicit engine identity, block/JIT cache, invalidation, fallback, unsupported-opcode, and CPUID capability diagnostics to every application trace
  - require Linux ThreadSanitizer, native ARM64 stress, TSO, 4 KiB-on-16 KiB isolation, and the complete 45,810-comparison baseline to remain green
  - require a reviewed performance report covering instruction throughput, state transfers, page snapshots, bytes copied/committed, block reuse, invalidations, conflict retries, lock wait, and Notepad startup distributions
  - exit gate: the expanded engine runs the existing interactive Notepad path with no new unsupported instruction, no widened CPUID lie, no silent fallback, and a measured improvement or clearly documented compatibility gain

- [ ] **Phase 7 — Establish native graphics bootstrap, software rendering, and presentation lanes**
  - treat GUI presentation and graphics translation as explicit runtime components rather than incidental Wine DLL loading
  - preserve or port the native Swift/CoreGraphics/Metal window and shader path already proven by MetalSharp's visible Steam bootstrap; bind its source, compiled shader artifacts, deployment target, and ARM64-only dependency closure before claiming it in SharpWine
  - distinguish the native Swift/Metal presentation helper from Google's SwiftShader software renderer in code, logs, manifests, and user-facing diagnostics
  - define four non-ambiguous graphics lanes: `gdi_native`, `opengl_native`, `vulkan_swiftshader`, and `dxmt_metal`; never select a lane solely because a DLL happens to load
  - keep GDI/User32 controls, menus, text, and ordinary installer windows on native `winemac.drv`/CoreGraphics presentation with no 3D dependency
  - bring up Wine's OpenGL path against an ARM64 macOS OpenGL host module for compatibility workloads that can tolerate Apple's legacy OpenGL surface; audit pixel formats, contexts, child windows, resize, swap, threading, and teardown
  - add deterministic OpenGL fixtures for context creation, clear, textured draw, readback, resize, visibility, and destruction before enabling the lane for applications
  - package an ARM64-only Vulkan loader and SwiftShader Vulkan ICD as a deliberate software/bootstrap route for Chromium/CEF and Steam UI experiments
  - verify SwiftShader's complete Mach-O closure, ICD manifest paths, code signing, executable-memory behavior, deployment target, licenses, and relocatability without Homebrew or build-tree paths
  - add Vulkan fixtures for instance/device creation, queue selection, surface creation, clear/present/readback, resize, device loss, multithreaded submission, cache cleanup, and deterministic teardown
  - test Steam bootstrap combinations explicitly: `-disable-gpu`, Vulkan plus SwiftShader, native OpenGL where supported, and software compositing; record command line, loaded DLLs, ICD, renderer strings, window evidence, CPU usage, and failure boundary
  - do not call `-disable-gpu` a graphics solution by itself; verify whether Chromium selects software compositing, SwiftShader, OpenGL, or another path and preserve that selection in evidence
  - retain DXMT/Winemetal as the paired ARM64 game-rendering lane and prove that enabling OpenGL or SwiftShader for Steam does not replace or contaminate per-game DXMT routing
  - add route isolation tests showing Steam may use a bootstrap renderer while a launched game independently uses DXMT/Metal in the same prefix and process tree
  - add capability-driven selection and a fail-closed doctor report for missing ICDs, wrong architecture, mismatched PE/native halves, unavailable surfaces, shader compilation errors, and accidental Rosetta dependencies
  - measure window time-to-first-paint, frame cadence, resize latency, CPU consumption, memory growth, and clean shutdown for every lane
  - exit gate: at least one fully audited ARM64 software/bootstrap lane and the native presentation lane produce a persistent interactive SteamSetup/CEF-class test window, while DXMT/Metal remains independently verified for game rendering

- [ ] **Phase 8 — Complete Steam-relevant Win32 subsystems, observability, and sustained-runtime hardening**
  - convert the first Steam/installer failure into a structured trace that identifies the earliest bad CPU, memory, syscall, callback, GUI, graphics, COM, process, service, TLS, or filesystem boundary
  - add versioned, redacted event tracing across GEM stops, Wine syscalls/Unix calls, exceptions, callbacks, process/thread creation, DLL resolution, graphics-lane selection, and window lifecycle
  - validate common controls and dialogs, menus, fonts, icons, cursors, clipboard, timers, drag/drop, focus, IME/text input, DPI changes, multiple windows, minimize/restore, and deterministic window destruction
  - validate COM/OLE initialization, apartments, marshaling, callbacks, class registration, shell integration, URL handling, and the specific interfaces exercised by SteamSetup and steamwebhelper
  - validate BCrypt/SChannel/certificate-store behavior, HTTPS downloads, proxy discovery, DNS, sockets, WebSocket use, clock/timezone behavior, and updater signature/hash verification
  - validate process creation, inherited handles, job-like cleanup policy, named pipes, shared memory, events, mutexes, semaphores, file locking, temporary files, environment propagation, and mixed-bitness child processes
  - validate registry redirection, Known Folders, Program Files/SysWOW64 selection, fonts and cache paths, installer state, uninstall metadata, and prefix persistence across restart
  - validate CEF/Chromium sandbox decisions explicitly; never disable a sandbox or security boundary without a scoped rationale, diagnostic, and separate hardened acceptance plan
  - add watchdog classification for hangs, livelocks, callback recursion, lock inversion, runaway child processes, repeated fault loops, renderer crashes, and updater restart loops
  - run long-lived multithreaded stress with concurrent GUI events, rendering, network traffic, process creation, self-modifying code, mapping churn, and clean shutdown
  - add memory and resource accounting for GEM pages, shadow snapshots, translated blocks, JIT arenas, Wine handles, Mach ports, file descriptors, windows, graphics objects, and child processes
  - require repeated launch/close cycles to return resources to a reviewed steady-state envelope with no orphan Wine, helper, renderer, or wineserver process
  - retain ARM64-only process/Mach-O audits throughout success, crash, timeout, update, and teardown paths
  - exit gate: the diagnosed SteamSetup path reaches its first interactive page repeatedly with no unknown stop, deadlock, graphics ambiguity, or unbounded resource growth, and every remaining failure is assigned to a named subsystem with a reproducer

- [ ] **Phase 9 — Pass visible 32-bit application and installer gates (partially complete)**
  - status: partially complete; a real 32-bit Notepad window already launches through the native SharpWine i386/WoW64 path, draws correctly, and accepts keyboard input
  - [x] repeatedly launch an interactive Notepad window
  - [x] verify keyboard input and visible text rendering
  - [x] complete initial performance hardening and verify mouse, focus, move, close, and clean process teardown
  - [ ] rerun Notepad against the completed Phase 6 engine and Phase 7 graphics matrix and retain equivalent or better behavior
  - [ ] validate common dialogs, controls, fonts, icons, timers, COM, clipboard, DPI, multiple windows, and window destruction through the Phase 8 subsystem gates
  - [ ] launch a persistent, interactive `SteamSetup.exe` window with the selected graphics lane recorded
  - [ ] advance through every installer page using real mouse and keyboard input
  - [ ] verify downloads, child processes, prefix files, registry state, shortcuts, uninstall metadata, and installer cleanup
  - [ ] close and resume or restart the installer without corrupting prefix or cached payload state
  - [ ] repeat from at least three fresh prefixes and archive normalized logs, screenshots/window metadata, process proofs, renderer identity, installed state, and teardown evidence
  - exit gate: Steam installation completes visibly and repeatably without Rosetta, translated host executables, an unidentified renderer, or manual mutation of the resulting prefix

- [ ] **Phase 10 — Pass the clean-prefix Steam product gate**
  - start from a newly initialized SharpWine prefix and signed native ARM64 bundle
  - prove that the complete SharpWine process tree and Mach-O closure use no translated host executable or fallback runtime
  - complete the visible Steam installation through the accepted Phase 9 route
  - allow the bootstrap client to download, verify, and apply updates
  - visibly launch the installed Steam client using an explicitly recorded bootstrap graphics lane
  - verify login presentation, common controls, library rendering, keyboard, mouse, scrolling, links, dialogs, and multiple-window behavior
  - verify steamwebhelper/CEF child creation, crash recovery, renderer selection, shared memory, IPC, networking, and cleanup
  - launch a bounded test game through an independently selected DXMT/Metal route while Steam remains on its bootstrap renderer
  - close Steam cleanly, prove complete child/helper teardown, and relaunch it directly from the installed prefix
  - repeat install/update/launch/close/relaunch from clean prefixes and after an interrupted update
  - record bundle hashes, engine and CPUID profile, graphics lanes, installer, logs, process proof, renderer strings, installed state, screenshots/window metadata, resource envelope, and visible-window evidence

### Final acceptance gate

A clean native ARM64 SharpWine build must visibly install, update, launch, render, close, and relaunch Steam from its own prefix, then launch a bounded DXMT/Metal test game without changing Steam's accepted bootstrap renderer. A transient setup window, installer-only launch, unidentified software renderer, or one-time success does not satisfy this gate.

## Working rules

- One milestone exit gate at a time; no integration work may bypass a failed lower-level gate.
- Every ABI behavior requires published documentation or a legal, reproducible fixture.
- Research notes and sample code are hypotheses until reproduced against pinned public specifications, tool output, and native tests.
- PE machine identifiers, CHPE layouts, load-config offsets, and thunk-table meanings must come from pinned definitions or verified legal fixtures; no guessed structures are accepted.
- No proprietary Windows binaries or private diagnostics enter the repository.
- No direct native PE execution is required for correctness.
- No optimized path ships without a deterministic fallback.
- Every runtime test is bounded by time, log size, process-group cleanup, and zero-Rosetta auditing.
