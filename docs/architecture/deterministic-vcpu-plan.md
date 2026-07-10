# Deterministic Virtual-CPU Escape Plan

Date: 2026-07-10
Status: architecture selected by user

## Executive decision

Stop making correct Windows execution depend on direct execution of PE instructions under undocumented Darwin VM/code-page behavior.

Keep Wine as the native ARM64 Windows personality, loader, server, Unix integration, and API implementation. Insert a **Guest Execution Manager (GEM)** between Wine and every Windows instruction stream:

- ARM64/ARM64EC PE instructions initially run under an established AArch64 virtual CPU engine.
- x86_64 PE instructions run under Blink through the existing `xtajit64` integration.
- ARM64EC call checkers and thunks transition through one explicit broker driven by Microsoft’s documented ABI and captured binaries.
- Guest x18 is a field in guest CPU state and is therefore always the canonical TEB, independent of Darwin’s x18, `TPIDR_EL0`, Mach-O `__PAGEZERO`, page faults, signals, or mapping provenance.
- Direct native ARM64EC execution becomes a later optional optimization, never the correctness foundation.

This is not a claim that any software project is literally guaranteed. It is the strongest deterministic escape because every presently blocking host behavior becomes non-authoritative. If a fast engine fails, a slower interpreter/TCG-compatible path remains the correctness oracle.

## Why not rewrite Wine

A new Wine implementation would have to reproduce the PE loader, ntdll, wineserver protocol, object manager, registry, synchronization, exceptions, APCs, process/thread semantics, COM, graphics plumbing, Unix calls, and decades of compatibility fixes. It would still face x18 and low-address constraints unless guest execution were virtualized.

The correct fork boundary is therefore **Wine’s CPU execution substrate**, not Wine’s Windows implementation.

## Evidence behind the decision

### Apple

The SDK contract for `os_set_custom_x18_abi_enabled()` states:

- mode is per-thread and strictly toggled;
- redundant setter calls abort;
- ordinary macOS libraries/frameworks cannot be called while enabled;
- signals and asynchronous entries require explicit bracketing;
- disabling destroys custom x18 and macOS owns the host x18 value;
- application code owns x18 only on the custom-ABI side.

Our tests additionally show that raw `TPIDR_EL0` presentation is execution-context-sensitive. It cannot serve as a universal logical-state oracle. Generic staged file mappings work, but Wine’s ARM64X pages exhibit different visible x18 behavior. Depending on undocumented page classification cannot be the correctness architecture.

Apple’s JIT guidance requires W^X discipline, `MAP_JIT` where applicable, thread-local write protection or allowlisted write callbacks, and instruction-cache invalidation before execution.

### Microsoft ARM64EC

Microsoft’s ABI documentation requires:

- x18 maps to x64 `GS.base` and is fixed to the TEB;
- ARM64EC uses only the registers representable in an x64 `CONTEXT`;
- x13, x14, x23, x24, x28 and v16-v31 are disallowed;
- indirect call checkers are mandatory, even when CFG is disabled;
- checker inputs/outputs use x9/x10/x11 and preserve specified parameter registers;
- entry and exit thunks are signature-specific;
- entry thunks preserve x64-nonvolatile XMM state and receive aligned SP/original x64 SP state;
- `__os_arm64x_dispatch_call_no_redirect` requires the `blr x16` hint contract;
- `__os_arm64x_dispatch_ret` returns from ARM64EC to x64 emulation;
- ARM64EC functions carry entry-thunk metadata immediately before function entry;
- ARM64X/CHPE metadata and code ranges identify native and x64 portions.

LLVM’s `AArch64Arm64ECCallLowering` is an executable reference for generating checkers and signature-specific entry/exit/guest-exit thunks. It should be treated as a conformance source alongside Microsoft’s documentation and Wine’s generated objects.

## Target architecture

```text
macOS ARM64 process
│
├── Native ARM64 Mach-O Wine host + Unix modules
│   ├── wineserver / NT objects / registry / I/O
│   ├── PE loader and ARM64X metadata parser
│   ├── signal and exception ingress
│   └── graphics/audio/media Unix bridges
│
└── Guest Execution Manager (GEM)
    ├── GuestMemoryMap
    │   ├── canonical Windows virtual addresses
    │   ├── high-address identity mappings where safe
    │   ├── low-address aliases (including 0x7ffe0000)
    │   └── guest page protections independent of 16 KiB host pages
    │
    ├── GuestThreadContext (one per Wine thread)
    │   ├── ARM64EC/x64 mapped GPR state
    │   ├── canonical guest x18 / GS.base / TEB
    │   ├── PC, SP, flags/PSTATE
    │   ├── v0-v15 / XMM0-XMM15
    │   ├── FPCR/FPSR/MXCSR representation
    │   └── exception, APC and suspend state
    │
    ├── ARM64EC Engine
    │   ├── correctness engine: established AArch64 emulator/TCG library
    │   ├── optional fast engine: Frida Gum Stalker after conformance
    │   └── per-block fallback to correctness engine
    │
    ├── x64 Engine
    │   └── Blink (`xtajit64`), per-thread Machine state
    │
    └── Transition Broker
        ├── ARM64EC call checkers
        ├── signature-specific entry/exit thunks
        ├── DispatchJump / ExitToX64 / RetToEntryThunk
        ├── syscall and Unix-call gates
        └── exception/context conversion
```

## Non-negotiable design rules

1. A guest PC is never invoked as a native C function pointer in the correctness path.
2. Darwin x18 is never used as authoritative guest state.
3. `GuestThreadContext.x18` must equal that thread’s TEB at every guest instruction boundary.
4. macOS/POSIX/framework calls occur only in native host mode with Darwin ABI restored.
5. Every architecture transition is represented as a state-machine operation, not a signal-handler trick.
6. No static x18-to-x28 substitution.
7. No guessed ARM64EC helper ABI.
8. ARM64X address classification comes from parsed image metadata, not instruction guessing.
9. Engines may optimize execution but cannot own canonical state; GEM owns it.
10. Every optimized block has a deterministic fallback.

## Canonical state model

Create `struct gem_thread_context` with explicit fixed-width fields and compile-time layout assertions. Do not reuse host `ucontext_t` as canonical state.

Minimum state:

- mapped integer registers x0-x12, x15-x22, x25-x27, fp, lr, sp and pc;
- guest x18/TEB;
- ARM64EC-visible x64 aliases (RCX/RDX/R8/R9/RAX/RSP/RIP/etc.);
- v0-v15 at full 128-bit width;
- NZCV and the supported x64 flags subset;
- FPCR/FPSR and normalized MXCSR;
- x64-only state Blink requires, including parity/auxiliary/direction flags and x87/MM registers;
- current ISA (`ARM64EC` or `X64`), run reason, pending exception and transition frames.

Write conversion routines as pure functions and test them exhaustively:

- ARM64EC → x64/Blink;
- x64/Blink → ARM64EC;
- ARM64EC → Windows `CONTEXT`;
- Windows `CONTEXT` → ARM64EC;
- signal/host fault → Windows exception record without adopting host register state as canonical.

## Memory model

GEM owns a page table with Windows protection semantics and a configurable guest page granularity. Host mappings are implementation details.

- Preserve canonical guest addresses.
- Identity-map safe high ranges only as an optimization.
- Resolve low addresses through aliases or engine memory callbacks.
- Split 16 KiB host pages into logical guest protection subranges where necessary.
- Keep code bytes immutable to execution engines until Wine changes guest protections.
- Track ARM64X code ranges and architecture at page/range granularity.
- Never infer ISA solely from bytes at an indirect target.

All engine memory access goes through `gem_translate_read/write/execute()`. Direct host dereference is optional only after proving an identity mapping and protection match.

## Transition broker

Implement the documented contracts in this order:

1. **Address classifier**
   - Parse load-config CHPE/ARM64X metadata.
   - Return ARM64EC, x64, thunk, fast-forward, data, or invalid.

2. **Call checker**
   - Implement `__os_arm64x_check_icall` and CFG variant semantics.
   - Inputs/outputs exactly follow x9/x10/x11 contracts.
   - Preserve x0-x8, x15 and q0-q7 as required.

3. **ARM64EC → x64**
   - Execute the compiler-generated signature-specific exit thunk in the ARM64EC engine.
   - Trap the documented dispatch helper call.
   - Convert canonical state to Blink.
   - Push/record x64 and ARM64EC return information exactly as documented.

4. **x64 → ARM64EC**
   - Detect ARM64EC ranges through metadata.
   - Resolve the four-byte entry-thunk descriptor.
   - Align guest SP while retaining original x64 SP in the required register/state.
   - Convert Blink state, run the generated entry thunk in the ARM64EC engine, and preserve XMM6-XMM15.

5. **Return paths**
   - Implement `dispatch_ret`, `ExitToX64`, and `RetToEntryThunk` from captured state traces and documented contracts.
   - Validate normal return, tail call, indirect jump, exception unwind and longjmp independently.

## Engine strategy

### Correctness engine

Evaluate established multi-architecture virtual CPU libraries in a licensing and conformance spike. The engine must provide:

- AArch64 instruction coverage sufficient for Wine/LLVM ARM64EC output;
- complete register get/set;
- memory callbacks or deterministic mapped-memory control;
- synchronous fault hooks;
- single-step/block hooks;
- macOS ARM64 support;
- no Rosetta dependency;
- acceptable licensing for the intended distribution.

An emulator derived from QEMU TCG (for example a library-style integration) is the preferred correctness class because it virtualizes architectural state instead of relying on host registers. It is a correctness oracle, not necessarily the final high-performance engine.

### Fast engine

Prototype Frida Gum Stalker only after the oracle passes. Stalker may execute transformed AArch64 blocks from a controlled code cache, but it must synchronize state at every transition/fault and fall back whenever semantics are uncertain. It cannot silently use host x18 as canonical state.

QBDI remains the second fast-engine candidate if Stalker cannot meet context/fault requirements.

### x64 engine

Retain Blink. Do not replace a working x64 engine merely for architectural symmetry. Wrap it behind the same GEM run interface:

```c
enum gem_stop_reason gem_run_x64(struct gem_thread_context *, uint64_t budget);
```

## Implementation phases and gates

### Phase A — Freeze and specify (2-4 days)

- Create a clean Wine branch/worktree for GEM.
- Preserve current direct-execution work as diagnostics, not production behavior.
- Write `gem_thread_context`, transition-state diagrams and invariants.
- Extract Microsoft ABI examples into machine-checkable tests.
- Inventory ARM64X metadata from Wine ntdll and small test DLLs.

**Gate A:** state layout and all conversion contracts have tests before an engine is linked.

### Phase B — Engine bake-off (3-7 days)

Test the correctness-engine candidates with the same suite:

- arithmetic and branches;
- load/store and atomics;
- x18 independent of host x18;
- v0-v15, FPCR/FPSR;
- 4 KiB guest pages on 16 KiB host pages;
- low `0x7ffe0000` access;
- synchronous faults and deterministic stop reasons;
- self-modifying/protection-changing code;
- native ARM64 macOS build and licensing review.

**Gate B:** select one correctness engine only after every required primitive passes. Otherwise evaluate the next established engine.

### Phase C — GEM standalone harness (1-2 weeks)

- Implement canonical context and memory map.
- Load a minimal ARM64EC PE/ARM64X image without Wine startup.
- Execute a leaf ARM64EC function.
- Exercise call checkers and generated thunks.
- Transition ARM64EC → Blink x64 → ARM64EC.
- Compare every register, SIMD lane, flag and stack byte against expected fixtures.

**Gate C:** repeatable round trip with zero host-x18 dependency.

### Phase D — Wine integration (2-4 weeks)

- Add GEM as an ntdll Unix-side execution service.
- Route initial thread context to GEM instead of native `ret` into PE.
- Route syscalls/Unix calls back through explicit stop reasons.
- Connect Wine virtual-memory events to GEM mappings/protections.
- Convert Wine exceptions, APCs, suspend/resume and thread creation.
- Initialize one GEM context per Wine thread.

**Gate D:** fresh-prefix `wineboot --init` and ARM64 `cmd.exe /c exit` complete under the correctness engine.

### Phase E — ARM64EC/x64 completeness (2-4 weeks)

- Implement full checker/entry/exit/return broker.
- Reach and exercise `xtajit64` naturally.
- Run x64 console programs through Blink.
- Validate callbacks from x64 into ARM64EC and nested transitions.
- Add unwind, setjmp/longjmp, exceptions and APC stress tests.

**Gate E:** ARM64EC → x64 → ARM64EC works for direct, indirect, callback, exception and tail-call paths.

### Phase F — Performance (ongoing after correctness)

- Add block cache and high-address direct-memory fast paths.
- Prototype Stalker as an ARM64EC fast engine.
- Keep per-block oracle fallback.
- Profile transition count, memory translation and JIT contention.
- Preserve process serialization around Blink shared JIT generation until proven safe.

**Gate F:** optimization must produce identical state traces to the correctness engine.

### Phase G — Product validation

- Validate native ARM64, ARM64EC and x64/Blink in that order.
- Defer i386 until the 32-bit translated address-space implementation exists.
- Build/stage DXMT and Winemetal only after runtime gates pass.
- Audit every Mach-O file/process for ARM64 and every run for zero Rosetta.

## Test hierarchy

Every layer gets deterministic fixtures:

1. Pure context conversion unit tests.
2. Memory/protection/page-size tests.
3. Single-ISA engine tests.
4. Generated thunk fixtures from LLVM/MSVC-compatible output.
5. ARM64EC/x64 round-trip tests.
6. Exception/APC/context tests.
7. Wine startup tests.
8. Graphics and game tests.

Each runtime test uses a fresh prefix, timeout, 2 MiB retained log, process-group termination and wineserver cleanup.

## Stop conditions

Stop and redesign a component if:

- it requires native execution of arbitrary PE code for correctness;
- it stores canonical guest x18 only in host x18;
- it guesses target ISA from instruction bytes;
- it cannot reconstruct exact state after a fault;
- it requires Rosetta;
- it cannot fall back from optimized execution;
- its license is incompatible with the intended distribution.

## First concrete actions

1. Create `gem/ABI.md` defining canonical state and Microsoft mappings.
2. Extract Wine ARM64X load-config metadata from current `ntdll.dll` into JSON fixtures.
3. Build a 20-case engine conformance suite independent of Wine.
4. Evaluate a QEMU-TCG-derived library/runtime first for correctness, then Frida Stalker and QBDI as accelerated execution candidates.
5. Do not alter installed Wine startup until Gate C passes standalone.

## Primary references

- Apple SDK: `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/os/arch/arm64.h`
- Apple, “Porting just-in-time compilers to Apple silicon”:
  https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon
- Microsoft, “Overview of ARM64EC ABI conventions”:
  https://learn.microsoft.com/en-us/cpp/build/arm64ec-windows-abi-conventions
- Microsoft, “Understanding Arm64EC ABI and assembly code”:
  https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi
- LLVM ARM64EC call lowering:
  https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64Arm64ECCallLowering.cpp
- Wine source and generated ARM64X objects in this project.
