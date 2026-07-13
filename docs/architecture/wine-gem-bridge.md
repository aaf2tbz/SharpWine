# Wine/GEM native bridge contract

The integrated Wine build links its native ARM64 Unix-side runtime directly to
`libmetalsharp-gem-wine.0.dylib`. It must not discover the bridge with delayed
`dlopen`, statically absorb GEM into Wine, or invoke a Windows guest PC as a
Darwin function pointer.

This document describes bridge ABI version 1. It is an implementation contract,
not evidence that Wine startup or hybrid execution has passed Issue #15.

## Packaging and ABI

The bridge is built with `MSWR_BUILD_WINE_BRIDGE=ON` and installed with the
`metalsharp-gem-wine` CMake component. That component contains only:

- `lib/libmetalsharp-gem-wine.0.1.0.dylib` and its `.0` and unversioned symlinks;
- `include/metalsharp/gem/context.h`;
- `include/metalsharp/gem/wine_bridge.h`.

Fetched Dynarmic development files are not part of this install component. The
bridge contains its pinned implementation dependencies and exposes only the
symbols in `cmake/metalsharp-gem-wine.exports`.

`gem_wine_bridge_abi_version()` must return
`GEM_WINE_BRIDGE_ABI_VERSION`. All public aggregate structures carry a version
and byte size where they cross a call or callback boundary. Reserved fields must
be zero. The 720-byte `gem_thread_context` remains unchanged.

The bridge header owns fixed-width copies of stop information, page-protection
values, KUSER addresses, and the 4 KiB guest-page size. It does not expose the
internal ARM64EC engine ABI.

## Ownership

One `gem_wine_process` owns one checked sparse GEM address space and a registry
of bridge threads. One `gem_wine_thread` owns one transient engine view. GEM
remains authoritative for:

- the canonical thread context;
- `x18 == TEB`;
- guest mappings and protection checks;
- faults and stop classification;
- instruction and callback budgets;
- instruction-cache invalidation.

Wine owns the host allocations used for identity mappings and the externally
bound KUSER page. Those allocations must remain live until they are unmapped,
rebound, or the process is destroyed. Wine may update the KUSER page directly;
all guest accesses still use GEM's aliases and logical protections.

Native Windows ARM64 has v0-v31 while the fixed ARM64EC context carries
v0-v15. The native execution profile therefore owns a per-thread v16-v31
sidecar. Wine synchronizes that sidecar at every callback and bounded run so
`NtGetContextThread`, `NtSetContextThread`, continuation, and suspend/resume do
not lose upper SIMD state without changing the 720-byte ABI.

Wine reserves ranges in GEM before publishing committed identity backing.
Commit, decommit, partial unmap, full release, protection changes, guard and
WRITECOPY state, and executable invalidation are synchronized through the
versioned bridge. GEM tracks each 4 KiB guest page independently even when
multiple guest pages share a 16 KiB Darwin host page. Bridge mutations validate
the complete range before publication; a Wine-side synchronization failure
terminates the process instead of continuing with divergent state.

The sparse address space retains its ordered ownership list for teardown and
range mutation, plus a 65,536-bucket address index protected by the same memory
lock. Every translated fetch, load, and store therefore resolves a guest page
without scanning all Wine mappings; access checks, PAGE_GUARD consumption,
WRITECOPY, and precise fault replay remain on the checked-memory path.

Destroying a process with registered threads returns `GEM_WINE_CONFLICT`.
Destroying or re-entering a running thread returns `GEM_WINE_CONFLICT`. As with
other opaque C handles, callers must prevent a new operation from starting once
destruction of that same handle begins; the bridge does not make use-after-
destroy valid.

## Execution profiles

The initial process thread runtime uses `GEM_ARM64EC_PROFILE_NATIVE_ARM64` for
native Windows ARM64 instructions. This profile:

- executes through checked GEM memory and the pinned Dynarmic engine;
- treats instructions as ARM64 rather than applying ARM64EC forbidden-register
  operand rules;
- snapshots each instruction and rolls it back if it changes canonical `x18`;
- rejects attachment of an ARM64X metadata map.

This profile is the native ARM64 entry slice. For checked ARM64X images the
bridge attaches the parsed CHPE code map and routes execution through GEM's
hybrid coordinator while preserving the same memory, context, budget, and
fault authority.

## ARM64X and embedded x64 integration

Issue #24 extends the accepted Issue #23 native execution path without replacing
the staged Wine build. Wine registers each mapped ARM64X image with its load
configuration, code map, redirection metadata, and dispatch helpers. Registration
is process-wide and may be deferred until mappings are complete; activation is
atomic so an engine thread never observes a partially published image.

The coordinator classifies targets only from checked ARM64X metadata. ARM64 and
ARM64EC blocks execute through pinned Dynarmic; x64 blocks execute through the
pinned embedded Blink interpreter built with `--disable-jit`. Dispatch-call,
dispatch-jump, dispatch-return, entry/exit thunks, callbacks, tail calls, and
nested transitions share the broker-owned canonical context and bounded frame
stack. Wine callback responses restore the transition cookie and original x64
stack sidecars before execution resumes.

The accepting fixture is the authentic Microsoft-linked ARM64X DLL and x64 host
produced by the existing source-only fixture pipeline. Its staged-Wine run must
print `ARM64X linked fixture native execution passed`, exit zero, remain within
the bounded execution/transition budgets, and load no translated host process.
This is an x86-64 guest claim. A separate real PE32/i386 run is still required
before claiming 32-bit x86 support.

## Boundary callbacks

A boundary callback receives a read-only request and a preinitialized response.
Requests classify only engine stops. A Unix-call boundary is recognized only
when an instruction-fetch fault has all three exact values:

1. canonical PC equals the registered dispatcher address;
2. fault address equals that dispatcher address;
3. access type is instruction fetch.

Instruction bytes are never used to infer a Unix call.

A callback may resume, terminate, or fail. A resume is a proposal: the bridge
checks ABI version and size, context layout, reserved fields, ISA, TEB, x18,
stop state, and required PC progress before committing it. A rejected proposal
leaves the pre-callback canonical context intact. Unknown engine stops fail
closed as invariant violations rather than reaching Wine as extensible events.

Callbacks run while that thread's non-recursive run lock is held. A callback
must not wait for another operation that requires the same thread to finish.
Re-entry fails with `GEM_WINE_CONFLICT`.

On native ARM64 Wine, syscall and Unix-call trampolines are guest `svc`
instructions. `KeUserModeCallback` does not invoke the PE callback dispatcher
as a Darwin function pointer and does not nest the macOS JIT exception handler.
It publishes a checked callback PC and stack into the current Wine syscall
frame; `NtCallbackReturn` restores the saved guest continuation before GEM
resumes. Callback state is per thread and supports nested Windows callbacks.

The clean integration command validates this contract with one fresh Wine
prefix. `wineboot --init` and native ARM64 `cmd.exe /c exit` are each bounded
to 60 seconds. Both runs capture sampled process trees and
resolved executable paths; any observed Mach-O executable that is not
ARM64-only fails the build. Logs and process evidence are copied beside the
stage and SHA-256 bound into the build manifest.

## Run publication

`gem_wine_thread_run()` copies its input before execution. It accumulates the
result privately and publishes `out_context` and `gem_wine_run_result` only when
the bounded run returns. The result records the last engine stop, total retired
instructions, callback count, last boundary event, outcome, and termination
status.

A segment-budget expiration is an internal engine scheduling slice and does not
invoke Wine. The bridge clears that transient stop and continues until an event,
completion, or the public total budget is reached, avoiding a Wine/bridge
context round-trip for every JIT slice. The total budget still bounds the
complete run across resumed boundary segments. Exhausting the callback count
also fails closed as a budget expiration.

## Required evidence before Wine integration

PR #20 may merge only after all of the following bridge-foundation evidence is
archived:

- warning-clean native ARM64 build;
- C and C++ header ABI checks;
- exact exported-symbol allowlist;
- component-only install inventory;
- standalone installed-header consumer link and execution;
- lifecycle conflict, callback rejection, KUSER alias, Unix-call identity,
  instruction-budget, and x18 rollback tests;
- ASan+UBSan and zero-Rosetta audits;
- Mach-O dependency and architecture inspection.

PR #20 does not claim those items integrate Wine. Separate accepted PRs must
supply bounded evidence for the clean Wine build (#21), lifecycle plus
mapping/protection/invalidation wiring (#22), thread startup plus syscall,
Unix-call, exception, and native ARM64 execution (#23), checked ARM64X and x64
execution (#24), and packaged teardown, relocation, and release behavior (#25).

## Wine integration acceptance

Patch 6 makes native Darwin ARM64 configuration fail unless an absolute bridge
prefix provides the exact ABI-1 header and an ARM64-only
`libmetalsharp-gem-wine.0.dylib`. The resulting Unix `ntdll.so` has a direct
`@rpath/libmetalsharp-gem-wine.0.dylib` load command and resolves the staged
bridge through `@loader_path/../..`; there is no delayed loading or fallback.

`tools/release/build-integrated-wine.sh` is the single documented clean-build
entrypoint. It starts from a fresh checkout at the locked Wine 11.12 revision,
applies the ordered queue without fuzz, builds the GEM bridge and all four PE
architectures, stages both installations, audits every host Mach-O as ARM64-only,
and runs `METALSHARP_GEM_LIFECYCLE_PROBE=1` against a fresh prefix. The probe
must record process creation, initial thread creation, KUSER binding, checked
allocation/protection/invalidation/decommit/recommit/release, thread destruction,
and process destruction before guest entry. A timeout, signal, missing lifecycle
event, bridge mismatch, or mapping conflict fails the command.
