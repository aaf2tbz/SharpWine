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

This profile is only the native ARM64 entry slice. It does not by itself satisfy
the required ARM64EC/x64 hybrid path. A later reviewed bridge extension must
route checked ARM64X metadata and GEM's existing hybrid coordinator without
making instruction bytes, host `x18`, or Wine callbacks authoritative.

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

## Run publication

`gem_wine_thread_run()` copies its input before execution. It accumulates the
result privately and publishes `out_context` and `gem_wine_run_result` only when
the bounded run returns. The result records the last engine stop, total retired
instructions, callback count, last boundary event, outcome, and termination
status.

A segment-budget expiration is a bounded stop and does not invoke Wine. The
total budget additionally bounds execution across resumed boundary segments.
Exhausting the callback count also fails closed as a budget expiration.

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
