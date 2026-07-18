# Wine 11.12 patch queue

These patches modify Wine and are distributed under
`LGPL-2.1-or-later`, consistent with Wine upstream. Original runtime and
tooling code elsewhere in this repository remains Apache-2.0.

## Base

- repository: `https://gitlab.winehq.org/wine/wine.git`
- revision: `996020f410e7a1aa2dd6b44cf740854ea524d31a`
- upstream version: Wine 11.12
- order: the exact lexical list in `series`
- machine-readable hashes and evidence: `provenance.json`

The queue must apply with `git am` to a clean checkout at the exact base. A
dirty Wine tree, a patch applied with offsets, or a manually copied equivalent
is not a release input.

## Patches

1. `0001-darwin-arm64-preserve-4g-pagezero.patch`
   - explicitly preserves a 4 GiB `__PAGEZERO` for the native ARM64 internal
     loader;
   - does not apply the x86 4 KiB Mach-O segment alignment override to ARM64.
2. `0002-darwin-arm64-keep-installed-wrapper.patch`
   - exports and retains the loader reservation marker;
   - lets the installed native ARM64 wrapper initialize ntdll in-process rather
     than re-executing an equivalent loader.
3. `0003-darwin-arm64-high-guest-mappings.patch`
   - starts Darwin ARM64 Wine host mappings above 4 GiB;
   - moves Wine's host KUSER backing to `0x1007ffe0000`, which the packaged GEM
     bridge aliases to checked guest address `0x7ffe0000`;
   - removes the legacy below-2-GiB TEB placement constraint for this host.
4. `0004-arm64ec-avoid-x86-inline-assembly.patch`
   - keeps ARM64EC away from x86-only inline atomic and fast-fail assembly;
   - uses the ARM64EC-safe compiler intrinsics and `brk` fast-fail sequence.
5. `0005-arm64x-pass-mode-to-winebuild.patch`
   - passes ARM64X mode through to Wine's spec-object generator;
   - selects each PE target's Clang triple for spec-object assembly;
   - preserves native-architecture metadata when combining ARM64EC and native
     ARM64 objects.
6. `0006-ntdll-integrate-native-darwin-arm64-gem.patch`
   - requires the exact native ARM64 bridge ABI at configure time and links
     `ntdll.so` directly to `@rpath/libmetalsharp-gem-wine.0.dylib`;
   - creates one GEM process and one GEM object per Wine guest thread;
   - synchronizes reserve, identity commit, decommit, partial unmap, release,
     protection, high KUSER backing, executable invalidation, and teardown;
   - adds an opt-in pre-guest lifecycle probe for staged acceptance.
7. `0007-ntdll-execute-native-arm64-through-gem.patch`
   - replaces Darwin ARM64's direct PE thread entry with the checked,
     instruction-budgeted `gem_wine_thread_run()` loop;
   - converts Wine syscall frames to and from canonical GEM state while
     preserving x18/TEB and the native-only v16-v31 sidecar;
   - dispatches exact syscall and registered Unix-call stops, converts checked
     faults and BRK stops to Windows exceptions, and handles bounded suspend
     and termination safe points;
   - fails closed for unknown stops instead of invoking a guest PC natively.
8. `0008-darwin-arm64-add-native-gem-launch-contract.patch`
   - resolves installed builtin aliases to their exact staged ARM64 PE image
     and enters Unix ntdll through a private, versioned, in-process ABI;
   - fails closed if the matching ntdll ABI is absent instead of re-executing
     the loader or falling back through `start.exe`;
   - restores Wine's x18/TEB value from the syscall frame before Darwin resumes
     the syscall-return dispatcher;
   - preserves strict ordinary thread teardown while allowing the immediately
     terminating host process to reclaim its currently executing GEM runtime.
9. `0009-ntdll-complete-gem-fault-suspend-boundaries.patch`
   - synchronizes post-fault protection at Wine's committed 4 KiB guest-page
     granularity on a 16 KiB Darwin host page;
   - routes native GEM suspension through a lock-free cooperative engine stop.
10. `0010-ntdll-register-arm64x-images-with-gem.patch`
    - sends every mapped ARM64X image to GEM only after Wine installs its exact
      checker, call, jump, and return helper addresses;
    - atomically promotes deferred registrations after mappings and helper
      exports are complete, including ntdll and xtajit;
    - routes ARM64X metadata redirections and helper SVC boundaries through
      the process-wide hybrid coordinator while preserving Wine syscall,
      callback, suspension, exception, and return state;
    - fails closed when validated metadata cannot be attached or execution
      violates the bounded transition contract.
11. `0011-setupapi-add-bounded-native-bootstrap-mode.patch`
    - lets the relocatable launcher finish native `DefaultInstall` after an
      early-returning bootstrap Wineboot;
    - suppresses only fake-DLL `WINE_REGISTRY` resources during that explicit
      recovery pass while retaining manifest registration;
   - leaves ordinary setupapi installation behavior unchanged.
12. `0012-ntdll-preserve-hybrid-budget-context.patch`
   - preserves the complete GEM ARM64EC/x64 coordinator context across ordinary
     instruction-budget slices instead of round-tripping through Wine's
     ARM-only syscall frame;
   - publishes a resumable ARM64EC frame only when Wine has an actual pending
     suspend or externally supplied context;
   - defers an in-flight hybrid suspend until the coordinator reaches an
     ARM64EC boundary that Wine's public context machinery can represent.
13. `0013-ntdll-route-pure-amd64-guests-through-gem-x86-64.patch`
   - routes ordinary AMD64 PE32+ startup through the existing GEM x86-64
     engine without Rosetta.
14. `0014-ntdll-add-gem-backed-i386-wow64-execution-on-arm64.patch`
   - adds Wine's i386 `xtajit` CPU surface backed by the existing GEM i386
     engine while retaining the four-architecture Wine build;
   - maps 32-bit guest addresses through bounded high host shadow windows on
     Apple Silicon and preserves 32-bit values in the WoW64 ABI;
   - refreshes the emulated thread context after context-changing syscalls such
     as `NtContinue`, so startup resumes at the requested guest state.
15. `0015-ntdll-accept-relocated-initial-process-images.patch`
   - treats nonzero NT success statuses from initial executable mapping as
     successful instead of incorrectly falling back to `start.exe`;
   - prevents an ASLR-relocated `wineboot.exe` from causing a secondary
     `kernel32.dll` bootstrap failure.
16. `0016-darwin-arm64-enable-synchronous-gui-callbacks.patch`
   - preserves full-width syscall results and supports GUI syscalls with more
     than sixteen arguments;
   - completes translated user-mode callbacks synchronously and preserves
     their restored continuations;
   - uses a server-owned desktop without translated Explorer, loads
     `winemac.drv` directly, and reads KUSER from its canonical high mapping.
17. `0017-darwin-arm64-canonicalize-wow64-gui-pointers.patch`
   - canonicalizes 32-bit guest pointers embedded in WoW64 GUI, macdrv,
     printing, and code-page parameter blocks on Darwin ARM64;
   - initializes GDI stock objects safely for early dependency calls and
     guards callbacks until the 32-bit callback table is published;
   - preserves atom-valued properties and converts structured window-message
     pointers so 32-bit applications can create sustained interactive windows.
18. `0018-xtajit-map-normalized-i386-exceptions.patch`
   - maps stable GEM i386 exception identities to precise WoW64 exception
     records while preserving fault address and access class.
19. `0019-xtajit-preserve-i386-v2-legacy-state.patch`
   - round-trips x87 environment, XMM, flags, and segment metadata through the
     fixed-size legacy i386 context boundary.
20. `0020-xtajit-map-i386-avx-xstate.patch`
   - maps the standard-format WoW64 CONTEXT_EX AVX component to GEM ABI-v3
     YMM-upper and XCR0 state;
   - rejects compacted or undersized xstate layouts by leaving the extension
     inert instead of reinterpreting them;
   - maps GEM's normalized i386 general-protection status to the Windows
     privileged-instruction exception used for XSETBV.

## Current evidence and limitation

The unpatched installed wrapper reached `reexec_loader()` and was terminated by
`SIGKILL` in `execve`, producing no Wine log (`rc=-9`, retained bytes `0`). LLDB
located the stop at Wine `dlls/ntdll/unix/loader.c` in the loader re-exec path.

A build carrying this queue proceeds through `virtual_init`, high KUSER
mapping, TEB/stack allocation, PE `ntdll.dll` mapping, API-set loading, syscall
and Unix-call boundaries, callbacks, and process exit without the re-exec
`SIGKILL`. Its bounded opt-in probe exercises Wine's real allocation,
protection, instruction-cache flush, guard, decommit, recommit, release, thread
teardown, and process teardown paths. Normal Darwin ARM64 startup enters PE
`LdrInitializeThunk` only through GEM. Incremental staging completed a fresh
`wineboot --init` and `cmd.exe /c exit` with return code 0; those results are
diagnostic evidence, while the clean command below remains authoritative.

Local build trees and prefixes are not release inputs. The clean build command
owns the integrated runtime gate: it initializes one fresh prefix with
bounded `wineboot --init`, runs native ARM64 `cmd.exe /c exit` through that
prefix, samples both process trees, rejects non-ARM64 Mach-O executables, and
hashes the resulting logs and process evidence. The same staged runtime also
completed the authentic linked ARM64X DLL/x64-host fixture through GEM with a
zero exit status. Sanitizer, reproducibility, and final release packaging
remain separately gated stages.

## Clean build entrypoint

`tools/release/build-integrated-wine.sh` always clones Wine afresh at the
revision in `components.lock.json`, applies this queue with `git am`, and
rejects dirty sources or an incomplete dependency set. It builds and installs
only into temporary/external directories. The required invocation on native
Apple silicon is:

```sh
tools/release/build-integrated-wine.sh \
  --commit "$(git rev-parse HEAD)" \
  --llvm-mingw /external/llvm-mingw-20260616-ucrt-macos-universal \
  --deps /external/metalsharp-deps \
  --output /external/wine-foundation
```

The dependency lock requires the recorded LLVM-MinGW archive, Homebrew bison,
Mesa/EGL, Vulkan headers/loader, SDL2, SDL3, and the macOS OpenGL framework.
The external dependency directory must provide the locked ARM64 Vulkan loader
and MoltenVK binaries. The command also builds and stages the exact GEM bridge,
verifies ntdll's direct versioned dependency, native launch ABI, and relocatable
lookup path, audits every staged host Mach-O as ARM64-only, runs the bounded
pre-guest lifecycle probe, and executes the full fresh-prefix
`wineboot`/`cmd.exe` gate. The staged runtime has additionally produced an
on-screen native Cocoa window for ARM64X Notepad through GEM. The gate records
the exact staged PE selected by the
wrapper and rejects loader re-exec or `start.exe` fallback evidence. The
resulting `wine-build-manifest.json` records those results, evidence hashes,
configure flags, toolchain, dependency roots, installed files, and Mach-O audit
output. It is integration evidence, not a final release package.

Patch `0018` preserves the existing xtajit Unix-call ABI and maps stable GEM
i386 exception identities to Windows exception records. Access violations
retain exact read/write/execute information and the faulting address;
breakpoint, divide, overflow, stack, and illegal-instruction stops no longer
collapse into one fallback exception.

Patches `0019` and `0020` preserve the complete i386 legacy and AVX state
across the Wine/GEM boundary. Patch `0020` accepts only the standard
non-compacted xstate layout described by ADR 0013; CPUID advertisement remains
separately gated by the engine corpus and Windows oracle.

Patch `0021` adds one stable GEM_i386 diagnostic record to every xtajit run
trace. It identifies the native engine and version, reports JIT compilation,
execution, cache-hit, failure, precise invalidation, and zero-fallback counts,
records the last genuinely unsupported decoded opcode, and publishes the exact
deterministic CPUID profile. These values are observations of SharpWine's
native implementation; external execution remains comparison evidence rather
than a capability veto.

Patch `0022` services guest-resident GEM syscall and Unix-call boundaries when
native Darwin ARM64 Wine code re-enters them during an outer translated call.
It dispatches the requested service through Wine's native tables and restores
the ARM64 syscall-stub continuation instead of converting the boundary `svc`
into an access violation. This keeps alias probing and other native WoW64 GUI
work inside the implemented GEM/Wine path; it does not mask or discard the
guest operation.
