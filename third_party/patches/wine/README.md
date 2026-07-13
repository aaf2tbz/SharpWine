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

## Current evidence and limitation

The unpatched installed wrapper reached `reexec_loader()` and was terminated by
`SIGKILL` in `execve`, producing no Wine log (`rc=-9`, retained bytes `0`). LLDB
located the stop at Wine `dlls/ntdll/unix/loader.c` in the loader re-exec path.

A clean build carrying this queue proceeds through `virtual_init`, high KUSER
mapping, TEB/stack allocation, PE `ntdll.dll` mapping, and API-set loading
without the re-exec `SIGKILL`. Its bounded opt-in probe exercises Wine's real
allocation, protection, instruction-cache flush, guard, decommit, recommit,
release, thread teardown, and process teardown paths. Normal Darwin ARM64
startup then enters PE `LdrInitializeThunk` only through GEM.

Local build trees and prefixes are not release inputs. The clean build command
now owns the issue #23 runtime gate: it initializes one fresh prefix with
bounded `wineboot --init`, runs native ARM64 `cmd.exe /c exit` through that
prefix, samples both process trees, rejects non-ARM64 Mach-O executables, and
hashes the resulting logs and process evidence. Hybrid, sanitizer,
reproducibility, and final release packaging remain later integration stages.

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
verifies ntdll's direct versioned dependency and relocatable lookup path, audits
every staged host Mach-O as ARM64-only, runs the bounded pre-guest lifecycle
probe, and executes the full fresh-prefix `wineboot`/`cmd.exe` gate. The
resulting `wine-build-manifest.json` records those results, evidence hashes,
configure flags, toolchain, dependency roots, installed files, and Mach-O audit
output. It is integration evidence, not a final release package.
