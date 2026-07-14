# Issue #46: i386/WoW64 guest support through GEM/Blink

## Bound foundation and scope

This work starts from `main` and the published `v0.1.1` release at commit
`23732515220f3908e5c60d86697dd2a4e87d7c0a`. The downloaded release archive is
`metalsharp-wine-v0.1.1-macos-arm64.tar.zst`, SHA-256
`4abb76bd6515b841d40468e5603e583e3a6c5b009214c8c7ad378d0683b97469`.
Its manifest contains 830 files below `lib/wine/i386-windows`, including
`ntdll.dll`, `kernel32.dll`, and `cmd.exe`, but v0.1.1 explicitly excludes
i386/WoW64 execution from its support claim.

The accepted v0.1.1 host remains native ARM64 Wine, wineserver, Unix modules,
and the versioned GEM bridge. No 32-bit or x86_64 Mach-O process, Rosetta,
`arch -x86_64`, Intel macOS runner, or upstream x86_64 Unix-side DXMT module is
permitted. The target path is:

```text
i386 PE32 guest
  -> Wine 11.12 WoW64 loader and i386 PE modules
  -> checked, versioned Wine/GEM i386 boundary
  -> isolated GEM_i386 context and 32-bit address space
  -> pinned Blink IA-32 interpreter oracle or AArch64 JIT
  -> native ARM64 host code
```

The existing 720-byte `gem_thread_context` v1 ABI and the accepted ARM64EC and
`GEM_x86_64` implementations remain unchanged. i386 state is not overlaid on
x64 fields and Blink internals do not enter the shared ABI.

## Current seams in the repository and release

- `enum gem_isa` has only ARM64EC and x64 values. There is no i386 context,
  materializer, engine target, runtime, or conformance suite.
- `gem_memory` is a sparse 64-bit guest map. It has Windows-style page states,
  transactions, guard behavior, aliases, and KUSER support, but no enforced
  32-bit ceiling, allocation policy, pointer conversion contract, or wraparound
  rejection for an i386 process.
- `GEM_x86_64` embeds pinned Blink behind x64-specific public and internal
  interfaces. The pin and audit machinery are reusable inputs, not permission
  to widen x64 state or assume IA-32 JIT coverage.
- The Wine bridge ABI exports `gem_wine_process_prepare_arm64ec` and
  `gem_wine_process_prepare_x86_64`; it has no PE32 classifier, i386 preparation,
  WoW64 transition, segment/TEB, or 32-bit exception surface.
- Wine patch `0013` handles pure AMD64 PE32+ startup. No reviewed patch identifies
  and routes Wine 11.12's WoW64 CPU/loader interfaces for i386.
- CI builds an AMD64 PE32+ fixture and the release harness accepts only
  `--x86-64-fixture`. There is no native Windows WoW64 oracle or exact-byte
  Windows-to-macOS PE32 handoff.
- v0.1.1's focused binary-patch release pipeline changes four files on the
  v0.1.0 foundation. i386/WoW64 plus a paired DXMT rebuild is broader and must
  use a clean, source-bound build path with an explicit v0.1.1 regression
  baseline; it cannot silently widen the four-file overlay policy.
- The release has no DXMT component, source lock, bridge ABI evidence, or
  functional D3D probe.

## Implementation plan

### 1. Freeze architecture and ABI contracts

- [ ] Add an accepted architecture decision record for GEM_i386 ownership,
      32-bit address-space rules, Wine WoW64 boundaries, and the choice to keep
      `gem_thread_context` v1 byte-for-byte stable.
- [ ] Define a versioned `gem_i386_context` containing EAX-EDI, EIP, EFLAGS,
      x87/MMX/SSE, segment/descriptor state, FS/TEB state, debug/exception state,
      and explicit lifecycle metadata, with layout and serialization tests.
- [ ] Define checked conversion structures for each 32<->64 boundary. Every
      pointer, length, handle, callback, context, and structure conversion must
      reject truncation, overflow, unrepresentable values, and host pointers.
- [ ] Add a stable architecture dispatch entry for i386 without changing the
      meaning, layout, or behavior of ARM64EC and x64 dispatch.
- [ ] Document resource ceilings for instructions, transitions, threads,
      mappings, generated code, memory, wall time, logs, and child processes.

### 2. Implement the isolated 32-bit address space

- [ ] Add an i386 address-space policy layer above `gem_memory` that enforces
      the complete `[0, 2^32)` range, 32-bit arithmetic/wrap semantics, low
      allocation constraints, and collision isolation from native Wine/GEM/JIT
      mappings.
- [ ] Cover reserve, commit, decommit, release, protection changes, write-copy,
      guard pages, shared/aliased mappings, relocations, stack growth, KUSER,
      and deterministic fault delivery with positive and boundary-negative tests.
- [ ] Make executable-page writes and protection transitions invalidate the
      exact GEM_i386 translations and synchronize the ARM64 instruction cache.
- [ ] Add concurrent mapping/teardown and cross-page tests, including addresses
      around zero, 64 KiB, `0x7ffe0000`, `0x80000000`, and `0xffffffff`.
- [ ] Fail closed when Wine requests a mapping or transition that cannot be
      represented without exposing a host address or aliasing another owner.

### 3. Build and soundproof GEM_i386 with pinned Blink

- [ ] Add a dedicated `GEM_i386` CMake target, public runtime API, internal
      state, stop information, engine identity, invalidation, async stop, and
      teardown. Do not share mutable machine state with `GEM_x86_64`.
- [ ] Audit the pinned Blink revision for IA-32 decoding/execution on ARM64 and
      record an explicit source/handler inventory. Add reviewed pinned patches
      only for demonstrated gaps and bind every post-patch source hash.
- [ ] Implement an interpreter mode as the independent correctness oracle and
      an AArch64 JIT mode as the production path. JIT creation or execution
      failure must not silently fall back.
- [ ] Route all fetches, reads, writes, atomics, locked operations, and code
      invalidation through checked GEM transactions; generated code must remain
      in audited W^X ARM64 mappings.
- [ ] Compare complete architectural state at defined interpreter/JIT
      checkpoints for integer/flags, x87/MMX/SSE, segments, unaligned access,
      atomics, faults, self-modifying code, and concurrent threads.
- [ ] Prove cleanup and bounded failure for unsupported instructions, malformed
      state, exceptions, crashes, timeouts, and asynchronous stops.

### 4. Integrate the exact Wine 11.12 WoW64 interfaces

- [ ] Identify the exact Wine `996020f410e7a1aa2dd6b44cf740854ea524d31a`
      WoW64 CPU, loader, syscall, callback, exception, and thread interfaces in
      an ADR before writing patches; guessed private ABI is not acceptable.
- [ ] Extend the versioned Wine/GEM bridge with additive i386 process/thread
      preparation and transition APIs while retaining every v0.1.1 export and
      its behavior. Update the exported-symbol allowlist and bridge ABI tests.
- [ ] Add strict PE32 classification for optional-header magic `0x10b` and
      machine `IMAGE_FILE_MACHINE_I386`; reject PE32+, malformed, ambiguous, or
      mismatched images before architecture dispatch.
- [ ] Add ordered, provenance-bound Wine patches that select and execute the
      packaged i386 `ntdll`, `kernel32`, and related PE modules through GEM_i386.
- [ ] Implement and test startup, syscalls/Unix calls, 32<->64 callbacks,
      structured exceptions/unwind, APCs, TLS/TEB, thread creation, process
      teardown, and deterministic suspend/resume boundaries.
- [ ] Verify System32/SysWOW64 and registry redirection, environment and handle
      transfer, a 64-bit process launching a 32-bit child, and isolated/shared
      prefix coexistence with accepted x86_64 guests.

### 5. Add an independent PE32 corpus and differential CI

- [ ] Add redistributable source-only PE32 fixtures covering startup/imports,
      calling conventions and callbacks, integer/FP/SIMD state, TEB/PEB/TLS,
      heap/virtual memory, files, registry, console, synchronization, threads,
      atomics, APCs, exceptions, COM, DLL loading, children, and teardown.
- [ ] On native Windows x86_64, build every fixture twice with one pinned
      toolchain, require byte identity and valid i386 PE32 headers, execute them
      under Windows WoW64, and emit strict manifests plus normalized results.
- [ ] Hand the exact manifest-bound fixture bytes to native ARM64 macOS CI;
      reject stale artifacts, hash drift, wrong machine type, or missing oracle
      evidence.
- [ ] Run the corpus through GEM_i386 JIT and interpreter modes and compare both
      with normalized native Windows results under a documented nondeterminism
      allowlist.
- [ ] Require a real i386 `cmd.exe /c exit` smoke test, but never treat that
      loader-only probe as sufficient acceptance.
- [ ] Retain every current Linux, Apple Silicon, ARM64EC, x64, memory-order,
      page-isolation, repository-policy, sanitizer, leak, and zero-Rosetta gate.

### 6. Rebuild and validate the paired DXMT v0.80 bridge

- [ ] Pin DXMT tag `v0.80` at
      `589adb780354b461645b29999cefaf533594ee99`, all submodules/dependencies,
      toolchain/configuration, source hashes, and redistribution material. Treat
      the published `dxmt-v0.80-builtin.tar.gz` only as inventory/reference.
- [ ] Reproducibly build the i386 PE32 DXMT modules, including `d3d10core.dll`,
      `d3d11.dll`, `dxgi.dll`, and `winemetal.dll`, together with the paired
      native ARM64 Mach-O `winemetal.so` from the same source/configuration.
- [ ] Bind the pair's exports/imports, ABI/protocol version, layouts, calling
      conventions, hashes, install names, rpaths, deployment target, complete
      dependency closure, licenses, SBOM, and provenance.
- [ ] Reject any x86_64/universal-x86_64 Unix module, Homebrew/build-tree path,
      undeclared library, mismatched half, or unexplained difference between
      two clean builds.
- [ ] Prove selection of the rebuilt PE32 DLLs and trace a checked round trip
      through PE32 `winemetal.dll`, WoW64/GEM_i386, and native ARM64
      `winemetal.so` with adapter/device initialization, one deterministic D3D
      operation, callbacks, error propagation, resource destruction, and clean
      teardown.
- [ ] Run the portable Windows-facing DXMT probe under native Windows WoW64 and
      compare normalized results. Keep the source-built fixture corpus as the
      primary oracle and scope claims to the tested bridge scenario.

### 7. Replace the focused release path with a v0.1.2-capable gate

- [ ] Add a clean source-build release workflow for the broader i386/DXMT
      payload; do not reuse v0.1.1's four-file overlay as if it covered the new
      architecture and paired bridge.
- [ ] Bind Wine, GEM, Blink, DXMT, every patch, toolchain, source, fixture,
      Windows oracle, output hash, license, SBOM entry, and limitation to the
      protected `main` commit and `previousTag: v0.1.1`.
- [ ] Require two clean release builds to produce identical accepted bytes or
      account for and eliminate every difference before publication.
- [ ] Validate the complete archive manifest, ARM64-only Mach-O closure,
      relocatability with source/build trees unavailable, arbitrary install
      paths, fresh 32-bit and mixed-bitness prefixes, and bounded teardown.
- [ ] Publish immutable `metalsharp-wine-v0.1.2-macos-arm64.tar.zst` assets,
      redownload them on fresh native ARM64 macOS, revalidate all bindings, and
      rerun the accepted PE32, DXMT, AArch64, ARM64EC, and x86_64 gates.
- [ ] Update README, roadmap/ADR status, support evidence, release notes, and
      known limitations only after public-redownload acceptance. Claims remain
      limited to tested i386/WoW64 and DXMT scenarios.

## Merge and release acceptance gate

- [ ] GEM_i386 is isolated, versioned, bounded, and covered by complete state,
      address-space, transition, JIT/oracle, fault, and cleanup tests.
- [ ] Exact manifest-bound PE32 fixtures agree across native Windows WoW64,
      GEM_i386 interpreter, and GEM_i386 ARM64 JIT within the reviewed allowlist.
- [ ] The packaged Wine 11.12 runtime demonstrably selects its i386 PE tree and
      passes fresh-prefix, i386 cmd, mixed-bitness, stress, and failure tests.
- [ ] The paired DXMT rebuild crosses the PE32-to-native-ARM64 bridge and passes
      the scoped deterministic probe without an x86_64 Unix module.
- [ ] Host/process audits show ARM64-only execution and zero Rosetta for success,
      exception, crash, timeout, and teardown paths.
- [ ] All accepted v0.1.1 AArch64, ARM64EC, and pure x86_64 behavior remains green.
- [ ] The public v0.1.2 archive is reproducible, relocatable, provenance-bound,
      redownloaded, and independently verified before support claims change.

Implementation begins only after this planning checkpoint is reviewed.
