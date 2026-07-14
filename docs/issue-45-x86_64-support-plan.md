# Issue #45: x86_64 guest support plan

## Baseline and boundary

Implementation starts from `main` at `e331f067fc843df231238dd2398ad563f0de6614`
and the published `v0.1.0` archive with SHA-256
`294130ff359353f4b8224508fd8956ee314a8ceab5cf6ea9ddc39094b08bbdc4`.
The archive is the immutable foundation: it already contains native ARM64 Wine,
wineserver and Unix modules, the complete `x86_64-windows` PE tree, the
versioned Wine/GEM bridge, and pinned Blink.

The supported path is:

```text
x86_64 PE32+ Windows code
  -> shipped x86_64 Wine PE modules
  -> native ARM64 Wine Unix module
  -> versioned Wine/GEM architecture dispatch
  -> isolated GEM_x86_64 state
  -> pinned Blink x86_64 JIT
  -> native ARM64 code cache on Apple Silicon
```

This work adds no Intel CI runner, Intel macOS host, x86_64 Mach-O, Rosetta,
helper translator process, i386/WoW64 support, or general application-
compatibility claim. It does not rebuild Wine as a whole. A Wine component may
be rebuilt only when an audited dependency closure proves it is required; all
other files must remain byte-identical to `v0.1.0`.

## Implementation checklist

### 1. Reproduce and protect the released foundation

- [ ] Add a setup command that downloads `v0.1.0` into an absent internal-
      storage directory, verifies the published checksum and manifest, and
      extracts it without consulting a prior worktree or external source tree.
- [ ] Record a baseline inventory for host Mach-O files, Wine PE trees, bridge
      ABI, Blink revision/patch, release evidence, and accepted AArch64 and
      ARM64EC tests.
- [ ] Define a fail-closed overlay manifest listing every permitted replacement
      and its reason. Reject deletion or modification of any unlisted `v0.1.0`
      file.

### 2. Isolate `GEM_x86_64` and enable Blink JIT

- [ ] Split x86_64 ownership into a dedicated versioned target and context for
      GPRs, RIP/RFLAGS, x87/MMX/SIMD, stack, TLS/TEB, callbacks, exceptions,
      atomics, memory ordering, faults, and teardown without changing the
      accepted AArch64/ARM64EC context ABI.
- [ ] Build only the pinned, patched Blink embedding needed by `GEM_x86_64`
      with CMake, Ninja, Apple Clang, and LLVM tools; bind the source, patch,
      toolchain, options, and output hashes into provenance.
- [ ] Make JIT the explicit production engine and interpreter an explicit
      test-only oracle. A JIT refusal, unsupported instruction, bad transition,
      or state-conversion failure must stop execution; it must never fall back
      to the interpreter.
- [ ] Enforce `MAP_JIT`/W^X transitions, instruction-cache synchronization,
      bounded code and metadata caches, checked guest mappings, deterministic
      invalidation/self-modifying-code handling, asynchronous stop, and complete
      cleanup of executable mappings and resources.

### 3. Connect ordinary PE32+ startup to the existing Wine runtime

- [ ] Add checked AMD64 PE32+ classification and explicit dispatch from the
      native ARM64 Wine/GEM boundary into `GEM_x86_64`; reject ARM64EC, i386,
      malformed, and unregistered images on this path.
- [ ] Extend the narrow bridge only for required x86_64 process/thread setup,
      memory changes, Unix calls, callbacks, SEH/unwind/fault reconciliation,
      child-process lifecycle, and teardown.
- [ ] Reuse the shipped `x86_64-windows` modules byte-for-byte wherever
      possible. Before rebuilding Wine, derive the exact module/generated-file
      closure and limit the overlay to that list (expected starting point:
      native `aarch64-unix/ntdll.so`; x86_64 PE modules only if a guest-side ABI
      hook is proven necessary).
- [ ] Prove every host executable and dylib remains ARM64-only and directly
      relocatable; prove no Rosetta service, x86_64 host slice, helper emulator,
      or undeclared dependency enters the process or package closure.

### 4. Prove the claimed behavior

- [ ] Add source-only, redistributable x86_64 PE32+ fixtures covering startup,
      arguments/environment, imports, Win64 ABI and flags, floating point/SIMD,
      TEB/PEB/TLS, memory protection, files/registry/console, threads/atomics,
      callbacks, SEH/unwind/fault recovery, child processes, and teardown.
- [ ] Build each fixture twice with the pinned LLVM-MinGW x86_64 target and
      require byte identity. Bind the exact PE SHA-256 to normalized native-
      Windows reference evidence produced outside repository CI; commit no
      generated PE binary.
- [ ] Run those exact bytes separately through Blink JIT and the explicitly
      selected interpreter oracle on Apple Silicon, then require one normalized
      semantic result across native-Windows reference, JIT, and interpreter.
- [ ] Require routing/retirement evidence proving that ordinary `cmd.exe /c
      exit` and the corpus entered `GEM_x86_64`, executed through Blink, produced
      ARM64 JIT mappings, reconciled callbacks/exceptions, and cleaned up.

### 5. Add only product-relevant CI

- [ ] Add one native `macos-15` ARM64 build job that cross-builds the PE fixture
      twice, builds the focused GEM/Blink/bridge overlay, audits tools and
      architectures, and uploads a commit-bound manifest. It must not build all
      of Wine.
- [ ] Add one dependent native `macos-15` ARM64 acceptance job that downloads
      and verifies `v0.1.0`, applies only the manifest-listed overlay, runs the
      exact fixture under JIT and interpreter, validates the native-Windows
      reference binding, and tests fresh-prefix `cmd.exe /c exit`.
- [ ] In the acceptance job, reject stale/substituted evidence, interpreter
      fallback, bypassed GEM routing, non-ARM64 host processes, Rosetta,
      executable W+X mappings, unbounded resources/logs, timeout survivors, and
      changes to protected baseline files.
- [ ] Keep existing AArch64 and ARM64EC jobs as regression gates. Add no Intel
      runner; the existing Windows ARM64 fixture job remains baseline coverage
      and is not presented as x86_64 product proof.

### 6. Package and claim `v0.1.1`

- [ ] Assemble `v0.1.1` by deterministically overlaying the accepted focused
      outputs on the verified `v0.1.0` archive; update manifests, SBOM, licenses,
      engine/JIT provenance, fixture hashes, semantic evidence, and
      `release/current.json` with `previousTag: v0.1.0`.
- [ ] Run the complete x86_64 corpus plus all accepted `v0.1.0` AArch64 and
      ARM64EC tests from a fresh prefix and arbitrary extraction path with
      repository/build directories unavailable.
- [ ] Publish immutable assets, redownload them on native Apple Silicon, repeat
      checksum/closure/fresh-prefix/JIT/interpreter verification, and only then
      update support claims to tested x86_64 PE32+ guest support. Continue to
      exclude i386/WoW64 and blanket application compatibility.

## Acceptance gate

Issue #45 is complete only when the public ARM64-only `v0.1.1` archive runs the
accepted x86_64 PE32+ corpus through `GEM_x86_64` and Blink JIT on Apple Silicon
with zero Rosetta, matches the hash-bound interpreter and native-Windows
semantics, tears down cleanly, and leaves the accepted `v0.1.0` AArch64 and
ARM64EC behavior unchanged.
