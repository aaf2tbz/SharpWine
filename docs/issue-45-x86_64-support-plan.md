# Issue #45: focused x86_64 guest implementation

## Scope and immutable foundation

This PR starts from `main` at
`e331f067fc843df231238dd2398ad563f0de6614` and the published
`v0.1.0` archive (SHA-256
`294130ff359353f4b8224508fd8956ee314a8ceab5cf6ea9ddc39094b08bbdc4`).
The release remains the foundation: native ARM64 Wine, wineserver, Unix
modules, and the existing `x86_64-windows` PE tree are reused.

The implemented path is:

```text
x86_64 PE32+ guest
  -> existing x86_64 Wine PE modules
  -> focused x86_64 ntdll boundary pieces
  -> native ARM64 Wine ntdll.so
  -> versioned Wine/GEM bridge
  -> isolated GEM_x86_64
  -> pinned Blink one-instruction JIT
  -> native ARM64 host code
```

There is no Intel runner, Intel macOS support, Rosetta, x86_64 Mach-O,
translator process, i386/WoW64 path, interpreter fallback, or full Wine
rebuild. Release assembly may rebuild only the focused native
`aarch64-unix/ntdll.so` and guest `x86_64-windows/ntdll.dll` pieces required
by the new boundary. Every other runtime file must remain identical to
`v0.1.0`.

## PR implementation checklist

### Foundation and packaging boundary

- [x] Download and validate the published `v0.1.0` assets in a new
      internal-storage workspace without using an old worktree or external
      source tree.
- [x] Bind the exact release archive, manifest, tag, and prior release in
      `release/v0.1.1-overlay-policy.json`.
- [x] Limit the overlay to the ARM64 bridge, native ARM64 `ntdll.so`, x86_64
      guest `ntdll.dll`, and hash-bound acceptance evidence.
- [x] Add fail-closed foundation preparation and overlay application tools;
      reject base drift, unlisted payloads, wrong actions, and hash/size drift.

### Isolated GEM_x86_64 and Blink

- [x] Add dedicated `GEM_x86_64` context materialization, lifecycle, checked
      memory transactions, stop information, invalidation, and teardown without
      changing the accepted 720-byte shared context ABI.
- [x] Build the pinned Blink source as a native ARM64 CMake/Apple-Clang archive
      from an explicit source inventory.
- [x] Use the bounded native AArch64 JIT in production and keep the interpreter
      as an explicitly selected oracle only; JIT creation or execution failure
      fails closed.
- [x] Restrict each translated path to one decoded guest instruction. Generated
      paths call Blink's C opcode handler so exact read/write ranges are
      reconciled with canonical GEM memory before commit or retry.
- [x] Preserve bounded shadow state, checked fetch/read/write access,
      transactional writes, code invalidation, W^X policy, host instruction
      cache synchronization, and complete machine teardown.
- [x] Bind Blink revision, archive, both embedding patches, post-patch sources,
      handler manifest, and runtime provenance hashes.

### Wine routing and Windows boundaries

- [x] Classify pure AMD64 PE32+ startup and route it to the isolated x86_64
      runtime while preserving existing ARM64/ARM64EC routing.
- [x] Reuse the shipped x86_64 Wine PE tree and load its x86_64 `ntdll`,
      `kernelbase`, and `kernel32` modules without a host x86_64 process.
- [x] Handle the existing Wine syscall/unix-call thunks and direct x64
      `syscall` instructions as Windows boundaries; Blink's Linux syscall
      implementation is never executed.
- [x] Reconcile INT3 and memory faults through the Windows exception dispatcher,
      convert AMD64 exception context, and resume supported
      `NtContinue` requests.
- [x] Preserve the existing fixed dispatcher-page and versioned bridge ABI.

### Tests and Apple Silicon-only CI

- [x] Add JIT/oracle conformance for engine identity, no fallback, cache reuse,
      invalidation, guard faults, unsupported instructions, syscall routing, and
      cross-page execution.
- [x] Add Wine bridge conformance for AMD64 PE classification, JIT and explicit
      oracle selection, syscall/unix-call events, INT3 delivery, callbacks,
      budgets, and teardown.
- [x] Add a redistributable source-only PE32+ fixture that registers an ntdll
      vectored exception handler, recovers from INT3 through `NtContinue`, and
      exits through `NtTerminateProcess`.
- [x] Build the fixture twice with pinned native ARM64 LLVM-MinGW host tools and
      require byte identity, zero PE timestamp, AMD64 machine identity, and a
      commit-bound manifest. No generated PE is committed.
- [x] Run the x64 JIT/oracle and bridge tests on native `macos-15` ARM64,
      retain existing ARM64/ARM64EC regression jobs, and audit zero Rosetta.
      No Intel CI runner is added.
- [x] Keep Wine patch/overlay policy validation in repository CI; CI does not
      rebuild the complete Wine runtime.

## Validation record

- [x] All 13 Wine patches apply to Wine `11.12`
      (`996020f410...`) cleanly, with no fuzz or offsets.
- [x] The focused Release build targets macOS 15.0, contains only an ARM64
      Mach-O bridge, and passes the zero-Rosetta audit.
- [x] Applying the four-entry overlay to an exact copy of the published
      `v0.1.0` manifest changes only those four entries and preserves the other
      2,895 package entries.
- [x] Release CTest passes 19/19, including production JIT, interpreter oracle,
      both Wine bridge suites, page isolation, ARM64EC regression, and
      zero-Rosetta labels.
- [x] The reproducible exception fixture is PE32+ AMD64, 3,584 bytes, timestamp
      zero, and SHA-256
      `6bd63780629daf28abf168765f6b5f92a4b914601cfbc873930234931428c834`.
- [x] The exception fixture exits 0 through the native ARM64 Wine host with no
      Rosetta or host x86_64 binary.
- [x] The shipped `lib/wine/x86_64-windows/cmd.exe /d /c exit 0` exits 0
      through the same Release bridge and existing Wine PE tree.

## Release gate

This implementation PR does not publish a release or broaden compatibility
claims before merge. Release promotion must use the verified `v0.1.0`
foundation, build only the policy-listed bridge/ntdll pieces, apply the
hash-bound overlay, rerun the fixture and x86_64 `cmd.exe` smoke from a clean
prefix, run the retained ARM64/ARM64EC gates, redownload the candidate, and
verify it again on native Apple Silicon. Only that accepted artifact may update
the public support tier. i386/WoW64 and blanket arbitrary-application
compatibility remain excluded.
