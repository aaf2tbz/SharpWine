# Issue #45 x86_64 guest-support roadmap

## Goal and support boundary

Issue #45 promotes the existing ARM64EC/x86_64 transition proof into a tested
x86_64 PE32+ guest tier for the native ARM64 macOS runtime.  The accepted host
process graph remains ARM64-only: x86_64 is a Windows guest architecture routed
through GEM and Blink, never a Mach-O slice, Rosetta process, or `arch -x86_64`
fallback.

The release target is `v0.1.1`.  It retains every accepted `v0.1.0` AArch64 and
ARM64EC gate and does not claim i386/WoW64 or universal application
compatibility.

## Existing artifacts to preserve and reuse

- `gem_x64_context` is already a host-independent x86_64 architectural view.
  Its checked materialize/commit functions preserve the canonical GEM context.
- `gem_x64_runtime` already provides bounded, thread-confined execution,
  transactional checked memory, fail-closed stop reasons, decoder-owned
  retirement evidence, and an engine provenance surface.
- The pinned Blink embedding already hides `Machine`, aliases, host pointers,
  decode state, and memory commits behind a reviewed callback ABI.  Its current
  accepted backend is deliberately interpreter-only.
- `gem_hybrid_runtime` and the Wine bridge already coordinate accepted
  ARM64EC-to-x86_64 transitions and propagate checked invalidation, budgets,
  stop reasons, and cleanup.
- Wine 11.12 is already reproducibly built with
  `--enable-archs=i386,x86_64,aarch64,arm64ec`; the package contains the x86_64
  PE tree while every host Mach-O remains ARM64.
- CI already inventories Blink's memory-order/JIT implementation, compares a
  standalone JIT candidate with the interpreter, and audits zero Rosetta.  The
  embedded adapter and release remain JIT-disabled because the required cache,
  ownership, and concurrency contracts have not yet been accepted.
- Release tooling already creates deterministic, relocatable ARM64 archives,
  binds engine/component provenance, redownloads published assets, and runs
  fresh-prefix native and authentic-hybrid smoke tests.

These artifacts are baselines, not shortcuts around acceptance.  New work must
extend their explicit interfaces and keep their existing tests green.

## Phase plan

### Phase 1 — isolate the x86_64 product boundary

- [ ] Build the existing x64 sources as a dedicated `metalsharp_gem_x86_64`
      target with a versioned public ABI rather than folding the backend into
      the baseline GEM archive.
- [ ] Add checked PE-machine architecture dispatch and reject malformed,
      ambiguous, i386, ARM64, and ARM64EC inputs at the x86_64 boundary.
- [ ] Keep Blink headers, `Machine`, JIT state, host pointers, and
      x86_64-specific policy private to the implementation.
- [ ] Preserve the canonical AArch64/ARM64EC context ABI and demonstrate that
      baseline libraries do not acquire an unconditional Blink dependency.
- [ ] Add lifecycle, reentrancy, context, memory, classification, unsupported,
      and teardown conformance tests.

### Phase 2 — add a sound embedded Blink JIT

- [ ] Introduce explicit interpreter and JIT engine modes; never silently
      select or fall back between them.
- [ ] Extend the pinned embedding ABI for bounded block execution, canonical
      state reconciliation, checked memory, and execution-owned evidence.
- [ ] Require native ARM64 generated code on Apple Silicon and reject any
      x86_64 host code or translated process.
- [ ] Enforce `MAP_JIT`/W^X discipline, thread-local write protection, bounded
      cache size, instruction-cache synchronization, deterministic code
      invalidation, and safe self-modifying-code handling.
- [ ] Serialize shared JIT generation until a stronger concurrency proof is
      accepted; keep per-runtime architectural state thread-confined.
- [ ] Differentially compare JIT and interpreter state, memory, stops, faults,
      atomics, and x86-TSO outcomes for identical instruction streams.
- [ ] Add forced invalidation, stale-code, unsupported instruction,
      exception/fault, timeout, cleanup, sanitizer, and stress coverage.

### Phase 3 — route ordinary x86_64 Wine guests

- [ ] Extend the pinned Wine patch series through reviewed public bridge APIs
      so ordinary PE32+ x86_64 images enter `GEM_x86_64`, not only the accepted
      ARM64EC thunk fixture.
- [ ] Preserve Wine loader, wineserver, TEB/PEB, TLS, callback, exception,
      virtual-memory, and process/thread ownership at every transition.
- [ ] Prove entry/exit, imports, calling convention, integer/flags, x87/SIMD,
      memory, registry/file/console APIs, threads/atomics, exceptions, callbacks,
      child processes, and deterministic teardown with redistributable PE32+
      fixtures.
- [ ] Require machine-readable fixture results and retirement/transition
      evidence; `cmd.exe /c exit` is smoke coverage, not the complete gate.

### Phase 4 — add independent differential CI

- [ ] Run the same pinned fixture hashes under native x86_64 Wine on
      `macos-15-intel` and upload normalized reference evidence.
- [ ] Run the corpus on native ARM64 through explicit interpreter and JIT modes.
- [ ] Compare semantic output while permitting only documented nondeterminism;
      both hosts must independently pass.
- [ ] Reject stale/wrong-commit evidence, unused backends, wrong PE machines,
      non-ARM64 host processes, Rosetta, unbounded execution, and incomplete
      process/mapping cleanup.
- [ ] Keep the Intel oracle portable to a narrowly labeled self-hosted runner;
      Intel artifacts never become Apple-Silicon runtime inputs.

### Phase 5 — package, publish, and support the tested tier

- [ ] Extend manifests/evidence for explicit guest architecture, selected
      engine mode, JIT provenance, generated-host architecture, fixture hashes,
      semantic comparisons, resource bounds, invalidation, and cleanup.
- [ ] Rebuild the complete runtime when binary/engine changes require it; do not
      misrepresent a runtime overlay as proof of a new execution backend.
- [ ] Produce deterministic `metalsharp-wine-v0.1.1-macos-arm64.tar.zst` assets
      bound to the protected-main commit, SBOM, licenses, and limitations.
- [ ] Redownload the public artifact on fresh native ARM64 macOS, relocate it,
      initialize a fresh prefix, and rerun x86_64 interpreter/JIT plus all
      accepted `v0.1.0` tests.
- [ ] Update README, ADR/roadmap, release notes, support artifact, and known
      limitations only after the public-artifact gate passes.

## Pull-request evidence checklist

- [ ] Repository policy, formatting, unit, and conformance suites pass.
- [ ] Native ARM64 Mach-O/process closure and zero-Rosetta audit pass.
- [ ] `GEM_x86_64` isolation and fail-closed routing are demonstrated.
- [ ] Blink JIT emits only audited native ARM64 code and passes W^X/cache gates.
- [ ] Interpreter, JIT, and Intel-reference semantic evidence agree.
- [ ] Fresh-prefix PE32+ compatibility, stress, negative, sanitizer/leak, and
      cleanup tests pass.
- [ ] AArch64 and ARM64EC baseline evidence remains unchanged and green.
- [ ] Deterministic archive, SBOM, provenance, checksum, relocation, and
      published-redownload verification pass.
- [ ] The final PR head is green before conversion from draft to ready.

## Completion rule

Checkboxes record proven evidence, not implementation intent.  A phase is only
complete after its tests exercise the new path and fail when that path is
removed, bypassed, stale, wrong-architecture, or unbounded.  Issue #45 closes
only after the immutable `v0.1.1` artifact passes fresh-download verification
and the support claim is limited to that accepted evidence.
