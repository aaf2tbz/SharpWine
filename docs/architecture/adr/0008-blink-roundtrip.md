# ADR 0008: Deterministic ARM64EC to Blink x64 round trip

Date: 2026-07-11
Status: Proposed
Issue: [#14](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/issues/14)

## Context

Milestone 5 requires a standalone, repeatable ARM64EC → Blink x64 → ARM64EC proof before Wine
startup is changed. Milestones 1 through 4 established the inputs to that proof: a checked
ARM64X/CHPE classifier, the fixed 720-byte `gem_thread_context`, pure ARM64EC/x64 context
conversion, checked 4 KiB guest memory, pinned Dynarmic execution, and an authentic
Microsoft-linked ARM64X fixture pipeline. ADR 0006 also accepts Blink's bounded interpreter as the
x86 memory-order fallback while rejecting the timed-out concurrent JIT candidate.

The present ARM64EC runtime already has bounded runs, checked memory, stop information, metadata
attachment, boundary stops, and code invalidation. It stops before a metadata-classified x64
instruction is fetched. The repository does not yet expose an x64-engine runtime or establish how
the pinned Blink revision's internal `Machine`, memory, execution, fault, dispatch, and JIT
facilities can satisfy the same ownership contract. Names in existing boundary enums are not
proof of dispatcher semantics.

This ADR proposes the integration plan and acceptance contract. It does not accept an adapter or
claim unreviewed Blink behavior.

## Proposed decision

### Stable GEM x64-engine boundary

Introduce a public, engine-neutral x64 runtime boundary whose stable semantics mirror the existing
ARM64EC runtime: opaque runtime lifecycle, explicit association with GEM memory, bounded `run`,
structured last-stop information, explicit guest-code invalidation, and engine
name/version/license/provenance queries. A convenience `gem_run_x64(context, budget)` may use a
thread-confined current runtime as described by the deterministic vCPU plan.

The public boundary must mention no Blink `Machine`, host pointer, signal frame, JIT object, or
private type. Blink-specific state and any memory alias are adapter-owned synchronized views. The
concrete C declarations will be frozen only after the evidence phase proves that the pinned public
Blink source can implement all required operations without an unproven private API. Unsupported
operations fail closed; they do not widen the interface by guessing engine behavior.

A run has the following semantic contract:

- GEM validates the canonical context and nonzero bounded budget before entry.
- GEM imports a complete transient x64 view, runs no more than the authorized slice, then exports
  the complete view before reporting any stop.
- GEM, not Blink, owns instruction budgets, stop selection, faults, guest mappings, and transition
  frames. An engine counter is evidence consumed by GEM, not authority to exceed the budget.
- Every exit reports one existing `gem_stop_reason` plus checked details such as retired count,
  fault address/access/error, and engine status. Unknown, contradictory, or incomplete engine
  outcomes become `GEM_STOP_INVARIANT_VIOLATION` or a separately justified fail-closed result.
- No engine-private state remains the only copy of an architecturally visible mutation after a
  transition, fault, unsupported instruction, budget stop, or normal return.

### Canonical synchronization

`gem_thread_context` remains the sole canonical state and remains exactly layout version 1, 720
bytes. `gem_x64_context` is only a host-independent materialization. Implementation must test the
round trip for:

- all mapped GPRs, RIP/PC, RSP/SP, the ARM64EC return LR where the evidenced thunk contract uses it,
  and the canonical TEB/GS base;
- NZCV and the full retained RFLAGS state, including PF, AF, DF and the documented arithmetic carry
  treatment;
- v0-v15/XMM0-XMM15, with explicit preservation of XMM6-XMM15;
- independent FPCR/FPSR and MXCSR state, plus x87 control/status and all x87/MM slots;
- every stack byte read or written by calls, returns, alignment, shadow space, and thunks; and
- every guest-memory mutation through GEM's checked, transactional 4 KiB-page interface.

Conversion must be transactional: rejected state, including an unrepresentable FP mode, must not
partially change canonical state or caller outputs. Blink must not own guest mappings or bypass GEM
permissions with a host dereference. Any proven identity alias remains an optimization behind the
same checked memory and fault contract. All x64 memory behavior remains subject to ADR 0006 and all
subpage behavior remains subject to ADR 0007; byte-prefix ISA or memory-operation scanning is
forbidden.

### Transition ownership

The ADR 0003 broker remains the only owner of transitions. Nested transition frames are
broker-owned records, not Blink stack objects and not additions made implicitly to the fixed
context ABI. A frame records, after its exact representation is reviewed, the ARM64EC return LR,
x64 return address, aligned ARM64EC SP, original x64 SP, parent/depth identity, and the expected
return operation. `transition_cookie` may identify the broker's checked frame stack, but must not be
a raw host pointer. Push, pop, unwind, budget, and fault operations are bounded and fail closed on
mismatch, underflow, overflow, stale cookies, or unexpected return paths.

At every ARM64EC instruction, checker, thunk, broker, fault, budget, and return boundary,
`context.x[18] == context.teb`; x64 observes the same value as canonical GS base. Host x18 is never
read as guest authority.

The accepting path must begin with the authentic, source-produced, Microsoft-linked ARM64X image
and its checked load configuration, CHPE code map, relocations, imports, aliases, checker records,
entry descriptor, and signature-specific thunks. It must execute the compiler-generated exit
thunk in pinned Dynarmic, stop at the metadata-classified x64 target without fetching x64 in
Dynarmic, execute x64 through the GEM adapter, resolve and execute the authentic entry thunk, and
return to ARM64EC. Raw COFF, synthetic metadata, instruction bytes, or a hand-written substitute
cannot make this path pass. Generated binaries and evidence remain in runner-temporary build trees
and are checked for leakage.

### Evidence gates for Blink and dispatch

Before implementation chooses adapter entry points, record pinned public-source evidence for the
exact Blink revision in `components.lock.json` covering:

1. lifecycle and thread confinement of every `Machine` and shared system/JIT object used;
2. complete GPR, RIP, RFLAGS, XMM, MXCSR, x87/MM, and GS-base import/export;
3. checked memory access, cross-page transaction, fault, and self-modifying-code behavior;
4. bounded execution and distinguishable normal-return, fault, unsupported, and attention stops;
5. interpreter selection and the process-wide synchronization required for JIT generation; and
6. executable-memory creation/modification and the public cache-maintenance protocol on ARM64.

Likewise, dispatch-call, dispatch-ret, entry, exit, callback, tail-call, and nested-frame behavior
may be implemented only from Microsoft documentation, pinned upstream LLVM/Wine sources, and the
authentic linked producer/probe evidence. For each operation, the evidence must establish exact
register inputs/outputs, stack effects, return-address ownership, target classification, and stop
point. If that evidence is absent or conflicts with the pinned implementation, the relevant phase
stops as unsupported. This ADR deliberately does not infer those details from helper names,
disassembly byte patterns, or Blink internals.

### JIT, cache, and host architecture

The bounded interpreter remains the correctness fallback. If JIT is enabled for a covered case,
all host executable-code creation or modification is serialized by one process-wide GEM-owned
lock until a separate concurrency proof is accepted. A per-runtime or per-thread lock is
insufficient. JIT failure, timeout, or unsupported behavior falls back to a separately passing
interpreter execution rather than weakening the oracle.

Use platform instruction-cache maintenance only after host executable code is created or modified,
and only according to the evidenced public protocol. Guest architecture transitions alone do not
justify cache maintenance. No unconditional architecture-transition `ISB`, private TSO API,
Rosetta state, kernel extension, or unverified Virtualization.framework control is permitted.
The executable, Blink, Dynarmic, and every loaded Mach-O dependency must be native ARM64, and the
process must audit as untranslated.

## Constraints and non-goals

- GEM remains sole owner of canonical CPU state, checked memory, faults, budgets, stops, and
  transition frames.
- ARM64X/CHPE metadata is the sole ISA-classification authority; no byte-prefix decoder or native
  invocation of a guest PC is allowed.
- The accepted fallback must remain deterministic even when JIT and direct-memory optimizations are
  disabled.
- This milestone does not modify Wine startup, add syscall/Unix-call product integration, accept
  direct native ARM64EC execution, prove concurrent Blink JIT generation, or add i386 support.
- This milestone does not change the 720-byte context layout. Any discovered need that cannot be
  represented by canonical state plus checked broker-owned frames requires a new reviewed ABI
  decision, not an implicit extension.
- Proprietary binaries, generated Microsoft artifacts, fetched Blink sources, x64 guest images,
  and build products are never committed.

## Phased implementation plan

### Phase 0 — Evidence and fail-closed adapter spike

- Audit the pinned Blink source for every lifecycle, state, memory, run, fault, unsupported, JIT,
  and cache operation listed above; add hashes/provenance so source drift fails CI.
- Audit Microsoft, LLVM, Wine, and same-job linked-fixture evidence for each dispatch and return
  operation. Separate documented facts from observations and unresolved questions.
- Prove an ARM64-only build can link an embedding adapter using public, redistributable interfaces.

**Gate:** stop without an implementation claim if complete state extraction, checked GEM memory,
bounded stops, or authentic dispatch behavior cannot be established.

### Phase 1 — Stable x64 runtime and pure state adapter

- Add the engine-neutral public runtime and structured stop contract.
- Place all Blink types behind the private adapter; make runtime/thread/process ownership explicit.
- Implement transactional full-state import/export and focused bit/lane/x87 tests without a hybrid
  transition.

**Gate:** every state field round-trips through the adapter, failures leave canonical state valid,
and the 720-byte layout is unchanged.

### Phase 2 — Checked execution, memory, budgets, and faults

- Run bounded x64 leaf fixtures through GEM reads, writes, fetches, permissions, and invalidation.
- Translate normal return, `GEM_STOP_BUDGET_EXPIRED`, checked memory faults, and unsupported
  instructions into exact GEM stops, exporting state first.
- Keep the ADR 0006 interpreter fallback and ADR 0007 transactional page isolation active; add JIT
  only behind process serialization and identical-state comparison.

**Gate:** no access bypasses GEM, no failed access partially commits, and every run is bounded.

### Phase 3 — Evidence-backed broker and authentic round trip

- Extend the source-only authentic fixture/probe in runner-temporary build trees for the exact
  direct, indirect, callback, return, tail, and nesting evidence needed by the broker.
- Implement only evidenced dispatch-call/dispatch-ret and frame operations.
- Execute ARM64EC exit thunk → metadata-classified x64 → Blink → descriptor-resolved entry thunk →
  ARM64EC, checking x18/TEB and frame invariants at each boundary.

**Gate:** two clean authentic fixture builds produce equivalent normalized evidence and the same
final oracle; no generated artifact enters the checkout.

### Phase 4 — Path matrix and release validation

- Add direct call, mandatory checked indirect call, callback, tail-call, nested transition, normal
  return, memory/protection fault, unsupported-instruction, and budget-stop cases.
- Repeat the exact whole-state oracle and cross-cutting TSO/page-isolation suites on native ARM64
  macOS, with zero-Rosetta/dependency audits and supported sanitizers.
- Run repository policy, formatting, licensing/provenance, generated-artifact leakage, clean build,
  and the full CTest matrix.

**Gate:** all validation items below pass repeatedly; otherwise this ADR remains Proposed.

## Validation checklist

- [ ] A stable GEM x64-engine interface hides Blink aliases, `Machine`, JIT, and host-private state.
- [ ] Complete GPR, RIP/PC, RSP/SP, RFLAGS/NZCV, SIMD, FPCR/FPSR/MXCSR, x87/MM, TEB/GS, stack,
      and guest-memory synchronization is transactional and exact.
- [ ] XMM6-XMM15 and all x87/MM state survive every applicable entry, exit, callback, and nesting
      path.
- [ ] GEM alone owns bounded instruction budgets, explicit stops, checked faults, guest mappings,
      and bounded transition frames.
- [ ] Frames preserve evidenced ARM64EC return LR, x64 return address, aligned SP, original x64 SP,
      and nested parent/depth state without changing the 720-byte ABI.
- [ ] Documented dispatch-call and dispatch-ret stops use exact evidence-backed register, stack,
      target, and return contracts; unknown variants fail closed.
- [ ] The accepting round trip uses the authentic linked metadata/checker/exit-thunk/x64
      target/entry-descriptor/entry-thunk path, with all generated artifacts build-tree-only.
- [ ] Direct call and mandatory checked indirect-call cases stop and return deterministically.
- [ ] Callback, tail-call, nested-transition, and normal-return cases stop and return deterministically.
- [ ] Memory/protection faults, unsupported instructions, budget expiry, malformed metadata, and
      frame mismatches produce exact fail-closed stops without partial state or memory effects.
- [ ] `x[18] == teb` at every ARM64EC instruction and transition boundary, and x64 GS base agrees;
      Darwin x18 is never canonical.
- [ ] Every x64 memory effect uses ADR 0006 ordering and ADR 0007 checked 4 KiB-page semantics,
      including cross-page operations and canonical low addresses; no byte-prefix scanner is used.
- [ ] The bounded interpreter passes as the correctness fallback; every demonstrated optimized path
      produces the identical oracle or falls back deterministically.
- [ ] Blink JIT host-code generation/modification is process-serialized, including all shared JIT
      state, until a separate concurrency decision is accepted.
- [ ] Cache maintenance occurs only for evidenced host executable-code creation/modification; there
      is no unconditional transition `ISB` or unproven private control.
- [ ] The final oracle compares every expected register, flag, SIMD lane, FP/x87 field, stack byte,
      transition frame, stop detail, and guest-memory mutation across repeated runs.
- [ ] Existing x86 memory-order conformance and 4 KiB-on-16 KiB page-isolation suites continue to
      pass repeatedly with hardware TSO disabled or unavailable.
- [ ] The process and every Mach-O dependency are native ARM64 and zero-Rosetta audits pass.
- [ ] AddressSanitizer and UndefinedBehaviorSanitizer runs pass where the platform and dependencies
      support them; unsupported sanitizer combinations are explicitly reported, not silently
      skipped.
- [ ] Linux GCC/Clang, macOS Apple Clang, native Windows ARM64 fixture/probe, formatting,
      repository-policy, licensing/provenance, leakage, and full test gates pass.

## Consequences

If accepted, Blink becomes an x64 execution engine behind GEM rather than an owner of runtime
state. The first accepted path remains a standalone correctness proof with an interpreter fallback;
JIT and direct aliases remain removable optimizations. The evidence work may instead reveal an
unsupported embedding, state-extraction, memory, or dispatcher contract. In that event the project
stops at the relevant gate and revises the architecture rather than inventing behavior.

## References

- `ROADMAP.md`, release acceptance criteria and Milestone 5
- `docs/architecture/deterministic-vcpu-plan.md`, transition broker and x64 engine sections
- ADR 0001, engine ownership boundaries
- ADR 0003, transition ownership boundaries
- ADR 0005, authentic ARM64EC checker and thunk fixture evidence
- ADR 0006, x86-TSO correctness contract and Blink acceptance
- ADR 0007, 4 KiB guest-page isolation
- `docs/architecture/gem-abi.md`
- `components.lock.json`
