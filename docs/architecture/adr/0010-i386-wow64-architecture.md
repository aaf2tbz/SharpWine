# ADR 0010: Isolated i386/WoW64 guest architecture

Date: 2026-07-14
Status: Accepted for implementation
Issue: [#46](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/issues/46)

## Context

The v0.1.1 package inventories Wine's i386 PE tree but accepts only AArch64,
ARM64EC/x64, and the bounded pure x86_64 path. The shared 720-byte
`gem_thread_context` is already a stable ARM64EC/x64 ABI. i386 additionally
requires 32-bit pointer arithmetic, FS-based TEB state, legacy segmentation,
PE32 classification, and Wine WoW64 transitions. Reinterpreting x64 fields or
letting host mappings represent guest pointers would weaken the accepted ABI
and memory ownership rules.

## Decision

GEM_i386 is a separate architecture module with its own fixed 448-byte
`gem_i386_context` v1. It owns the eight IA-32 GPRs, EIP/EFLAGS, segment
selectors/bases/limits/attributes, eight XMM lanes, x87/MM state, FP control,
FS-based TEB address, transition cookie, and stop state. The ARM64EC/x64
context layout and meanings do not change.

All i386 addresses cross a policy layer that admits only nonempty ranges wholly
inside `[0, 2^32)`. Page operations retain GEM's transactional 4 KiB mapping,
guard, write-copy, alias, and protection semantics. Automatic reservations
begin at 64 KiB and advance by Windows allocation granularity. Host pointers
are never returned as guest addresses, and no i386 API exposes identity mapping.

Pinned Blink remains an adapter-owned transient execution view. Its system
continues to use the reviewed long-mode page-table implementation, while the
thread-confined machine decoder/executor is explicitly placed in
`XED_MACHINE_MODE_LEGACY_32`. Every fetch, read, write, and commit remains
checked against the i386 range and an active GEM transaction. Production uses
the bounded one-instruction AArch64 JIT; the interpreter is an explicit oracle,
not a silent fallback. Both modes import and export complete i386 state at each
instruction boundary. JIT failure, address escape, malformed state, or an
unknown engine outcome fails closed.

Wine integration is additive. A versioned i386 bridge configuration must
strictly classify PE32 magic `0x10b` and machine `0x014c`, publish explicit
WoW64 syscall/Unix-call boundaries, and create a GEM_i386 runtime per Wine
thread. Every 32-to-64 buffer, length, handle, context, callback, and pointer
conversion is checked before use. Existing bridge exports and ARM64EC/x64
behavior remain compatible.

Resource authority stays in GEM: per-segment and total instruction budgets,
boundary callbacks, mappings, shadow pages, JIT arena, threads, children, wall
time, logs, and teardown are bounded. A stop cannot leave architectural state
only inside Blink. Code writes and executable-protection changes invalidate
GEM_i386 paths before further execution.

## Acceptance consequences

- Native Windows x86_64 CI builds every PE32 fixture twice, requires identical
  bytes, executes the exact bytes under Windows WoW64, and emits normalized
  manifest-bound oracle results.
- Native ARM64 macOS consumes those exact bytes and compares GEM_i386 JIT and
  interpreter state/results with the Windows oracle.
- The packaged i386 ntdll/kernel32/cmd path, mixed-bitness children, registry
  and filesystem redirection, exceptions, APCs, threads, callbacks, and cleanup
  must be demonstrated; inventory or loader-only evidence is insufficient.
- DXMT acceptance requires a same-source paired PE32 `winemetal.dll` and native
  ARM64 `winemetal.so` rebuild. An upstream x86_64 Unix module is prohibited.
- v0.1.2 must use a clean, provenance-bound build and public-redownload gate.
  The v0.1.1 four-file overlay policy is not widened to disguise a new runtime.

## Rejected alternatives

- Widening or unioning `gem_thread_context` v1 with IA-32 state.
- Treating the packaged i386 PE inventory as executable support.
- Running a 32-bit/x86_64 Mach-O helper, Rosetta, or `arch -x86_64`.
- Using Blink's Linux syscall implementation or an x86_64 DXMT Unix module.
- Falling back from a failed production JIT run without separately executing
  and identifying the interpreter oracle.
