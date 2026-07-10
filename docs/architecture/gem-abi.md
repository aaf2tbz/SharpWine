# GEM Canonical ABI Contract

Status: initial specification; no engine-specific layout may override this contract.

## Ownership

`gem_thread_context` is the only canonical guest CPU state. Host registers, Darwin `ucontext_t`, Blink internals, and an AArch64 engine's register bank are synchronized views.

## Integer mapping

| ARM64EC | x64 | Rule |
|---|---|---|
| x0 | RCX | volatile / argument 1 |
| x1 | RDX | volatile / argument 2 |
| x2 | R8 | volatile / argument 3 |
| x3 | R9 | volatile / argument 4 |
| x4 | R10 | volatile |
| x5 | R11 | volatile |
| x8 | RAX | return mapping |
| x18 | GS.base | fixed canonical TEB |
| x19-x22 | R12-R15 | nonvolatile |
| x25 | RSI | nonvolatile |
| x26 | RDI | nonvolatile |
| x27 | RBX | nonvolatile |
| fp | RBP | nonvolatile |
| sp | RSP | stack pointer |
| pc | RIP | instruction pointer |

x13, x14, x23, x24 and x28 are disallowed in ARM64EC guest code. The engine must diagnose their use rather than silently assigning ABI meaning.

## SIMD and flags

- v0-v15 map to XMM0-XMM15.
- v16-v31 are disallowed for ARM64EC.
- Full XMM6-XMM15 preservation is enforced across x64-origin entry thunks.
- NZCV maps to the documented x64 SF/ZF/CF/OF subset; subtraction carry inversion is handled at transition materialization.
- PF, AF and DF remain explicit x64 state because they have no direct ARM64 PSTATE representation.
- FPCR/FPSR and MXCSR are stored independently and converted only by tested routines.

## Required context fields

The implementation structure must contain, at minimum:

```c
struct gem_thread_context {
    uint64_t x[31];
    uint64_t sp, pc;
    uint32_t nzcv, fpcr, fpsr;
    struct { uint64_t lo, hi; } v[16];

    uint64_t x64_rflags;
    uint32_t x64_mxcsr;
    uint16_t x64_fcw, x64_fsw;
    struct { uint64_t lo, hi; } x87[8];

    uint64_t teb;
    uint64_t original_x64_sp;
    uint64_t transition_cookie;
    uint32_t isa;
    uint32_t stop_reason;
};
```

The concrete structure may add fields but may not alias guest x18 solely to host x18. At every guest boundary, `x[18] == teb` is an asserted invariant.

## ARM64EC helper contracts

### Indirect checker

Inputs: target and thunk state in x9/x10/x11 according to the specific checker form. Preserve x0-x8, x15, q0-q7. Classify targets from ARM64X CHPE code maps, never instruction bytes.

### ARM64EC to x64

Execute the compiler-generated signature-specific exit thunk. Trap the dispatch helper operation, preserve its `blr x16` hint/return contract, then convert canonical state into Blink.

### x64 to ARM64EC

Use CHPE metadata and the four-byte descriptor before an ARM64EC function to locate its entry thunk. Pop the x64 return address into guest LR, align SP to 16 bytes, retain original x64 SP in the required entry state, and preserve full XMM6-XMM15.

## Stop reasons

Engines return to GEM only with an explicit reason:

- syscall / Unix call;
- architecture transition;
- normal return to host sentinel;
- memory/protection fault;
- Windows exception;
- APC/suspend request;
- unsupported instruction;
- instruction-budget expiration;
- fatal invariant violation.

No signal-handler side effect is treated as an implicit transition.

## Sources

- Microsoft ARM64EC ABI conventions
- Microsoft ARM64EC assembly/entry/exit thunk documentation
- LLVM `AArch64Arm64ECCallLowering.cpp`
- Wine ARM64X generated objects and CHPE metadata
