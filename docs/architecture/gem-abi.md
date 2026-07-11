# GEM Canonical ABI Contract

Status: accepted v1 in-process ABI; no engine-specific layout may override this contract.

## Ownership

`gem_thread_context` is the only canonical guest CPU state. Host registers, Darwin `ucontext_t`, Blink internals, and an AArch64 engine's register bank are synchronized views.

## Versioning scope

Two versions are deliberately separate:

- `GEM_CONTEXT_LAYOUT_VERSION == 1` identifies the in-process C ABI layout compiled from `include/metalsharp/gem/context.h`.
- `GEM_CONTEXT_SERIALIZATION_VERSION == 1` is reserved for the portable, field-wise, little-endian serialized context contract.

The C structure is **not** a wire format. Raw `struct gem_thread_context` dumps, hashes, `memcpy()` images, fixture blobs, traces, IPC payloads, and saved-state records are forbidden as portable serialization. A serializer must encode named fixed-width fields in little-endian order and belongs to issue #6 / Milestone 2.

Any change to field order, size, alignment, meaning, invariants, or enum values requires a new layout version. Any change to the portable field-wise encoding requires a new serialization version and either an explicit decoder or explicit rejection of unsupported versions.

## v1 in-process layout

The supported ABI is 64-bit C11/C++ with 8-byte `uint64_t` alignment. `gem_context_initialize()` sets `layout_version`, `context_size`, the canonical TEB fields, and ISA. `gem_context_is_valid()` rejects stale layout versions, stale sizes, invalid ISA values, zero TEB, and `x[18] != teb`.

| Field | Offset | Size | Notes |
|---|---:|---:|---|
| `layout_version` | 0 | 4 | Must equal `GEM_CONTEXT_LAYOUT_VERSION` (`1`). |
| `context_size` | 4 | 4 | Must equal `GEM_THREAD_CONTEXT_SIZE_V1` (`720`). |
| `x[31]` | 8 | 248 | ARM64EC-visible integer register bank; `x[18]` is canonical TEB. |
| `sp` | 256 | 8 | Guest stack pointer. |
| `pc` | 264 | 8 | Guest instruction pointer. |
| `nzcv` | 272 | 4 | ARM64 flags subset. |
| `fpcr` | 276 | 4 | ARM FP control. |
| `fpsr` | 280 | 4 | ARM FP status. |
| `reserved0` | 284 | 4 | Reserved; initialized to zero. |
| `v[16]` | 288 | 256 | v0-v15 / XMM0-XMM15 as 128-bit lanes. |
| `x64_rflags` | 544 | 8 | x64 flags not fully represented by NZCV. |
| `x64_mxcsr` | 552 | 4 | x64 SIMD FP control/status. |
| `x64_fcw` | 556 | 2 | x87 control word. |
| `x64_fsw` | 558 | 2 | x87 status word. |
| `x87[8]` | 560 | 128 | x87/MM storage required by x64 engine state. |
| `teb` | 688 | 8 | Canonical Windows TEB / x64 GS.base. |
| `original_x64_sp` | 696 | 8 | Transition entry state for ARM64EC/x64 thunks. |
| `transition_cookie` | 704 | 8 | Broker-owned transition state token. |
| `isa` | 712 | 4 | `GEM_ISA_ARM64EC` or `GEM_ISA_X64`. |
| `stop_reason` | 716 | 4 | Explicit engine stop reason. |

Total v1 size: 720 bytes. Total v1 alignment: 8 bytes. The public header contains compile-time size, alignment, offset, fixed-width integer, and enum-value assertions; `tests/context_layout_test.c` mirrors key checks for focused diagnostics.

## Portable serialization contract

Milestone 0 defines the contract but does not implement the encoder/decoder. A future version-1 serialized context must:

- start with a documented header containing magic, serialization version, header size, layout version, and context size;
- encode every field explicitly by name in a fixed order;
- write all multi-byte integers little-endian regardless of host endianness;
- encode enum values as the asserted `uint32_t` values from the public header;
- reject unknown versions, wrong layout version/size, truncated records, out-of-range enum values, nonzero reserved data unless the version permits it, and `x[18] != teb`;
- never include host pointers, host register snapshots, padding bytes, private paths, proprietary bytes, or raw C struct images.

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
- FPCR/FPSR and MXCSR are stored independently and converted only by tested routines. IOC/IDC/DZC/OFC/UFC/IXC map explicitly to IE/DE/ZE/OE/UE/PE; ARM trap enables invert MXCSR masks, rounding encodings are translated, and FZ maps to FZ. x86 DAZ is rejected by checked conversion because ARM64 has no equivalent. ARM DN, QC, and all other architecture-only bits remain in their independently stored ARM fields; they are never silently folded into MXCSR.

## Required context fields

The implementation structure is:

```c
struct gem_thread_context {
    uint32_t layout_version;
    uint32_t context_size;
    uint64_t x[31];
    uint64_t sp, pc;
    uint32_t nzcv, fpcr, fpsr, reserved0;
    struct gem_u128 v[16];

    uint64_t x64_rflags;
    uint32_t x64_mxcsr;
    uint16_t x64_fcw, x64_fsw;
    struct gem_u128 x87[8];

    uint64_t teb;
    uint64_t original_x64_sp;
    uint64_t transition_cookie;
    uint32_t isa;
    uint32_t stop_reason;
};
```

The concrete structure may not alias guest x18 solely to host x18. At every guest boundary, `x[18] == teb` is an asserted invariant.

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
