# ADR 0013: i386 context ABI v3: YMM, XCR0, and xsave state

Date: 2026-07-17
Status: Accepted

## Context

The Phase 6 roadmap requires VEX decode and full XSAVE/XRSTOR/XGETBV state
foundations before OSXSAVE, AVX, AVX2, or FMA may be advertised, and requires
deterministic timestamp-policy coverage (ROADMAP Phase 6, lines 255-258).
ADR 0008 requires a reviewed ABI decision before any new state family crosses
the GEM boundary. This ADR is that decision for YMM, XCR0, and xsave state on
the i386 lane. Every layout number below is computed from the cited source,
not estimated.

### Current i386 context ABI (verified)

`include/metalsharp/gem/i386_context.h` defines `struct gem_i386_context` at
exactly 448 bytes with alignment 8 (`GEM_I386_CONTEXT_SIZE_V1` /
`GEM_I386_CONTEXT_SIZE_V2` both 448, lines 19-21; static asserts lines
98-119). The v1→v2 precedent: v2 kept the size at 448 and repurposed the
20-byte trailing `reserved[5]` into the
`union { uint32_t reserved[5]; struct gem_i386_x87_environment ... }`
(lines 84-87), gated by `layout_version`. Static offset asserts pin `gpr`@8,
`eip`@40, `segment`@48, `xmm`@136, `x87`@264, `transition_cookie`@416,
`stop_reason`@424, and the x87 environment at 428-447. From these offsets the
padding is derived, not guessed: 4 bytes after `segment_attributes` (ends 132)
for 8-alignment of `gem_u128 xmm[8]`@136, and 4 bytes after `reserved0`@408
for 8-alignment of `transition_cookie`@416. `gem_u128` is 16 bytes, alignment
8 (`include/metalsharp/gem/context.h:44-47,90-92`).

`gem_i386_context_is_valid` (`src/gem/i386_context.c:19-34`) accepts only
`layout_version` 1 or 2 with `context_size == 448` exactly, requires
`teb != 0`, `EFLAGS REQUIRED`, `reserved0 == 0`, zeroed version-specific
reserved fields, and `stop_reason <= GEM_STOP_INVARIANT_VIOLATION`.

`GEM_I386_CONTEXT_SERIALIZATION_VERSION` is declared as 1 in
`i386_context.h:18` but has no i386 implementation: the only serializer in
the tree (`src/gem/context_serialization.c`) serializes the x64
`gem_thread_context` (`GEM_CONTEXT_SERIALIZATION_VERSION` /
`GEM_CONTEXT_WIRE_SIZE_V1`). i386 today crosses ABIs only as the raw struct.

The Wine/GEM bridge embeds `struct gem_i386_context` **by value** in
`gem_wine_i386_boundary_request` and `gem_wine_i386_boundary_response`
(`include/metalsharp/gem/wine_bridge.h:197-213`), each carrying explicit
`version` + `struct_size` fields validated at the boundary
(`src/gem/wine_bridge.c`, e.g. lines 558-560, 858-859). The bridge ABI is
therefore versioned end to end: growing the context does not silently break
it, but it does change `sizeof` those two structs and must be surfaced as a
bridge boundary-version bump, not absorbed silently.

### Blink's actual VEX/AVX/XSAVE capability (inventoried)

Against the pinned tree `_deps/blink_gem-src` (jart/blink
@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580 plus patches 0001-0014):

- **VEX decode exists upstream**: `blink/x86.c:386-495` implements the 0xc4 /
  0xc5 scanners (`xed_vex_c4_scanner`, `xed_vex_c5_scanner`), gated on
  `DISABLE_BMI2` at `blink/x86.c:731-733`. VEX-encoded instructions decode to
  mopcodes in the 0x2xx-0x3xx range and dispatch through `GetOp`
  (`blink/machine.c:2101-2160`).
- **VEX-era implementations are 128-bit only**: BMI2 shifts exist
  (`blink/bmi2.c:102` `Op2f5`, `:192` `OpShx`; `OpRorx` at map 0x3f0), CRC32
  (`blink/crc32.c:68` `Op2f01`), MULX (`blink/divmul.c:591` `Op2f6`), AES
  (`blink/machine.c:2145-2151`), and VEX-encoded 128-bit SSE via the shared
  `OpSse4` (`blink/sse4.c:298`). With `DISABLE_BMI2` these collapse to `OpUd`
  (`blink/machine.c:1559-1561`).
- **There is no YMM register file**: `struct Machine` stores vector state as
  `u8 xmm[16][16]` (`blink/machine.h:403`, comment "128-BIT VECTOR REGISTER
  FILE"; mirrored at `blink/machine.h:241`). No `ymm` identifier exists
  outside the VEX decode fields in `blink/x86.c`. AVX-256, AVX2 gather, and
  FMA have **no implementations to enable**.
- **XSAVE is a stub, XRSTOR/XSAVEOPT are silently wrong upstream**:
  `OpXsave` is an empty function (`blink/machine.c:1307`); the 0x0f 0xae
  group dispatcher (`blink/machine.c:1350-1410`, `Op1ae`) routes modrm.reg 4
  memory (XSAVE) to the empty stub, modrm.reg 5 (XRSTOR) to `OpLfence`
  unconditionally, and modrm.reg 6 (XSAVEOPT) to `OpMfence` unconditionally.
  There is no xgetbv/xsetbv/xcr0 modeling anywhere: `Op101` register-form
  modrm.reg 2 (which includes XGETBV/XSETBV encodings 0x0f 0x01 0xd0-0xd7)
  falls to `OpUdImpl` (`blink/op101.c:197-203`); `xcr0` appeared in no source
  file before SharpWine blink patch 0017.
- Consequence for today: a guest XSAVE/XRSTOR/XSAVEOPT would **retire as a
  silent no-op or wrong op**, not fault. This is currently survivable only
  because the legacy32 CPUID profile
  (`third_party/patches/blink/0009-gem-i386-legacy-state.patch`, cpuid.c hunk
  at patch lines 186-234) advertises no OSXSAVE/AVX/XSAVE bit, and the
  GemHandlerId legacy32 mask (patch 0009:812-823, applied at
  `blink/machine.c:2181-2192`) excludes decoded forms GEM cannot restore:
  0x1c7 with modrm.reg >= 6, REP-prefixed 0x1ae with modrm.reg <= 3, 0x101
  with modrm 0xd0/0xf9, VEX BMI mopcodes 0x2f2-0x2f7, and 0x3f0 (RORX).
  Notably the plain 0x1ae xsave group was **not** in that mask; SharpWine blink
  patch 0017 closes it by admitting implemented XSAVE/XRSTOR forms and
  rejecting XSAVEOPT.

**Finding, stated plainly: SharpWine implements XSAVE/XRSTOR/XGETBV in blink
patch 0017 and implements AVX handlers incrementally in W5. Upstream blink
provides VEX decode and 128-bit VEX/BMI building blocks, but there was no
existing AVX/XSAVE implementation to merely enable, and two group entries
(XRSTOR, XSAVEOPT) had to be replaced, not reused.**

### Embedding seams to extend

- `struct blink_gem_state` (`blink/gem_embed.h:148-158`,
  `BLINK_GEM_STATE_ABI_VERSION 2`): `{u32 abi_version, size; u64 gpr[16]; u64
  rip, rflags; u8 xmm[16][16]; u32 mxcsr; u16 fcw, fsw; u8 x87[8][16]; u64
  gs_base, fs_base; u16 ftw, reserved[3]; u32 fip, fdp; u16 fcs, fds, fop,
  state_reserved; struct blink_gem_segment segments[6];}`.
- `import_state` / `export_state` in `src/gem/i386_blink.c` copy the complete
  448-byte-equivalent state across that struct on every step and run boundary;
  every new state field must cross the same boundary in both directions.
- The GemHandlerId legacy32 mask (`blink/machine.c:2181-2192`, from patch
  0009:812-823) is the admission point where new families are unmasked per
  reviewed gate, exactly as the roadmap's "retain explicit masking until its
  reviewed gate passes" requires.
- The CPUID profile seam is the cpuid.c legacy branch from patch 0009
  (patch lines 186-234), which today reports a deterministic family-6 profile
  with SSE/SSE2/SSE3/SSSE3/SSE4.1/SSE4.2/PCLMUL and ERMS only.

### Wine/WoW64 side

Today `dlls/xtajit/unixlib.c` maps the i386 `I386_CONTEXT.ExtendedRegisters`
as a plain `XSAVE_FORMAT` (the 512-byte legacy FXSAVE area): wine patch 0019
(`third_party/patches/wine/0019-xtajit-preserve-i386-v2-legacy-state.patch`)
round-trips fcw/fsw/ftw/fop, the x87 environment (fip/fdp/fcs/fds), the eight
XMM lanes, and the eight 80-bit x87 registers through that struct. No
XSTATE/AVX state exists on this path today.

For AVX state, Windows hands 32-bit apps a `CONTEXT` whose `ContextFlags`
includes `CONTEXT_XSTATE`; the trailing interpretation is an `XSTATE_CONTEXT`
(`https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-xstate_context`:
`DWORD64 Mask; DWORD Length; DWORD Reserved1; PXSAVE_AREA Area;`) pointing at
an `XSAVE_AREA`: the 512-byte `XSAVE_FORMAT` legacy region
(`https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-xsave_format`)
plus the 64-byte `XSAVE_AREA_HEADER` (`Mask`, `CompactionMask`,
`Reserved2[6]`), plus the extended region. In the standard (non-compacted)
format Intel documents (Intel SDM Vol. 1, chapter 13, "XSAVE Feature Set";
CPUID leaf 0DH), state component 2 (YMM) occupies 256 bytes at offset 576 —
i.e. 512 (legacy) + 64 (header). A 32-bit WoW64 app sees 8 YMM registers
(YMM0-7); the GEM context needs only the 128-bit upper halves, since the
lower halves are the existing XMM lanes.

## Decision

### a. Context growth: in-struct append, layout version 3

`struct gem_i386_context` grows by appending after the existing 448 bytes,
preserving every existing offset and static assert:

| field | type | offset | size | computed as |
| --- | --- | --- | --- | --- |
| (existing v1/v2 body) | | 0 | 448 | unchanged |
| `ymm_upper[8]` | `struct gem_u128[8]` | 448 | 128 | 448 + 8*16 = 576 |
| `xcr0` | `uint64_t` | 576 | 8 | 576 + 8 = 584 |
| `reserved1` | `uint64_t` | 584 | 8 | 584 + 8 = 592 |

New constants: `GEM_I386_CONTEXT_LAYOUT_VERSION_V3 = 3`,
`GEM_I386_CONTEXT_SIZE_V3 = 592`. Alignment stays 8 (largest member alignment
is `gem_u128` = 8; 592 is a multiple of 16, keeping the record 16-byte
friendly for future xsave-area staging). `GEM_I386_CONTEXT_LAYOUT_VERSION`
becomes V3; `gem_i386_context_initialize` zero-initializes the extension and
sets size 592. `gem_i386_context_is_valid` accepts (v1|v2, 448) and (v3, 592),
requiring `reserved1 == 0` and `xcr0` within the supported mask (b) for v3.

Chosen over a separate versioned extension struct (`abi_version`/`size`
query in the style of `gem_i386_performance_info`, ADR 0010 line 77): the
context is a single architectural record that must cross the blink boundary
and the Wine bridge atomically; two objects would create a
lifetime/consistency seam every caller would have to get right. The v1→v2
precedent already extends semantics inside the fixed record while preserving
offsets, and the bridge boundary structs carry `version` + `struct_size`, so
the size change flows through a versioned channel rather than breaking
callers. The performance-info pattern remains the right model for
*statistics*, not for *state*.

Bridge consequence (explicit, not silent):
`gem_wine_i386_boundary_request`/`gem_wine_i386_boundary_response` grow to
592-byte context payloads; their boundary `version` is bumped alongside, with
the old version accepted for v1/v2-sized contexts during the same transition
window the engine accepts them.

Implemented by Wine patch 0020 and `GEM_WINE_I386_BOUNDARY_ABI_VERSION_V2`:
new callbacks receive the 648-byte request and return the 608-byte response;
the bridge accepts an explicitly versioned 464-byte v1 response only when its
embedded context declares layout v1/v2 and size 448. The x64/ARM64EC boundary
stays at `GEM_WINE_BOUNDARY_ABI_VERSION` 1.

### b. XCR0 policy

- Supported mask: `XCR0 = x87 | SSE | AVX = 0x7`. No other bit is ever set;
  `xcr0 & ~0x7 != 0` fails validation closed.
- `XGETBV` (`0x0f 0x01 0xd0`) returns the current xcr0 in `edx:eax`
  (eax = 0x7, edx = 0 while only the base mask exists).
- `XSETBV` (`0x0f 0x01 0xd1`) in user mode raises #GP(0) on real hardware;
  GEM maps it to the existing Windows-exception boundary with a documented
  `GEM_I386_EXCEPTION_GENERAL_PROTECTION` engine_status, and Wine patch 0020
  translates that identity to `EXCEPTION_PRIV_INSTRUCTION`, never
  silently ignoring it and never allowing a narrower mask (state would be
  lost) or a wider one (unsupported state).
- CPUID rules follow from the mask. Patch 0032 advertises OSXSAVE (bit 27),
  XSAVE (bit 26), and AVX (bit 28) after their W5 semantic, state/fault,
  interpreter/JIT, inventory, corpus, and loaded-program gates pass; FMA
  (bit 12) remains 0 until its own gate passes. Leaf 0x0d is then reported
  exactly per
  Intel's leaf-0DH definition: subleaf 0: eax = 0x7 (supported-state mask),
  ebx = 832 (bytes required for enabled states under XCR0 = 0x7: 512 legacy
  + 64 header + 256 YMM), ecx = 832 (maximum for all supported states),
  edx = 0; subleaf 1: eax = 0
  (no XSAVEOPT/XSAVEC/XSAVES features, see c); subleaf 2: eax = 256 (YMM
  component size), ebx = 576 (YMM component offset), ecx = 0, edx = 0.
  Subleaves above 2 report eax = ebx = ecx = edx = 0.
- Before patch 0032's reviewed W5 gate, OSXSAVE stayed masked and this state
  was inert and zero (see g). It is now advertised with the qualified AVX
  family while unsupported extended-state features remain zero.

### c. xsave area semantics

- Standard (non-compacted) format only. `XSAVE` (`0x0f 0xae /4`), `XRSTOR`
  (`0x0f 0xae /5`), and `XGETBV` operate between guest memory and the v3
  state (xmm lanes + ymm uppers + x87/SSE legacy fields + xcr0). The request
  mask is `edx:eax`; bits outside 0x7 raise #GP-class rejection through the
  documented exception boundary.
- `XSAVEOPT` (`0x0f 0xae /6`), `XSAVEC` (`0x0f 0xc7 /4`), `XSAVES`
  (`0x0f 0xc7 /5`), and `XRSTORS` are explicitly out: no modified/component
  optimization, no compaction, no supervisor states. The GemHandlerId mask is
  extended to keep them out (0x1c7 modrm.reg >= 6 is already masked; the W5
  patch adds the plain 0x1ae xsave group and the remaining 0x1c7 xsave forms
  to the admission list only as they are implemented, replacing blink's empty
  `OpXsave` and its XRSTOR-as-LFENCE / XSAVEOPT-as-MFENCE misdispatches).
- The xsave header's `XSTATE_BV` (`XSAVE_AREA_HEADER.Mask`) records which
  components hold meaningful data; XRSTOR restores only the requested
  components and zeroes the rest of the requested-in-xcr0 set, per Intel SDM
  Vol. 1 §13.8. `mxcsr_mask` (legacy offset 28) is reported as 0x0000ffff,
  matching the existing baseline fixture convention
  (`tests/fixtures/i386_phase4_baseline.c` `fill_fx`).
- Faults: an xsave area can span up to 832 bytes (512 legacy + 64 header +
  256 YMM) and therefore cross a 4 KiB
  guest page boundary. Validation follows the existing per-access
  transaction rules; a fault mid-operand reports the existing
  `GEM_STOP_MEMORY_FAULT` path with the faulting address, and the
  restartable-REP machinery is not extended to xsave: an xsave instruction
  that faults after partially writing memory is retried whole after the fault
  is handled, so its memory writes must be idempotent (restarting rewrites
  the same bytes). Architectural state (registers) is never committed on a
  faulted xsave, consistent with the current one-instruction commit model.

### d. Serialization: i386 wire format version 2

i386 gains a real serializer where only a declared constant existed. Wire
header `{ magic, serialization_version, layout_version, payload_size }`;
version 1 is defined retroactively as layout_version 1|2 with a 448-byte
payload; **version 2 is layout_version 3 with a 592-byte payload** in field
order: the 448-byte v1/v2 body, then `ymm_upper[8]` (128 bytes), then `xcr0`
(8), then 8 bytes zero padding. `gem_context_serialized_size(2)` returns
header + 592. Version-1 blobs are **rejected by the default deserializer**
(no silent reinterpretation); an explicitly named migration entry point
converts v1 → v2 by zero-initializing `ymm_upper` and `xcr0` and stamping
layout_version 3, so a caller must state that it wants migration. Anything
with an unknown version, size, or layout fails closed.

### e. Blink state ABI

`BLINK_GEM_STATE_ABI_VERSION` bumps to 3. `struct blink_gem_state` appends,
after `segments[6]`: `uint8_t ymm_upper[8][16]` (128 bytes) and
`uint64_t xcr0` (8 bytes). `import_state` / `export_state` transfer both
fields on every boundary in both directions. Because upstream blink has no
YMM storage (`machine.h:403`), SharpWine blink patches 0016–0017 add
upper-half storage to the gem machine wrapper and Machine state, and implement
the XSAVE handlers; AVX handlers follow incrementally in W5. Handlers that
blink cannot execute must fail through the
existing `BLINK_GEM_UNSUPPORTED` path, never through the silent
XSAVE-stub/XRSTOR-as-LFENCE dispatches (c). The AArch64 JIT obligation is
unchanged in kind: a VEX/AVX handler either receives reviewed JIT lowering or
forces the existing per-instruction / quantum-boundary path (the same
mechanism `nofault_batch_instruction` already uses to exclude ineligible
handlers), and both must produce bit-identical committed state and trace
identity.

### f. Deterministic timestamp policy (RDTSC/RDTSCP)

Kept in this ADR as its own section rather than deferred: it is small,
shares this review, and ADR 0008's gate covers exactly this kind of
state-crossing decision. Blink's `OpRdtsc` reads the host counter
(`blink/time.c:49-57`: `cntvct_el0` scaled by 48 on aarch64), which is
nondeterministic across runs and diverges between interpreter, JIT, and any
future optimized path. GEM instead owns a virtual TSC: a per-guest monotonic
counter derived from retired-instruction accounting at quantum boundaries,
advanced identically in every execution mode, with no raw host counter
crossing the boundary. RDTSC is admitted at the GEM adapter boundary (not via
blink's host-backed handler); RDTSCP now uses the same qualified boundary and
additionally returns a fixed guest TSC_AUX (0). The counter's epoch is 0
and its step is one tick per committed retired guest instruction. Transaction
conflicts do not advance it, so a retry observes the same value. The
deterministic corpus asserts this policy across interpreter/JIT modes and
different quantum partitions.

### g. Backward compatibility

- Existing v1/v2 contexts (448 bytes) remain valid inputs everywhere v1/v2 is
  accepted today; `gem_i386_context_is_valid` continues to accept them
  unchanged. The 45,810-comparison corpus and all existing hash-bound
  evidence remain valid because no existing offset, mask, or selection
  changes.
- AVX state is zero-initialized and inert while CPUID keeps OSXSAVE/XSAVE/AVX
  masked: a v3 context with zeroed `ymm_upper` and `xcr0 = 0` is
  semantically identical to its v2 projection for every instruction the
  legacy profile can currently execute.
- The gem_i386_engine_ops seam (Phase 6 W2) is unaffected: new execution
  behavior arrives through the same seven entries with the same ops ABI
  version; the state-width change is carried by the context, not the ops
  table.

## Consequences

- The ABI review gate for W5 is this document: VEX decode work may start
  against it, but OSXSAVE/XSAVE/AVX CPUID bits stay masked until W5's own
  gate passes against real native implementations. That gate requires
  architecture assertions, interpreter/JIT parity, precise state and fault
  behavior, the hash-bound corpus, and application compatibility. Native
  Windows supplies exact comparison evidence where it exposes the family; a
  missing Prism feature does not veto a stronger proven SharpWine capability.
- The Wine bridge boundary version and `xtajit/unixlib.c` mapping must be
  extended in the same change that grows the context: XSTATE_CONTEXT →
  XSAVE_AREA mapping for the AVX component, keeping the documented
  structures only (Microsoft `XSTATE_CONTEXT`, `XSAVE_FORMAT`,
  `XSAVE_AREA_HEADER`; Intel SDM Vol. 1 ch. 13 for component layout).
- Two upstream blink behaviors are now on record as silently wrong and must
  be overridden, not enabled: XRSTOR dispatched as LFENCE and XSAVEOPT as
  MFENCE (`blink/machine.c` Op1ae), plus the empty `OpXsave`
  (`blink/machine.c:1307`).
- The v3 append reserves exactly one `uint64_t` (`reserved1`) so the next
  state family does not force another size change for a single field; any
  further growth repeats this ADR process.
