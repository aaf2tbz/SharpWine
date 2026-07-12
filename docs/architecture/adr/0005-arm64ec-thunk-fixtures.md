# ADR 0005: ARM64EC checker and thunk fixture evidence

Date: 2026-07-10

## Status

Accepted — linked-image prerequisite and checker/thunk engine conformance satisfied.

## Decision

GEM must not treat a raw ARM64EC COFF object, its `.hybmp$x` section, linker-generated
`.hexpthk`/`.a64xrm` sections, or synthetic CHPE metadata as a linked ARM64X fixture. They do
not prove the native and ARM64EC load configurations, `__chpe_metadata`, x64 target
classification, or executable transition required by Milestone 4.

LLVM/lld 22.1.8 is available for structural research. Its ARM64EC COFF output may remain a
build-tree-only, non-binding artifact when explicitly enabled. The generator rejects a compiler
whose reported version does not match the repository's LLVM revision lock. This does not advance
this ADR or the Milestone 4 exit gate. The optional generator is disabled by default; it must not manufacture
CHPE/load-config data or claim that COFF relocation semantics are linked-image semantics.

The metadata target-map and descriptor-resolution APIs are deliberately limited implementation
groundwork. `gem_arm64ec_target_resolve` classifies only checked CHPE/code-map records, follows
redirections transactionally, and retains executable-section semantics by owning an immutable
parser clone. It translates metadata at a caller-supplied loaded base but does not load or relocate
bytes; execution at a nonpreferred base is permitted only from an already materialized, checked
loader view. CFG authorization is a separate fail-closed policy call; it does not influence ISA
dispatch. When attached to the Dynarmic runtime, the map is checked both before each step and in
the code-fetch callback. ARM64 and ARM64EC ranges may execute; an x64 range returns exactly at the
resolved boundary without fetching x64 bytes or invoking Blink. The unchecked legacy transition
sentinel is disabled in this mode.

`gem_arm64ec_descriptor_resolve` performs one checked four-byte GEM read, including a cross-page
read. Microsoft documents the descriptor at `function_va - 4`: clear its low two tag bits and add
the remaining relative value to `function_va`. Native run `29159938430` reproduced that rule for
the linked fixture: for example `0x1800029b0 + (0x00000f81 & ~3) == 0x180003930`, the mapped
`$ientry_thunk$cdecl$i8$i8`; floating, aggregate, and variadic records resolved identically.
Resolution and optional CFG authorization commit output only after all checked arithmetic,
metadata, executable-range, and policy checks pass. These APIs must be validated against an
authentic linked image before any ARM64EC checker, entry-thunk,
exit-thunk, descriptor, CFG, or transition behavior is accepted. Instruction bytes and raw COFF
sections are never ISA evidence.

## Evidence for the stop

With Homebrew LLVM/lld 22.1.8, the supplied ARM64EC object is
`IMAGE_FILE_MACHINE_ARM64EC (0xA641)` and has `.hybmp$x`, but no `__chpe_metadata` or
`_load_config_used`. Direct `/machine:ARM64EC` and `/machine:ARM64X` links require unresolved
symbol forcing for the fixture's `ext_integer` target. The resulting images respectively identify
as AMD64 and ARM64, both have a zero load-config directory, and neither retains `.hybmp$x`.
They therefore cannot prove a metadata-classified local x64 destination or a real transition.

This STOP is reproducible with the installed toolchain: configure with
`-DCMAKE_C_COMPILER=/opt/homebrew/Cellar/llvm/22.1.8/bin/clang` and
`-DMSWR_GENERATE_ARM64EC_THUNK_FIXTURES=ON`, build
`arm64ec_llvm_thunk_fixtures`, then link its object with
`/opt/homebrew/Cellar/lld/22.1.8/bin/lld-link /dll /noentry /force:unresolved`
and either `/machine:ARM64EC` or `/machine:ARM64X`. Inspect each output with
`/opt/homebrew/Cellar/llvm/22.1.8/bin/llvm-readobj --file-headers --coff-load-config`.
The forced-unresolved links respectively report AMD64 and ARM64 machines with zero
load-config RVA and size; they are negative evidence only and must not be retained as fixtures.

## Linked-image prerequisite result

The prerequisite is satisfied. The reviewed producer lock was established by run
`29143495718`; issue #10's completion run `29146642211` then built two clean Microsoft-linked
ARM64X images outside the checkout, inspected their load configuration and CHPE metadata with the
repository parser, compared normalized evidence, and executed both native ARM64EC validation
hosts on `windows-11-arm`. The DLL and all Microsoft-generated OBJ, LIB, EXE, PDB, MAP, and
inspection outputs remained runner-temporary and were neither committed nor uploaded.

That evidence corrected the former fixture blocker. Issue #11 completion run `29168212337` then
selected checker, entry-thunk, and exit-thunk paths from checked linked metadata, loaded and
relocated them in GEM, and executed them through pinned Dynarmic across two clean builds. The
four-byte descriptor arithmetic, checker contract, relocation, import binding, and alias behavior
were consumed from stage-specific native evidence. Instruction bytes remain invalid as ISA
classification or as a substitute for linked evidence.

## Consequences

The source-only linked fixture pipeline is accepted as the authentic producer for subsequent
same-job conformance. Run `29159938430` also captured the linked function bodies, generated entry
and exit thunk symbols, checker call sites, and descriptor words used by the checked resolver.
Synthetic metadata remains supplemental malformed/boundary coverage only.
The repository continues to contain only Apache-2.0 source and build-tree research outputs; it
contains no copied Windows binary fixture. For Issue #14 only, freshly produced DLLs and sanitized
evidence may cross from the native Windows ARM64 producer job to the native macOS ARM64 consumer
job as a one-day, run-scoped Actions artifact under ADR 0008's SHA-pinned, commit-bound,
inner-manifest and allowlist rules. That ephemeral handoff is neither a committed/released fixture
nor retroactive evidence for Issue #11; all PDB/OBJ/LIB/MAP/EXE and system files remain forbidden.
Dynarmic conformance remains governed by ADR 0004,
Blink was not introduced for the issue #11 boundary, and Milestone 4 is complete based on the
authentic generated execution evidence in run `29168212337`.
