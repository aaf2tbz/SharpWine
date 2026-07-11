# ADR 0007: 4 KiB guest-page isolation on 16 KiB hosts

- Status: Accepted
- Issue: [#13](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/issues/13)

## Context

Windows guests require independent 4 KiB page semantics while native Apple silicon macOS uses
16 KiB host pages. Four logical guest pages can therefore share one host page. Host VM protection
cannot express those four independent policies, and temporarily widening a host page would expose
adjacent guest pages.

GEM already owns a sparse checked 4 KiB page table and validates complete accesses before copying
bytes. Its page list, backing reference counts, guard consumption, write-copy detachment, and
protection changes were single-threaded before this decision. Issue #13 requires those operations to remain
transactional and deterministic under concurrent access.

## Decision

Use a per-`gem_memory` cross-platform mutex to make the checked software path linearizable. Every
public operation that observes or mutates page-table state will hold the same lock for its complete
validation and commit. Internal locked helpers will preserve atomic compound operations such as
identity mapping and rollback.

Identity mappings remain backing-storage optimizations only. All guest reads, writes, fetches, and
permission queries continue through GEM. GEM will not use `mprotect`, temporary host-page permission
widening, signals, guessed `ucontext_t` state, process-global stepping, or Mach exceptions for
correctness. Object destruction requires external lifetime coordination so no operation starts or
remains active after destruction begins.

## Implementation plan

1. Add and initialize a portable per-memory lock; split public wrappers from internal locked helpers.
2. Make reserve, commit, decommit, release, protect, alias, identity map, read, write, fetch, peek,
   execute query, guard consumption, and write-copy detachment linearizable.
3. Add a test using one aligned 16 KiB identity backing as four independently protected 4 KiB guest
   pages.
4. Cover read, write, execute, guard, no-access, reserve/commit/decommit, aliases, write-copy,
   misaligned and cross-page operations, and unchanged outputs on failure.
5. Stress concurrent guard faults, write-copy detachment, independent subpage access, and rejected
   cross-page writes without partial effects.
6. Add a native ARM64 macOS zero-Rosetta CI lane that requires a 16 KiB host page and repeatedly runs
   the isolation test.
7. Record passing evidence, accept this ADR, update the roadmap, and retain direct mappings or Mach
   exceptions only as separately proven optional accelerations.

## Validation checklist

- [x] Four 4 KiB logical pages share one verified 16 KiB host backing on native ARM64 macOS.
- [x] Read, write, execute, guard, and no-access policies remain independent per logical page.
- [x] Reserve, commit, decommit, alias, and write-copy behavior remains independent per logical page.
- [x] Misaligned and cross-page failures leave guest memory and caller outputs unchanged.
- [x] Concurrent guard access has exactly one guard consumer and deterministic checked results.
- [x] Concurrent write-copy detachment preserves the source and commits every accepted write.
- [x] Repeated concurrent denied accesses produce no partial mutation or neighboring-page exposure.
- [x] No host permission widening, signal single-stepping, guessed debug state, or private VM control
      is used.
- [x] Linux GCC/Clang, macOS Apple Clang, native Windows ARM64, formatting, and repository policy pass.
- [x] The dedicated native ARM64 macOS 16 KiB-page stress lane passes repeatedly with zero Rosetta.

## Acceptance evidence

Native CI run [29171803452](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/actions/runs/29171803452)
passed every job: repository policy, formatting, Linux GCC and Clang, macOS Apple Clang, native
Windows ARM64/ARM64X toolchain, x86-TSO conformance, ARM64EC engine conformance, and the dedicated
native ARM64 macOS 16 KiB page-isolation lane. That lane verified `uname -m = arm64`,
`sysctl -n hw.pagesize = 16384`, and `sysctl -in sysctl.proc_translated = 0`, then ran
`ctest --output-on-failure --repeat until-fail:100 -L page-isolation` (100 repeated page-isolation
passes) followed by `tools/ci/audit-zero-rosetta.sh` (zero-Rosetta audit passed).
