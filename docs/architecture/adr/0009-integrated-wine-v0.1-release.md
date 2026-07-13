# ADR 0009: Publish v0.1 only as an integrated native Wine release

- Status: Accepted
- Date: 2026-07-12
- Issue: [#15](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/issues/15)
- Supersedes: the standalone-only v0.1 boundary in `ROADMAP.md`

## Context

Milestones 0–5 established a standalone deterministic ARM64EC → Blink x64 → ARM64EC substrate. The original roadmap placed Wine startup after v0.1. That boundary would allow a release carrying only a library or a vanilla Wine installation next to an unused engine. It would not prove that users receive a working Wine runtime.

The existing local Wine 11.12 worktree is research evidence, not release input. It is dirty, contains probe-only changes and an older direct Blink/JIT path, and is not reproducible from this repository. In particular, that path gives the engine host identity mappings and execution authority that conflict with accepted GEM ownership, checked memory, interpreter, x18, and transition contracts. None of those local changes may be copied into a release patch queue without independent review and conformance.

## Decision

v0.1.0 will be published only as an actual integrated, self-contained Wine installation for native Apple silicon. The protected-main release workflow must build pinned Wine 11.12 with an ordered LGPL-2.1-or-later patch series from this repository, build the pinned GEM/Dynarmic/Blink implementation, link it into Wine's selected execution path, and exercise that path before packaging. Issue #15 tracks the release as an epic; PR #20 establishes the bridge and inert release contracts, and Issues #21–#25 require separate accepted PRs for the clean Wine build, ntdll integration, native ARM64 execution, authentic hybrid execution, and final relocatable release.

The release gate requires all of the following:

1. Wine is built from the revision in `components.lock.json`; every modification is an ordered patch with source, license, hash, and purpose recorded.
2. Configuration preserves `--enable-archs=i386,x86_64,aarch64,arm64ec`.
3. GEM remains the sole owner of canonical CPU state, guest memory, faults, x18/TEB, budgets, and transition frames. Wine and engine adapters may hold only synchronized transient views. Wine's native ARM64 Unix-side runtime links directly to the versioned `libmetalsharp-gem-wine.0.dylib` ABI described in [`wine-gem-bridge.md`](../wine-gem-bridge.md); delayed `dlopen`, static absorption into Wine, and adjacent-but-unused bridge packaging do not qualify.
4. `wineboot --init`, ARM64 `cmd.exe /c exit`, and accepted ARM64EC/x64 transition probes run with fresh prefixes under bounded process-group and log limits.
5. Every packaged Mach-O and every observed process is native ARM64. Rosetta, translated dependencies, native guest-PC invocation, process-global signal stepping, and guessed `ucontext_t` mutation are prohibited.
6. Packaging is deterministic and allowlisted. The primary asset is `metalsharp-wine-v0.1.0-macos-arm64.tar.zst`; checksums, SPDX SBOM, provenance, known limitations, and an evidence index are separate release assets and are also represented inside the archive where appropriate.
7. Publication runs only for the protected `main` commit produced by the final #25 release PR. Pull requests may build and validate the candidate but receive no `contents: write` permission and cannot create a release.
8. The publication job receives `contents: write` only after all build, integration-test, package-validation, and evidence gates succeed. The immutable `v0.1.0` tag and release must resolve to that exact tested commit.
9. The final merge replaces README's development-status notice with an accurate v0.1.0 status and links to the release, known limitations, and evidence. It names only support demonstrated by release CI and continues to identify unaccepted acceleration, graphics, i386, and broader application coverage as out of scope.

A runtime-only archive, a vanilla Wine build with adjacent unused libraries, a package made from a local worktree, or an archive lacking integration execution evidence fails closed.

## Release workflow shape

PR #20 introduces the main-only release workflow in an intentionally inert state: without the reviewed readiness record it performs no build or publication. The final #25 release PR may add that record only after the intervening issue gates pass. The activated workflow repeats the release-critical build and tests rather than trusting an unrelated workflow run, creates the archive in runner-temporary storage, validates its manifest and architecture, then publishes with the GitHub CLI using the job token. An existing tag or release is never replaced; any pre-existing or mismatched publication fails.

Pull-request CI validates scripts, manifests, patch application, clean Wine builds, runtime tests, and archive reproducibility without publishing. Release assets never pass through an untrusted pull-request artifact.

## Consequences

- Wine integration moves into Milestone 6 and is part of v0.1 rather than a post-v0.1 plan.
- Issue #15 is a multi-PR epic, but the first official archive has an honest product meaning.
- The local experimental Wine trees remain excluded from source and provenance.
- DXMT, Winemetal, accelerated ARM64EC execution, and i386 execution remain post-v0.1 unless separately accepted.
- ADR 0009 is accepted by the completed #21–#25 implementation chain. The protected-main workflow remains the final enforcement point: it publishes only after rebuilding twice, comparing byte-identical archives, redownloading every draft asset, and rerunning the packaged native/hybrid smoke test. A failure leaves the release unpublished.
