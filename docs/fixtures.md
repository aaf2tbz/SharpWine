# Redistributable Fixture Policy

Status: accepted for Milestone 0.

Fixtures must make ABI behavior reviewable without putting proprietary or generated executable payloads in the repository.

## Allowed fixtures

- Source files, generator scripts, and expected metadata under an Apache-2.0-compatible license, unless an explicitly isolated license is documented.
- Test-time generated synthetic objects built from committed source by documented public toolchain commands.
- Sanitized JSON/YAML/text metadata containing only non-executable facts needed by tests, with provenance and reproduction commands.
- Wine-derived patches only under `third_party/patches/wine`, under LGPL-2.1-or-later.

## Disallowed fixtures

- Proprietary Windows, SDK, toolchain, application, or private diagnostic binaries.
- Checked-in generated `.exe`, `.dll`, `.sys`, `.pdb`, `.dmp`, object, library, archive, or debug-symbol artifacts.
- Wine prefixes, local build trees, crash dumps, minidumps, opaque compressed blobs, or base64 payloads that bypass repository policy.
- Private paths, user or machine identifiers, secrets, proprietary instruction streams, private symbols, or copied code bytes from non-redistributable inputs.

## Sanitized metadata

Sanitized metadata may be contributed only when it:

1. contains non-executable facts required by deterministic tests;
2. excludes proprietary bytes, instruction streams, strings beyond necessary public names, private symbols, private paths, and secrets;
3. records the source provenance, tool command, tool version, and sanitization steps;
4. is reproducible from a contributor-held legal input; and
5. explains why no committed binary is required.

## Required PR evidence

Every fixture-related PR must include:

- fixture provenance and license/SPDX identifier;
- exact generation or extraction command;
- source inputs and toolchain version;
- expected hash of generated build-directory output when generation is part of the test;
- the ABI/runtime rule validated by the fixture; and
- confirmation that no generated or proprietary binary is committed.

When in doubt, generate artifacts in the build directory during tests and commit only source plus expected metadata.

## Ephemeral Issue #14 CI handoff

Issue #14 may transport freshly generated Microsoft-linked ARM64X DLLs and sanitized evidence from
a native Windows ARM64 producer job to a native macOS ARM64 consumer job in the same GitHub Actions
run. This narrow exception requires SHA-pinned upload/download actions, one-day retention, an exact
allowlist rooted under `runner.temp`, a commit-bound inner manifest with sizes and SHA-256 hashes,
service-digest verification, and strict consumer validation before any DLL is parsed. PDB, OBJ,
LIB, MAP, EXE, system files, private paths, release assets, and committed generated files remain
forbidden. The handoff is ephemeral integrity-checked CI transport, not redistribution or a fixture
accepted independently of its source producer.

## ARM64X compatibility input

`tests/data/wine-11.12-ntdll-arm64x.txt` contains only sanitized structural expectations. The corresponding Wine DLL is never committed. Where a locally built, legally held Wine input is available, run `pe_arm64x_probe /path/to/ntdll.dll`; the probe reads at most 16 MiB, parses metadata only, and never launches Wine or executes image bytes.
