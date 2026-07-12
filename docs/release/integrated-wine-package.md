# Integrated Wine v0.1 release package contract

Issue #15 publishes one primary runtime archive:

```text
metalsharp-wine-v0.1.0-macos-arm64.tar.zst
└── metalsharp-wine-v0.1.0-macos-arm64/
    ├── bin/
    ├── lib/
    ├── share/
    ├── LICENSES/
    └── share/metalsharp/
        ├── release-manifest.json
        ├── wine-integration-evidence.json
        ├── sbom.spdx.json
        ├── evidence-index.json
        └── KNOWN-LIMITATIONS.md
```

The exact install inventory will be frozen only after the clean Wine integration build exists. Until then, this document specifies constraints rather than an allowlist that guesses Wine output.

## Required bindings

`release-manifest.json` is canonical JSON and binds:

- schema and release version;
- Git repository and exact protected-main commit;
- Wine, Dynarmic, and Blink repositories, revisions, archive hashes, and licenses;
- ordered Wine patch names and SHA-256 hashes;
- GEM/Blink embedding patch hashes;
- host, PE architecture set, compilers, SDK, deployment target, and configure options;
- every packaged regular file and symlink, including type, mode, size, and SHA-256 where applicable;
- hashes of the SBOM, integration evidence, evidence index, and known-limitations document;
- release archive SHA-256 and deterministic packaging parameters in the external publication manifest.

No absolute path, home-directory name, runner-temporary path, token, Wine prefix, crash report, generated debug file, source checkout, or unlisted file may appear in the package.

`wine-integration-evidence.json` binds bounded fresh-prefix results for `wineboot --init`, ARM64 `cmd.exe /c exit`, and accepted ARM64EC/x64 hybrid execution. It also records canonical x18/TEB checks, engine provenance, instruction/transition budgets, process architecture observations, timeout/log limits, and cleanup results.

## Architecture and execution audit

Every Mach-O file is inspected recursively. Each accepted slice is ARM64; x86_64-only and universal binaries containing x86_64 are rejected. Scripts and data are allowlisted separately. The runtime test records all launched process identities and architectures and fails if `/usr/libexec/rosetta/`, `arch -x86_64`, an x86_64 Mach-O loader, or another translated dependency is observed.

Windows PE payloads may contain i386, x86_64, AArch64, and ARM64EC machine code because those are guest architectures. They are not host Mach-O exceptions and must be identified as PE artifacts in the manifest.

## Determinism

The package creator uses a fixed lexical path order, numeric owner/group zero, empty owner/group names, normalized modes, a fixed timestamp derived from `SOURCE_DATE_EPOCH`, and deterministic Zstandard options. Symlinks must be relative, normalized, non-traversing, and resolve within the package root. Hard links, devices, sockets, FIFOs, extended attributes, resource forks, and Finder metadata are rejected.

Two clean builds from the same source and declared toolchain must produce identical install manifests. Archive byte identity is required when the pinned macOS toolchain produces reproducible Wine outputs; otherwise every differing field must be identified and eliminated before v0.1 publication. A nondeterminism waiver is not a release path.

## Workflow activation

`.github/workflows/release.yml` is intentionally inert on `main` until the final Issue #15 change adds `release/v0.1.0-ready.json`. A pull request must not add that record until `tools/release/build-integrated-wine.sh` exists and all integration, packaging, reproducibility, evidence, and policy checks pass. The readiness record will bind its own schema, version, expected protected-main parent, release script hashes, and accepted evidence criteria; release CI must validate it before using it.

A premature manual dispatch fails. A normal `main` push without the record succeeds without building or publishing. Once the reviewed record is present, the same workflow run builds the candidate with read-only repository permission, hands it to the publication job through a one-day same-run artifact with an Actions service digest, revalidates it, reconfirms the exact current `main` head, and only then uses a separate `contents: write` job to create the release.

## Publication assets

The GitHub `v0.1.0` release receives:

- `metalsharp-wine-v0.1.0-macos-arm64.tar.zst`;
- `metalsharp-wine-v0.1.0-macos-arm64.tar.zst.sha256`;
- `release-manifest.json`;
- `wine-integration-evidence.json`;
- `sbom.spdx.json`;
- `evidence-index.json`;
- `KNOWN-LIMITATIONS.md`.

Release CI compares each uploaded asset's local hash and size to the publication manifest after upload. An existing tag or release is accepted only when it points to the exact tested protected-main commit and all asset hashes match; otherwise publication fails without replacement.
