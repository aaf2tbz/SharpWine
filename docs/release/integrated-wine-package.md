# Integrated Wine v0.1 release package contract

Issue #15 is the release epic; its final #25 PR publishes one primary runtime archive:

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

The runtime `lib/` inventory must include `libmetalsharp-gem-wine.0.1.0.dylib` and relative `.0`/unversioned symlinks. Wine's selected native ARM64 Unix-side module must carry a direct Mach-O load command for `@rpath/libmetalsharp-gem-wine.0.dylib`; a delayed load or unused adjacent dylib fails validation. Bridge staging uses the `metalsharp-gem-wine` CMake install component so fetched Dynarmic headers, static archives, and CMake metadata cannot leak into the runtime package.

## Required bindings

`release-manifest.json` is canonical JSON and binds:

- schema and release version;
- Git repository and exact protected-main commit;
- Wine, Dynarmic, and Blink repositories, revisions, archive hashes, and licenses;
- ordered Wine patch names and SHA-256 hashes;
- GEM/Blink embedding patch hashes;
- Wine/GEM bridge ABI version, dylib install name, current/compatibility versions, exported-symbol allowlist, and direct Wine loader binding;
- host, PE architecture set, compilers, SDK, deployment target, and configure options;
- every packaged regular file and symlink, including type, mode, size, and SHA-256 where applicable;
- hashes of the SBOM, integration evidence, evidence index, and known-limitations document;
- release archive SHA-256 and deterministic packaging parameters in the external publication manifest.

No absolute path, home-directory name, runner-temporary path, token, Wine prefix, crash report, generated debug file, source checkout, or unlisted file may appear in the package. The unpacked runtime must operate from an arbitrary clean location while the repository and build trees are unavailable. Every redistributable non-system runtime dependency must be contained in the archive with a relocatable binding; Homebrew paths, adjacent developer checkouts, and temporary install trees are forbidden runtime dependencies.

`wine-integration-evidence.json` binds bounded fresh-prefix results for `wineboot --init`, ARM64 `cmd.exe /c exit`, and accepted ARM64EC/x64 hybrid execution. It also records canonical x18/TEB checks, engine provenance, instruction/transition budgets, process architecture observations, timeout/log limits, and cleanup results.

## Architecture and execution audit

Every Mach-O file is inspected recursively. Each accepted slice is ARM64; x86_64-only and universal binaries containing x86_64 are rejected. Scripts and data are allowlisted separately. The runtime test records all launched process identities and architectures and fails if `/usr/libexec/rosetta/`, `arch -x86_64`, an x86_64 Mach-O loader, or another translated dependency is observed.

Windows PE payloads may contain i386, x86_64, AArch64, and ARM64EC machine code because those are guest architectures. They are not host Mach-O exceptions and must be identified as PE artifacts in the manifest.

## Determinism

The package creator uses a fixed lexical path order, numeric owner/group zero, empty owner/group names, normalized modes, a fixed timestamp derived from `SOURCE_DATE_EPOCH`, and deterministic Zstandard options. Symlinks must be relative, normalized, non-traversing, and resolve within the package root. Hard links, devices, sockets, FIFOs, extended attributes, resource forks, and Finder metadata are rejected.

Two clean builds from the same source and declared toolchain must produce identical install manifests. Archive byte identity is required when the pinned macOS toolchain produces reproducible Wine outputs; otherwise every differing field must be identified and eliminated before v0.1 publication. A nondeterminism waiver is not a release path.

## Workflow activation

`.github/workflows/release.yml` is intentionally inert on `main` until the final #25 release PR adds `release/v0.1.0-ready.json`. No earlier pull request may add that record; it remains forbidden until `tools/release/build-integrated-wine.sh` exists and all #21–#25 integration, packaging, reproducibility, evidence, and policy gates pass. The readiness record will bind its own schema, version, expected protected-main parent, release script hashes, and accepted evidence criteria; release CI must validate it before using it.

A premature manual dispatch fails. A normal `main` push without the record succeeds without building or publishing. Once the reviewed record is present, the same workflow run builds the candidate with read-only repository permission, hands it to the publication job through a one-day same-run artifact with an Actions service digest, revalidates it, reconfirms the exact current `main` head, and only then uses a separate `contents: write` job to create the release.

The readiness record must also bind the final README status block. Before the record is admitted, README's current architecture-foundation notice is replaced with the accepted v0.1.0 status, supported scope, predictable `v0.1.0` release URL, known-limitations asset URL, and evidence asset URL. Release validation rejects either the old notice or claims beyond the tested support matrix. This README change lands through the same protected final #25 merge; release automation never pushes an unreviewed documentation commit to `main`.

## Publication assets

The GitHub `v0.1.0` release receives:

- `metalsharp-wine-v0.1.0-macos-arm64.tar.zst`;
- `metalsharp-wine-v0.1.0-macos-arm64.tar.zst.sha256`;
- `release-manifest.json`;
- `wine-integration-evidence.json`;
- `sbom.spdx.json`;
- `evidence-index.json`;
- `KNOWN-LIMITATIONS.md`.

Release CI compares each uploaded asset's local hash and size to the publication manifest after upload. Any pre-existing `v0.1.0` tag or release fails publication and is never reused or replaced.
