<div align="center">

# SharpWine

**Zero-Rosetta Wine for Apple Silicon**

Updated July 14, 2026

[![CI](https://img.shields.io/github/actions/workflow/status/aaf2tbz/SharpWine/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/aaf2tbz/SharpWine/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/aaf2tbz/SharpWine?style=for-the-badge)](https://github.com/aaf2tbz/SharpWine/releases)
[![License](https://img.shields.io/github/license/aaf2tbz/SharpWine?style=for-the-badge)](LICENSE)

</div>

---

SharpWine is a native Apple-silicon Wine runtime with four Windows guest architectures and an ARM64-only macOS host process graph. It packages Wine 11.12, GEM translation engines, Blink JIT execution, and a paired DXMT graphics bridge without requiring Rosetta.

## Quick Start

Download the v0.1.2 archive and checksum from [Releases](https://github.com/aaf2tbz/SharpWine/releases/tag/v0.1.2), then run:

```bash
shasum -a 256 -c sharpwine-v0.1.2-macos-arm64.tar.zst.sha256
zstd -d --stdout sharpwine-v0.1.2-macos-arm64.tar.zst | tar -xf -

export WINEPREFIX="$HOME/.sharpwine"
./sharpwine-v0.1.2-macos-arm64/bin/wineboot --init
./sharpwine-v0.1.2-macos-arm64/bin/wine cmd.exe /c exit
```

## Execution Routes

| Windows guest | Runtime route | macOS host |
|---|---|---|
| AArch64 | Native Wine builtins | ARM64 |
| ARM64EC / x64 | GEM hybrid boundary | ARM64 |
| x86_64 | GEM_x86_64 / Blink | ARM64 |
| i386 / WoW64 | GEM_i386 / Blink | ARM64 |

The archive contains PE files for i386, x86_64, AArch64, and ARM64EC. Those are Windows guest formats; every packaged host Mach-O must be ARM64-only, and release validation rejects translated processes.

## Release Guarantees

- The v0.1.2 release is a hash-bound upgrade of the immutable v0.1.1 archive.
- The i386/WoW64 route is proven with a source-built bounded PE32 acceptance fixture.
- DXMT v0.80 is built twice from pinned source as paired i386 PE modules and an ARM64 Unix bridge, then compared byte-for-byte.
- The v0.1.1 x86_64 patched files and acceptance evidence are carried forward; v0.1.2 CI focuses the new i386 overlay alongside the retained AArch64 and ARM64EC/x64 lifecycle gates.
- Release CI audits deployment targets, dynamic-library closure, embedded build paths, checksums, provenance, and native ARM64 process execution.

Corpus-wide application and game compatibility testing is intentionally deferred until SharpWine is integrated into [MetalSharp](https://github.com/aaf2tbz/metalsharp). See each release's `KNOWN-LIMITATIONS.md` for the exact claimed scope.

## Requirements

- Apple Silicon Mac
- macOS 15 or later
- `zstd` for archive extraction
- Rosetta is neither required nor supported as a host execution path

## Developer Setup

```bash
git clone https://github.com/aaf2tbz/SharpWine.git
cd SharpWine
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Release construction additionally uses the pinned dependencies in [`components.lock.json`](components.lock.json), Xcode 27, LLVM-MinGW, LLVM 15, Meson, Ninja, and Zstandard. The release workflow starts from the published v0.1.1 tarball and applies only reviewed, digest-bound v0.1.2 payload changes.

## Documentation

- [Architecture decisions](docs/architecture/adr/)
- [Integrated release package](docs/release/integrated-wine-package.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Community

- [Issues](https://github.com/aaf2tbz/SharpWine/issues)
- [Discussions](https://github.com/aaf2tbz/SharpWine/discussions)
- [Releases](https://github.com/aaf2tbz/SharpWine/releases)

## License

Original SharpWine code is licensed under Apache-2.0. Wine-derived changes are LGPL-2.1-or-later, and bundled third-party components retain their respective licenses. SharpWine is independent of Microsoft, Apple, WineHQ, and the DXMT project.
