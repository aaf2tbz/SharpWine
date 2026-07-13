# MetalSharp Wine Runtime for Apple Silicon

[![CI](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/actions/workflows/ci.yml/badge.svg)](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/actions/workflows/ci.yml)

MetalSharp Wine Runtime is a native Apple-silicon Wine distribution for running the supported Windows AArch64 and ARM64EC/x64 paths without Rosetta. It combines Wine 11.12 with a four-architecture PE installation, a self-contained macOS runtime closure, and an ARM64-only host Mach-O process graph.

The current release is [v0.1.0](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/tag/v0.1.0). It proves fresh-prefix Wineboot, native AArch64 builtins, and the repository's authentic ARM64EC/x64 fixture. It does not claim general i386 or x86_64 application compatibility yet; see the [known limitations](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/download/v0.1.0/KNOWN-LIMITATIONS.md).

## What it is

Wine supplies the Windows loader, PE builtins, registry/prefix handling, wineserver, Unix integration, graphics drivers, and the normal Windows-facing API surface. MetalSharp adds the execution and state-management layer needed where Windows guest ABI rules cannot safely be delegated to Darwin.

The release ships i386, x86_64, AArch64, and ARM64EC PE files. Those are guest architectures, not host binaries: every packaged host Mach-O is ARM64-only and the verification suite rejects Rosetta use.

## What GEM is

GEM, the Guest Execution Manager, owns canonical Windows guest state at every execution boundary. In particular, it keeps the Windows TEB relation (`x18 == NtCurrentTeb()`) in explicit per-thread guest context rather than assuming macOS will preserve Darwin ABI register state through faults, signals, or host calls.

GEM also owns guest virtual-memory semantics, page-protection transitions, exception boundaries, ARM64X metadata classification, and ARM64EC state conversion. Wine's native ARM64 Unix-side `ntdll` links directly to the versioned GEM bridge, so startup and supported guest execution follow one deliberate native path.

## Blink integration

Blink is the pinned x86_64 guest interpreter used for the supported ARM64EC/x64 transition path. The release uses Blink's interpreter mode with JIT disabled: correctness, deterministic state transfer, fault handling, and traceability take priority over speculative host-code generation.

ARM64EC transitions are classified from copied, bounds-checked ARM64X/CHPE metadata. GEM converts canonical register, stack, SIMD, flags, and TEB state between the ARM64EC and Blink views; it does not guess target architecture from instruction bytes or rely on Darwin register conventions.

## Install and run

On Apple silicon, download the archive and its checksum from [v0.1.0](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/tag/v0.1.0). You need `zstd`, `tar`, and a writable location for `WINEPREFIX`.

```sh
shasum -a 256 -c metalsharp-wine-v0.1.0-macos-arm64.tar.zst.sha256
zstd -d --stdout metalsharp-wine-v0.1.0-macos-arm64.tar.zst | tar -xf -
export WINEPREFIX="$PWD/metalsharp-prefix"
./metalsharp-wine-v0.1.0-macos-arm64/bin/wineboot --init
./metalsharp-wine-v0.1.0-macos-arm64/bin/wine cmd.exe /c exit
```

Do not use `arch -x86_64`, Rosetta, or an x86_64 Homebrew environment. The packaged runtime includes its declared non-system dependencies; macOS system frameworks remain external by design.

## Included tools and runtime components

The archive contains:

- Wine launchers: `wine`, `wineboot`, `wineserver`, `winecfg`, `regedit`, `regsvr32`, `msiexec`, and the usual Wine utility aliases;
- four-architecture Wine PE trees and native ARM64 Unix-side modules;
- the direct GEM bridge plus native ARM64 and authentic hybrid self-tests;
- packaged Vulkan/MoltenVK, Mesa EGL/OpenGL, SDL2, SDL3, FreeType, X11 client, LLVM, Zstandard, and related runtime dependencies;
- a manifest, SBOM, evidence index, and known-limitations document.

For development, use CMake 3.24+, a C11 compiler, Python 3.11+, Git, CTest, and `clang-format`. ARM64EC engine development additionally uses the locked LLVM-MinGW, Dynarmic, and Blink inputs recorded in [`components.lock.json`](components.lock.json).

## Verification and release CI

Mainline release verification downloads the already-published archive, validates its checksum, manifest, and ARM64-only host closure, then runs isolated fresh-prefix Wineboot/native/hybrid smoke tests. It does not build Wine in GitHub Actions.

Local repository checks remain available through:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMSWR_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
tools/ci/run-all.sh
```

## Documentation

- [GEM ABI contract](docs/architecture/gem-abi.md)
- [Guest memory model](docs/architecture/guest-memory.md)
- [Deterministic virtual-CPU plan](docs/architecture/deterministic-vcpu-plan.md)
- [Release package contract](docs/release/integrated-wine-package.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

Original MetalSharp code is Apache-2.0; Wine-derived patches are LGPL-2.1-or-later. MetalSharp Wine Runtime is independent of Microsoft, Apple, and WineHQ.
