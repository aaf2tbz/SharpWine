# MetalSharp Wine — ARM64 / ARM64EC / AArch64 / i386 Runtime

[![CI](https://github.com/aaf2tbz/metalsharp-wine-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/aaf2tbz/metalsharp-wine-runtime/actions/workflows/ci.yml)

MetalSharp Wine Runtime is a zero-Rosetta Wine research and implementation project for Apple silicon. It preserves Wine’s mature Windows personality, loader, wineserver, and Unix integration while adding a deterministic **Guest Execution Manager (GEM)** for ARM64, ARM64EC, x86_64, and eventually i386 Windows code.

The central rule is simple: **Windows CPU state belongs to the guest runtime, not the Darwin ABI.** Canonical Windows `x18 == NtCurrentTeb()` is held in an explicit per-thread guest context. It is never made dependent on macOS preserving host x18 across page faults, signals, code-page transitions, or framework calls.

> **Project status:** v0.1.0 integrated native Apple-silicon Wine release. The packaged Wine 11.12 environment starts a fresh prefix through GEM, executes native ARM64 builtins, and completes the accepted authentic ARM64EC/x64 fixture with an ARM64-only host process closure. [Download v0.1.0](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/tag/v0.1.0), read the [known limitations](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/download/v0.1.0/KNOWN-LIMITATIONS.md), or inspect the [evidence index](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/download/v0.1.0/evidence-index.json).

## Why this project exists

Windows ARM64EC combines native AArch64 instructions with x86_64 code in ARM64X images. It requires:

- a canonical TEB in x18 / x64 `GS.base`;
- mandatory architecture-aware indirect-call checkers;
- signature-specific entry and exit thunks;
- exact ARM64EC/x64 register, stack, SIMD, and flag conversion;
- an x64 emulator for hybrid calls;
- Windows virtual-address behavior that differs from macOS’s 16 KiB pages and lower-4-GB Mach-O reservation.

Direct execution of arbitrary PE pages on Darwin makes correctness depend on host VM and ABI behavior that Wine does not control. GEM removes that dependency by making guest registers, memory protections, exceptions, and architecture transitions explicit runtime state.

## Architecture

```text
macOS ARM64 process
│
├── Native ARM64 Mach-O Wine host and Unix modules
│   ├── wineserver and NT objects
│   ├── PE/ARM64X loader and metadata parser
│   ├── exceptions, APCs, threads, and I/O
│   └── graphics/audio/media bridges
│
└── Guest Execution Manager (GEM)
    ├── canonical per-thread guest CPU context
    ├── Windows virtual-memory and protection model
    ├── ARM64/ARM64EC correctness engine
    ├── pinned Blink x86_64 interpreter (JIT disabled for v0.1 correctness)
    │    └─ decoder-owned retired-handler trace + last decode attempt
    ├── future i386 translated address space
    └── evidence-driven ARM64EC transition broker
```

### Canonical state

`gem_thread_context` is the sole authoritative register state. Emulator registers, Blink state, host signal contexts, and optimized code-cache registers are synchronized views. At every guest boundary:

```c
context.x[18] == context.teb
```

The context also carries ARM64EC/x64 mapped GPRs, PC, SP, NZCV/RFLAGS, v0-v15/XMM0-XMM15, FPCR/FPSR/MXCSR, x87 state, current ISA, and an explicit stop reason.

### Memory model

GEM owns Windows virtual addresses and logical guest protections:

- safe high addresses may use validated identity mappings as an optimization while retaining checks;
- exceptional low addresses, including `0x7ffe0000`, use logical aliases or engine callbacks;
- guest-page protections remain independent of the 16 KiB host page size;
- ARM64X code ranges come from a bounds-checked, copied-ownership CHPE v1/v2 metadata parser;
- engines access memory through checked GEM translation APIs unless an identity fast path is proven safe.

### ARM64EC transitions

The transition broker implements Microsoft’s published ABI rather than inferring behavior:

1. classify targets from ARM64X/CHPE metadata;
2. run mandatory `__os_arm64x_check_icall` semantics;
3. execute compiler-generated signature-specific exit or entry thunks;
4. convert canonical state between ARM64EC and Blink;
5. implement dispatch and return helpers only from documentation and captured fixtures.

No static x18-to-x28 substitution and no guessed dispatcher ABI are accepted.

## Repository layout

```text
.
├── .github/
│   ├── workflows/          Pinned-action CI with least-privilege permissions
│   └── ISSUE_TEMPLATE/     Structured, privacy-safe reports
├── docs/
│   ├── architecture/
│   │   ├── adr/          Accepted ownership architecture records
│   │   ├── deterministic-vcpu-plan.md
│   │   └── gem-abi.md
│   └── fixtures.md       Redistributable fixture policy
├── include/metalsharp/gem/ Public GEM interfaces
├── src/gem/                Runtime implementation
├── tests/                  Deterministic unit/conformance tests
├── third_party/
│   └── patches/wine/       Reviewed Wine patch queue; no vendored build tree
├── tools/ci/               Local equivalents of required CI gates
├── components.lock.json    Pinned upstream revisions and licenses
├── CMakeLists.txt          Portable build and test entry point
├── CONTRIBUTING.md         Evidence, testing, and licensing rules
├── NOTICE.md               Mixed-license notices
└── SECURITY.md             Private vulnerability reporting policy
```

This repository intentionally excludes Wine prefixes, SDKs, toolchain archives, generated binaries, crash dumps, local diagnostics, and proprietary Windows files. Fixture contributions must follow [`docs/fixtures.md`](docs/fixtures.md).

## Tooling

### Required for the current foundation

- CMake 3.24 or newer
- a C11 compiler:
  - Apple Clang on macOS ARM64;
  - Clang or GCC on Linux CI
- Python 3.11 or newer for repository-policy checks
- `clang-format` 18 for deterministic formatting
- Git and CTest

### v0.1 runtime toolchain

- LLVM/Clang and LLD with ARM64EC/ARM64X support
- LLVM MinGW for Wine’s embedded x86_64 ARM64EC slices
- Dynarmic 6.7.0 as the reviewed AArch64 virtual-CPU correctness engine (optional fetched build)
- pinned Blink for x86_64 Windows execution, subject to the x86-TSO contract in
  [`ADR 0006`](docs/architecture/adr/0006-x86-tso-correctness-contract.md)
- Frida Gum Stalker or QBDI only as validated fast-engine candidates
- packaged MoltenVK/Vulkan, Mesa EGL, OpenGL, FreeType, SDL2, and SDL3 runtime closure
- native ARM64 DXMT and Winemetal remain future work

Third-party engines are not accepted until instruction coverage, register fidelity, fault behavior, macOS ARM64 support, deterministic fallback, and distribution licensing have been reviewed. The selected Milestone 3 engine decision is recorded in [`docs/architecture/adr/0004-aarch64-correctness-engine.md`](docs/architecture/adr/0004-aarch64-correctness-engine.md).

## Use the v0.1.0 package

Download the archive and checksum from the immutable [v0.1.0 release](https://github.com/aaf2tbz/MetalSharp-Wine-Runtime-MacOS-Arm64/releases/tag/v0.1.0), verify the checksum, and unpack it anywhere writable:

```sh
shasum -a 256 -c metalsharp-wine-v0.1.0-macos-arm64.tar.zst.sha256
zstd -d --stdout metalsharp-wine-v0.1.0-macos-arm64.tar.zst | tar -xf -
export WINEPREFIX="$PWD/metalsharp-prefix"
./metalsharp-wine-v0.1.0-macos-arm64/bin/wineboot --init
./metalsharp-wine-v0.1.0-macos-arm64/bin/wine cmd.exe /c exit
```

The archive contains i386, x86_64, AArch64, and ARM64EC guest files because Wine is built with all four PE architectures. v0.1.0 claims native AArch64 builtins and the bound authentic ARM64EC/x64 fixture only; it does not claim general i386 or x86_64 application compatibility. The host itself never uses Rosetta.

## Build and test

```sh
git clone https://github.com/aaf2tbz/metalsharp-wine-runtime.git
cd metalsharp-wine-runtime
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DMSWR_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Run every local required gate:

```sh
tools/ci/run-all.sh
```

Run the optional ARM64EC engine conformance gate (requires CMake to find Boost and fetch the pinned Dynarmic revision):

```sh
cmake -S . -B build/engine \
  -DCMAKE_BUILD_TYPE=Debug \
  -DMSWR_WARNINGS_AS_ERRORS=ON \
  -DMSWR_ENABLE_ARM64EC_ENGINE=ON \
  -DMSWR_ENGINE_CONFORMANCE=ON \
  -DMSWR_ZERO_ROSETTA_AUDIT=ON
cmake --build build/engine --parallel
ctest --test-dir build/engine --output-on-failure -L gem.engine
```

Use another build directory if desired:

```sh
MSWR_BUILD_DIR=/tmp/mswr-build tools/ci/run-all.sh
```

## Quality gates

Pull requests must pass:

- repository hygiene and accidental-secret checks;
- rejection of tracked PE, ELF, or Mach-O binaries;
- rejection of build trees, prefixes, oversized files, and private local paths;
- UTF-8, final-newline, and trailing-whitespace checks;
- `clang-format` validation;
- warnings-as-errors builds with Apple Clang, LLVM Clang, and GCC;
- deterministic CTest suites;
- reviewed and resolved pull-request conversations.

GitHub Actions are pinned to commit SHAs and run with read-only repository permissions. Branch protection requires current CI results before merge.

## Testing philosophy

Tests progress from pure state to complete runtime behavior:

1. canonical context invariants and pure conversion routines;
2. guest memory, protection, low-alias, and page-size behavior;
3. isolated AArch64 and x86_64 execution engines;
4. generated ARM64EC checker/thunk fixtures;
5. ARM64EC → x86_64 → ARM64EC state round trips;
6. faults, exceptions, unwind, APC, suspend, and thread tests;
7. bounded Wine startup with fresh prefixes;
8. graphics and representative application tests.

Runtime tests must enforce a timeout, retain at most 2 MiB of logs, terminate the entire process group, stop wineserver, and audit for zero Rosetta usage.

## Development workflow

1. Open an issue defining the failure and expected architectural state.
2. Cite a published ABI rule or add a reproducible captured fixture.
3. Implement the smallest coherent change.
4. Add deterministic tests before enabling optimized execution.
5. Run `tools/ci/run-all.sh`.
6. Submit a pull request using the repository template.
7. Merge only after required CI and review gates pass.

Wine-derived changes are maintained as a reviewable patch series until a dedicated upstream/fork workflow is justified. `components.lock.json` identifies the exact upstream revision each patch queue targets.

## Roadmap

The gated v0.1 execution roadmap is tracked in [`ROADMAP.md`](ROADMAP.md).

- **A — Specification:** canonical state, ARM64X fixtures, ABI tests.
- **B — Engine bake-off:** select an established AArch64 correctness engine.
- **C — Standalone GEM:** execute ARM64EC and round-trip through Blink.
- **D — Wine integration:** route PE startup, syscalls, memory, and exceptions through GEM.
- **E — Hybrid completeness:** callbacks, tail calls, unwind, APCs, and nested transitions.
- **F — Performance:** validated code-cache acceleration with per-block fallback.
- **G — Product validation:** ARM64, ARM64EC, x86_64/Blink, then i386; DXMT and Winemetal afterward.

The detailed plan is in [`docs/architecture/deterministic-vcpu-plan.md`](docs/architecture/deterministic-vcpu-plan.md).

## Non-goals

- Reimplementing all of Wine from scratch.
- Using Rosetta or x86_64 Mach-O dependencies.
- Treating Darwin x18 or `ucontext_t` as canonical Windows state.
- Warming pages or masking/retrying faults to hide ABI failures.
- Guessing target ISA from bytes instead of ARM64X metadata.
- Guessing ARM64EC helper register or stack semantics.
- Shipping a fast path without a correctness fallback.

## Documentation and references

- [GEM ABI contract](docs/architecture/gem-abi.md)
- [GEM logical guest memory](docs/architecture/guest-memory.md)
- [Deterministic virtual-CPU plan](docs/architecture/deterministic-vcpu-plan.md)
- [Redistributable fixture policy](docs/fixtures.md)
- [ADR 0001: Engine ownership](docs/architecture/adr/0001-engine-ownership.md)
- [ADR 0002: Memory ownership](docs/architecture/adr/0002-memory-ownership.md)
- [ADR 0003: Transition ownership](docs/architecture/adr/0003-transition-ownership.md)
- [Microsoft ARM64EC ABI conventions](https://learn.microsoft.com/en-us/cpp/build/arm64ec-windows-abi-conventions)
- [Microsoft ARM64EC assembly and thunk documentation](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)
- [Apple JIT guidance for Apple silicon](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)
- [Wine upstream](https://gitlab.winehq.org/wine/wine)
- [LLVM ARM64EC call lowering](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64Arm64ECCallLowering.cpp)

## Licensing

Original MetalSharp Wine Runtime code is licensed under Apache-2.0. Wine-derived patches under `third_party/patches/wine` are LGPL-2.1-or-later. Third-party components retain their own licenses and must be recorded before integration. See `LICENSE`, `LICENSES/`, and `NOTICE.md`.

MetalSharp Wine Runtime is an independent project and is not affiliated with or endorsed by Microsoft, Apple, or WineHQ.
