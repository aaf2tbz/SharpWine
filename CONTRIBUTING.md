# Contributing

1. Open an issue describing the ABI, runtime, or compatibility problem.
2. Keep changes focused and include deterministic tests.
3. Run `tools/ci/run-all.sh` before pushing.
4. Do not commit generated binaries, build trees, Wine prefixes, SDK files, or proprietary PE files.
5. Wine-derived patches belong under `third_party/patches/wine` and remain under Wine's LGPL-2.1-or-later terms.
6. Every transition implementation must cite captured evidence or a published ABI contract. Guessed dispatcher behavior is rejected.

All changes require pull-request review, passing required checks, and resolved review conversations.
