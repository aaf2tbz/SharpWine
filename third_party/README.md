# Third-party components

Third-party source is not vendored by default. `components.lock.json` pins reviewed upstream revisions and licenses.
Wine-derived patch files retain Wine's LGPL-2.1-or-later licensing.

Dynarmic is selected as the optional Milestone 3 AArch64 correctness engine and is fetched by CMake at the
pinned revision only when engine support is enabled. Its generated source and build trees must remain under
ignored build directories; do not commit fetched Dynarmic sources, static libraries, or binaries here.

Blink is pinned for issue #12 evidence and the opt-in issue #14 x64 adapter. Sources and generated
artifacts remain build-tree-only. The separately ISC-licensed patch wraps Blink's real decoder and
interpreter behind transactional GEM shadow pages and a reviewed handler allowlist. The accepting target
is configured with `--disable-jit`; repository-original adapter code remains Apache-2.0.

Each future component must be recorded in `NOTICE.md` and pass license review before integration.
