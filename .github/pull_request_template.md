## Summary

## Evidence and ABI source

<!-- Link published documentation, captured traces, or reproducible fixtures. -->

## Tests

- [ ] `tools/ci/run-all.sh` passes
- [ ] New behavior has deterministic tests
- [ ] No binaries, prefixes, build products, private paths, or proprietary files are included
- [ ] Licensing is identified for third-party or Wine-derived work

## Runtime invariants

- [ ] Canonical guest x18 remains the TEB
- [ ] No Rosetta dependency is introduced
- [ ] No dispatcher semantics are guessed
- [ ] Optimized execution has a deterministic fallback
