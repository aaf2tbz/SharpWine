# DXMT v0.80 paired i386/ARM64 build patch

This queue applies only to DXMT tag `v0.80`, commit
`589adb780354b461645b29999cefaf533594ee99`. It changes the upstream Win32
cross-build from its default i386-PE/x86_64-Unix pairing into one build graph
that emits i386 PE modules and a native ARM64 `winemetal.so` on Apple Silicon.

The queue does not import either half from the upstream binary archive. The
Windows and Unix modules are built together from the locked DXMT source and
submodule revisions, then audited as a single unit. In particular,
`x86_64-unix/winemetal.so` is forbidden from the build and release outputs.

The first patch selects the native ARM64 build machine for the Unix half and
adds deterministic PE/Mach-O link settings. The second is the exact upstream
Xcode 27 Metal compatibility fix from commit
`06065754af91352caaf8db87d4566fecc4124552`. The third canonicalizes source
paths in embedded Metal AIR bitcode so two clean build roots produce identical
runtime bytes and no local source path enters the release. The fourth binds the
paired module set to `v0.80-metalsharp.1` instead of embedding the transient
patch-application commit hash. The fifth selects ld64's reproducible layout;
the build entrypoint also sets `ZERO_AR_DATE=1` so native archive member times
cannot perturb that layout.

Apply the queue from the DXMT source root with:

```sh
git am /path/to/third_party/patches/dxmt/*.patch
```

`provenance.json` binds the upstream source, submodules, reviewed authoring
commit, patch bytes, and reference-only upstream archive.
