# Checked preferred-base ARM64X materializer

`gem_pe_arm64x_materialize_preferred` is the deliberately narrow Issue #14 image path. It parses
the source bytes with the checked ARM64X parser and requires the requested guest base to equal the
PE preferred image base. GEM's address space is virtual, so this avoids relocations without a host
mapping requirement. A different base fails with `GEM_PE_MATERIALIZE_RELOCATION_REQUIRED`; no
relocation kind is guessed or silently ignored.

The materializer reserves one complete `SizeOfImage` range in the caller's single `gem_memory`,
zero-initializes it, copies `SizeOfHeaders` and each file-backed section through checked RVA/file
mapping, and applies page permissions derived exactly from PE read/write/execute characteristics.
Overlapping sections are rejected by the parser, and incompatible permissions sharing one 4 KiB
page fail closed rather than being widened. Any error releases the entire reservation before an
image object is published.

The materializer does not execute or resolve imports, TLS callbacks, initializers, exception
registration, or `DllMain`. Evidence-provided helper pointer slots may be bound before final
permissions are applied. Each binding must identify a complete eight-byte slot in a nonexecutable
section, use a nonzero value outside the image, and be unique. The Phase 3 fixture binds only its
producer-reported checker, dispatch-call-no-redirect, and dispatch-ret slots to distinct broker
sentinels. Ordinary imports remain unreachable; reaching one fails metadata or checked-memory
validation.

The returned object owns immutable parsed metadata but not GEM memory. Destroying it never unmaps
the caller-owned address space. Blink and Dynarmic consume the same GEM memory, and ISA decisions
continue to come only from that immutable CHPE metadata.
