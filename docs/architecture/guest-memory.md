# GEM logical guest memory

GEM owns a sparse, 4 KiB-page Windows address space.  `gem_memory` never assumes the host page size and does not dereference guest virtual addresses.  Every reserve, commit, decommit, release, alias, protection change, read, write, and instruction fetch validates overflow, page alignment, reservation, commitment, and logical protection before touching backing storage.

`0x7ffe0000` is an ordinary supported low guest address; no low host mapping is required. Aliases share a backing page. A write through `PAGE_WRITECOPY` or `PAGE_EXECUTE_WRITECOPY` first detaches a private zero-host-independent 4 KiB copy. Guard pages fail one access with `GEM_MEMORY_GUARD_PAGE` and then clear their guard bit. Execute permission is checked independently through `gem_memory_fetch` or `gem_memory_is_executable`.

`gem_memory_map_identity` is a deliberately explicit optimization boundary. It installs host storage only after the same logical reservation and protection checks, and all subsequent accesses continue through GEM. It therefore cannot bypass guard, write-copy, commitment, alias, or execute semantics. Callers retain ownership of identity storage until it is unmapped or GEM is destroyed.

Identity requires a pointer whose numeric value is exactly the guest address, at or above 4 GiB, and whose address and span meet the host-page alignment constraint. GEM does not own that storage: callers must keep it live and unchanged until unmap/release or GEM destruction. Low KUSER (`0x7ffe0000`) is instead an alias of a separate canonical GEM mapping. The API is single-threaded at present. Concurrent callers must serialize access; future synchronization must preserve the atomic validation behavior of these operations.
