// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_MEMORY_H
#define METALSHARP_GEM_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_GUEST_PAGE_SIZE UINT64_C(4096)
#define GEM_MEMORY_ANY UINT64_C(0)
#define GEM_KUSER_SHARED_DATA_ADDRESS UINT64_C(0x7ffe0000)
#define GEM_KUSER_CANONICAL_ADDRESS UINT64_C(0x1007ffe0000)

enum gem_memory_error {
    GEM_MEMORY_OK = 0,
    GEM_MEMORY_INVALID_ARGUMENT,
    GEM_MEMORY_OVERFLOW,
    GEM_MEMORY_NO_MEMORY,
    GEM_MEMORY_CONFLICT,
    GEM_MEMORY_NOT_RESERVED,
    GEM_MEMORY_NOT_COMMITTED,
    GEM_MEMORY_ACCESS_DENIED,
    GEM_MEMORY_GUARD_PAGE,
    GEM_MEMORY_NOT_FOUND
};

enum gem_memory_protection {
    GEM_PAGE_NOACCESS = 0x01,
    GEM_PAGE_READONLY = 0x02,
    GEM_PAGE_READWRITE = 0x04,
    GEM_PAGE_WRITECOPY = 0x08,
    GEM_PAGE_EXECUTE = 0x10,
    GEM_PAGE_EXECUTE_READ = 0x20,
    GEM_PAGE_EXECUTE_READWRITE = 0x40,
    GEM_PAGE_EXECUTE_WRITECOPY = 0x80,
    GEM_PAGE_GUARD = 0x100
};

/*
 * `gem_memory` is an opaque, sparse, 4 KiB-page Windows address space.  Every
 * public operation that observes or mutates page-table state is linearizable:
 * it holds a single per-object exclusive lock across complete validation,
 * allocation/state publication, and caller-buffer copying.  Concurrent callers
 * of the same `gem_memory` are therefore serialized, and compound operations
 * (identity mapping and its rollback) never partially publish state.
 *
 * Object destruction requires external lifetime coordination: no operation may
 * start or remain active on a `gem_memory` once `gem_memory_destroy` begins.
 * External identity storage passed to `gem_memory_map_identity` remains owned
 * by the caller and must stay live and unchanged except through GEM until the
 * mapping is unmapped/released or the `gem_memory` is destroyed.
 */
/* A real access to PAGE_GUARD follows Windows one-shot semantics: it returns
 * GEM_MEMORY_GUARD_PAGE and consumes the guard after whole-range validation.
 * CPU state and data writes remain uncommitted; retry succeeds unless the
 * caller explicitly re-applies guard protection. Query operations do not
 * consume guards. */
struct gem_memory;
struct gem_memory *gem_memory_create(void);
void gem_memory_destroy(struct gem_memory *memory);

enum gem_memory_error gem_memory_reserve(struct gem_memory *memory, uint64_t *address,
                                         uint64_t size);
enum gem_memory_error gem_memory_commit(struct gem_memory *memory, uint64_t address, uint64_t size,
                                        uint32_t protection);
enum gem_memory_error gem_memory_decommit(struct gem_memory *memory, uint64_t address,
                                          uint64_t size);
enum gem_memory_error gem_memory_release(struct gem_memory *memory, uint64_t address,
                                         uint64_t size);
enum gem_memory_error gem_memory_unmap(struct gem_memory *memory, uint64_t address, uint64_t size);
enum gem_memory_error gem_memory_protect(struct gem_memory *memory, uint64_t address, uint64_t size,
                                         uint32_t protection, uint32_t *old_protection);
/* Alias requires source committed pages and shares their contents until write-copy detaches. */
enum gem_memory_error gem_memory_alias(struct gem_memory *memory, uint64_t address, uint64_t source,
                                       uint64_t size, uint32_t protection);
/* A validated identity mapping is still subject to all logical checks and protections. */
enum gem_memory_error gem_memory_map_identity(struct gem_memory *memory, uint64_t address,
                                              void *host, uint64_t size, uint32_t protection);
enum gem_memory_error gem_memory_read(struct gem_memory *memory, uint64_t address, void *buffer,
                                      size_t size);
enum gem_memory_error gem_memory_write(struct gem_memory *memory, uint64_t address,
                                       const void *buffer, size_t size);
enum gem_memory_error gem_memory_fetch(struct gem_memory *memory, uint64_t address, void *buffer,
                                       size_t size);
bool gem_memory_is_executable(struct gem_memory *memory, uint64_t address, size_t size);
const char *gem_memory_error_name(enum gem_memory_error error);

#ifdef __cplusplus
}
#endif
#endif
