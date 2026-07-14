// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_MEMORY_H
#define METALSHARP_GEM_I386_MEMORY_H

#include "metalsharp/gem/memory.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_I386_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define GEM_I386_LOWEST_ALLOCATION UINT32_C(0x00010000)
#define GEM_I386_ALLOCATION_GRANULARITY UINT32_C(0x00010000)

bool gem_i386_memory_range_valid(uint32_t address, uint64_t size);
enum gem_memory_error gem_i386_memory_reserve(struct gem_memory *memory, uint32_t *address,
                                              uint64_t size);
enum gem_memory_error gem_i386_memory_commit(struct gem_memory *memory, uint32_t address,
                                             uint64_t size, uint32_t protection);
enum gem_memory_error gem_i386_memory_commit_host(struct gem_memory *memory, uint32_t address,
                                                  void *host, uint64_t size, uint32_t protection);
enum gem_memory_error gem_i386_memory_decommit(struct gem_memory *memory, uint32_t address,
                                               uint64_t size);
enum gem_memory_error gem_i386_memory_release(struct gem_memory *memory, uint32_t address,
                                              uint64_t size);
enum gem_memory_error gem_i386_memory_unmap(struct gem_memory *memory, uint32_t address,
                                            uint64_t size);
enum gem_memory_error gem_i386_memory_protect(struct gem_memory *memory, uint32_t address,
                                              uint64_t size, uint32_t protection,
                                              uint32_t *old_protection);
enum gem_memory_error gem_i386_memory_alias(struct gem_memory *memory, uint32_t address,
                                            uint32_t source, uint64_t size, uint32_t protection);
enum gem_memory_error gem_i386_memory_read(struct gem_memory *memory, uint32_t address,
                                           void *buffer, size_t size);
enum gem_memory_error gem_i386_memory_write(struct gem_memory *memory, uint32_t address,
                                            const void *buffer, size_t size);
enum gem_memory_error gem_i386_memory_fetch(struct gem_memory *memory, uint32_t address,
                                            void *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif
