// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_memory.h"

static enum gem_memory_error range_error(uint32_t address, uint64_t size) {
    if (size == 0U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (size > GEM_I386_ADDRESS_SPACE_SIZE)
        return GEM_MEMORY_OVERFLOW;
    return (uint64_t)address > GEM_I386_ADDRESS_SPACE_SIZE - size ? GEM_MEMORY_OVERFLOW
                                                                  : GEM_MEMORY_OK;
}

bool gem_i386_memory_range_valid(uint32_t address, uint64_t size) {
    return size <= GEM_I386_ADDRESS_SPACE_SIZE && range_error(address, size) == GEM_MEMORY_OK;
}

enum gem_memory_error gem_i386_memory_reserve(struct gem_memory *memory, uint32_t *address,
                                              uint64_t size) {
    uint64_t candidate;
    enum gem_memory_error error;
    if (memory == NULL || address == NULL || size == 0U ||
        (size & (GEM_GUEST_PAGE_SIZE - 1U)) != 0U || size > GEM_I386_ADDRESS_SPACE_SIZE)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (*address != 0U) {
        candidate = *address;
        if (range_error(*address, size) != GEM_MEMORY_OK)
            return GEM_MEMORY_OVERFLOW;
        return gem_memory_reserve(memory, &candidate, size);
    }
    for (candidate = GEM_I386_LOWEST_ALLOCATION; candidate <= GEM_I386_ADDRESS_SPACE_SIZE - size;
         candidate += GEM_I386_ALLOCATION_GRANULARITY) {
        uint64_t requested = candidate;
        error = gem_memory_reserve(memory, &requested, size);
        if (error == GEM_MEMORY_OK) {
            *address = (uint32_t)requested;
            return GEM_MEMORY_OK;
        }
        if (error != GEM_MEMORY_CONFLICT)
            return error;
    }
    return GEM_MEMORY_NO_MEMORY;
}

#define GEM_I386_PAGE_WRAPPER(name, target)                                                        \
    enum gem_memory_error name(struct gem_memory *memory, uint32_t address, uint64_t size) {       \
        enum gem_memory_error error = range_error(address, size);                                  \
        if (error != GEM_MEMORY_OK)                                                                \
            return error;                                                                          \
        return target(memory, address, size);                                                      \
    }

GEM_I386_PAGE_WRAPPER(gem_i386_memory_decommit, gem_memory_decommit)
GEM_I386_PAGE_WRAPPER(gem_i386_memory_release, gem_memory_release)
GEM_I386_PAGE_WRAPPER(gem_i386_memory_unmap, gem_memory_unmap)

#undef GEM_I386_PAGE_WRAPPER

enum gem_memory_error gem_i386_memory_commit(struct gem_memory *memory, uint32_t address,
                                             uint64_t size, uint32_t protection) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK ? gem_memory_commit(memory, address, size, protection) : error;
}

enum gem_memory_error gem_i386_memory_commit_host(struct gem_memory *memory, uint32_t address,
                                                  void *host, uint64_t size, uint32_t protection) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK
               ? gem_memory_commit_external(memory, address, host, size, protection)
               : error;
}

enum gem_memory_error gem_i386_memory_protect(struct gem_memory *memory, uint32_t address,
                                              uint64_t size, uint32_t protection,
                                              uint32_t *old_protection) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK
               ? gem_memory_protect(memory, address, size, protection, old_protection)
               : error;
}

enum gem_memory_error gem_i386_memory_alias(struct gem_memory *memory, uint32_t address,
                                            uint32_t source, uint64_t size, uint32_t protection) {
    enum gem_memory_error error = range_error(address, size);
    if (error == GEM_MEMORY_OK)
        error = range_error(source, size);
    return error == GEM_MEMORY_OK ? gem_memory_alias(memory, address, source, size, protection)
                                  : error;
}

enum gem_memory_error gem_i386_memory_read(struct gem_memory *memory, uint32_t address,
                                           void *buffer, size_t size) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK ? gem_memory_read(memory, address, buffer, size) : error;
}

enum gem_memory_error gem_i386_memory_write(struct gem_memory *memory, uint32_t address,
                                            const void *buffer, size_t size) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK ? gem_memory_write(memory, address, buffer, size) : error;
}

enum gem_memory_error gem_i386_memory_fetch(struct gem_memory *memory, uint32_t address,
                                            void *buffer, size_t size) {
    enum gem_memory_error error = range_error(address, size);
    return error == GEM_MEMORY_OK ? gem_memory_fetch(memory, address, buffer, size) : error;
}
