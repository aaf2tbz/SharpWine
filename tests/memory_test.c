// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/memory.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
#if defined(__APPLE__) && defined(__aarch64__)
    assert(sysconf(_SC_PAGESIZE) == 16384);
#endif
    struct gem_memory *memory = gem_memory_create();
    uint64_t base = UINT64_C(0x7ffc0000);
    uint8_t input[2] = {1U, 2U};
    uint8_t output[2] = {0U, 0U};
    const size_t host_page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *identity = NULL;
    assert(memory != NULL);
    assert(gem_memory_read(memory, 0U, output, SIZE_MAX) == GEM_MEMORY_OVERFLOW);
    assert(gem_memory_write(memory, GEM_KUSER_CANONICAL_ADDRESS, input, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_read(memory, GEM_KUSER_SHARED_DATA_ADDRESS, output, 1U) == GEM_MEMORY_OK &&
           output[0] == input[0]);
    assert(gem_memory_reserve(memory, &base, GEM_GUEST_PAGE_SIZE * 2U) == GEM_MEMORY_OK);
    assert(gem_memory_commit(memory, base, GEM_GUEST_PAGE_SIZE * 2U, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_memory_protect(memory, base, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_READWRITE | GEM_PAGE_WRITECOPY,
                              NULL) == GEM_MEMORY_INVALID_ARGUMENT);
    assert(gem_memory_write(memory, base + GEM_GUEST_PAGE_SIZE - 1U, input, sizeof(input)) ==
           GEM_MEMORY_OK);
    assert(gem_memory_read(memory, base + GEM_GUEST_PAGE_SIZE - 1U, output, sizeof(output)) ==
           GEM_MEMORY_OK);
    assert(memcmp(input, output, sizeof(input)) == 0);

    /* A denied later page makes a cross-page write fully transactional. */
    assert(gem_memory_protect(memory, base + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_READONLY, NULL) == GEM_MEMORY_OK);
    output[0] = 7U;
    assert(gem_memory_write(memory, base + GEM_GUEST_PAGE_SIZE - 1U, output, sizeof(output)) ==
           GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_read(memory, base + GEM_GUEST_PAGE_SIZE - 1U, output, 1U) == GEM_MEMORY_OK &&
           output[0] == input[0]);
    assert(gem_memory_protect(memory, base + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_READWRITE, NULL) == GEM_MEMORY_OK);

    assert(gem_memory_alias(memory, UINT64_C(0x7ffd0000), base, GEM_GUEST_PAGE_SIZE,
                            GEM_PAGE_WRITECOPY) == GEM_MEMORY_OK);
    output[0] = 9U;
    assert(gem_memory_write(memory, UINT64_C(0x7ffd0000), output, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_read(memory, base, output, 1U) == GEM_MEMORY_OK && output[0] == 0U);
    assert(gem_memory_unmap(memory, UINT64_C(0x7ffd0000), GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_memory_read(memory, UINT64_C(0x7ffd0000), output, 1U) == GEM_MEMORY_NOT_RESERVED);

    identity = aligned_alloc(host_page_size, host_page_size);
    assert(identity != NULL && (uint64_t)(uintptr_t)identity >= UINT64_C(0x100000000));
    assert(gem_memory_map_identity(memory, (uint64_t)(uintptr_t)identity, identity, host_page_size,
                                   GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_memory_map_identity(memory, UINT64_C(0x100000000), identity, host_page_size,
                                   GEM_PAGE_READWRITE) == GEM_MEMORY_INVALID_ARGUMENT);
    assert(gem_memory_unmap(memory, (uint64_t)(uintptr_t)identity, host_page_size) ==
           GEM_MEMORY_OK);
    free(identity);

    assert(gem_memory_protect(memory, base, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_EXECUTE_READ | GEM_PAGE_GUARD, NULL) == GEM_MEMORY_OK);
    assert(gem_memory_is_executable(memory, base, 1U)); /* query must not consume guard */
    assert(gem_memory_fetch(memory, base, output, 1U) == GEM_MEMORY_GUARD_PAGE);
    assert(gem_memory_fetch(memory, base, output, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_is_executable(memory, base, 1U));
    assert(gem_memory_write(memory, base, output, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_decommit(memory, base + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_memory_read(memory, base + GEM_GUEST_PAGE_SIZE, output, 1U) ==
           GEM_MEMORY_NOT_COMMITTED);
    assert(gem_memory_release(memory, base, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_INVALID_ARGUMENT);
    assert(gem_memory_release(memory, base, GEM_GUEST_PAGE_SIZE * 2U) == GEM_MEMORY_OK);
    gem_memory_destroy(memory);
    return 0;
}
