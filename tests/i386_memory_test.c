// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    struct gem_memory *memory = gem_memory_create();
    uint32_t automatic = 0U;
    uint32_t top = UINT32_C(0xfffff000);
    uint8_t input[2] = {0x12U, 0x34U};
    uint8_t output[2] = {0U, 0U};
    uint8_t *host = aligned_alloc((size_t)GEM_GUEST_PAGE_SIZE, (size_t)GEM_GUEST_PAGE_SIZE);
    assert(memory != NULL);
    assert(host != NULL);
    assert(gem_i386_memory_range_valid(0U, 1U));
    assert(gem_i386_memory_range_valid(UINT32_MAX, 1U));
    assert(!gem_i386_memory_range_valid(UINT32_MAX, 2U));
    assert(!gem_i386_memory_range_valid(0U, 0U));
    assert(gem_i386_memory_reserve(memory, &automatic, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(automatic == GEM_I386_LOWEST_ALLOCATION);
    assert(gem_i386_memory_commit(memory, automatic, 2U * GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, automatic + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U, input,
                                 sizeof(input)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_read(memory, automatic + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U, output,
                                sizeof(output)) == GEM_MEMORY_OK);
    assert(memcmp(input, output, sizeof(input)) == 0);
    {
        uint32_t external = UINT32_C(0x00200000);
        assert(gem_i386_memory_reserve(memory, &external, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_commit_host(memory, external, host, GEM_GUEST_PAGE_SIZE,
                                           GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
        host[0] = UINT8_C(0xa5);
        assert(gem_i386_memory_read(memory, external, output, 1U) == GEM_MEMORY_OK);
        assert(output[0] == UINT8_C(0xa5));
        input[0] = UINT8_C(0x5a);
        assert(gem_i386_memory_write(memory, external, input, 1U) == GEM_MEMORY_OK);
        assert(host[0] == UINT8_C(0x5a));
        assert(gem_i386_memory_release(memory, external, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    }
    assert(gem_i386_memory_reserve(memory, &top, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, top, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, UINT32_MAX, input, 2U) == GEM_MEMORY_OVERFLOW);
    assert(gem_i386_memory_fetch(memory, UINT32_MAX, output, 2U) == GEM_MEMORY_OVERFLOW);
    assert(gem_i386_memory_release(memory, top, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_release(memory, automatic, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    gem_memory_destroy(memory);
    free(host);
    return 0;
}
