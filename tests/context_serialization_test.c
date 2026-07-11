// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context_serialization.h"
#include <assert.h>
#include <string.h>
int main(void) {
    struct gem_thread_context input, output;
    uint8_t wire[GEM_CONTEXT_WIRE_SIZE_V1];
    size_t n = 0;
    unsigned i;
    gem_context_initialize(&input, UINT64_C(0x12345000), GEM_ISA_ARM64EC);
    for (i = 0; i < 31; ++i)
        input.x[i] = UINT64_C(0x0102030405060708) + i;
    input.x[18] = input.teb;
    for (i = 0; i < 16; ++i) {
        input.v[i].lo = i;
        input.v[i].hi = ~UINT64_C(0) - i;
    }
    assert(gem_context_serialized_size(1) == sizeof(wire));
    assert(gem_context_serialized_size(2) == 0U);
    assert(gem_context_serialize(&input, wire, sizeof(wire), &n) && n == sizeof(wire));
    assert(gem_context_deserialize(&output, wire, sizeof(wire), &n) && n == sizeof(wire));
    assert(memcmp(&input, &output, sizeof(input)) == 0);
    assert(!gem_context_deserialize(&output, wire, sizeof(wire) - 1U, NULL));
    wire[0] ^= 1U;
    assert(!gem_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[0] ^= 1U;
    wire[16] ^= 1U;
    assert(!gem_context_deserialize(&output, wire, sizeof(wire), NULL));
    return 0;
}
