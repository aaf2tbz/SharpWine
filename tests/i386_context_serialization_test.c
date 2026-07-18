// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_context_serialization.h"

#include <assert.h>
#include <string.h>

static void seed_v3(struct gem_i386_context *context) {
    unsigned i;
    gem_i386_context_initialize(context, UINT32_C(0x7ffde000));
    for (i = 0U; i < 8U; ++i) {
        context->gpr[i] = UINT32_C(0x10203040) + i;
        context->xmm[i].lo = UINT64_C(0x1111111111111111) * (i + 1U);
        context->xmm[i].hi = UINT64_C(0xeeeeeeeeeeeeeeee) - i;
        context->x87[i].lo = UINT64_C(0x8000000000000000) | i;
        context->x87[i].hi = UINT64_C(0x3fff);
        context->ymm_upper[i].lo = UINT64_C(0xaaaa555500000000) + i;
        context->ymm_upper[i].hi = UINT64_C(0x123456789abcdef0) - i;
    }
    context->eip = UINT32_C(0x00400000);
    context->x87_environment.fip = UINT32_C(0x401000);
    context->x87_environment.fds = UINT16_C(0x2b);
    context->xcr0 = GEM_I386_XCR0_SUPPORTED;
}

static void make_v1_blob(const struct gem_i386_context *source, uint32_t layout, uint8_t *blob,
                         size_t blob_size) {
    /* Hand-build a retroactive version-1 blob: header + the 448-byte body as
     * produced by the version 2 body's shared prefix. */
    size_t written = 0U;
    struct gem_i386_context v3 = *source;
    uint8_t v2blob[GEM_I386_CONTEXT_WIRE_SIZE_V2];
    assert(blob_size == GEM_I386_CONTEXT_WIRE_SIZE_V1);
    v3.xcr0 = 0U;
    assert(gem_i386_context_serialize(&v3, v2blob, sizeof(v2blob), &written));
    assert(written == sizeof(v2blob));
    blob[0] = v2blob[0];
    blob[1] = v2blob[1];
    blob[2] = v2blob[2];
    blob[3] = v2blob[3];
    blob[4] = 1U;
    blob[5] = blob[6] = blob[7] = 0U;
    blob[8] = (uint8_t)layout;
    blob[9] = blob[10] = blob[11] = 0U;
    blob[12] = (uint8_t)GEM_I386_CONTEXT_SIZE_V2;
    blob[13] = (uint8_t)(GEM_I386_CONTEXT_SIZE_V2 >> 8U);
    blob[14] = blob[15] = 0U;
    memcpy(blob + GEM_I386_CONTEXT_WIRE_HEADER_SIZE, v2blob + GEM_I386_CONTEXT_WIRE_HEADER_SIZE,
           GEM_I386_CONTEXT_SIZE_V2);
    /* The body's embedded layout fields must tell the same story. */
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE] = (uint8_t)layout;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 1U] = 0U;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 2U] = 0U;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 3U] = 0U;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 4U] = (uint8_t)GEM_I386_CONTEXT_SIZE_V2;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 5U] = (uint8_t)(GEM_I386_CONTEXT_SIZE_V2 >> 8U);
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 6U] = 0U;
    blob[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 7U] = 0U;
}

int main(void) {
    struct gem_i386_context input;
    struct gem_i386_context output;
    uint8_t wire[GEM_I386_CONTEXT_WIRE_SIZE_V2];
    uint8_t v1wire[GEM_I386_CONTEXT_WIRE_SIZE_V1];
    size_t n = 0U;
    seed_v3(&input);

    /* Size query and v2 round-trip preserve every byte, ymm and xcr0
     * included. */
    assert(gem_i386_context_serialized_size(GEM_I386_CONTEXT_SERIALIZATION_VERSION_V1) ==
           sizeof(v1wire));
    assert(gem_i386_context_serialized_size(GEM_I386_CONTEXT_SERIALIZATION_VERSION_V2) ==
           sizeof(wire));
    assert(gem_i386_context_serialized_size(0U) == 0U &&
           gem_i386_context_serialized_size(99U) == 0U);
    assert(gem_i386_context_serialize(&input, wire, sizeof(wire), &n));
    assert(n == sizeof(wire));
    assert(gem_i386_context_deserialize(&output, wire, sizeof(wire), &n));
    assert(n == sizeof(wire));
    assert(memcmp(&input, &output, sizeof(input)) == 0);

    /* Serialize rejects invalid input and short buffers. */
    assert(!gem_i386_context_serialize(&input, wire, sizeof(wire) - 1U, NULL));
    output = input;
    output.reserved1 = 1U;
    assert(!gem_i386_context_serialize(&output, wire, sizeof(wire), NULL));
    output = input;
    output.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    output.context_size = GEM_I386_CONTEXT_SIZE_V2;
    assert(!gem_i386_context_serialize(&output, wire, sizeof(wire), NULL));

    /* Default deserializer fails closed on every mutation. */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire) - 1U, NULL));
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire) + 1U, NULL));
    wire[0] ^= 1U; /* magic */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[0] ^= 1U;
    wire[4] ^= 1U; /* serialization version */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[4] ^= 1U;
    wire[8] ^= 1U; /* layout version */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[8] ^= 1U;
    wire[12] ^= 1U; /* payload size */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[12] ^= 1U;
    wire[GEM_I386_CONTEXT_WIRE_SIZE_V2 - 1U] ^= 1U; /* trailing padding */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[GEM_I386_CONTEXT_WIRE_SIZE_V2 - 1U] ^= 1U;
    wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 132U] ^= 1U; /* body padding */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 132U] ^= 1U;
    wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 4U] ^= 1U; /* body context size */
    assert(!gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 4U] ^= 1U;
    assert(gem_i386_context_deserialize(&output, wire, sizeof(wire), NULL));
    assert(memcmp(&input, &output, sizeof(input)) == 0);

    /* The default deserializer rejects version-1 blobs; the explicitly named
     * migration entry point converts them with a zeroed extension. */
    make_v1_blob(&input, GEM_I386_CONTEXT_LAYOUT_VERSION_V2, v1wire, sizeof(v1wire));
    memset(&output, 0xff, sizeof(output));
    assert(!gem_i386_context_deserialize(&output, v1wire, sizeof(v1wire), NULL));
    assert(gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), &n));
    assert(n == sizeof(v1wire));
    assert(output.layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V3);
    assert(output.context_size == GEM_I386_CONTEXT_SIZE_V3);
    assert(output.xcr0 == 0U && output.reserved1 == 0U);
    {
        unsigned i;
        for (i = 0U; i < 8U; ++i)
            assert(output.ymm_upper[i].lo == 0U && output.ymm_upper[i].hi == 0U);
        /* Everything past the layout/size prefix is carried byte-identically. */
        assert(memcmp((const char *)&output + 8U, (const char *)&input + 8U,
                      (size_t)GEM_I386_CONTEXT_SIZE_V2 - 8U) == 0);
    }
    assert(gem_i386_context_is_valid(&output));

    /* Migration fails closed: unknown version, wrong layout, wrong size,
     * truncation, nonzero padding, and contexts invalid under their own
     * layout. */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire) - 1U, NULL));
    v1wire[4] = 2U; /* serialization version */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    v1wire[4] = 1U;
    v1wire[8] = 3U; /* v1 blob may not carry layout 3 */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    v1wire[8] = (uint8_t)GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    v1wire[12] ^= 1U; /* payload size */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    v1wire[12] ^= 1U;
    v1wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 132U] = 1U; /* body padding */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    v1wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE + 132U] = 0U;
    v1wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE] = 1U; /* body layout disagrees */
    assert(!gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    v1wire[GEM_I386_CONTEXT_WIRE_HEADER_SIZE] = 2U;
    assert(gem_i386_context_deserialize_migrate(&output, v1wire, sizeof(v1wire), NULL));
    return 0;
}
