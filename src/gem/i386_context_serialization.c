// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_context_serialization.h"

#include <string.h>

static void put16(uint8_t **p, uint16_t v) {
    *(*p)++ = (uint8_t)v;
    *(*p)++ = (uint8_t)(v >> 8);
}
static void put32(uint8_t **p, uint32_t v) {
    unsigned i;
    for (i = 0; i < 4; ++i)
        *(*p)++ = (uint8_t)(v >> (i * 8));
}
static void put64(uint8_t **p, uint64_t v) {
    unsigned i;
    for (i = 0; i < 8; ++i)
        *(*p)++ = (uint8_t)(v >> (i * 8));
}
static uint16_t get16(const uint8_t **p) {
    uint16_t v = (uint16_t)((uint16_t)(*p)[0] | ((uint16_t)(*p)[1] << 8));
    *p += 2;
    return v;
}
static uint32_t get32(const uint8_t **p) {
    uint32_t v = 0;
    unsigned i;
    for (i = 0; i < 4; ++i)
        v |= (uint32_t)(*p)[i] << (i * 8);
    *p += 4;
    return v;
}
static uint64_t get64(const uint8_t **p) {
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; ++i)
        v |= (uint64_t)(*p)[i] << (i * 8);
    *p += 8;
    return v;
}
static void put128(uint8_t **p, struct gem_u128 v) {
    put64(p, v.lo);
    put64(p, v.hi);
}
static struct gem_u128 get128(const uint8_t **p) {
    struct gem_u128 v = {get64(p), get64(p)};
    return v;
}

/* The shared 448-byte v1/v2 body, encoded field by field in declaration
 * order with the two pinned padding slots explicit and required zero. */
static void encode_body(uint8_t **p, const struct gem_i386_context *c) {
    unsigned i;
    put32(p, c->layout_version);
    put32(p, c->context_size);
    for (i = 0; i < 8U; ++i)
        put32(p, c->gpr[i]);
    put32(p, c->eip);
    put32(p, c->eflags);
    for (i = 0; i < 6U; ++i)
        put16(p, c->segment[i]);
    for (i = 0; i < 6U; ++i)
        put32(p, c->segment_base[i]);
    for (i = 0; i < 6U; ++i)
        put32(p, c->segment_limit[i]);
    for (i = 0; i < 6U; ++i)
        put32(p, c->segment_attributes[i]);
    put32(p, 0U);
    for (i = 0; i < 8U; ++i)
        put128(p, c->xmm[i]);
    for (i = 0; i < 8U; ++i)
        put128(p, c->x87[i]);
    put32(p, c->mxcsr);
    put16(p, c->fcw);
    put16(p, c->fsw);
    put16(p, c->ftw);
    put16(p, c->fop);
    put32(p, c->teb);
    put32(p, c->reserved0);
    put32(p, 0U);
    put64(p, c->transition_cookie);
    put32(p, c->stop_reason);
    for (i = 0; i < 5U; ++i)
        put32(p, c->reserved[i]);
}
static bool decode_body(const uint8_t **p, struct gem_i386_context *c) {
    unsigned i;
    c->layout_version = get32(p);
    c->context_size = get32(p);
    for (i = 0; i < 8U; ++i)
        c->gpr[i] = get32(p);
    c->eip = get32(p);
    c->eflags = get32(p);
    for (i = 0; i < 6U; ++i)
        c->segment[i] = get16(p);
    for (i = 0; i < 6U; ++i)
        c->segment_base[i] = get32(p);
    for (i = 0; i < 6U; ++i)
        c->segment_limit[i] = get32(p);
    for (i = 0; i < 6U; ++i)
        c->segment_attributes[i] = get32(p);
    if (get32(p) != 0U)
        return false;
    for (i = 0; i < 8U; ++i)
        c->xmm[i] = get128(p);
    for (i = 0; i < 8U; ++i)
        c->x87[i] = get128(p);
    c->mxcsr = get32(p);
    c->fcw = get16(p);
    c->fsw = get16(p);
    c->ftw = get16(p);
    c->fop = get16(p);
    c->teb = get32(p);
    c->reserved0 = get32(p);
    if (get32(p) != 0U)
        return false;
    c->transition_cookie = get64(p);
    c->stop_reason = get32(p);
    for (i = 0; i < 5U; ++i)
        c->reserved[i] = get32(p);
    return true;
}

size_t gem_i386_context_serialized_size(uint32_t version) {
    if (version == GEM_I386_CONTEXT_SERIALIZATION_VERSION_V1)
        return GEM_I386_CONTEXT_WIRE_SIZE_V1;
    if (version == GEM_I386_CONTEXT_SERIALIZATION_VERSION_V2)
        return GEM_I386_CONTEXT_WIRE_SIZE_V2;
    return 0U;
}

bool gem_i386_context_serialize(const struct gem_i386_context *context, uint8_t *buffer,
                                size_t buffer_size, size_t *bytes_written) {
    uint8_t *p;
    unsigned i;
    if (bytes_written != NULL)
        *bytes_written = 0U;
    if (context == NULL || buffer == NULL || buffer_size < GEM_I386_CONTEXT_WIRE_SIZE_V2 ||
        context->layout_version != GEM_I386_CONTEXT_LAYOUT_VERSION_V3 ||
        !gem_i386_context_is_valid(context))
        return false;
    p = buffer;
    put32(&p, GEM_I386_CONTEXT_WIRE_MAGIC);
    put32(&p, GEM_I386_CONTEXT_SERIALIZATION_VERSION_V2);
    put32(&p, GEM_I386_CONTEXT_LAYOUT_VERSION_V3);
    put32(&p, GEM_I386_CONTEXT_SIZE_V3);
    encode_body(&p, context);
    for (i = 0; i < 8U; ++i)
        put128(&p, context->ymm_upper[i]);
    put64(&p, context->xcr0);
    put64(&p, 0U);
    if (bytes_written != NULL)
        *bytes_written = (size_t)(p - buffer);
    return true;
}

bool gem_i386_context_deserialize(struct gem_i386_context *context, const uint8_t *buffer,
                                  size_t buffer_size, size_t *bytes_read) {
    const uint8_t *p;
    struct gem_i386_context temporary;
    unsigned i;
    if (bytes_read != NULL)
        *bytes_read = 0U;
    if (context == NULL || buffer == NULL || buffer_size != GEM_I386_CONTEXT_WIRE_SIZE_V2)
        return false;
    p = buffer;
    /* Fail closed: only the version 2 wire format is accepted here. */
    if (get32(&p) != GEM_I386_CONTEXT_WIRE_MAGIC ||
        get32(&p) != GEM_I386_CONTEXT_SERIALIZATION_VERSION_V2)
        return false;
    memset(&temporary, 0, sizeof(temporary));
    temporary.layout_version = get32(&p);
    temporary.context_size = get32(&p);
    if (temporary.layout_version != GEM_I386_CONTEXT_LAYOUT_VERSION_V3 ||
        temporary.context_size != GEM_I386_CONTEXT_SIZE_V3)
        return false;
    if (!decode_body(&p, &temporary))
        return false;
    /* The body's embedded layout fields must match the wire header: a v2
     * wire blob carries exactly a layout-3, 592-byte context. */
    if (temporary.layout_version != GEM_I386_CONTEXT_LAYOUT_VERSION_V3 ||
        temporary.context_size != GEM_I386_CONTEXT_SIZE_V3)
        return false;
    for (i = 0; i < 8U; ++i)
        temporary.ymm_upper[i] = get128(&p);
    temporary.xcr0 = get64(&p);
    if (get64(&p) != 0U)
        return false;
    if (!gem_i386_context_is_valid(&temporary))
        return false;
    *context = temporary;
    if (bytes_read != NULL)
        *bytes_read = (size_t)(p - buffer);
    return true;
}

bool gem_i386_context_deserialize_migrate(struct gem_i386_context *context, const uint8_t *buffer,
                                          size_t buffer_size, size_t *bytes_read) {
    const uint8_t *p;
    struct gem_i386_context temporary;
    if (bytes_read != NULL)
        *bytes_read = 0U;
    if (context == NULL || buffer == NULL || buffer_size != GEM_I386_CONTEXT_WIRE_SIZE_V1)
        return false;
    p = buffer;
    if (get32(&p) != GEM_I386_CONTEXT_WIRE_MAGIC ||
        get32(&p) != GEM_I386_CONTEXT_SERIALIZATION_VERSION_V1)
        return false;
    memset(&temporary, 0, sizeof(temporary));
    {
        const uint32_t header_layout = get32(&p);
        const uint32_t header_size = get32(&p);
        if ((header_layout != GEM_I386_CONTEXT_LAYOUT_VERSION_V1 &&
             header_layout != GEM_I386_CONTEXT_LAYOUT_VERSION_V2) ||
            header_size != GEM_I386_CONTEXT_SIZE_V2)
            return false;
        if (!decode_body(&p, &temporary))
            return false;
        /* The body's embedded layout fields must match the wire header. */
        if (temporary.layout_version != header_layout || temporary.context_size != header_size)
            return false;
    }
    /* Validate the body under its own layout rules first so a malformed
     * v1/v2 blob can never be laundered into a valid-looking v3 record. */
    if (!gem_i386_context_is_valid(&temporary))
        return false;
    /* Explicit opt-in migration: the v3 extension is zero-initialized and the
     * result is stamped layout 3; nothing is reinterpreted silently. */
    temporary.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V3;
    temporary.context_size = GEM_I386_CONTEXT_SIZE_V3;
    if (!gem_i386_context_is_valid(&temporary))
        return false;
    *context = temporary;
    if (bytes_read != NULL)
        *bytes_read = (size_t)(p - buffer);
    return true;
}
