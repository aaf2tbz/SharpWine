// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context_serialization.h"

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

size_t gem_context_serialized_size(uint32_t version) {
    return version == GEM_CONTEXT_SERIALIZATION_VERSION ? GEM_CONTEXT_WIRE_SIZE_V1 : 0U;
}
static void encode(uint8_t **p, const struct gem_thread_context *c) {
    unsigned i;
    put32(p, c->layout_version);
    put32(p, c->context_size);
    for (i = 0; i < 31; ++i)
        put64(p, c->x[i]);
    put64(p, c->sp);
    put64(p, c->pc);
    put32(p, c->nzcv);
    put32(p, c->fpcr);
    put32(p, c->fpsr);
    put32(p, c->reserved0);
    for (i = 0; i < 16; ++i)
        put128(p, c->v[i]);
    put64(p, c->x64_rflags);
    put32(p, c->x64_mxcsr);
    put16(p, c->x64_fcw);
    put16(p, c->x64_fsw);
    for (i = 0; i < 8; ++i)
        put128(p, c->x87[i]);
    put64(p, c->teb);
    put64(p, c->original_x64_sp);
    put64(p, c->transition_cookie);
    put32(p, c->isa);
    put32(p, c->stop_reason);
}
static void decode(const uint8_t **p, struct gem_thread_context *c) {
    unsigned i;
    c->layout_version = get32(p);
    c->context_size = get32(p);
    for (i = 0; i < 31; ++i)
        c->x[i] = get64(p);
    c->sp = get64(p);
    c->pc = get64(p);
    c->nzcv = get32(p);
    c->fpcr = get32(p);
    c->fpsr = get32(p);
    c->reserved0 = get32(p);
    for (i = 0; i < 16; ++i)
        c->v[i] = get128(p);
    c->x64_rflags = get64(p);
    c->x64_mxcsr = get32(p);
    c->x64_fcw = get16(p);
    c->x64_fsw = get16(p);
    for (i = 0; i < 8; ++i)
        c->x87[i] = get128(p);
    c->teb = get64(p);
    c->original_x64_sp = get64(p);
    c->transition_cookie = get64(p);
    c->isa = get32(p);
    c->stop_reason = get32(p);
}
bool gem_context_serialize(const struct gem_thread_context *c, uint8_t *b, size_t n,
                           size_t *written) {
    uint8_t *p;
    if (written != 0)
        *written = 0;
    if (!gem_context_is_valid(c) || c->reserved0 != 0U ||
        c->stop_reason > GEM_STOP_INVARIANT_VIOLATION || b == 0 || n < GEM_CONTEXT_WIRE_SIZE_V1)
        return false;
    p = b;
    put32(&p, GEM_CONTEXT_WIRE_MAGIC);
    put32(&p, GEM_CONTEXT_SERIALIZATION_VERSION);
    put32(&p, GEM_CONTEXT_WIRE_HEADER_SIZE_V1);
    put32(&p, GEM_CONTEXT_LAYOUT_VERSION);
    put32(&p, GEM_THREAD_CONTEXT_SIZE_V1);
    encode(&p, c);
    if (written != 0)
        *written = (size_t)(p - b);
    return true;
}
bool gem_context_deserialize(struct gem_thread_context *c, const uint8_t *b, size_t n,
                             size_t *read) {
    const uint8_t *p;
    struct gem_thread_context temporary;
    if (read != 0)
        *read = 0;
    if (c == 0 || b == 0 || n != GEM_CONTEXT_WIRE_SIZE_V1)
        return false;
    p = b;
    if (get32(&p) != GEM_CONTEXT_WIRE_MAGIC || get32(&p) != GEM_CONTEXT_SERIALIZATION_VERSION ||
        get32(&p) != GEM_CONTEXT_WIRE_HEADER_SIZE_V1 || get32(&p) != GEM_CONTEXT_LAYOUT_VERSION ||
        get32(&p) != GEM_THREAD_CONTEXT_SIZE_V1)
        return false;
    decode(&p, &temporary);
    if (!gem_context_is_valid(&temporary) || temporary.reserved0 != 0U ||
        temporary.stop_reason > GEM_STOP_INVARIANT_VIOLATION)
        return false;
    *c = temporary;
    if (read != 0)
        *read = (size_t)(p - b);
    return true;
}
