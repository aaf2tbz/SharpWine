// SPDX-License-Identifier: Apache-2.0
#include "blink/gem_embed.h"
#include "x64_engine_internal.h"
#include <stdlib.h>
#include <string.h>
static uint32_t snapshot(void *o, uint64_t a, uint8_t data[4096], uint32_t *p) {
    struct gem_x64_runtime *r = o;
    uint32_t gp = 0;
    enum gem_memory_error e = gem_memory_transaction_snapshot_page(r->transaction, a, data, &gp);
    uint32_t b = gp & ~(uint32_t)GEM_PAGE_GUARD;
    *p = 0;
    if (b != GEM_PAGE_NOACCESS) {
        if (b != GEM_PAGE_EXECUTE)
            *p |= 1;
        if (b == GEM_PAGE_READWRITE || b == GEM_PAGE_WRITECOPY || b == GEM_PAGE_EXECUTE_READWRITE ||
            b == GEM_PAGE_EXECUTE_WRITECOPY)
            *p |= 2;
        if (b == GEM_PAGE_EXECUTE || b == GEM_PAGE_EXECUTE_READ ||
            b == GEM_PAGE_EXECUTE_READWRITE || b == GEM_PAGE_EXECUTE_WRITECOPY)
            *p |= 4;
    }
    return e;
}
static uint32_t validate(void *o, uint64_t a, size_t n, enum blink_gem_access x) {
    struct gem_x64_runtime *r = o;
    return gem_memory_transaction_validate(r->transaction, a, n, x == BLINK_GEM_ACCESS_WRITE,
                                           x == BLINK_GEM_ACCESS_FETCH);
}
static uint32_t commit(void *o, const struct blink_gem_write *w, size_t n,
                       uint64_t *fault_address) {
    struct gem_x64_runtime *r = o;
    struct gem_memory_page_write *pages;
    enum gem_memory_error e;
    size_t i;
    if (!n)
        return 0;
    pages = calloc(n, sizeof(*pages));
    if (!pages)
        return GEM_MEMORY_NO_MEMORY;
    for (i = 0; i < n; ++i) {
        if (w[i].size != 4096) {
            free(pages);
            return GEM_MEMORY_INVALID_ARGUMENT;
        }
        pages[i].address = w[i].address;
        pages[i].data = w[i].data;
    }
    e = gem_memory_transaction_commit_pages(r->transaction, pages, n, fault_address);
    free(pages);
    return e;
}
bool gem_x64_blink_create(struct gem_x64_runtime *r) {
    const struct blink_gem_callbacks c = {BLINK_GEM_ABI_VERSION, sizeof(c), snapshot, validate,
                                          commit};
    r->backend = blink_gem_machine_create(&c, r);
    return r->backend != 0;
}
void gem_x64_blink_destroy(struct gem_x64_runtime *r) {
    blink_gem_machine_destroy(r->backend);
    r->backend = 0;
}
static void import(const struct gem_x64_context *s, struct blink_gem_state *d) {
    memset(d, 0, sizeof(*d));
    d->abi_version = 1;
    d->size = sizeof(*d);
    memcpy(d->gpr, s->gpr, sizeof(d->gpr));
    d->rip = s->rip;
    d->rflags = s->rflags;
    memcpy(d->xmm, s->xmm, sizeof(d->xmm));
    d->mxcsr = s->mxcsr;
    d->fcw = s->fcw;
    d->fsw = s->fsw;
    memcpy(d->x87, s->x87, sizeof(d->x87));
    d->gs_base = s->teb;
}
static void export(const struct blink_gem_state *s, struct gem_x64_context *d) {
    memcpy(d->gpr, s->gpr, sizeof(d->gpr));
    d->rip = s->rip;
    d->rflags = s->rflags;
    memcpy(d->xmm, s->xmm, sizeof(d->xmm));
    d->mxcsr = s->mxcsr;
    d->fcw = s->fcw;
    d->fsw = s->fsw;
    memcpy(d->x87, s->x87, sizeof(d->x87));
    d->teb = s->gs_base;
}
enum gem_stop_reason gem_x64_blink_step(struct gem_x64_runtime *r, const struct gem_x64_context *in,
                                        struct gem_x64_context *out, uint32_t *retired) {
    struct blink_gem_state bi, bo;
    struct blink_gem_result br;
    import(in, &bi);
    br = blink_gem_machine_step(r->backend, &bi, &bo);
    *retired = br.retired;
    r->last_stop.fault_address = br.fault_address;
    r->last_stop.access = (enum gem_x64_memory_access)br.access;
    r->last_stop.memory_error = br.memory_error;
    r->last_stop.engine_status = br.engine_status;
    if (br.outcome == BLINK_GEM_RETIRED) {
        export(&bo, out);
        return br.retired == 1 ? GEM_STOP_NONE : GEM_STOP_INVARIANT_VIOLATION;
    }
    if (br.outcome == BLINK_GEM_MEMORY_FAULT)
        return GEM_STOP_MEMORY_FAULT;
    if (br.outcome == BLINK_GEM_UNSUPPORTED)
        return GEM_STOP_UNSUPPORTED_INSTRUCTION;
    return GEM_STOP_INVARIANT_VIOLATION;
}
const char *gem_x64_blink_version(void) {
    return blink_gem_embedding_version();
}
