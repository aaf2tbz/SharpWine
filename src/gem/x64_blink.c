// SPDX-License-Identifier: Apache-2.0
#include "blink/gem_embed.h"
#include "x64_engine_internal.h"
#include "x64_engine_trace.h"
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
    const struct blink_gem_config config = {BLINK_GEM_CONFIG_ABI_VERSION, sizeof(config),
                                            r->config.engine_mode == GEM_X86_64_ENGINE_JIT
                                                ? BLINK_GEM_ENGINE_JIT
                                                : BLINK_GEM_ENGINE_INTERPRETER,
                                            0};
    r->backend = blink_gem_machine_create_with_config(&config, &c, r);
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
        struct blink_gem_decode_attempt attempt;
        memset(&attempt, 0, sizeof(attempt));
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt);
        export(&bo, out);
        if (br.retired == 1 && blink_gem_machine_decode_attempt_info(r->backend, &attempt) &&
            attempt.valid) {
            r->last_instruction_was_call = attempt.handler_id == BLINK_GEM_HANDLER_OP_CALL_JVDS ||
                                           attempt.handler_id == BLINK_GEM_HANDLER_OP_CALL_EQ;
            r->last_instruction_was_ret = attempt.handler_id == BLINK_GEM_HANDLER_OP_RET;
        }
        return br.retired == 1 ? GEM_STOP_NONE : GEM_STOP_INVARIANT_VIOLATION;
    }
    if (br.outcome == BLINK_GEM_MEMORY_FAULT)
        return GEM_STOP_MEMORY_FAULT;
    if (br.outcome == BLINK_GEM_UNSUPPORTED) {
        struct blink_gem_decode_attempt attempt;
        memset(&attempt, 0, sizeof(attempt));
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt);
        if (blink_gem_machine_decode_attempt_info(r->backend, &attempt) && attempt.valid &&
            strcmp(attempt.name, "OpInterrupt3") == 0)
            return GEM_STOP_WINDOWS_EXCEPTION;
        if (attempt.valid && strcmp(attempt.name, "OpSyscall") == 0) {
            r->last_stop.engine_status = GEM_X64_BOUNDARY_WINDOWS_SYSCALL;
            return GEM_STOP_SYSCALL;
        }
        return GEM_STOP_UNSUPPORTED_INSTRUCTION;
    }
    return GEM_STOP_INVARIANT_VIOLATION;
}
const char *gem_x64_blink_version(void) {
    return blink_gem_embedding_version();
}
bool gem_x64_blink_engine_info(const struct gem_x64_runtime *r,
                               struct gem_x86_64_engine_info *out) {
    struct blink_gem_engine_info info;
    if (!r || !out || out->abi_version != 1U || out->size != sizeof(*out))
        return false;
    memset(&info, 0, sizeof(info));
    info.abi_version = BLINK_GEM_ENGINE_INFO_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_engine_info(r->backend, &info))
        return false;
    out->engine_mode =
        info.engine == BLINK_GEM_ENGINE_JIT ? GEM_X86_64_ENGINE_JIT : GEM_X86_64_ENGINE_INTERPRETER;
    out->host_arch = info.host_arch == BLINK_GEM_HOST_AARCH64 ? GEM_X86_64_HOST_AARCH64
                                                              : GEM_X86_64_HOST_UNKNOWN;
    out->jit_compilations = info.jit_compilations;
    out->jit_executions = info.jit_executions;
    out->jit_failures = info.jit_failures;
    out->write_xor_execute = info.write_xor_execute;
    out->reserved = 0;
    return true;
}
bool gem_x64_blink_invalidate_code(struct gem_x64_runtime *r, uint64_t address, uint64_t size) {
    return r && blink_gem_machine_invalidate_code(r->backend, address, size);
}
void gem_x64_runtime_handler_trace_reset(struct gem_x64_runtime *r) {
    if (r)
        blink_gem_machine_trace_reset(r->backend);
}
bool gem_x64_runtime_handler_trace_info(const struct gem_x64_runtime *r, uint32_t *count,
                                        uint32_t *overflowed) {
    struct blink_gem_trace_info info;
    if (!r)
        return false;
    info.abi_version = BLINK_GEM_TRACE_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_trace_info(r->backend, &info))
        return false;
    if (count)
        *count = info.count;
    if (overflowed)
        *overflowed = info.overflowed;
    return true;
}
bool gem_x64_runtime_handler_trace_read(const struct gem_x64_runtime *r, size_t index,
                                        uint64_t *rip, uint32_t *handler_id) {
    struct blink_gem_trace_entry entry;
    if (!r || !blink_gem_machine_trace_read(r->backend, index, &entry))
        return false;
    if (rip)
        *rip = entry.rip;
    if (handler_id)
        *handler_id = entry.handler_id;
    return true;
}
const char *gem_x64_runtime_handler_name(uint32_t handler_id) {
    return blink_gem_handler_name(handler_id);
}
bool gem_x64_runtime_decode_attempt_info(const struct gem_x64_runtime *r,
                                         struct blink_gem_decode_attempt *out) {
    struct blink_gem_decode_attempt probe;
    if (!r || !out)
        return false;
    /* Validate the caller's struct ABI up front so a future caller ABI drift
     * fails closed at the wrapper boundary instead of silently reading or
     * writing past the destination buffer.  We honour the caller's abi_version
     * and size (rather than overwriting them) so that a mismatched caller is
     * rejected before any Blink-owned storage is touched. */
    if (out->abi_version != BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION || out->size != sizeof(probe))
        return false;
    probe.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
    probe.size = sizeof(probe);
    if (!blink_gem_machine_decode_attempt_info(r->backend, &probe))
        return false;
    /* Copy into caller storage: the Blink-owned name buffer is bounded by
     * BLINK_GEM_DECODE_ATTEMPT_NAME_BYTES and is always NUL-terminated, so a
     * memcpy of the entire struct preserves those invariants. */
    *out = probe;
    return true;
}
