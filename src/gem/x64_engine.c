// SPDX-License-Identifier: Apache-2.0
#include "x64_engine_internal.h"
#include <stdlib.h>
#include <string.h>

static uint32_t boundary_status(const struct gem_x64_runtime *r, uint64_t pc) {
    if (r->config.windows_syscall_boundary && pc == r->config.windows_syscall_boundary)
        return GEM_X64_BOUNDARY_WINDOWS_SYSCALL;
    if (r->config.unix_call_boundary && pc == r->config.unix_call_boundary)
        return GEM_X64_BOUNDARY_UNIX_CALL;
    return 0;
}

struct gem_x64_runtime *gem_x64_runtime_create(struct gem_memory *m,
                                               const struct gem_x64_runtime_config *c) {
    struct gem_x64_runtime *r;
    if (!m)
        return 0;
    r = calloc(1, sizeof(*r));
    if (!r)
        return 0;
    atomic_init(&r->async_stop_requested, false);
    r->memory = m;
    if (c)
        r->config = *c;
    if (r->config.reserved || (r->config.engine_mode != GEM_X86_64_ENGINE_DEFAULT &&
                               r->config.engine_mode != GEM_X86_64_ENGINE_JIT &&
                               r->config.engine_mode != GEM_X86_64_ENGINE_INTERPRETER)) {
        free(r);
        return 0;
    }
    if (r->config.engine_mode == GEM_X86_64_ENGINE_DEFAULT)
        r->config.engine_mode = GEM_X86_64_ENGINE_JIT;
    if (!r->config.host_return_sentinel)
        r->config.host_return_sentinel = GEM_X64_DEFAULT_HOST_RETURN_SENTINEL;
    if ((r->config.windows_syscall_boundary &&
         r->config.windows_syscall_boundary == r->config.host_return_sentinel) ||
        (r->config.unix_call_boundary &&
         r->config.unix_call_boundary == r->config.host_return_sentinel) ||
        (r->config.windows_syscall_boundary && r->config.unix_call_boundary &&
         r->config.windows_syscall_boundary == r->config.unix_call_boundary)) {
        free(r);
        return 0;
    }
    if (!gem_x64_blink_create(r)) {
        free(r);
        return 0;
    }
    return r;
}
void gem_x64_runtime_destroy(struct gem_x64_runtime *r) {
    if (r) {
        gem_x64_blink_destroy(r);
        free(r);
    }
}
enum gem_stop_reason gem_x64_runtime_run(struct gem_x64_runtime *r, struct gem_thread_context *c,
                                         uint64_t budget) {
    struct gem_x64_context in, out;
    enum gem_stop_reason reason = GEM_STOP_BUDGET_EXPIRED;
    uint64_t retired = 0;
    if (!r)
        return GEM_STOP_INVARIANT_VIOLATION;
    memset(&r->last_stop, 0, sizeof(r->last_stop));
    r->last_instruction_was_call = false;
    r->last_instruction_was_ret = false;
    if (r->running || r->backend_failed || !gem_context_x64_materialize(c, &in) ||
        (r->config.max_budget && budget > r->config.max_budget)) {
        r->last_stop.reason = GEM_STOP_INVARIANT_VIOLATION;
        return GEM_STOP_INVARIANT_VIOLATION;
    }
    if (!budget) {
        c->stop_reason = GEM_STOP_BUDGET_EXPIRED;
        r->last_stop.reason = GEM_STOP_BUDGET_EXPIRED;
        return GEM_STOP_BUDGET_EXPIRED;
    }
    r->running = true;
    while (retired < budget) {
        uint32_t one = 0;
        if (in.rip == r->config.host_return_sentinel) {
            reason = GEM_STOP_HOST_RETURN;
            break;
        }
        if (atomic_exchange_explicit(&r->async_stop_requested, false, memory_order_acq_rel)) {
            reason = GEM_STOP_ASYNC_REQUEST;
            break;
        }
        const uint32_t boundary = boundary_status(r, in.rip);
        if (boundary) {
            r->last_stop.engine_status = boundary;
            reason = GEM_STOP_SYSCALL;
            break;
        }
        r->transaction = gem_memory_transaction_begin(r->memory);
        if (!r->transaction) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
            break;
        }
        reason = gem_x64_blink_step(r, &in, &out, &one);
        gem_memory_transaction_end(r->transaction);
        r->transaction = 0;
        if (reason != GEM_STOP_NONE)
            break;
        if (one != 1 || !gem_context_x64_commit(&out, c)) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
            break;
        }
        in = out;
        ++retired;
        if (c->pc == r->config.host_return_sentinel) {
            reason = GEM_STOP_HOST_RETURN;
            break;
        }
    }
    r->running = false;
    if (reason == GEM_STOP_NONE)
        reason = GEM_STOP_BUDGET_EXPIRED;
    r->last_stop.reason = reason;
    r->last_stop.instructions_retired = retired;
    if (reason != GEM_STOP_INVARIANT_VIOLATION)
        c->stop_reason = reason;
    return reason;
}
bool gem_x64_runtime_last_stop_info(const struct gem_x64_runtime *r, struct gem_x64_stop_info *o) {
    if (!r || !o)
        return false;
    *o = r->last_stop;
    return true;
}
bool gem_x64_runtime_engine_info(const struct gem_x64_runtime *r,
                                 struct gem_x86_64_engine_info *out) {
    return gem_x64_blink_engine_info(r, out);
}
bool gem_x64_runtime_last_instruction_was_call(const struct gem_x64_runtime *r) {
    return r != NULL && r->last_stop.instructions_retired != 0U && r->last_instruction_was_call;
}
bool gem_x64_runtime_last_instruction_was_ret(const struct gem_x64_runtime *r) {
    return r != NULL && r->last_stop.instructions_retired != 0U && r->last_instruction_was_ret;
}
void gem_x64_runtime_invalidate_code(struct gem_x64_runtime *r, uint64_t a, uint64_t s) {
    if (r && (r->running || !gem_x64_blink_invalidate_code(r, a, s)))
        r->backend_failed = true;
}
void gem_x64_runtime_request_async_stop(struct gem_x64_runtime *r) {
    if (r)
        atomic_store_explicit(&r->async_stop_requested, true, memory_order_release);
}
const char *gem_x64_runtime_engine_name(const struct gem_x64_runtime *r) {
    if (!r)
        return "unavailable";
    return r->config.engine_mode == GEM_X86_64_ENGINE_JIT ? "GEM_x86_64 Blink AArch64 JIT"
                                                          : "GEM_x86_64 Blink interpreter oracle";
}
const char *gem_x64_runtime_engine_version(const struct gem_x64_runtime *r) {
    return r ? gem_x64_blink_version() : "unavailable";
}
const char *gem_x64_runtime_engine_license(const struct gem_x64_runtime *r) {
    return r ? "ISC" : "unavailable";
}
const char *gem_x64_runtime_engine_provenance(const struct gem_x64_runtime *r) {
    if (!r)
        return "unavailable";
    return r->config.engine_mode == GEM_X86_64_ENGINE_JIT
               ? "jart/blink@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580;bounded-aarch64-jit;"
                 "one-instruction-path;patch-sha256="
                 "797f92651c17b86cce97a5bc73dd88e0c014e4f7c8664b4ee4d4c431a8175c80"
               : "jart/blink@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580;interpreter-oracle;"
                 "patch-sha256="
                 "797f92651c17b86cce97a5bc73dd88e0c014e4f7c8664b4ee4d4c431a8175c80";
}
