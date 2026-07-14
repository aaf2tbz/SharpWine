// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"

#include <stdlib.h>
#include <string.h>

static uint32_t boundary_status(const struct gem_i386_runtime *runtime, uint32_t eip) {
    if (runtime->config.windows_syscall_boundary != 0U &&
        eip == runtime->config.windows_syscall_boundary)
        return GEM_I386_BOUNDARY_WINDOWS_SYSCALL;
    if (runtime->config.unix_call_boundary != 0U && eip == runtime->config.unix_call_boundary)
        return GEM_I386_BOUNDARY_UNIX_CALL;
    return 0U;
}

struct gem_i386_runtime *gem_i386_runtime_create(struct gem_memory *memory,
                                                 const struct gem_i386_runtime_config *config) {
    struct gem_i386_runtime *runtime;
    if (memory == NULL)
        return NULL;
    runtime = (struct gem_i386_runtime *)calloc(1U, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    runtime->memory = memory;
    if (config != NULL)
        runtime->config = *config;
    if ((runtime->config.engine_mode != GEM_I386_ENGINE_DEFAULT &&
         runtime->config.engine_mode != GEM_I386_ENGINE_JIT &&
         runtime->config.engine_mode != GEM_I386_ENGINE_INTERPRETER) ||
        runtime->config.reserved[0] != 0U || runtime->config.reserved[1] != 0U ||
        runtime->config.reserved[2] != 0U || runtime->config.reserved[3] != 0U) {
        free(runtime);
        return NULL;
    }
    if (runtime->config.engine_mode == GEM_I386_ENGINE_DEFAULT)
        runtime->config.engine_mode = GEM_I386_ENGINE_JIT;
    if (runtime->config.host_return_sentinel == 0U)
        runtime->config.host_return_sentinel = GEM_I386_DEFAULT_HOST_RETURN_SENTINEL;
    if (runtime->config.windows_syscall_boundary == runtime->config.host_return_sentinel ||
        runtime->config.unix_call_boundary == runtime->config.host_return_sentinel ||
        (runtime->config.windows_syscall_boundary != 0U &&
         runtime->config.windows_syscall_boundary == runtime->config.unix_call_boundary) ||
        !gem_i386_blink_create(runtime)) {
        free(runtime);
        return NULL;
    }
    atomic_init(&runtime->async_stop_requested, false);
    return runtime;
}

void gem_i386_runtime_destroy(struct gem_i386_runtime *runtime) {
    if (runtime != NULL) {
        gem_i386_blink_destroy(runtime);
        free(runtime);
    }
}

enum gem_stop_reason gem_i386_runtime_run(struct gem_i386_runtime *runtime,
                                          struct gem_i386_context *context, uint64_t budget) {
    enum gem_stop_reason reason = GEM_STOP_BUDGET_EXPIRED;
    uint64_t retired = 0U;
    if (runtime == NULL)
        return GEM_STOP_INVARIANT_VIOLATION;
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    if (runtime->running || runtime->backend_failed || !gem_i386_context_is_valid(context) ||
        (runtime->config.max_budget != 0U && budget > runtime->config.max_budget)) {
        runtime->last_stop.reason = GEM_STOP_INVARIANT_VIOLATION;
        return GEM_STOP_INVARIANT_VIOLATION;
    }
    if (budget == 0U) {
        context->stop_reason = GEM_STOP_BUDGET_EXPIRED;
        runtime->last_stop.reason = GEM_STOP_BUDGET_EXPIRED;
        return GEM_STOP_BUDGET_EXPIRED;
    }
    runtime->running = true;
    while (retired < budget) {
        struct gem_i386_context output;
        uint32_t one = 0U;
        uint32_t boundary;
        if (context->eip == runtime->config.host_return_sentinel) {
            reason = GEM_STOP_HOST_RETURN;
            break;
        }
        if (atomic_exchange_explicit(&runtime->async_stop_requested, false, memory_order_acq_rel)) {
            reason = GEM_STOP_ASYNC_REQUEST;
            break;
        }
        boundary = boundary_status(runtime, context->eip);
        if (boundary != 0U) {
            runtime->last_stop.engine_status = boundary;
            reason = GEM_STOP_SYSCALL;
            break;
        }
        runtime->transaction = gem_memory_transaction_begin(runtime->memory);
        if (runtime->transaction == NULL) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
            break;
        }
        reason = gem_i386_blink_step(runtime, context, &output, &one);
        gem_memory_transaction_end(runtime->transaction);
        runtime->transaction = NULL;
        if (reason != GEM_STOP_NONE)
            break;
        if (one != 1U || !gem_i386_context_is_valid(&output)) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
            break;
        }
        *context = output;
        ++retired;
        if (context->eip == runtime->config.host_return_sentinel) {
            reason = GEM_STOP_HOST_RETURN;
            break;
        }
    }
    runtime->running = false;
    if (reason == GEM_STOP_NONE)
        reason = GEM_STOP_BUDGET_EXPIRED;
    runtime->last_stop.reason = reason;
    runtime->last_stop.instructions_retired = (uint32_t)retired;
    if (reason != GEM_STOP_INVARIANT_VIOLATION)
        context->stop_reason = (uint32_t)reason;
    return reason;
}

bool gem_i386_runtime_last_stop_info(const struct gem_i386_runtime *runtime,
                                     struct gem_i386_stop_info *out) {
    if (runtime == NULL || out == NULL)
        return false;
    *out = runtime->last_stop;
    return true;
}

bool gem_i386_runtime_engine_info(const struct gem_i386_runtime *runtime,
                                  struct gem_i386_engine_info *out) {
    return gem_i386_blink_engine_info(runtime, out);
}

void gem_i386_runtime_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                      uint64_t size) {
    if (runtime != NULL &&
        (runtime->running || !gem_i386_blink_invalidate_code(runtime, address, size)))
        runtime->backend_failed = true;
}

void gem_i386_runtime_request_async_stop(struct gem_i386_runtime *runtime) {
    if (runtime != NULL)
        atomic_store_explicit(&runtime->async_stop_requested, true, memory_order_release);
}

const char *gem_i386_runtime_engine_name(const struct gem_i386_runtime *runtime) {
    if (runtime == NULL)
        return "unavailable";
    return runtime->config.engine_mode == GEM_I386_ENGINE_JIT ? "GEM_i386 Blink AArch64 JIT"
                                                              : "GEM_i386 Blink interpreter";
}

const char *gem_i386_runtime_engine_version(const struct gem_i386_runtime *runtime) {
    return runtime != NULL ? "blink-f006a4fc-gem-i386-v1" : "unavailable";
}

const char *gem_i386_runtime_engine_license(const struct gem_i386_runtime *runtime) {
    return runtime != NULL ? "ISC" : "unavailable";
}

const char *gem_i386_runtime_engine_provenance(const struct gem_i386_runtime *runtime) {
    return runtime != NULL ? "jart/blink@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580;legacy32;"
                             "one-instruction;interpreter-or-aarch64-jit"
                           : "unavailable";
}
