// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"

#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sched.h>
#endif

static void yield_execution(void) {
#if defined(_WIN32)
    (void)SwitchToThread();
#else
    (void)sched_yield();
#endif
}

struct gem_i386_runtime *gem_i386_runtime_create(struct gem_memory *memory,
                                                 const struct gem_i386_runtime_config *config) {
    enum gem_i386_engine_mode mode = GEM_I386_ENGINE_DEFAULT;
    if (config != NULL)
        mode = config->engine_mode;
    return gem_i386_runtime_create_with_ops(memory, config,
                                            mode == GEM_I386_ENGINE_INTERPRETER
                                                ? &gem_i386_blink_interpreter_ops
                                                : &gem_i386_blink_jit_ops);
}

struct gem_i386_runtime *
gem_i386_runtime_create_with_ops(struct gem_memory *memory,
                                 const struct gem_i386_runtime_config *config,
                                 const struct gem_i386_engine_ops *ops) {
    struct gem_i386_runtime *runtime;
    if (memory == NULL || ops == NULL || ops->abi_version != GEM_I386_ENGINE_OPS_ABI_VERSION ||
        (ops->engine_mode != GEM_I386_ENGINE_JIT &&
         ops->engine_mode != GEM_I386_ENGINE_INTERPRETER) ||
        ops->create == NULL || ops->destroy == NULL || ops->sync == NULL || ops->step == NULL ||
        ops->run == NULL || ops->engine_info == NULL || ops->invalidate_code == NULL)
        return NULL;
    runtime = (struct gem_i386_runtime *)calloc(1U, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    runtime->memory = memory;
    runtime->ops = ops;
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
        runtime->config.engine_mode = ops->engine_mode;
    if (runtime->config.engine_mode != ops->engine_mode) {
        free(runtime);
        return NULL;
    }
    if (runtime->config.host_return_sentinel == 0U)
        runtime->config.host_return_sentinel = GEM_I386_DEFAULT_HOST_RETURN_SENTINEL;
    if (runtime->config.windows_syscall_boundary == runtime->config.host_return_sentinel ||
        runtime->config.unix_call_boundary == runtime->config.host_return_sentinel ||
        (runtime->config.windows_syscall_boundary != 0U &&
         runtime->config.windows_syscall_boundary == runtime->config.unix_call_boundary) ||
        !ops->create(runtime)) {
        free(runtime);
        return NULL;
    }
    atomic_init(&runtime->async_stop_requested, false);
    runtime->quantum_budget = 64U;
    runtime->performance.abi_version = GEM_I386_PERFORMANCE_INFO_ABI_VERSION;
    runtime->performance.size = sizeof(runtime->performance);
    return runtime;
}

void gem_i386_runtime_destroy(struct gem_i386_runtime *runtime) {
    if (runtime != NULL) {
        runtime->ops->destroy(runtime);
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
        uint32_t quantum_retired = 0U;
        uint64_t remaining = budget - retired;
        uint32_t quantum_budget = runtime->quantum_budget;
        struct gem_i386_context output;
        struct gem_i386_context quantum_input = *context;
        enum gem_memory_error transaction_error;
        uint64_t transaction_fault = 0U;
        if ((uint64_t)quantum_budget > remaining)
            quantum_budget = (uint32_t)remaining;
        runtime->transaction = gem_memory_transaction_begin(runtime->memory);
        if (runtime->transaction == NULL) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
            break;
        }
        runtime->ops->sync(runtime);
        ++runtime->performance.quanta;
        ++runtime->performance.decode_resets;
        reason = runtime->ops->run(runtime, context, &output, quantum_budget, &quantum_retired);
        transaction_error = gem_memory_transaction_finish(runtime->transaction, &transaction_fault);
        if (transaction_error == GEM_MEMORY_CONFLICT) {
            output = quantum_input;
            quantum_retired = 0U;
            runtime->last_stop.fault_address = (uint32_t)transaction_fault;
            runtime->last_stop.access = GEM_I386_ACCESS_NONE;
            runtime->last_stop.memory_error = GEM_MEMORY_CONFLICT;
            reason = GEM_STOP_MEMORY_FAULT;
        } else if (transaction_error != GEM_MEMORY_OK) {
            reason = GEM_STOP_INVARIANT_VIOLATION;
        }
        if (quantum_retired != 0U || reason == GEM_STOP_NONE || reason == GEM_STOP_HOST_RETURN ||
            reason == GEM_STOP_SYSCALL || reason == GEM_STOP_ASYNC_REQUEST ||
            (reason == GEM_STOP_MEMORY_FAULT &&
             runtime->last_stop.engine_status == GEM_I386_ENGINE_STATUS_RESTARTABLE_REP)) {
            if (!gem_i386_context_is_valid(&output))
                reason = GEM_STOP_INVARIANT_VIOLATION;
            else
                *context = output;
        }
        retired += quantum_retired;
        runtime->performance.retired_instructions += quantum_retired;
        runtime->performance.lock_wait_nanoseconds +=
            gem_memory_transaction_lock_wait_nanoseconds(runtime->transaction);
        gem_memory_transaction_end(runtime->transaction);
        runtime->transaction = NULL;
        if (reason == GEM_STOP_MEMORY_FAULT &&
            runtime->last_stop.memory_error == GEM_MEMORY_CONFLICT) {
            ++runtime->performance.retries;
            ++runtime->consecutive_conflicts;
            if (runtime->quantum_budget > 1U)
                runtime->quantum_budget /= 2U;
            if (runtime->consecutive_conflicts >= 8U) {
                runtime->consecutive_conflicts = 0U;
                yield_execution();
            }
            reason = GEM_STOP_NONE;
            continue;
        }
        runtime->consecutive_conflicts = 0U;
        if (reason == GEM_STOP_NONE) {
            if (runtime->quantum_budget < 256U)
                runtime->quantum_budget *= 2U;
            if (runtime->quantum_budget > 256U)
                runtime->quantum_budget = 256U;
        } else {
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
    if (runtime == NULL)
        return false;
    return runtime->ops->engine_info(runtime, out);
}

bool gem_i386_runtime_performance_info(const struct gem_i386_runtime *runtime,
                                       struct gem_i386_performance_info *out) {
    if (runtime == NULL || out == NULL ||
        out->abi_version != GEM_I386_PERFORMANCE_INFO_ABI_VERSION || out->size != sizeof(*out))
        return false;
    *out = runtime->performance;
    return true;
}

void gem_i386_runtime_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                      uint64_t size) {
    if (runtime != NULL &&
        (runtime->running || !runtime->ops->invalidate_code(runtime, address, size)))
        runtime->backend_failed = true;
}

void gem_i386_runtime_request_async_stop(struct gem_i386_runtime *runtime) {
    if (runtime != NULL)
        atomic_store_explicit(&runtime->async_stop_requested, true, memory_order_release);
}

const char *gem_i386_runtime_engine_name(const struct gem_i386_runtime *runtime) {
    if (runtime == NULL || runtime->ops->engine_name == NULL)
        return "unavailable";
    return runtime->ops->engine_name;
}

const char *gem_i386_runtime_engine_version(const struct gem_i386_runtime *runtime) {
    if (runtime == NULL || runtime->ops->engine_version == NULL)
        return "unavailable";
    return runtime->ops->engine_version;
}

const char *gem_i386_runtime_engine_license(const struct gem_i386_runtime *runtime) {
    return runtime != NULL ? "ISC" : "unavailable";
}

const char *gem_i386_runtime_engine_provenance(const struct gem_i386_runtime *runtime) {
    if (runtime == NULL || runtime->ops->engine_provenance == NULL)
        return "unavailable";
    return runtime->ops->engine_provenance;
}
