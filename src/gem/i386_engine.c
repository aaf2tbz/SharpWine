// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"

#include <stdio.h>
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
        ops->run == NULL || ops->engine_info == NULL || ops->block_info == NULL ||
        ops->invalidate_code == NULL)
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
             (runtime->last_stop.engine_status == GEM_I386_ENGINE_STATUS_RESTARTABLE_REP ||
              runtime->last_stop.engine_status == GEM_I386_ENGINE_STATUS_RESTARTABLE_GATHER))) {
            if (!gem_i386_context_is_valid(&output))
                reason = GEM_STOP_INVARIANT_VIOLATION;
            else
                *context = output;
        }
        retired += quantum_retired;
        if (transaction_error == GEM_MEMORY_OK)
            runtime->virtual_tsc += quantum_retired;
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

bool gem_i386_runtime_performance_info_v2(const struct gem_i386_runtime *runtime,
                                          struct gem_i386_performance_info_v2 *out) {
    struct gem_i386_engine_info engine = {0};
    if (runtime == NULL || out == NULL ||
        out->abi_version != GEM_I386_PERFORMANCE_INFO_V2_ABI_VERSION || out->size != sizeof(*out))
        return false;
    engine.abi_version = 1U;
    engine.size = sizeof(engine);
    if (!runtime->ops->engine_info(runtime, &engine))
        return false;
    memset(out, 0, sizeof(*out));
    out->abi_version = GEM_I386_PERFORMANCE_INFO_V2_ABI_VERSION;
    out->size = sizeof(*out);
    out->retired_instructions = runtime->performance.retired_instructions;
    out->quanta = runtime->performance.quanta;
    out->retries = runtime->performance.retries;
    out->page_snapshots = runtime->performance.page_snapshots;
    out->bytes_copied = runtime->performance.bytes_copied;
    out->bytes_committed = runtime->performance.bytes_committed;
    out->state_imports = runtime->performance.state_imports;
    out->state_exports = runtime->performance.state_exports;
    out->decode_resets = runtime->performance.decode_resets;
    out->lock_wait_nanoseconds = runtime->performance.lock_wait_nanoseconds;
    out->jit_compilations = engine.jit_compilations;
    out->jit_executions = engine.jit_executions;
    out->jit_cache_hits = engine.jit_executions > engine.jit_compilations
                              ? engine.jit_executions - engine.jit_compilations
                              : 0U;
    out->jit_failures = engine.jit_failures;
    out->code_invalidations = runtime->code_invalidations;
    return true;
}

bool gem_i386_runtime_diagnostics(const struct gem_i386_runtime *runtime,
                                  struct gem_i386_diagnostics *out) {
    struct gem_i386_engine_info engine = {0};
    struct gem_i386_block_info blocks = {0};
    if (runtime == NULL || out == NULL || out->abi_version != GEM_I386_DIAGNOSTICS_ABI_VERSION ||
        out->size != sizeof(*out))
        return false;
    engine.abi_version = 1U;
    engine.size = sizeof(engine);
    if (!runtime->ops->engine_info(runtime, &engine))
        return false;
    blocks.abi_version = GEM_I386_BLOCK_INFO_ABI_VERSION;
    blocks.size = sizeof(blocks);
    if (!runtime->ops->block_info(runtime, &blocks))
        return false;
    memset(out, 0, sizeof(*out));
    out->abi_version = GEM_I386_DIAGNOSTICS_ABI_VERSION;
    out->size = sizeof(*out);
    out->engine_mode = engine.engine_mode;
    out->host_arch = engine.host_arch;
    out->cpuid_leaf1_ecx = (1U << 0U) | (1U << 1U) | (1U << 9U) | (1U << 12U) | (1U << 19U) |
                           (1U << 20U) | (1U << 23U) | (1U << 25U) | (1U << 26U) | (1U << 27U) |
                           (1U << 28U) | (1U << 30U);
    out->cpuid_leaf1_edx = (1U << 0U) | (1U << 8U) | (1U << 15U) | (1U << 23U) | (1U << 24U) |
                           (1U << 25U) | (1U << 26U);
    out->cpuid_leaf7_ebx =
        (1U << 3U) | (1U << 5U) | (1U << 8U) | (1U << 9U) | (1U << 18U) | (1U << 19U);
    out->cpuid_leaf7_ecx = 1U << 22U;
    out->cpuid_extended1_edx =
        (1U << 0U) | (1U << 8U) | (1U << 15U) | (1U << 23U) | (1U << 24U) | (1U << 27U);
    out->last_unsupported_eip = runtime->last_unsupported_eip;
    out->last_unsupported_mopcode = runtime->last_unsupported_mopcode;
    out->last_unsupported_length = runtime->last_unsupported_length;
    out->jit_compilations = engine.jit_compilations;
    out->jit_executions = engine.jit_executions;
    out->jit_cache_hits = engine.jit_executions > engine.jit_compilations
                              ? engine.jit_executions - engine.jit_compilations
                              : 0U;
    out->jit_failures = engine.jit_failures;
    out->code_invalidations = runtime->code_invalidations;
    out->interpreter_fallbacks = 0U;
    out->unsupported_instructions = runtime->unsupported_instructions;
    snprintf(out->engine_name, sizeof(out->engine_name), "%s", runtime->ops->engine_name);
    snprintf(out->engine_version, sizeof(out->engine_version), "%s", runtime->ops->engine_version);
    memcpy(out->last_unsupported_name, runtime->last_unsupported_name,
           sizeof(out->last_unsupported_name));
    out->blocks_created = blocks.blocks_created;
    out->block_cache_hits = blocks.block_cache_hits;
    out->direct_link_hits = blocks.direct_link_hits;
    out->call_predictions = blocks.call_predictions;
    out->return_predictions = blocks.return_predictions;
    out->return_prediction_hits = blocks.return_prediction_hits;
    out->block_invalidations = blocks.block_invalidations;
    return true;
}

bool gem_i386_runtime_block_info(const struct gem_i386_runtime *runtime,
                                 struct gem_i386_block_info *out) {
    if (runtime == NULL)
        return false;
    return runtime->ops->block_info(runtime, out);
}

void gem_i386_runtime_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                      uint64_t size) {
    if (runtime == NULL)
        return;
    if (runtime->running || !runtime->ops->invalidate_code(runtime, address, size)) {
        runtime->backend_failed = true;
        return;
    }
    ++runtime->code_invalidations;
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
