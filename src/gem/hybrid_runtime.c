// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/hybrid_runtime.h"

#include "hybrid_runtime_internal.h"
#include "memory_internal.h"

#include <stdlib.h>
#include <string.h>

#define GEM_HYBRID_INTERNAL_HOST_RETURN UINT64_C(0xfffffffffffff800)

enum hybrid_stage {
    HYBRID_STAGE_IDLE = 0,
    HYBRID_STAGE_ARM_TO_X64,
    HYBRID_STAGE_ARM_ENTRY,
    HYBRID_STAGE_ARM_RETURN,
    HYBRID_STAGE_CALLBACK_X64,
    HYBRID_STAGE_CALLBACK_ARM_ENTRY
};

enum hybrid_operation {
    HYBRID_OPERATION_NONE = 0,
    HYBRID_OPERATION_ROUNDTRIP_RETURN,
    HYBRID_OPERATION_CALLBACK_RESUME,
    HYBRID_OPERATION_NESTED
};

struct hybrid_frame {
    uint64_t arm_resume_pc;
    uint64_t dispatch_sp;
    uint64_t original_x64_sp;
    uint64_t arm_entry_sp;
    uint64_t x64_return;
    uint64_t callback_target;
    uint64_t callback_call_sp;
    uint64_t callback_record_address;
    uint64_t callback_resume_pc;
    uint64_t callback_original_x64_sp;
    uint64_t callback_arm_entry_sp;
    uint64_t cookie;
    enum hybrid_operation operation;
    bool active;
};

struct gem_hybrid_runtime {
    struct gem_memory *memory;
    struct gem_arm64ec_target_map *map;
    struct gem_arm64ec_runtime *arm;
    struct gem_x64_runtime *x64;
    struct gem_hybrid_runtime_config config;
    struct hybrid_frame frame;
    struct hybrid_frame nested_frame;
    struct gem_hybrid_roundtrip_stats stats;
    struct gem_hybrid_stop_info last_stop;
    enum hybrid_stage stage;
    uint64_t generation;
    bool running;
    enum gem_hybrid_return_mode return_mode;
    uint64_t expected_x64_target;
    uint64_t expected_nested_x64_target;
};

bool gem_hybrid_frame_contract_validate(const struct gem_hybrid_frame_contract *contract) {
    return contract != NULL && contract->active && contract->depth != 0U &&
           contract->depth <= contract->maximum_depth && contract->maximum_depth == 2U &&
           contract->expected_cookie != 0U &&
           contract->observed_cookie == contract->expected_cookie &&
           contract->observed_return_pc == contract->expected_return_pc &&
           contract->observed_sp == contract->expected_sp &&
           contract->observed_original_x64_sp == contract->expected_original_x64_sp &&
           (!contract->require_record ||
            (contract->record_readable && contract->observed_record == contract->expected_record));
}

static bool stack_record_supported(struct gem_memory *memory, uint64_t address) {
    struct gem_memory_transaction *transaction;
    uint8_t page[GEM_GUEST_PAGE_SIZE];
    uint32_t protection = 0U;
    enum gem_memory_error error;
    transaction = gem_memory_transaction_begin(memory);
    if (transaction == NULL)
        return false;
    error = gem_memory_transaction_snapshot_page(
        transaction, address & ~(uint64_t)(GEM_GUEST_PAGE_SIZE - 1U), page, &protection);
    gem_memory_transaction_end(transaction);
    return error == GEM_MEMORY_OK && protection == GEM_PAGE_READWRITE;
}

static enum gem_memory_error replace_stack_record(struct gem_memory *memory, uint64_t address,
                                                  uint64_t value, uint64_t *old_value) {
    struct gem_memory_transaction *transaction;
    struct gem_memory_page_write write;
    uint8_t page[GEM_GUEST_PAGE_SIZE];
    uint32_t protection = 0U;
    uint64_t page_address = address & ~(uint64_t)(GEM_GUEST_PAGE_SIZE - 1U);
    size_t offset = (size_t)(address - page_address);
    enum gem_memory_error error;
    if (offset > GEM_GUEST_PAGE_SIZE - sizeof(value))
        return GEM_MEMORY_INVALID_ARGUMENT;
    transaction = gem_memory_transaction_begin(memory);
    if (transaction == NULL)
        return GEM_MEMORY_INVALID_ARGUMENT;
    error = gem_memory_transaction_snapshot_page(transaction, page_address, page, &protection);
    if (error == GEM_MEMORY_OK && protection != GEM_PAGE_READWRITE)
        error = GEM_MEMORY_ACCESS_DENIED;
    if (error == GEM_MEMORY_OK) {
        if (old_value != NULL)
            memcpy(old_value, page + offset, sizeof(*old_value));
        memcpy(page + offset, &value, sizeof(value));
        write.address = page_address;
        write.data = page;
        error = gem_memory_transaction_commit_pages(transaction, &write, 1U, NULL);
    }
    gem_memory_transaction_end(transaction);
    return error;
}

static enum gem_arm64ec_boundary_action hybrid_boundary(void *opaque, uint64_t pc,
                                                        struct gem_thread_context *context,
                                                        enum gem_arm64ec_boundary_kind *out_kind) {
    struct gem_hybrid_runtime *runtime = (struct gem_hybrid_runtime *)opaque;
    uint64_t callback_record = 0U;
    if (context->x[18] != context->teb)
        return GEM_ARM64EC_BOUNDARY_FAIL;
    if (runtime->stage == HYBRID_STAGE_ARM_TO_X64 && pc == runtime->config.checker_helper) {
        struct gem_arm64ec_target_result target;
        if (runtime->stats.checker_boundaries != 0U)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        if (runtime->return_mode != 0) {
            *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
            if (gem_arm64ec_target_resolve(runtime->map, context->x[11], &target) !=
                    GEM_ARM64EC_TARGET_OK ||
                target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
                target.resolved_va != runtime->expected_x64_target)
                return GEM_ARM64EC_BOUNDARY_FAIL;
        } else {
            *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL_CFG;
            if (gem_arm64ec_checker_dispatch(runtime->map, NULL, false, context, &target) !=
                    GEM_ARM64EC_TARGET_OK ||
                target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
                context->x[11] != context->x[10] ||
                (runtime->expected_x64_target != 0U &&
                 target.resolved_va != runtime->expected_x64_target))
                return GEM_ARM64EC_BOUNDARY_FAIL;
        }
        ++runtime->stats.checker_boundaries;
        context->pc = context->x[30];
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }
    if (runtime->stage == HYBRID_STAGE_CALLBACK_ARM_ENTRY &&
        runtime->frame.operation == HYBRID_OPERATION_NESTED &&
        pc == runtime->config.checker_helper) {
        struct gem_arm64ec_target_result target;
        *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
        if (runtime->stats.checker_boundaries != 1U || runtime->nested_frame.active ||
            gem_arm64ec_target_resolve(runtime->map, context->x[11], &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
            target.resolved_va != runtime->expected_nested_x64_target)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        ++runtime->stats.checker_boundaries;
        context->pc = context->x[30];
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }
    if (runtime->stage == HYBRID_STAGE_ARM_TO_X64 && pc == runtime->config.dispatch_call_helper) {
        struct gem_arm64ec_target_result target;
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
        if (runtime->stats.dispatch_call_boundaries != 0U || runtime->frame.active ||
            gem_arm64ec_target_resolve(runtime->map, context->x[9], &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
            (runtime->expected_x64_target != 0U &&
             target.resolved_va != runtime->expected_x64_target))
            return GEM_ARM64EC_BOUNDARY_FAIL;
        runtime->frame.arm_resume_pc = context->x[30];
        runtime->frame.dispatch_sp = context->sp;
        runtime->frame.x64_return = runtime->config.x64_return_sentinel;
        ++runtime->stats.dispatch_call_boundaries;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }
    if ((runtime->stage == HYBRID_STAGE_ARM_ENTRY ||
         runtime->stage == HYBRID_STAGE_CALLBACK_ARM_ENTRY) &&
        pc == runtime->config.dispatch_ret_helper) {
        const bool callback = runtime->stage == HYBRID_STAGE_CALLBACK_ARM_ENTRY;
        const bool require_record =
            callback && runtime->frame.operation == HYBRID_OPERATION_CALLBACK_RESUME;
        struct gem_hybrid_frame_contract contract;
        bool operation_valid;
        memset(&contract, 0, sizeof(contract));
        if (require_record)
            contract.record_readable =
                gem_memory_read(runtime->memory, runtime->frame.callback_record_address,
                                &callback_record, sizeof(callback_record)) == GEM_MEMORY_OK;
        contract.expected_cookie = runtime->frame.cookie;
        contract.observed_cookie = context->transition_cookie;
        contract.expected_return_pc =
            callback ? runtime->frame.callback_resume_pc : runtime->frame.x64_return;
        contract.observed_return_pc = context->x[30];
        contract.expected_sp =
            callback ? runtime->frame.callback_arm_entry_sp : runtime->frame.arm_entry_sp;
        contract.observed_sp = context->sp;
        contract.expected_original_x64_sp =
            callback ? runtime->frame.callback_original_x64_sp : runtime->frame.original_x64_sp;
        contract.observed_original_x64_sp = context->original_x64_sp;
        contract.expected_record = runtime->frame.callback_resume_pc;
        contract.observed_record = callback_record;
        contract.depth = runtime->nested_frame.active ? 2U : (runtime->frame.active ? 1U : 0U);
        contract.maximum_depth = 2U;
        contract.active = runtime->frame.active;
        contract.require_record = require_record;
        operation_valid = callback
                              ? (runtime->frame.operation == HYBRID_OPERATION_CALLBACK_RESUME ||
                                 runtime->frame.operation == HYBRID_OPERATION_NESTED)
                              : runtime->frame.operation == HYBRID_OPERATION_ROUNDTRIP_RETURN;
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
        /* The non-leaf nested callback's linked ARM64EC prologue reuses the
         * x64 CALL slot while preserving the resume PC in x30. The leaf
         * callback contract instead retains and checks that slot. */
        if (!operation_valid || !gem_hybrid_frame_contract_validate(&contract) ||
            runtime->stats.dispatch_ret_boundaries != 0U)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        ++runtime->stats.dispatch_ret_boundaries;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }
    if (runtime->stage == HYBRID_STAGE_ARM_RETURN && pc == runtime->config.host_return_sentinel) {
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
        context->pc = GEM_HYBRID_INTERNAL_HOST_RETURN;
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }
    return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
}

static bool capture_arm_stop(struct gem_hybrid_runtime *runtime) {
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->last_stop.source = GEM_HYBRID_STOP_SOURCE_ARM64EC;
    if (!gem_arm64ec_runtime_last_stop_info(runtime->arm, &runtime->last_stop.arm64ec))
        return false;
    runtime->last_stop.reason = runtime->last_stop.arm64ec.reason;
    return true;
}

static bool consume_arm_budget(struct gem_hybrid_runtime *runtime, uint64_t *budget) {
    if (!capture_arm_stop(runtime) || runtime->last_stop.arm64ec.instructions_retired > *budget)
        return false;
    runtime->stats.arm64ec_instructions_retired += runtime->last_stop.arm64ec.instructions_retired;
    *budget -= runtime->last_stop.arm64ec.instructions_retired;
    return true;
}

static bool capture_x64_stop(struct gem_hybrid_runtime *runtime) {
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->last_stop.source = GEM_HYBRID_STOP_SOURCE_X64;
    if (!gem_x64_runtime_last_stop_info(runtime->x64, &runtime->last_stop.x64))
        return false;
    runtime->last_stop.reason = runtime->last_stop.x64.reason;
    return true;
}

static void record_broker_stop(struct gem_hybrid_runtime *runtime, enum gem_stop_reason reason) {
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->last_stop.reason = reason;
    runtime->last_stop.source = GEM_HYBRID_STOP_SOURCE_BROKER;
}

struct gem_hybrid_runtime *
gem_hybrid_runtime_create(struct gem_memory *memory, const struct gem_pe_arm64x_image *image,
                          const struct gem_hybrid_runtime_config *config) {
    struct gem_hybrid_runtime *runtime;
    struct gem_arm64ec_runtime_config arm_config;
    struct gem_x64_runtime_config x64_config;
    if (memory == NULL || image == NULL || config == NULL ||
        config->version != GEM_HYBRID_RUNTIME_CONFIG_VERSION || config->reserved != 0U ||
        config->loaded_base == 0U || config->checker_helper == 0U ||
        config->dispatch_call_helper == 0U || config->dispatch_ret_helper == 0U ||
        config->x64_return_sentinel == 0U || config->host_return_sentinel == 0U ||
        config->checker_helper == config->dispatch_call_helper ||
        config->checker_helper == config->dispatch_ret_helper ||
        config->dispatch_call_helper == config->dispatch_ret_helper ||
        config->x64_return_sentinel == config->host_return_sentinel ||
        config->x64_return_sentinel == config->checker_helper ||
        config->x64_return_sentinel == config->dispatch_call_helper ||
        config->x64_return_sentinel == config->dispatch_ret_helper ||
        config->host_return_sentinel == config->checker_helper ||
        config->host_return_sentinel == config->dispatch_call_helper ||
        config->host_return_sentinel == config->dispatch_ret_helper || config->max_budget == 0U)
        return NULL;
    runtime = (struct gem_hybrid_runtime *)calloc(1U, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    runtime->memory = memory;
    runtime->config = *config;
    if (gem_arm64ec_target_map_create(image, config->loaded_base, &runtime->map) !=
        GEM_ARM64EC_TARGET_OK)
        goto Fail;
    memset(&arm_config, 0, sizeof(arm_config));
    arm_config.host_return_sentinel = GEM_HYBRID_INTERNAL_HOST_RETURN;
    arm_config.arch_transition_sentinel = UINT64_C(0xffffffffffffffe0);
    arm_config.max_budget = config->max_budget;
    runtime->arm = gem_arm64ec_runtime_create(memory, &arm_config);
    if (runtime->arm == NULL ||
        !gem_arm64ec_runtime_attach_arm64x(runtime->arm, image, config->loaded_base) ||
        !gem_arm64ec_runtime_set_boundary_broker(runtime->arm, hybrid_boundary, runtime))
        goto Fail;
    memset(&x64_config, 0, sizeof(x64_config));
    x64_config.host_return_sentinel = config->x64_return_sentinel;
    x64_config.max_budget = config->max_budget;
    runtime->x64 = gem_x64_runtime_create(memory, &x64_config);
    if (runtime->x64 == NULL)
        goto Fail;
    return runtime;

Fail:
    gem_hybrid_runtime_destroy(runtime);
    return NULL;
}

bool gem_hybrid_runtime_last_stop_info(const struct gem_hybrid_runtime *runtime,
                                       struct gem_hybrid_stop_info *out_info) {
    if (runtime == NULL || out_info == NULL || runtime->last_stop.reason == GEM_STOP_NONE)
        return false;
    *out_info = runtime->last_stop;
    return true;
}

void gem_hybrid_runtime_destroy(struct gem_hybrid_runtime *runtime) {
    if (runtime != NULL) {
        gem_x64_runtime_destroy(runtime->x64);
        gem_arm64ec_runtime_destroy(runtime->arm);
        gem_arm64ec_target_map_destroy(runtime->map);
        free(runtime);
    }
}

static enum gem_stop_reason fail(struct gem_thread_context *context) {
    if (context != NULL)
        context->stop_reason = GEM_STOP_INVARIANT_VIOLATION;
    return GEM_STOP_INVARIANT_VIOLATION;
}

enum gem_stop_reason gem_hybrid_runtime_run_integer_roundtrip(
    struct gem_hybrid_runtime *runtime, struct gem_thread_context *context, uint64_t caller_va,
    uint64_t finish_va, uint64_t budget, struct gem_hybrid_roundtrip_stats *stats) {
    struct gem_arm64ec_target_result target;
    struct gem_arm64ec_target_result thunk;
    enum gem_stop_reason reason;
    struct gem_thread_context entry_context;
    uint64_t return_record;
    uint64_t overwritten_stack = 0U;
    uint64_t return_record_address = 0U;
    uint64_t original_x64_sp;
    uint64_t descriptor_va;
    bool return_record_written = false;
    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    if (runtime == NULL)
        return fail(context);
    if (context == NULL || runtime->running || runtime->frame.active ||
        !gem_context_is_valid(context) || context->isa != GEM_ISA_ARM64EC ||
        context->pc != caller_va || context->transition_cookie != 0U || budget == 0U ||
        budget > runtime->config.max_budget || context->x[18] != context->teb ||
        context->sp < sizeof(uint64_t) ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t))) {
        record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
        return fail(context);
    }
    entry_context = *context;
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->running = true;
    runtime->stage = HYBRID_STAGE_ARM_TO_X64;
    context->stop_reason = GEM_STOP_NONE;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Budget;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Propagate;
    if (runtime->stats.checker_boundaries != 1U || runtime->stats.dispatch_call_boundaries != 1U)
        goto Invariant;
    if (budget == 0U)
        goto Budget;

    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->frame.cookie = runtime->generation;
    runtime->frame.operation = HYBRID_OPERATION_ROUNDTRIP_RETURN;
    runtime->frame.active = true;
    context->transition_cookie = runtime->frame.cookie;
    ++runtime->stats.frame_pushes;
    runtime->stats.maximum_frame_depth = 1U;
    if (context->sp < sizeof(return_record))
        goto Invariant;
    return_record_address = context->sp - sizeof(return_record);
    context->sp = return_record_address;
    return_record = runtime->frame.x64_return;
    if (replace_stack_record(runtime->memory, return_record_address, return_record,
                             &overwritten_stack) != GEM_MEMORY_OK)
        goto Invariant;
    return_record_written = true;
    if (gem_arm64ec_target_resolve(runtime->map, context->x[9], &target) != GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
        goto Invariant;
    context->pc = target.resolved_va;
    context->isa = GEM_ISA_X64;
    context->stop_reason = GEM_STOP_NONE;

    for (;;) {
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
            goto Invariant;
        if (target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
            break;
        if (budget == 0U)
            goto Budget;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime))
            goto Invariant;
        if (runtime->last_stop.reason != reason || runtime->last_stop.x64.instructions_retired > 1U)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            goto Propagate;
        if (runtime->last_stop.x64.instructions_retired != 1U)
            goto Invariant;
        runtime->stats.x64_instructions_retired += runtime->last_stop.x64.instructions_retired;
        --budget;
        context->stop_reason = GEM_STOP_NONE;
    }
    if (target.kind != GEM_ARM64EC_TARGET_ARM64EC || target.resolved_va != finish_va)
        goto Invariant;
    ++runtime->stats.x64_to_arm64ec_boundaries;
    if (context->sp > UINT64_MAX - sizeof(return_record) ||
        gem_memory_read(runtime->memory, context->sp, &return_record, sizeof(return_record)) !=
            GEM_MEMORY_OK ||
        return_record != runtime->frame.x64_return)
        goto Invariant;
    context->sp += sizeof(return_record);
    original_x64_sp = context->sp;
    runtime->frame.original_x64_sp = original_x64_sp;
    runtime->frame.arm_entry_sp = original_x64_sp & ~UINT64_C(15);
    if (target.resolved_va < 4U)
        goto Invariant;
    descriptor_va = target.resolved_va - 4U;
    if (gem_arm64ec_descriptor_resolve(runtime->map, runtime->memory, descriptor_va, NULL,
                                       &thunk) != GEM_ARM64EC_TARGET_OK)
        goto Invariant;
    ++runtime->stats.descriptor_resolutions;
    context->x[30] = runtime->frame.x64_return;
    context->x[4] = original_x64_sp;
    context->x[9] = target.resolved_va;
    context->original_x64_sp = original_x64_sp;
    context->sp = runtime->frame.arm_entry_sp;
    context->pc = thunk.resolved_va;
    context->isa = GEM_ISA_ARM64EC;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_ARM_ENTRY;
    if (budget == 0U)
        goto Budget;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Budget;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Propagate;
    if (runtime->stats.dispatch_ret_boundaries != 1U || !runtime->frame.active ||
        context->transition_cookie != runtime->frame.cookie)
        goto Invariant;
    if (budget == 0U)
        goto Budget;

    context->pc = runtime->frame.arm_resume_pc;
    context->sp = runtime->frame.dispatch_sp;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_ARM_RETURN;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason != GEM_STOP_HOST_RETURN)
        goto Propagate;
    if (context->pc != GEM_HYBRID_INTERNAL_HOST_RETURN || context->x[18] != context->teb)
        goto Invariant;
    context->pc = runtime->config.host_return_sentinel;
    context->original_x64_sp = entry_context.original_x64_sp;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    context->transition_cookie = 0U;
    ++runtime->stats.frame_pops;
    runtime->stats.final_frame_depth = 0U;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    record_broker_stop(runtime, GEM_STOP_HOST_RETURN);
    if (stats != NULL)
        *stats = runtime->stats;
    return GEM_STOP_HOST_RETURN;

Budget:
    reason = GEM_STOP_BUDGET_EXPIRED;
    if (runtime->last_stop.reason != reason)
        record_broker_stop(runtime, reason);
    context->stop_reason = reason;
    goto FinishFailure;
Propagate:
    if (reason == GEM_STOP_NONE)
        reason = GEM_STOP_INVARIANT_VIOLATION;
    context->stop_reason = reason;
    goto FinishFailure;
Invariant:
    reason = GEM_STOP_INVARIANT_VIOLATION;
    record_broker_stop(runtime, reason);
    context->stop_reason = reason;
FinishFailure:
    if (runtime->frame.active)
        ++runtime->stats.frame_pops;
    if (return_record_written && replace_stack_record(runtime->memory, return_record_address,
                                                      overwritten_stack, NULL) != GEM_MEMORY_OK) {
        reason = GEM_STOP_INVARIANT_VIOLATION;
        record_broker_stop(runtime, reason);
    }
    runtime->frame.active = false;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->stats.final_frame_depth = 0U;
    *context = entry_context;
    context->stop_reason = reason;
    if (stats != NULL)
        *stats = runtime->stats;
    return reason;
}

enum gem_stop_reason gem_hybrid_runtime_run_integer_callback_resume(
    struct gem_hybrid_runtime *runtime, struct gem_thread_context *context, uint64_t callback_va,
    uint64_t expected_resume_va, uint64_t budget, struct gem_hybrid_roundtrip_stats *stats) {
    struct gem_thread_context entry_context;
    struct gem_arm64ec_target_result entry_target, callback_target, resume_target, target, thunk;
    enum gem_stop_reason reason = GEM_STOP_INVARIANT_VIOLATION;
    uint64_t pre_step_sp = 0U, record = 0U, descriptor_va;

    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    if (runtime == NULL)
        return fail(context);
    if (context == NULL || runtime->running || runtime->frame.active ||
        !gem_context_is_valid(context) || context->isa != GEM_ISA_X64 ||
        context->transition_cookie != 0U || context->x[18] != context->teb || budget == 0U ||
        budget > runtime->config.max_budget || callback_va < 4U ||
        gem_arm64ec_target_resolve(runtime->map, context->pc, &entry_target) !=
            GEM_ARM64EC_TARGET_OK ||
        entry_target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        entry_target.resolved_va != context->pc ||
        gem_arm64ec_target_resolve(runtime->map, callback_va, &callback_target) !=
            GEM_ARM64EC_TARGET_OK ||
        callback_target.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        callback_target.resolved_va != callback_va ||
        gem_arm64ec_target_resolve(runtime->map, expected_resume_va, &resume_target) !=
            GEM_ARM64EC_TARGET_OK ||
        resume_target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        resume_target.resolved_va != expected_resume_va) {
        record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
        return fail(context);
    }

    entry_context = *context;
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->running = true;
    runtime->stage = HYBRID_STAGE_CALLBACK_X64;
    context->stop_reason = GEM_STOP_NONE;

    for (;;) {
        if (budget == 0U) {
            reason = GEM_STOP_BUDGET_EXPIRED;
            record_broker_stop(runtime, reason);
            goto Failure;
        }
        pre_step_sp = context->sp;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED || runtime->last_stop.x64.instructions_retired != 1U)
            goto Propagate;
        ++runtime->stats.x64_instructions_retired;
        --budget;
        context->stop_reason = GEM_STOP_NONE;
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
            goto Invariant;
        if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
            if (target.resolved_va != context->pc)
                goto Invariant;
            continue;
        }
        if (target.kind != GEM_ARM64EC_TARGET_ARM64EC || context->pc != callback_va ||
            target.resolved_va != callback_target.resolved_va ||
            !gem_x64_runtime_last_instruction_was_call(runtime->x64) ||
            pre_step_sp < sizeof(record) || context->sp != pre_step_sp - sizeof(record) ||
            gem_memory_read(runtime->memory, context->sp, &record, sizeof(record)) !=
                GEM_MEMORY_OK ||
            record != expected_resume_va)
            goto Invariant;
        break;
    }

    ++runtime->stats.x64_to_arm64ec_boundaries;
    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->frame.cookie = runtime->generation;
    runtime->frame.operation = HYBRID_OPERATION_CALLBACK_RESUME;
    runtime->frame.active = true;
    runtime->frame.callback_target = callback_target.resolved_va;
    runtime->frame.callback_call_sp = pre_step_sp;
    runtime->frame.callback_record_address = context->sp;
    runtime->frame.callback_resume_pc = expected_resume_va;
    runtime->frame.callback_original_x64_sp = pre_step_sp;
    runtime->frame.callback_arm_entry_sp = pre_step_sp & ~UINT64_C(15);
    context->transition_cookie = runtime->frame.cookie;
    ++runtime->stats.frame_pushes;
    runtime->stats.maximum_frame_depth = 1U;
    runtime->stats.final_frame_depth = 1U;

    descriptor_va = callback_target.resolved_va - 4U;
    if (gem_arm64ec_descriptor_resolve(runtime->map, runtime->memory, descriptor_va, NULL,
                                       &thunk) != GEM_ARM64EC_TARGET_OK ||
        thunk.kind != GEM_ARM64EC_TARGET_ARM64EC)
        goto Invariant;
    ++runtime->stats.descriptor_resolutions;
    context->x[30] = expected_resume_va;
    context->x[4] = pre_step_sp;
    context->x[9] = callback_target.resolved_va;
    context->original_x64_sp = pre_step_sp;
    context->sp = runtime->frame.callback_arm_entry_sp;
    context->pc = thunk.resolved_va;
    context->isa = GEM_ISA_ARM64EC;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_CALLBACK_ARM_ENTRY;
    if (budget == 0U) {
        reason = GEM_STOP_BUDGET_EXPIRED;
        record_broker_stop(runtime, reason);
        goto Failure;
    }
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Failure;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Failure;
    if (runtime->stats.dispatch_ret_boundaries != 1U)
        goto Invariant;

    context->pc = expected_resume_va;
    context->sp = pre_step_sp;
    context->isa = GEM_ISA_X64;
    context->original_x64_sp = entry_context.original_x64_sp;
    context->x[18] = context->teb;
    context->transition_cookie = 0U;
    context->stop_reason = GEM_STOP_ARCH_TRANSITION;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    ++runtime->stats.frame_pops;
    runtime->stats.final_frame_depth = 0U;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    record_broker_stop(runtime, GEM_STOP_ARCH_TRANSITION);
    if (stats != NULL)
        *stats = runtime->stats;
    return GEM_STOP_ARCH_TRANSITION;

Propagate:
    if (reason == GEM_STOP_NONE)
        reason = GEM_STOP_INVARIANT_VIOLATION;
    goto Failure;
Invariant:
    reason = GEM_STOP_INVARIANT_VIOLATION;
    record_broker_stop(runtime, reason);
Failure:
    if (runtime->frame.active)
        ++runtime->stats.frame_pops;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->stats.final_frame_depth = 0U;
    *context = entry_context;
    context->stop_reason = reason;
    if (stats != NULL)
        *stats = runtime->stats;
    return reason;
}

enum gem_stop_reason
gem_hybrid_runtime_run_integer_return(struct gem_hybrid_runtime *runtime,
                                      struct gem_thread_context *context,
                                      const struct gem_hybrid_return_control *control,
                                      uint64_t budget, struct gem_hybrid_roundtrip_stats *stats) {
    struct gem_thread_context entry;
    struct gem_arm64ec_target_result start, target;
    enum gem_stop_reason reason = GEM_STOP_INVARIANT_VIOLATION;
    uint64_t remaining = budget, record_address = 0U, old_record = 0U;
    bool record_written = false;

    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    if (runtime == NULL)
        return fail(context);
    if (context == NULL || control == NULL || control->reserved != 0U || runtime->running ||
        runtime->frame.active || !gem_context_is_valid(context) ||
        context->isa != GEM_ISA_ARM64EC || context->pc != control->requested_start_va ||
        context->transition_cookie != 0U || context->x[18] != context->teb || budget == 0U ||
        budget > runtime->config.max_budget ||
        (control->mode != GEM_HYBRID_RETURN_NORMAL && control->mode != GEM_HYBRID_RETURN_TAIL) ||
        control->expected_x64_target_va == 0U ||
        gem_arm64ec_target_resolve(runtime->map, control->requested_start_va, &start) !=
            GEM_ARM64EC_TARGET_OK ||
        start.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        start.resolved_va != control->expected_resolved_start_va ||
        context->sp < sizeof(uint64_t) ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t))) {
        record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
        return fail(context);
    }
    entry = *context;
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->running = true;
    runtime->stage = HYBRID_STAGE_ARM_TO_X64;
    runtime->return_mode = control->mode;
    runtime->expected_x64_target = control->expected_x64_target_va;
    context->pc = start.resolved_va;
    context->stop_reason = GEM_STOP_NONE;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Failure;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Failure;
    if (runtime->stats.checker_boundaries != 1U || runtime->stats.dispatch_call_boundaries != 0U ||
        context->x[18] != entry.x[18] || context->sp != entry.sp || context->x[30] != entry.x[30])
        goto Invariant;
    if (remaining == 0U)
        goto Budget;

    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->frame.cookie = runtime->generation;
    runtime->frame.operation = HYBRID_OPERATION_ROUNDTRIP_RETURN;
    runtime->frame.active = true;
    context->transition_cookie = runtime->frame.cookie;
    ++runtime->stats.frame_pushes;
    runtime->stats.maximum_frame_depth = 1U;
    record_address = context->sp - sizeof(uint64_t);
    if (replace_stack_record(runtime->memory, record_address, runtime->config.x64_return_sentinel,
                             &old_record) != GEM_MEMORY_OK)
        goto Invariant;
    record_written = true;
    context->sp = record_address;
    if (gem_arm64ec_target_resolve(runtime->map, control->expected_x64_target_va, &target) !=
            GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        target.resolved_va != control->expected_x64_target_va)
        goto Invariant;
    context->pc = target.resolved_va;
    context->isa = GEM_ISA_X64;

    while (context->pc != runtime->config.x64_return_sentinel) {
        if (remaining == 0U)
            goto Budget;
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY || target.resolved_va != context->pc)
            goto Invariant;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED && reason != GEM_STOP_HOST_RETURN)
            goto Failure;
        if (runtime->last_stop.x64.instructions_retired != 1U)
            goto Invariant;
        ++runtime->stats.x64_instructions_retired;
        --remaining;
        if (context->pc == runtime->config.x64_return_sentinel) {
            if (reason != GEM_STOP_HOST_RETURN ||
                !gem_x64_runtime_last_instruction_was_ret(runtime->x64))
                goto Invariant;
            break;
        }
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            goto Failure;
        context->stop_reason = GEM_STOP_NONE;
    }
    ++runtime->stats.x64_to_arm64ec_boundaries;
    if (context->sp != record_address + sizeof(uint64_t) ||
        replace_stack_record(runtime->memory, record_address, old_record, NULL) != GEM_MEMORY_OK)
        goto Invariant;
    record_written = false;
    context->x[0] = context->x[8];
    context->isa = GEM_ISA_ARM64EC;
    if (context->sp != entry.sp || context->x[30] != entry.x[30])
        goto Invariant;
    context->pc = context->x[30];
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_ARM_RETURN;
    if (remaining == 0U)
        goto Budget;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason != GEM_STOP_HOST_RETURN || context->pc != GEM_HYBRID_INTERNAL_HOST_RETURN)
        goto Failure;
    context->pc = runtime->config.host_return_sentinel;
    context->transition_cookie = 0U;
    context->original_x64_sp = entry.original_x64_sp;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    ++runtime->stats.frame_pops;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->return_mode = 0;
    runtime->expected_x64_target = 0U;
    record_broker_stop(runtime, GEM_STOP_HOST_RETURN);
    if (stats != NULL)
        *stats = runtime->stats;
    return GEM_STOP_HOST_RETURN;

Budget:
    reason = GEM_STOP_BUDGET_EXPIRED;
    record_broker_stop(runtime, reason);
    goto Failure;
Invariant:
    reason = GEM_STOP_INVARIANT_VIOLATION;
    record_broker_stop(runtime, reason);
Failure:
    if (record_written &&
        replace_stack_record(runtime->memory, record_address, old_record, NULL) != GEM_MEMORY_OK) {
        reason = GEM_STOP_INVARIANT_VIOLATION;
        record_broker_stop(runtime, reason);
    }
    if (runtime->frame.active)
        ++runtime->stats.frame_pops;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    runtime->stats.final_frame_depth = 0U;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->return_mode = 0;
    runtime->expected_x64_target = 0U;
    *context = entry;
    context->stop_reason = reason;
    if (stats != NULL)
        *stats = runtime->stats;
    return reason;
}

enum gem_stop_reason
gem_hybrid_runtime_run_integer_nested(struct gem_hybrid_runtime *runtime,
                                      struct gem_thread_context *context,
                                      const struct gem_hybrid_nested_control *control,
                                      uint64_t budget, struct gem_hybrid_roundtrip_stats *stats) {
    struct gem_thread_context entry;
    struct gem_arm64ec_target_result start, outer, callback, resume, inner, target, thunk;
    enum gem_stop_reason reason = GEM_STOP_INVARIANT_VIOLATION;
    uint64_t remaining = budget;
    uint64_t root_record_address = 0U, root_old_record = 0U;
    uint64_t inner_record_address = 0U, inner_old_record = 0U;
    uint64_t pre_step_sp = 0U, record = 0U;
    bool root_record_written = false, inner_record_written = false;

    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    if (runtime == NULL)
        return fail(context);
    if (context == NULL || control == NULL ||
        control->version != GEM_HYBRID_NESTED_CONTROL_VERSION || control->reserved != 0U ||
        runtime->running || runtime->frame.active || runtime->nested_frame.active ||
        !gem_context_is_valid(context) || context->isa != GEM_ISA_ARM64EC ||
        context->pc != control->requested_start_va || context->transition_cookie != 0U ||
        context->x[18] != context->teb || budget == 0U || budget > runtime->config.max_budget ||
        gem_arm64ec_target_resolve(runtime->map, control->requested_start_va, &start) !=
            GEM_ARM64EC_TARGET_OK ||
        start.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        start.resolved_va != control->expected_resolved_start_va ||
        gem_arm64ec_target_resolve(runtime->map, control->outer_x64_target_va, &outer) !=
            GEM_ARM64EC_TARGET_OK ||
        outer.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        outer.resolved_va != control->outer_x64_target_va ||
        gem_arm64ec_target_resolve(runtime->map, control->callback_va, &callback) !=
            GEM_ARM64EC_TARGET_OK ||
        callback.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        callback.resolved_va != control->callback_va || control->callback_va < 4U ||
        gem_arm64ec_target_resolve(runtime->map, control->outer_resume_va, &resume) !=
            GEM_ARM64EC_TARGET_OK ||
        resume.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        resume.resolved_va != control->outer_resume_va ||
        gem_arm64ec_target_resolve(runtime->map, control->inner_x64_target_va, &inner) !=
            GEM_ARM64EC_TARGET_OK ||
        inner.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        inner.resolved_va != control->inner_x64_target_va || context->sp < sizeof(uint64_t) ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t))) {
        record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
        return fail(context);
    }

    entry = *context;
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->running = true;
    runtime->stage = HYBRID_STAGE_ARM_TO_X64;
    runtime->return_mode = GEM_HYBRID_RETURN_NORMAL;
    runtime->expected_x64_target = outer.resolved_va;
    runtime->expected_nested_x64_target = inner.resolved_va;
    context->pc = start.resolved_va;
    context->stop_reason = GEM_STOP_NONE;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Failure;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Failure;
    if (runtime->stats.checker_boundaries != 1U || context->pc != outer.resolved_va ||
        context->sp != entry.sp || context->x[30] != entry.x[30] || context->x[18] != entry.x[18])
        goto Invariant;
    if (remaining == 0U)
        goto Budget;

    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->frame.cookie = runtime->generation;
    runtime->frame.operation = HYBRID_OPERATION_NESTED;
    runtime->frame.active = true;
    context->transition_cookie = runtime->frame.cookie;
    ++runtime->stats.frame_pushes;
    runtime->stats.maximum_frame_depth = 1U;
    runtime->stats.final_frame_depth = 1U;
    root_record_address = context->sp - sizeof(uint64_t);
    if (replace_stack_record(runtime->memory, root_record_address,
                             runtime->config.x64_return_sentinel,
                             &root_old_record) != GEM_MEMORY_OK)
        goto Invariant;
    root_record_written = true;
    context->sp = root_record_address;
    context->pc = outer.resolved_va;
    context->isa = GEM_ISA_X64;
    context->stop_reason = GEM_STOP_NONE;

    for (;;) {
        if (remaining == 0U)
            goto Budget;
        pre_step_sp = context->sp;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED && reason != GEM_STOP_HOST_RETURN)
            goto Failure;
        if (runtime->last_stop.x64.instructions_retired != 1U)
            goto Invariant;
        ++runtime->stats.x64_instructions_retired;
        --remaining;
        context->stop_reason = GEM_STOP_NONE;
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
            goto Invariant;
        if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
            if (reason != GEM_STOP_BUDGET_EXPIRED || target.resolved_va != context->pc)
                goto Invariant;
            continue;
        }
        if (reason != GEM_STOP_BUDGET_EXPIRED || target.kind != GEM_ARM64EC_TARGET_ARM64EC ||
            target.resolved_va != callback.resolved_va || context->pc != callback.resolved_va ||
            !gem_x64_runtime_last_instruction_was_call(runtime->x64) ||
            pre_step_sp < sizeof(record) || context->sp != pre_step_sp - sizeof(record) ||
            gem_memory_read(runtime->memory, context->sp, &record, sizeof(record)) !=
                GEM_MEMORY_OK ||
            record != resume.resolved_va)
            goto Invariant;
        break;
    }

    ++runtime->stats.x64_to_arm64ec_boundaries;
    runtime->frame.callback_target = callback.resolved_va;
    runtime->frame.callback_call_sp = pre_step_sp;
    runtime->frame.callback_record_address = context->sp;
    runtime->frame.callback_resume_pc = resume.resolved_va;
    runtime->frame.callback_original_x64_sp = pre_step_sp;
    runtime->frame.callback_arm_entry_sp = pre_step_sp & ~UINT64_C(15);
    if (gem_arm64ec_descriptor_resolve(runtime->map, runtime->memory, callback.resolved_va - 4U,
                                       NULL, &thunk) != GEM_ARM64EC_TARGET_OK ||
        thunk.kind != GEM_ARM64EC_TARGET_ARM64EC)
        goto Invariant;
    ++runtime->stats.descriptor_resolutions;
    context->x[30] = resume.resolved_va;
    context->x[4] = pre_step_sp;
    context->x[9] = callback.resolved_va;
    context->original_x64_sp = pre_step_sp;
    context->sp = runtime->frame.callback_arm_entry_sp;
    context->pc = thunk.resolved_va;
    context->isa = GEM_ISA_ARM64EC;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_CALLBACK_ARM_ENTRY;
    if (remaining == 0U)
        goto Budget;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Failure;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Failure;
    if (context->pc != inner.resolved_va || runtime->stats.checker_boundaries != 2U ||
        runtime->stats.dispatch_ret_boundaries != 0U || context->x[18] != context->teb ||
        context->sp < sizeof(uint64_t) ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t)))
        goto Invariant;
    if (remaining == 0U)
        goto Budget;

    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->nested_frame.cookie = runtime->generation;
    runtime->nested_frame.operation = HYBRID_OPERATION_NESTED;
    runtime->nested_frame.active = true;
    runtime->nested_frame.arm_resume_pc = context->x[30];
    runtime->nested_frame.dispatch_sp = context->sp;
    context->transition_cookie = runtime->nested_frame.cookie;
    ++runtime->stats.frame_pushes;
    runtime->stats.maximum_frame_depth = 2U;
    runtime->stats.final_frame_depth = 2U;
    inner_record_address = context->sp - sizeof(uint64_t);
    if (replace_stack_record(runtime->memory, inner_record_address,
                             runtime->config.x64_return_sentinel,
                             &inner_old_record) != GEM_MEMORY_OK)
        goto Invariant;
    inner_record_written = true;
    context->sp = inner_record_address;
    context->pc = inner.resolved_va;
    context->isa = GEM_ISA_X64;
    context->stop_reason = GEM_STOP_NONE;

    while (context->pc != runtime->config.x64_return_sentinel) {
        if (remaining == 0U)
            goto Budget;
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY || target.resolved_va != context->pc)
            goto Invariant;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED && reason != GEM_STOP_HOST_RETURN)
            goto Failure;
        if (runtime->last_stop.x64.instructions_retired != 1U)
            goto Invariant;
        ++runtime->stats.x64_instructions_retired;
        --remaining;
        if (context->pc == runtime->config.x64_return_sentinel) {
            if (reason != GEM_STOP_HOST_RETURN ||
                !gem_x64_runtime_last_instruction_was_ret(runtime->x64))
                goto Invariant;
            break;
        }
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            goto Failure;
        context->stop_reason = GEM_STOP_NONE;
    }
    ++runtime->stats.x64_to_arm64ec_boundaries;
    if (context->sp != inner_record_address + sizeof(uint64_t) ||
        replace_stack_record(runtime->memory, inner_record_address, inner_old_record, NULL) !=
            GEM_MEMORY_OK)
        goto Invariant;
    inner_record_written = false;
    context->x[0] = context->x[8];
    context->isa = GEM_ISA_ARM64EC;
    context->pc = runtime->nested_frame.arm_resume_pc;
    context->sp = runtime->nested_frame.dispatch_sp;
    context->original_x64_sp = runtime->frame.callback_original_x64_sp;
    context->transition_cookie = runtime->frame.cookie;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    memset(&runtime->nested_frame, 0, sizeof(runtime->nested_frame));
    ++runtime->stats.frame_pops;
    runtime->stats.final_frame_depth = 1U;

    if (remaining == 0U)
        goto Budget;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Failure;
    if (reason != GEM_STOP_ARCH_TRANSITION)
        goto Failure;
    if (runtime->stats.dispatch_ret_boundaries != 1U ||
        context->transition_cookie != runtime->frame.cookie)
        goto Invariant;

    context->pc = resume.resolved_va;
    context->sp = runtime->frame.callback_call_sp;
    context->isa = GEM_ISA_X64;
    context->original_x64_sp = entry.original_x64_sp;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    while (context->pc != runtime->config.x64_return_sentinel) {
        if (remaining == 0U)
            goto Budget;
        if (gem_arm64ec_target_resolve(runtime->map, context->pc, &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY || target.resolved_va != context->pc)
            goto Invariant;
        reason = gem_x64_runtime_run(runtime->x64, context, 1U);
        if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason)
            goto Invariant;
        if (reason != GEM_STOP_BUDGET_EXPIRED && reason != GEM_STOP_HOST_RETURN)
            goto Failure;
        if (runtime->last_stop.x64.instructions_retired != 1U)
            goto Invariant;
        ++runtime->stats.x64_instructions_retired;
        --remaining;
        if (context->pc == runtime->config.x64_return_sentinel) {
            if (reason != GEM_STOP_HOST_RETURN ||
                !gem_x64_runtime_last_instruction_was_ret(runtime->x64))
                goto Invariant;
            break;
        }
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            goto Failure;
        context->stop_reason = GEM_STOP_NONE;
    }
    ++runtime->stats.x64_to_arm64ec_boundaries;
    if (context->sp != root_record_address + sizeof(uint64_t) ||
        replace_stack_record(runtime->memory, root_record_address, root_old_record, NULL) !=
            GEM_MEMORY_OK)
        goto Invariant;
    root_record_written = false;
    context->x[0] = context->x[8];
    context->isa = GEM_ISA_ARM64EC;
    context->sp = entry.sp;
    context->x[30] = entry.x[30];
    context->pc = entry.x[30];
    context->original_x64_sp = entry.original_x64_sp;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_ARM_RETURN;
    if (remaining == 0U)
        goto Budget;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, remaining);
    if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
        goto Invariant;
    if (reason != GEM_STOP_HOST_RETURN || context->pc != GEM_HYBRID_INTERNAL_HOST_RETURN)
        goto Failure;

    context->pc = runtime->config.host_return_sentinel;
    context->transition_cookie = 0U;
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    ++runtime->stats.frame_pops;
    runtime->stats.final_frame_depth = 0U;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->return_mode = 0;
    runtime->expected_x64_target = 0U;
    runtime->expected_nested_x64_target = 0U;
    record_broker_stop(runtime, GEM_STOP_HOST_RETURN);
    if (stats != NULL)
        *stats = runtime->stats;
    return GEM_STOP_HOST_RETURN;

Budget:
    reason = GEM_STOP_BUDGET_EXPIRED;
    record_broker_stop(runtime, reason);
    goto Failure;
Invariant:
    reason = GEM_STOP_INVARIANT_VIOLATION;
    record_broker_stop(runtime, reason);
Failure:
    if (inner_record_written && replace_stack_record(runtime->memory, inner_record_address,
                                                     inner_old_record, NULL) != GEM_MEMORY_OK) {
        reason = GEM_STOP_INVARIANT_VIOLATION;
        record_broker_stop(runtime, reason);
    }
    if (root_record_written && replace_stack_record(runtime->memory, root_record_address,
                                                    root_old_record, NULL) != GEM_MEMORY_OK) {
        reason = GEM_STOP_INVARIANT_VIOLATION;
        record_broker_stop(runtime, reason);
    }
    if (runtime->nested_frame.active)
        ++runtime->stats.frame_pops;
    if (runtime->frame.active)
        ++runtime->stats.frame_pops;
    memset(&runtime->nested_frame, 0, sizeof(runtime->nested_frame));
    memset(&runtime->frame, 0, sizeof(runtime->frame));
    runtime->stats.final_frame_depth = 0U;
    runtime->stage = HYBRID_STAGE_IDLE;
    runtime->running = false;
    runtime->return_mode = 0;
    runtime->expected_x64_target = 0U;
    runtime->expected_nested_x64_target = 0U;
    *context = entry;
    context->stop_reason = reason;
    if (stats != NULL)
        *stats = runtime->stats;
    return reason;
}
