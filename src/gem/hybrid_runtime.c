// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/hybrid_runtime.h"

#include "memory_internal.h"

#include <stdlib.h>
#include <string.h>

#define GEM_HYBRID_INTERNAL_HOST_RETURN UINT64_C(0xfffffffffffff800)

enum hybrid_stage {
    HYBRID_STAGE_IDLE = 0,
    HYBRID_STAGE_ARM_TO_X64,
    HYBRID_STAGE_ARM_ENTRY,
    HYBRID_STAGE_ARM_RETURN
};

struct hybrid_frame {
    uint64_t arm_resume_pc;
    uint64_t dispatch_sp;
    uint64_t original_x64_sp;
    uint64_t arm_entry_sp;
    uint64_t x64_return;
    uint64_t cookie;
    bool active;
};

struct gem_hybrid_runtime {
    struct gem_memory *memory;
    struct gem_arm64ec_target_map *map;
    struct gem_arm64ec_runtime *arm;
    struct gem_x64_runtime *x64;
    struct gem_hybrid_runtime_config config;
    struct hybrid_frame frame;
    struct gem_hybrid_roundtrip_stats stats;
    enum hybrid_stage stage;
    uint64_t generation;
    bool running;
};

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
    if (context->x[18] != context->teb)
        return GEM_ARM64EC_BOUNDARY_FAIL;
    if (runtime->stage == HYBRID_STAGE_ARM_TO_X64 && pc == runtime->config.checker_helper) {
        struct gem_arm64ec_target_result target;
        *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL_CFG;
        if (runtime->stats.checker_boundaries != 0U ||
            gem_arm64ec_checker_dispatch(runtime->map, NULL, false, context, &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY || context->x[11] != context->x[10])
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
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        runtime->frame.arm_resume_pc = context->x[30];
        runtime->frame.dispatch_sp = context->sp;
        runtime->frame.x64_return = runtime->config.x64_return_sentinel;
        ++runtime->stats.dispatch_call_boundaries;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }
    if (runtime->stage == HYBRID_STAGE_ARM_ENTRY && pc == runtime->config.dispatch_ret_helper) {
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
        if (!runtime->frame.active || context->transition_cookie != runtime->frame.cookie ||
            context->x[30] != runtime->frame.x64_return ||
            context->sp != runtime->frame.arm_entry_sp ||
            context->original_x64_sp != runtime->frame.original_x64_sp ||
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

static bool consume_arm_budget(struct gem_hybrid_runtime *runtime, uint64_t *budget) {
    struct gem_arm64ec_stop_info stop;
    if (!gem_arm64ec_runtime_last_stop_info(runtime->arm, &stop) ||
        stop.instructions_retired > *budget)
        return false;
    runtime->stats.arm64ec_instructions_retired += stop.instructions_retired;
    *budget -= stop.instructions_retired;
    return true;
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
    if (runtime == NULL || context == NULL || runtime->running || runtime->frame.active ||
        !gem_context_is_valid(context) || context->isa != GEM_ISA_ARM64EC ||
        context->pc != caller_va || context->transition_cookie != 0U || budget == 0U ||
        budget > runtime->config.max_budget || context->x[18] != context->teb ||
        context->sp < sizeof(uint64_t) ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t)))
        return fail(context);
    entry_context = *context;
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    runtime->running = true;
    runtime->stage = HYBRID_STAGE_ARM_TO_X64;
    context->stop_reason = GEM_STOP_NONE;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget))
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Budget;
    if (reason != GEM_STOP_ARCH_TRANSITION || runtime->stats.checker_boundaries != 1U ||
        runtime->stats.dispatch_call_boundaries != 1U)
        goto Invariant;
    if (budget == 0U)
        goto Budget;

    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    runtime->frame.cookie = runtime->generation;
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
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            goto Propagate;
        ++runtime->stats.x64_instructions_retired;
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
    if (!consume_arm_budget(runtime, &budget))
        goto Invariant;
    if (reason == GEM_STOP_BUDGET_EXPIRED)
        goto Budget;
    if (reason != GEM_STOP_ARCH_TRANSITION || runtime->stats.dispatch_ret_boundaries != 1U ||
        !runtime->frame.active || context->transition_cookie != runtime->frame.cookie)
        goto Invariant;
    if (budget == 0U)
        goto Budget;

    context->pc = runtime->frame.arm_resume_pc;
    context->sp = runtime->frame.dispatch_sp;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->stage = HYBRID_STAGE_ARM_RETURN;
    reason = gem_arm64ec_runtime_run(runtime->arm, context, budget);
    if (!consume_arm_budget(runtime, &budget))
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
    if (stats != NULL)
        *stats = runtime->stats;
    return GEM_STOP_HOST_RETURN;

Budget:
    reason = GEM_STOP_BUDGET_EXPIRED;
    context->stop_reason = reason;
    goto FinishFailure;
Propagate:
    if (reason == GEM_STOP_NONE)
        reason = GEM_STOP_INVARIANT_VIOLATION;
    context->stop_reason = reason;
    goto FinishFailure;
Invariant:
    reason = GEM_STOP_INVARIANT_VIOLATION;
    context->stop_reason = reason;
FinishFailure:
    if (return_record_written && replace_stack_record(runtime->memory, return_record_address,
                                                      overwritten_stack, NULL) != GEM_MEMORY_OK)
        reason = GEM_STOP_INVARIANT_VIOLATION;
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
