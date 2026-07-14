// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/hybrid_runtime.h"

#include "hybrid_runtime_internal.h"
#include "memory_internal.h"

#include <stdatomic.h>
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

enum hybrid_generic_stage {
    HYBRID_GENERIC_IDLE = 0,
    HYBRID_GENERIC_ARM,
    HYBRID_GENERIC_X64,
    HYBRID_GENERIC_ARM_CALLBACK,
};

enum hybrid_generic_callback {
    HYBRID_GENERIC_CALLBACK_NONE = 0,
    HYBRID_GENERIC_CALLBACK_CALL,
    HYBRID_GENERIC_CALLBACK_TAIL,
};

struct hybrid_generic_frame {
    uint64_t cookie;
    uint64_t arm_resume_pc;
    uint64_t arm_resume_sp;
    uint64_t prior_original_x64_sp;
    uint64_t record_address;
    uint64_t old_record;
    uint64_t callback_resume_pc;
    uint64_t callback_pre_call_sp;
    uint64_t callback_arm_entry_sp;
    uint64_t callback_prior_original_x64_sp;
    enum hybrid_generic_callback callback;
    bool record_written;
    bool resume_arm_callback;
    bool callback_nested;
};

struct hybrid_generic_state {
    struct hybrid_generic_frame frames[2];
    enum hybrid_generic_stage stage;
    uint32_t depth;
    uint64_t native_return_pc;
    uint64_t pending_x64_target;
    uint64_t pending_arm_resume_pc;
    uint64_t pending_arm_resume_sp;
    bool active;
    bool pending_dispatch;
    bool pending_callback_return;
    bool pending_native_return;
    uint32_t boundary_failure;
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
    struct hybrid_generic_state generic;
    atomic_bool async_stop_requested;
};

static enum gem_arm64ec_target_status hybrid_resolve(const struct gem_hybrid_runtime *runtime,
                                                     uint64_t requested_va,
                                                     struct gem_arm64ec_target_result *out_target) {
    if (runtime->config.target_resolver != NULL)
        return runtime->config.target_resolver(runtime->config.target_resolver_opaque, requested_va,
                                               out_target);
    return gem_arm64ec_target_resolve(runtime->map, requested_va, out_target);
}

static enum gem_arm64ec_target_status
hybrid_checker_dispatch(const struct gem_hybrid_runtime *runtime,
                        struct gem_thread_context *context,
                        struct gem_arm64ec_target_result *out_target) {
    struct gem_arm64ec_target_result target;
    struct gem_arm64ec_target_result exit_thunk;
    uint64_t original_target;
    enum gem_arm64ec_target_status status;

    if (context == NULL || out_target == NULL || !gem_context_is_valid(context) ||
        context->isa != (uint32_t)GEM_ISA_ARM64EC)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    original_target = context->x[11];
    status = hybrid_resolve(runtime, original_target, &target);
    if (status != GEM_ARM64EC_TARGET_OK)
        return status;
    if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
        status = hybrid_resolve(runtime, context->x[10], &exit_thunk);
        if (status != GEM_ARM64EC_TARGET_OK)
            return status;
        if (exit_thunk.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY)
            return GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
        context->x[9] = original_target;
        context->x[11] = exit_thunk.resolved_va;
    }
    *out_target = target;
    return GEM_ARM64EC_TARGET_OK;
}

static enum gem_arm64ec_target_status
hybrid_descriptor_resolve(const struct gem_hybrid_runtime *runtime, uint64_t descriptor_va,
                          struct gem_arm64ec_target_result *out_target) {
    uint8_t bytes[4];
    uint32_t encoded;
    uint64_t function_va;
    uint64_t offset;

    if (out_target == NULL || descriptor_va > UINT64_MAX - sizeof(bytes))
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    if (gem_memory_read(runtime->memory, descriptor_va, bytes, sizeof(bytes)) != GEM_MEMORY_OK)
        return GEM_ARM64EC_TARGET_MEMORY_FAULT;
    encoded = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) | ((uint32_t)bytes[2] << 16U) |
              ((uint32_t)bytes[3] << 24U);
    function_va = descriptor_va + sizeof(bytes);
    offset = encoded & ~UINT32_C(3);
    if (function_va > UINT64_MAX - offset)
        return GEM_ARM64EC_TARGET_OVERFLOW;
    return hybrid_resolve(runtime, function_va + offset, out_target);
}

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

static struct hybrid_generic_frame *generic_current_frame(struct gem_hybrid_runtime *runtime) {
    if (runtime->generic.depth == 0U || runtime->generic.depth > 2U)
        return NULL;
    return &runtime->generic.frames[runtime->generic.depth - 1U];
}

static enum gem_arm64ec_boundary_action generic_boundary(struct gem_hybrid_runtime *runtime,
                                                         uint64_t pc,
                                                         struct gem_thread_context *context,
                                                         enum gem_arm64ec_boundary_kind *out_kind) {
    struct hybrid_generic_frame *frame;
    struct gem_arm64ec_target_result target;
    uint32_t failure = 0U;

    if (!runtime->generic.active)
        return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
    runtime->generic.boundary_failure = 0U;
    if (context->x[18] != context->teb || (runtime->generic.stage != HYBRID_GENERIC_ARM &&
                                           runtime->generic.stage != HYBRID_GENERIC_ARM_CALLBACK)) {
        runtime->generic.boundary_failure = UINT32_C(0x47420001); /* "GB" + entry */
        return GEM_ARM64EC_BOUNDARY_FAIL;
    }

    if (pc == runtime->config.checker_helper) {
        *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
        if (hybrid_checker_dispatch(runtime, context, &target) != GEM_ARM64EC_TARGET_OK)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        ++runtime->stats.checker_boundaries;
        context->pc = context->x[30];
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }

    if (pc == runtime->config.dispatch_call_helper ||
        (runtime->config.dispatch_jump_helper != 0U &&
         pc == runtime->config.dispatch_jump_helper)) {
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
        if (runtime->generic.pending_dispatch || runtime->generic.depth >= 2U ||
            hybrid_resolve(runtime, context->x[9], &target) != GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        runtime->generic.pending_x64_target = target.resolved_va;
        runtime->generic.pending_arm_resume_pc = context->x[30];
        runtime->generic.pending_arm_resume_sp = context->sp;
        runtime->generic.pending_dispatch = true;
        ++runtime->stats.dispatch_call_boundaries;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }

    if (pc == runtime->config.dispatch_ret_helper) {
        frame = generic_current_frame(runtime);
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
        if (runtime->generic.stage != HYBRID_GENERIC_ARM_CALLBACK)
            failure |= UINT32_C(1) << 0U;
        if (frame == NULL)
            failure |= UINT32_C(1) << 1U;
        if (frame != NULL && frame->callback == HYBRID_GENERIC_CALLBACK_NONE)
            failure |= UINT32_C(1) << 2U;
        if (runtime->generic.pending_callback_return)
            failure |= UINT32_C(1) << 3U;
        if (frame != NULL && context->transition_cookie != frame->cookie)
            failure |= UINT32_C(1) << 4U;
        if (frame != NULL && context->x[30] != frame->callback_resume_pc)
            failure |= UINT32_C(1) << 5U;
        if (frame != NULL && context->sp != frame->callback_arm_entry_sp)
            failure |= UINT32_C(1) << 6U;
        if (frame != NULL && context->original_x64_sp != frame->callback_pre_call_sp)
            failure |= UINT32_C(1) << 7U;
        if (failure != 0U) {
            runtime->generic.boundary_failure = UINT32_C(0x47520000) | failure; /* "GR" */
            return GEM_ARM64EC_BOUNDARY_FAIL;
        }
        /* The x64 CALL record sits eight bytes below the restored x64 SP.
         * ARM64EC entry thunks legitimately reuse that dead slot as the x30
         * half of a standard `stp x29,x30,[sp,#-16]!` prologue. The
         * coordinator already owns and validates the resume PC in both the
         * frame and x30, so the scratch slot is not a return authority. */
        runtime->generic.pending_callback_return = true;
        ++runtime->stats.dispatch_ret_boundaries;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }

    if (runtime->generic.depth == 0U && runtime->generic.stage == HYBRID_GENERIC_ARM &&
        pc == runtime->generic.native_return_pc) {
        *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
        runtime->generic.pending_native_return = true;
        return GEM_ARM64EC_BOUNDARY_STOP;
    }
    return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
}

static enum gem_arm64ec_boundary_action hybrid_boundary(void *opaque, uint64_t pc,
                                                        struct gem_thread_context *context,
                                                        enum gem_arm64ec_boundary_kind *out_kind) {
    struct gem_hybrid_runtime *runtime = (struct gem_hybrid_runtime *)opaque;
    uint64_t callback_record = 0U;
    if (runtime->generic.active)
        return generic_boundary(runtime, pc, context, out_kind);
    if (context->x[18] != context->teb)
        return GEM_ARM64EC_BOUNDARY_FAIL;
    if (runtime->stage == HYBRID_STAGE_ARM_TO_X64 && pc == runtime->config.checker_helper) {
        struct gem_arm64ec_target_result target;
        if (runtime->stats.checker_boundaries != 0U)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        if (runtime->return_mode != 0) {
            *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
            if (hybrid_resolve(runtime, context->x[11], &target) != GEM_ARM64EC_TARGET_OK ||
                target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
                target.resolved_va != runtime->expected_x64_target)
                return GEM_ARM64EC_BOUNDARY_FAIL;
        } else {
            *out_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL_CFG;
            if (hybrid_checker_dispatch(runtime, context, &target) != GEM_ARM64EC_TARGET_OK ||
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
            hybrid_resolve(runtime, context->x[11], &target) != GEM_ARM64EC_TARGET_OK ||
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
            hybrid_resolve(runtime, context->x[9], &target) != GEM_ARM64EC_TARGET_OK ||
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
    if (runtime->last_stop.arm64ec.reason == GEM_STOP_INVARIANT_VIOLATION &&
        runtime->last_stop.arm64ec.engine_status == GEM_ARM64EC_BOUNDARY_FAIL &&
        runtime->generic.boundary_failure != 0U) {
        runtime->last_stop.arm64ec.engine_status = runtime->generic.boundary_failure;
    }
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
        config->version != GEM_HYBRID_RUNTIME_CONFIG_VERSION ||
        config->boundary_delivery < GEM_ARM64EC_BOUNDARY_PRECISE ||
        config->boundary_delivery > GEM_ARM64EC_BOUNDARY_SVC_TRAP || config->loaded_base == 0U ||
        config->checker_helper == 0U || config->dispatch_call_helper == 0U ||
        config->dispatch_ret_helper == 0U || config->x64_return_sentinel == 0U ||
        config->host_return_sentinel == 0U ||
        config->checker_helper == config->dispatch_call_helper ||
        config->checker_helper == config->dispatch_ret_helper ||
        config->dispatch_call_helper == config->dispatch_ret_helper ||
        (config->dispatch_jump_helper != 0U &&
         (config->dispatch_jump_helper == config->checker_helper ||
          config->dispatch_jump_helper == config->dispatch_call_helper ||
          config->dispatch_jump_helper == config->dispatch_ret_helper)) ||
        config->x64_return_sentinel == config->host_return_sentinel ||
        config->x64_return_sentinel == config->checker_helper ||
        config->x64_return_sentinel == config->dispatch_call_helper ||
        config->x64_return_sentinel == config->dispatch_ret_helper ||
        (config->dispatch_jump_helper != 0U &&
         config->x64_return_sentinel == config->dispatch_jump_helper) ||
        config->host_return_sentinel == config->checker_helper ||
        config->host_return_sentinel == config->dispatch_call_helper ||
        config->host_return_sentinel == config->dispatch_ret_helper ||
        (config->dispatch_jump_helper != 0U &&
         config->host_return_sentinel == config->dispatch_jump_helper) ||
        config->max_budget == 0U ||
        (config->target_resolver == NULL) != (config->target_resolver_opaque == NULL))
        return NULL;
    runtime = (struct gem_hybrid_runtime *)calloc(1U, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    runtime->memory = memory;
    runtime->config = *config;
    atomic_init(&runtime->async_stop_requested, false);
    if (gem_arm64ec_target_map_create(image, config->loaded_base, &runtime->map) !=
        GEM_ARM64EC_TARGET_OK)
        goto Fail;
    memset(&arm_config, 0, sizeof(arm_config));
    arm_config.host_return_sentinel = GEM_HYBRID_INTERNAL_HOST_RETURN;
    arm_config.arch_transition_sentinel = UINT64_C(0xffffffffffffffe0);
    arm_config.max_budget = config->max_budget;
    arm_config.boundary_delivery = config->boundary_delivery;
    runtime->arm = gem_arm64ec_runtime_create(memory, &arm_config);
    if (runtime->arm == NULL ||
        !gem_arm64ec_runtime_attach_arm64x(runtime->arm, image, config->loaded_base) ||
        (config->target_resolver != NULL &&
         !gem_arm64ec_runtime_set_target_resolver(runtime->arm, config->target_resolver,
                                                  config->target_resolver_opaque)) ||
        !gem_arm64ec_runtime_set_boundary_broker(runtime->arm, hybrid_boundary, runtime))
        goto Fail;
    memset(&x64_config, 0, sizeof(x64_config));
    x64_config.host_return_sentinel = config->x64_return_sentinel;
    x64_config.max_budget = config->max_budget;
    x64_config.engine_mode = GEM_X86_64_ENGINE_INTERPRETER;
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

bool gem_hybrid_runtime_coordinator_active(const struct gem_hybrid_runtime *runtime) {
    return runtime != NULL && runtime->generic.active;
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

static bool generic_context_valid(const struct gem_hybrid_runtime *runtime,
                                  const struct gem_thread_context *context) {
    const struct hybrid_generic_frame *frame = NULL;
    uint64_t expected_cookie = 0U;
    uint32_t expected_isa = GEM_ISA_ARM64EC;

    if (context == NULL || !gem_context_is_valid(context) || context->x[18] != context->teb ||
        runtime->generic.depth > 2U)
        return false;
    if (runtime->generic.depth != 0U) {
        frame = &runtime->generic.frames[runtime->generic.depth - 1U];
        expected_cookie = frame->cookie;
    }
    if (runtime->generic.stage == HYBRID_GENERIC_X64)
        expected_isa = GEM_ISA_X64;
    else if (runtime->generic.stage != HYBRID_GENERIC_ARM &&
             runtime->generic.stage != HYBRID_GENERIC_ARM_CALLBACK)
        return false;
    return context->isa == expected_isa && context->transition_cookie == expected_cookie;
}

static void generic_publish_stats(struct gem_hybrid_runtime *runtime,
                                  struct gem_hybrid_roundtrip_stats *stats) {
    runtime->stats.final_frame_depth = runtime->generic.depth;
    if (stats != NULL)
        *stats = runtime->stats;
}

static enum gem_stop_reason generic_return(struct gem_hybrid_runtime *runtime,
                                           struct gem_thread_context *context,
                                           enum gem_stop_reason reason,
                                           struct gem_hybrid_roundtrip_stats *stats) {
    context->stop_reason = reason;
    runtime->running = false;
    generic_publish_stats(runtime, stats);
    return reason;
}

static bool generic_restore_records(struct gem_hybrid_runtime *runtime) {
    bool restored = true;
    uint32_t depth;
    for (depth = runtime->generic.depth; depth != 0U; --depth) {
        struct hybrid_generic_frame *frame = &runtime->generic.frames[depth - 1U];
        if (frame->record_written && replace_stack_record(runtime->memory, frame->record_address,
                                                          frame->old_record, NULL) != GEM_MEMORY_OK)
            restored = false;
    }
    return restored;
}

static enum gem_stop_reason generic_invariant_at(struct gem_hybrid_runtime *runtime,
                                                 struct gem_thread_context *context,
                                                 struct gem_hybrid_roundtrip_stats *stats,
                                                 uint32_t source_line) {
    (void)generic_restore_records(runtime);
    memset(&runtime->generic, 0, sizeof(runtime->generic));
    record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
    /* Broker failures otherwise look like an engine stop with all-zero
     * detail at Wine's boundary. Preserve the rejected PC and a stable build
     * diagnostic (the coordinator source line) without changing canonical
     * context or selecting an engine-owned stop source. */
    runtime->last_stop.arm64ec.fault_address = context->pc;
    runtime->last_stop.arm64ec.engine_status = source_line;
    context->transition_cookie = 0U;
    context->isa = GEM_ISA_ARM64EC;
    return generic_return(runtime, context, GEM_STOP_INVARIANT_VIOLATION, stats);
}

#define generic_invariant(runtime, context, stats)                                                 \
    generic_invariant_at((runtime), (context), (stats), (uint32_t)__LINE__)

static bool generic_push_x64(struct gem_hybrid_runtime *runtime, struct gem_thread_context *context,
                             uint64_t target_va, uint64_t arm_resume_pc, uint64_t arm_resume_sp) {
    struct hybrid_generic_frame *frame;
    struct hybrid_generic_frame *parent;
    struct gem_arm64ec_target_result target;
    const bool resume_arm_callback = runtime->generic.stage == HYBRID_GENERIC_ARM_CALLBACK;

    if (runtime->generic.depth >= 2U || context->sp < sizeof(uint64_t) ||
        context->sp != arm_resume_sp ||
        hybrid_resolve(runtime, target_va, &target) != GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        !stack_record_supported(runtime->memory, context->sp - sizeof(uint64_t)))
        return false;
    parent = generic_current_frame(runtime);
    if (resume_arm_callback) {
        if (parent == NULL || parent->callback == HYBRID_GENERIC_CALLBACK_NONE)
            return false;
        parent->callback_nested = true;
    }
    frame = &runtime->generic.frames[runtime->generic.depth];
    memset(frame, 0, sizeof(*frame));
    runtime->generation = runtime->generation == UINT64_MAX ? 1U : runtime->generation + 1U;
    frame->cookie = runtime->generation;
    frame->arm_resume_pc = arm_resume_pc;
    frame->arm_resume_sp = arm_resume_sp;
    frame->prior_original_x64_sp = context->original_x64_sp;
    frame->record_address = context->sp - sizeof(uint64_t);
    frame->resume_arm_callback = resume_arm_callback;
    if (replace_stack_record(runtime->memory, frame->record_address,
                             runtime->config.x64_return_sentinel,
                             &frame->old_record) != GEM_MEMORY_OK) {
        memset(frame, 0, sizeof(*frame));
        return false;
    }
    frame->record_written = true;
    ++runtime->generic.depth;
    ++runtime->stats.frame_pushes;
    if (runtime->generic.depth > runtime->stats.maximum_frame_depth)
        runtime->stats.maximum_frame_depth = runtime->generic.depth;
    context->sp = frame->record_address;
    context->pc = target.resolved_va;
    context->isa = GEM_ISA_X64;
    context->transition_cookie = frame->cookie;
    context->stop_reason = GEM_STOP_NONE;
    runtime->generic.stage = HYBRID_GENERIC_X64;
    return true;
}

static bool generic_pop_x64(struct gem_hybrid_runtime *runtime,
                            struct gem_thread_context *context) {
    struct hybrid_generic_frame frame;
    struct hybrid_generic_frame *outer;

    if (runtime->generic.depth == 0U)
        return false;
    frame = runtime->generic.frames[runtime->generic.depth - 1U];
    if (!frame.record_written || context->sp != frame.record_address + sizeof(uint64_t) ||
        replace_stack_record(runtime->memory, frame.record_address, frame.old_record, NULL) !=
            GEM_MEMORY_OK)
        return false;
    memset(&runtime->generic.frames[runtime->generic.depth - 1U], 0,
           sizeof(runtime->generic.frames[0]));
    --runtime->generic.depth;
    ++runtime->stats.frame_pops;
    context->x[0] = context->x[8];
    context->pc = frame.arm_resume_pc;
    context->sp = frame.arm_resume_sp;
    context->original_x64_sp = frame.prior_original_x64_sp;
    context->isa = GEM_ISA_ARM64EC;
    outer = generic_current_frame(runtime);
    context->transition_cookie = outer != NULL ? outer->cookie : 0U;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->generic.stage =
        frame.resume_arm_callback ? HYBRID_GENERIC_ARM_CALLBACK : HYBRID_GENERIC_ARM;
    return true;
}

static bool generic_enter_callback(struct gem_hybrid_runtime *runtime,
                                   struct gem_thread_context *context,
                                   const struct gem_arm64ec_target_result *target,
                                   uint64_t pre_step_sp, bool was_call) {
    struct hybrid_generic_frame *frame = generic_current_frame(runtime);
    struct gem_arm64ec_target_result thunk;
    uint64_t record = 0U;
    uint64_t original_x64_sp;

    if (frame == NULL || frame->callback != HYBRID_GENERIC_CALLBACK_NONE ||
        target->resolved_va < sizeof(uint32_t))
        return false;
    if (was_call) {
        if (pre_step_sp < sizeof(uint64_t) || context->sp != pre_step_sp - sizeof(uint64_t) ||
            gem_memory_read(runtime->memory, context->sp, &record, sizeof(record)) != GEM_MEMORY_OK)
            return false;
        frame->callback = HYBRID_GENERIC_CALLBACK_CALL;
        frame->callback_resume_pc = record;
        original_x64_sp = pre_step_sp;
    } else {
        if (context->sp != frame->record_address ||
            gem_memory_read(runtime->memory, context->sp, &record, sizeof(record)) !=
                GEM_MEMORY_OK ||
            record != runtime->config.x64_return_sentinel)
            return false;
        frame->callback = HYBRID_GENERIC_CALLBACK_TAIL;
        frame->callback_resume_pc = runtime->config.x64_return_sentinel;
        original_x64_sp = context->sp + sizeof(uint64_t);
        context->sp = original_x64_sp;
    }
    if (hybrid_descriptor_resolve(runtime, target->resolved_va - sizeof(uint32_t), &thunk) !=
            GEM_ARM64EC_TARGET_OK ||
        thunk.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
        frame->callback = HYBRID_GENERIC_CALLBACK_NONE;
        return false;
    }
    frame->callback_pre_call_sp = original_x64_sp;
    frame->callback_arm_entry_sp = original_x64_sp & ~UINT64_C(15);
    frame->callback_prior_original_x64_sp = context->original_x64_sp;
    ++runtime->stats.x64_to_arm64ec_boundaries;
    ++runtime->stats.descriptor_resolutions;
    context->x[30] = frame->callback_resume_pc;
    context->x[4] = original_x64_sp;
    context->x[9] = target->resolved_va;
    context->original_x64_sp = original_x64_sp;
    context->sp = frame->callback_arm_entry_sp;
    context->pc = thunk.resolved_va;
    context->isa = GEM_ISA_ARM64EC;
    context->x[18] = context->teb;
    context->stop_reason = GEM_STOP_NONE;
    runtime->generic.stage = HYBRID_GENERIC_ARM_CALLBACK;
    return true;
}

static bool generic_finish_callback(struct gem_hybrid_runtime *runtime,
                                    struct gem_thread_context *context) {
    struct hybrid_generic_frame *frame = generic_current_frame(runtime);
    enum hybrid_generic_callback callback;

    if (frame == NULL || frame->callback == HYBRID_GENERIC_CALLBACK_NONE)
        return false;
    callback = frame->callback;
    runtime->generic.pending_callback_return = false;
    if (callback == HYBRID_GENERIC_CALLBACK_CALL) {
        context->pc = frame->callback_resume_pc;
        context->sp = frame->callback_pre_call_sp;
        context->original_x64_sp = frame->callback_prior_original_x64_sp;
        context->isa = GEM_ISA_X64;
        context->transition_cookie = frame->cookie;
        context->stop_reason = GEM_STOP_NONE;
        frame->callback = HYBRID_GENERIC_CALLBACK_NONE;
        frame->callback_resume_pc = 0U;
        frame->callback_pre_call_sp = 0U;
        frame->callback_arm_entry_sp = 0U;
        frame->callback_prior_original_x64_sp = 0U;
        runtime->generic.stage = HYBRID_GENERIC_X64;
        return true;
    }
    /* A tail transfer uses the coordinator-owned sentinel as its x64 return.
     * Model the completed ARM64EC return as that sentinel's checked RET. */
    context->sp = frame->record_address + sizeof(uint64_t);
    return generic_pop_x64(runtime, context);
}

static bool generic_begin(struct gem_hybrid_runtime *runtime, struct gem_thread_context *context) {
    struct gem_arm64ec_target_result target;
    if (context->isa != GEM_ISA_ARM64EC || context->transition_cookie != 0U ||
        context->x[18] != context->teb || context->x[30] == 0U ||
        hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK ||
        target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY)
        return false;
    memset(&runtime->generic, 0, sizeof(runtime->generic));
    runtime->generic.active = true;
    runtime->generic.stage = HYBRID_GENERIC_ARM;
    /* A Wine resume can enter at the caller PC while x30 still names that
     * same PC; the caller has not yet restored its own link register. SVC
     * delivery therefore runs ARM64EC frames continuously until the explicit
     * bridge host sentinel instead of synthesizing a zero-progress return. */
    runtime->generic.native_return_pc =
        runtime->config.boundary_delivery == GEM_ARM64EC_BOUNDARY_SVC_TRAP
            ? runtime->config.host_return_sentinel
            : context->x[30];
    context->pc = target.resolved_va;
    return true;
}

enum gem_stop_reason gem_hybrid_runtime_run(struct gem_hybrid_runtime *runtime,
                                            struct gem_thread_context *context, uint64_t budget,
                                            struct gem_hybrid_roundtrip_stats *stats) {
    enum gem_stop_reason reason = GEM_STOP_INVARIANT_VIOLATION;
    uint64_t remaining = budget;

    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    if (runtime == NULL)
        return fail(context);
    if (context == NULL || runtime->running || !gem_context_is_valid(context) || budget == 0U ||
        budget > runtime->config.max_budget || context->stop_reason != GEM_STOP_NONE ||
        (!runtime->generic.active && !generic_begin(runtime, context)) ||
        !generic_context_valid(runtime, context)) {
        record_broker_stop(runtime, GEM_STOP_INVARIANT_VIOLATION);
        return fail(context);
    }
    memset(&runtime->stats, 0, sizeof(runtime->stats));
    memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
    runtime->stats.maximum_frame_depth = runtime->generic.depth;
    runtime->running = true;

    for (;;) {
        struct gem_arm64ec_target_result target;
        if (atomic_exchange_explicit(&runtime->async_stop_requested, false, memory_order_acq_rel)) {
            record_broker_stop(runtime, GEM_STOP_ASYNC_REQUEST);
            return generic_return(runtime, context, GEM_STOP_ASYNC_REQUEST, stats);
        }
        if (remaining == 0U) {
            if (runtime->last_stop.reason != GEM_STOP_BUDGET_EXPIRED)
                record_broker_stop(runtime, GEM_STOP_BUDGET_EXPIRED);
            return generic_return(runtime, context, GEM_STOP_BUDGET_EXPIRED, stats);
        }

        if (runtime->generic.stage == HYBRID_GENERIC_ARM ||
            runtime->generic.stage == HYBRID_GENERIC_ARM_CALLBACK) {
            const uint64_t arm_budget =
                runtime->config.boundary_delivery == GEM_ARM64EC_BOUNDARY_SVC_TRAP
                    ? remaining
                    : (remaining < UINT64_C(4096) ? remaining : UINT64_C(4096));
            if (runtime->config.boundary_delivery == GEM_ARM64EC_BOUNDARY_SVC_TRAP &&
                !gem_arm64ec_runtime_set_boundary_return_pc(
                    runtime->arm,
                    runtime->generic.stage == HYBRID_GENERIC_ARM && runtime->generic.depth == 0U
                        ? runtime->generic.native_return_pc
                        : 0U))
                return generic_invariant(runtime, context, stats);
            reason = gem_arm64ec_runtime_run(runtime->arm, context, arm_budget);
            if (!consume_arm_budget(runtime, &remaining) || runtime->last_stop.reason != reason)
                return generic_invariant(runtime, context, stats);
            if (reason == GEM_STOP_BUDGET_EXPIRED) {
                /* The ARM backend may yield before consuming the caller's
                 * exact remainder when the next translated block is larger
                 * than that remainder. Preserve the stateful sidecar and let
                 * Wine resume with a fresh segment budget. */
                return generic_return(runtime, context, reason, stats);
            }
            if (reason != GEM_STOP_ARCH_TRANSITION)
                return generic_return(runtime, context, reason, stats);
            if (runtime->generic.pending_native_return) {
                if (runtime->generic.depth != 0U ||
                    context->pc != runtime->generic.native_return_pc)
                    return generic_invariant(runtime, context, stats);
                memset(&runtime->generic, 0, sizeof(runtime->generic));
                context->transition_cookie = 0U;
                context->isa = GEM_ISA_ARM64EC;
                record_broker_stop(runtime, GEM_STOP_ARCH_TRANSITION);
                return generic_return(runtime, context, GEM_STOP_ARCH_TRANSITION, stats);
            }
            if (runtime->generic.pending_callback_return) {
                if (!generic_finish_callback(runtime, context))
                    return generic_invariant(runtime, context, stats);
                continue;
            }
            if (runtime->generic.pending_dispatch) {
                const uint64_t x64_target = runtime->generic.pending_x64_target;
                const uint64_t resume_pc = runtime->generic.pending_arm_resume_pc;
                const uint64_t resume_sp = runtime->generic.pending_arm_resume_sp;
                runtime->generic.pending_dispatch = false;
                runtime->generic.pending_x64_target = 0U;
                runtime->generic.pending_arm_resume_pc = 0U;
                runtime->generic.pending_arm_resume_sp = 0U;
                if (!generic_push_x64(runtime, context, x64_target, resume_pc, resume_sp))
                    return generic_invariant(runtime, context, stats);
                continue;
            }
            if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK ||
                target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
                !generic_push_x64(runtime, context, target.resolved_va, context->x[30],
                                  context->sp))
                return generic_invariant(runtime, context, stats);
            continue;
        }

        if (runtime->generic.stage == HYBRID_GENERIC_X64) {
            const uint64_t pre_step_sp = context->sp;
            reason = gem_x64_runtime_run(runtime->x64, context, 1U);
            if (!capture_x64_stop(runtime) || runtime->last_stop.reason != reason ||
                runtime->last_stop.x64.instructions_retired > remaining)
                return generic_invariant(runtime, context, stats);
            runtime->stats.x64_instructions_retired += runtime->last_stop.x64.instructions_retired;
            remaining -= runtime->last_stop.x64.instructions_retired;
            if (reason != GEM_STOP_BUDGET_EXPIRED && reason != GEM_STOP_HOST_RETURN)
                return generic_return(runtime, context, reason, stats);
            if (runtime->last_stop.x64.instructions_retired != 1U)
                return generic_invariant(runtime, context, stats);
            if (context->pc == runtime->config.x64_return_sentinel) {
                if (reason != GEM_STOP_HOST_RETURN ||
                    !gem_x64_runtime_last_instruction_was_ret(runtime->x64) ||
                    !generic_pop_x64(runtime, context))
                    return generic_invariant(runtime, context, stats);
                continue;
            }
            if (reason != GEM_STOP_BUDGET_EXPIRED ||
                hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
                return generic_invariant(runtime, context, stats);
            if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
                if (target.resolved_va != context->pc)
                    return generic_invariant(runtime, context, stats);
                context->stop_reason = GEM_STOP_NONE;
                continue;
            }
            if ((target.kind != GEM_ARM64EC_TARGET_ARM64EC &&
                 target.kind != GEM_ARM64EC_TARGET_ARM64) ||
                !generic_enter_callback(runtime, context, &target, pre_step_sp,
                                        gem_x64_runtime_last_instruction_was_call(runtime->x64)))
                return generic_invariant(runtime, context, stats);
            continue;
        }
        return generic_invariant(runtime, context, stats);
    }
}

void gem_hybrid_runtime_request_async_stop(struct gem_hybrid_runtime *runtime) {
    if (runtime != NULL)
        atomic_store_explicit(&runtime->async_stop_requested, true, memory_order_release);
}

void gem_hybrid_runtime_invalidate_code(struct gem_hybrid_runtime *runtime, uint64_t address,
                                        uint64_t size) {
    if (runtime == NULL || size == 0U)
        return;
    gem_arm64ec_runtime_invalidate_code(runtime->arm, address, size);
    gem_x64_runtime_invalidate_code(runtime->x64, address, size);
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
    if (hybrid_resolve(runtime, context->x[9], &target) != GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
        goto Invariant;
    context->pc = target.resolved_va;
    context->isa = GEM_ISA_X64;
    context->stop_reason = GEM_STOP_NONE;

    for (;;) {
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
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
    if (hybrid_descriptor_resolve(runtime, descriptor_va, &thunk) != GEM_ARM64EC_TARGET_OK)
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
        hybrid_resolve(runtime, context->pc, &entry_target) != GEM_ARM64EC_TARGET_OK ||
        entry_target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        entry_target.resolved_va != context->pc ||
        hybrid_resolve(runtime, callback_va, &callback_target) != GEM_ARM64EC_TARGET_OK ||
        callback_target.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        callback_target.resolved_va != callback_va ||
        hybrid_resolve(runtime, expected_resume_va, &resume_target) != GEM_ARM64EC_TARGET_OK ||
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
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
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
    if (hybrid_descriptor_resolve(runtime, descriptor_va, &thunk) != GEM_ARM64EC_TARGET_OK ||
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
        hybrid_resolve(runtime, control->requested_start_va, &start) != GEM_ARM64EC_TARGET_OK ||
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
    if (hybrid_resolve(runtime, control->expected_x64_target_va, &target) !=
            GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        target.resolved_va != control->expected_x64_target_va)
        goto Invariant;
    context->pc = target.resolved_va;
    context->isa = GEM_ISA_X64;

    while (context->pc != runtime->config.x64_return_sentinel) {
        if (remaining == 0U)
            goto Budget;
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK ||
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
        hybrid_resolve(runtime, control->requested_start_va, &start) != GEM_ARM64EC_TARGET_OK ||
        start.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        start.resolved_va != control->expected_resolved_start_va ||
        hybrid_resolve(runtime, control->outer_x64_target_va, &outer) != GEM_ARM64EC_TARGET_OK ||
        outer.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        outer.resolved_va != control->outer_x64_target_va ||
        hybrid_resolve(runtime, control->callback_va, &callback) != GEM_ARM64EC_TARGET_OK ||
        callback.kind != GEM_ARM64EC_TARGET_ARM64EC ||
        callback.resolved_va != control->callback_va || control->callback_va < 4U ||
        hybrid_resolve(runtime, control->outer_resume_va, &resume) != GEM_ARM64EC_TARGET_OK ||
        resume.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY ||
        resume.resolved_va != control->outer_resume_va ||
        hybrid_resolve(runtime, control->inner_x64_target_va, &inner) != GEM_ARM64EC_TARGET_OK ||
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
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK)
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
    if (hybrid_descriptor_resolve(runtime, callback.resolved_va - 4U, &thunk) !=
            GEM_ARM64EC_TARGET_OK ||
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
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK ||
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
        if (hybrid_resolve(runtime, context->pc, &target) != GEM_ARM64EC_TARGET_OK ||
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
