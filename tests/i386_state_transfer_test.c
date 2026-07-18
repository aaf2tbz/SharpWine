// SPDX-License-Identifier: Apache-2.0
/* ADR 0013 section e state-transfer coverage: ymm_upper and xcr0 round-trip
 * through the step and run boundaries, v1/v2 layouts export a zeroed
 * extension, and the blink state ABI version gate fails closed. */
#include "i386_engine_internal.h"
#include "i386_engine_trace.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)

static const uint8_t nop[] = {0x90U};

static struct gem_memory *create_memory(void) {
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, nop, sizeof(nop)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    return memory;
}

static struct gem_i386_runtime *create_runtime(struct gem_memory *memory,
                                               enum gem_i386_engine_mode mode) {
    struct gem_i386_runtime_config config;
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(nop);
    config.max_budget = 1U;
    return gem_i386_runtime_create(memory, &config);
}

static void seed_v3(struct gem_i386_context *context) {
    uint32_t i;
    gem_i386_context_initialize(context, UINT32_C(0x7ffde000));
    context->eip = CODE;
    context->gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
    for (i = 0U; i < 8U; ++i) {
        context->ymm_upper[i].lo = UINT64_C(0xa5a5000000000000) + i;
        context->ymm_upper[i].hi = UINT64_C(0x5a5a000000000000) - i;
    }
    context->xcr0 = GEM_I386_XCR0_SUPPORTED;
}

static void assert_extension(const struct gem_i386_context *expected,
                             const struct gem_i386_context *actual) {
    uint32_t i;
    for (i = 0U; i < 8U; ++i) {
        assert(actual->ymm_upper[i].lo == expected->ymm_upper[i].lo);
        assert(actual->ymm_upper[i].hi == expected->ymm_upper[i].hi);
    }
    assert(actual->xcr0 == expected->xcr0);
}

static void exercise_v3_run(enum gem_i386_engine_mode mode) {
    struct gem_memory *memory = create_memory();
    struct gem_i386_runtime *runtime = create_runtime(memory, mode);
    struct gem_i386_context context;
    struct gem_i386_context expected;
    assert(runtime != NULL);
    seed_v3(&context);
    expected = context;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert_extension(&expected, &context);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_v3_step(void) {
    struct gem_memory *memory = create_memory();
    struct gem_i386_runtime *runtime = create_runtime(memory, GEM_I386_ENGINE_INTERPRETER);
    struct gem_i386_context context;
    struct gem_i386_context output;
    struct gem_i386_context expected;
    uint32_t retired = 0U;
    assert(runtime != NULL);
    seed_v3(&context);
    expected = context;
    runtime->transaction = gem_memory_transaction_begin(memory);
    assert(runtime->transaction != NULL);
    runtime->ops->sync(runtime);
    assert(runtime->ops->step(runtime, &context, &output, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    gem_memory_transaction_end(runtime->transaction);
    runtime->transaction = NULL;
    assert_extension(&expected, &output);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_v2_zeroed_extension(void) {
    struct gem_memory *memory = create_memory();
    struct gem_i386_runtime *runtime = create_runtime(memory, GEM_I386_ENGINE_INTERPRETER);
    struct gem_i386_context context;
    uint32_t i;
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    context.context_size = GEM_I386_CONTEXT_SIZE_V2;
    context.eip = CODE;
    context.gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
    memset(context.ymm_upper, 0xa5, sizeof(context.ymm_upper));
    context.xcr0 = UINT64_C(0xffffffffffffffff);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    for (i = 0U; i < 8U; ++i) {
        assert(context.ymm_upper[i].lo == 0U);
        assert(context.ymm_upper[i].hi == 0U);
    }
    assert(context.xcr0 == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_abi_fail_closed(void) {
    struct gem_memory *memory = create_memory();
    struct gem_i386_runtime *runtime = create_runtime(memory, GEM_I386_ENGINE_INTERPRETER);
    struct gem_i386_context context;
    struct blink_gem_state state_in;
    struct blink_gem_state state_out;
    struct blink_gem_run_request request;
    assert(runtime != NULL);
    seed_v3(&context);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);

    memset(&state_in, 0, sizeof(state_in));
    state_in.size = sizeof(state_in);
    state_in.rip = CODE;
    state_in.gpr[4] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
    state_in.fs_base = UINT32_C(0x7ffde000);

    state_in.abi_version = 2U;
    assert(blink_gem_machine_step(runtime->backend, &state_in, &state_out).outcome ==
           BLINK_GEM_INVALID);
    state_in.abi_version = BLINK_GEM_STATE_ABI_VERSION;
    state_in.size = sizeof(state_in) - 1U;
    assert(blink_gem_machine_step(runtime->backend, &state_in, &state_out).outcome ==
           BLINK_GEM_INVALID);

    memset(&request, 0, sizeof(request));
    request.abi_version = BLINK_GEM_RUN_REQUEST_ABI_VERSION;
    request.size = sizeof(request);
    request.instruction_budget = 1U;
    state_in.size = sizeof(state_in);
    state_in.abi_version = 2U;
    assert(blink_gem_machine_run(runtime->backend, &request, &state_in, &state_out).outcome ==
           BLINK_GEM_INVALID);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

int main(void) {
    exercise_v3_run(GEM_I386_ENGINE_INTERPRETER);
    exercise_v3_run(GEM_I386_ENGINE_JIT);
    exercise_v3_step();
    exercise_v2_zeroed_extension();
    exercise_abi_fail_closed();
    return 0;
}
