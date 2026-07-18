// SPDX-License-Identifier: Apache-2.0
/* ADR 0013 W4 gate: RDTSC is adapter-owned, deterministic, and derived from
 * committed retired-instruction accounting in both execution modes. */
#include "i386_engine_internal.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define STACK UINT32_C(0x00500000)

static const uint8_t sequence[] = {0x90U, 0x0fU, 0x31U, 0x90U, 0x66U, 0x0fU,
                                   0x31U, 0x90U, 0x66U, 0x0fU, 0x01U, 0xf9U};

static struct gem_memory *make_memory(void) {
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, sequence, sizeof(sequence)) == GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    return memory;
}

static struct gem_i386_runtime *make_runtime(struct gem_memory *memory,
                                             enum gem_i386_engine_mode mode) {
    struct gem_i386_runtime_config config;
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(sequence);
    config.max_budget = 6U;
    return gem_i386_runtime_create(memory, &config);
}

static void initialize(struct gem_i386_context *context) {
    gem_i386_context_initialize(context, UINT32_C(0x7ffde000));
    context->eip = CODE;
    context->gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
}

static void exercise(enum gem_i386_engine_mode mode) {
    struct gem_memory *whole_memory = make_memory();
    struct gem_memory *split_memory = make_memory();
    struct gem_memory *step_memory = make_memory();
    struct gem_i386_runtime *whole = make_runtime(whole_memory, mode);
    struct gem_i386_runtime *split = make_runtime(split_memory, mode);
    struct gem_i386_runtime *step = make_runtime(step_memory, mode);
    struct gem_i386_context whole_context, split_context, step_context, step_output;
    struct gem_i386_stop_info stop;
    uint64_t fault = 0U;
    uint32_t retired = 0U;
    assert(whole != NULL && split != NULL && step != NULL);
    initialize(&whole_context);
    initialize(&split_context);

    assert(gem_i386_runtime_run(whole, &whole_context, 6U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_runtime_last_stop_info(whole, &stop));
    assert(stop.instructions_retired == 6U);
    assert(whole->virtual_tsc == 6U);
    assert(whole_context.gpr[GEM_I386_EAX] == 5U);
    assert(whole_context.gpr[GEM_I386_EDX] == 0U);
    assert(whole_context.gpr[GEM_I386_ECX] == 0U);

    assert(gem_i386_runtime_run(split, &split_context, 3U) == GEM_STOP_BUDGET_EXPIRED);
    assert(gem_i386_runtime_last_stop_info(split, &stop));
    assert(stop.instructions_retired == 3U);
    assert(split->virtual_tsc == 3U);
    assert(split_context.gpr[GEM_I386_EAX] == 1U);
    assert(split_context.gpr[GEM_I386_EDX] == 0U);
    assert(gem_i386_runtime_run(split, &split_context, 3U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_runtime_last_stop_info(split, &stop));
    assert(stop.instructions_retired == 3U);
    assert(split->virtual_tsc == 6U);
    assert(split_context.gpr[GEM_I386_EAX] == whole_context.gpr[GEM_I386_EAX]);
    assert(split_context.gpr[GEM_I386_EDX] == whole_context.gpr[GEM_I386_EDX]);
    assert(split_context.gpr[GEM_I386_ECX] == whole_context.gpr[GEM_I386_ECX]);
    assert(split_context.eip == whole_context.eip);

    initialize(&step_context);
    step_context.eip = CODE + 1U;
    step->transaction = gem_memory_transaction_begin(step_memory);
    assert(step->transaction != NULL);
    step->ops->sync(step);
    assert(step->ops->step(step, &step_context, &step_output, &retired) == GEM_STOP_NONE);
    assert(gem_memory_transaction_finish(step->transaction, &fault) == GEM_MEMORY_OK);
    gem_memory_transaction_end(step->transaction);
    step->transaction = NULL;
    assert(retired == 1U && step_output.eip == CODE + 3U);
    assert(step_output.gpr[GEM_I386_EAX] == 0U && step_output.gpr[GEM_I386_EDX] == 0U);
    assert(step->virtual_tsc == 0U);

    initialize(&step_context);
    step_context.eip = CODE + 8U;
    step_context.gpr[GEM_I386_ECX] = UINT32_C(0xfeedbeef);
    retired = 0U;
    fault = 0U;
    step->transaction = gem_memory_transaction_begin(step_memory);
    assert(step->transaction != NULL);
    step->ops->sync(step);
    assert(step->ops->step(step, &step_context, &step_output, &retired) == GEM_STOP_NONE);
    assert(gem_memory_transaction_finish(step->transaction, &fault) == GEM_MEMORY_OK);
    gem_memory_transaction_end(step->transaction);
    step->transaction = NULL;
    assert(retired == 1U && step_output.eip == CODE + sizeof(sequence));
    assert(step_output.gpr[GEM_I386_EAX] == 0U && step_output.gpr[GEM_I386_EDX] == 0U);
    assert(step_output.gpr[GEM_I386_ECX] == 0U);
    assert(step->virtual_tsc == 0U);

    gem_i386_runtime_destroy(step);
    gem_i386_runtime_destroy(split);
    gem_i386_runtime_destroy(whole);
    gem_memory_destroy(split_memory);
    gem_memory_destroy(whole_memory);
    gem_memory_destroy(step_memory);
}

int main(void) {
    exercise(GEM_I386_ENGINE_INTERPRETER);
    exercise(GEM_I386_ENGINE_JIT);
    return 0;
}
