// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

static const uint8_t test_code[] = {0xb8U, 0x78U, 0x56U, 0x34U, 0x12U, 0x83U, 0xc0U, 0x01U};

static struct gem_memory *create_memory(uint32_t *code_address, uint32_t *stack_address) {
    struct gem_memory *memory = gem_memory_create();
    *code_address = UINT32_C(0x00400000);
    *stack_address = UINT32_C(0x00100000);
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, code_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, *code_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, *code_address, test_code, sizeof(test_code)) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, *stack_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    return memory;
}

static void exercise_bound_ops(enum gem_i386_engine_mode mode,
                               const struct gem_i386_engine_ops *ops) {
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_i386_context output;
    struct gem_i386_engine_info info;
    struct gem_memory *memory;
    uint32_t code_address;
    uint32_t stack_address;
    uint32_t retired = 0U;
    uint64_t fault = 0U;
    memory = create_memory(&code_address, &stack_address);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(test_code);
    config.max_budget = 2U;
    runtime = gem_i386_runtime_create_with_ops(memory, &config, ops);
    assert(runtime != NULL);
    assert(runtime->ops == ops);
    assert(runtime->config.engine_mode == mode);
    assert(strcmp(gem_i386_runtime_engine_name(runtime), ops->engine_name) == 0);
    assert(strcmp(gem_i386_runtime_engine_version(runtime), ops->engine_version) == 0);
    assert(strcmp(gem_i386_runtime_engine_provenance(runtime), ops->engine_provenance) == 0);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;

    runtime->transaction = gem_memory_transaction_begin(memory);
    assert(runtime->transaction != NULL);
    ops->sync(runtime);
    assert(ops->step(runtime, &context, &output, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    assert(output.gpr[GEM_I386_EAX] == UINT32_C(0x12345678));
    gem_memory_transaction_end(runtime->transaction);
    runtime->transaction = NULL;
    context = output;

    runtime->transaction = gem_memory_transaction_begin(memory);
    assert(runtime->transaction != NULL);
    ops->sync(runtime);
    retired = 0U;
    assert(ops->run(runtime, &context, &output, 1U, &retired) == GEM_STOP_HOST_RETURN);
    assert(retired == 1U);
    assert(output.gpr[GEM_I386_EAX] == UINT32_C(0x12345679));
    assert(output.eip == config.host_return_sentinel);
    assert(gem_memory_transaction_finish(runtime->transaction, &fault) == GEM_MEMORY_OK);
    gem_memory_transaction_end(runtime->transaction);
    runtime->transaction = NULL;

    memset(&info, 0, sizeof(info));
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(ops->engine_info(runtime, &info));
    assert(info.engine_mode == mode);
    assert(ops->invalidate_code(runtime, code_address, GEM_GUEST_PAGE_SIZE));

    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_public_create(enum gem_i386_engine_mode mode,
                                   const struct gem_i386_engine_ops *ops) {
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_engine_info info;
    struct gem_memory *memory = gem_memory_create();
    assert(memory != NULL);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    assert(runtime->ops == ops);
    assert(runtime->config.engine_mode == ops->engine_mode);
    assert(strcmp(gem_i386_runtime_engine_name(runtime), ops->engine_name) == 0);
    memset(&info, 0, sizeof(info));
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    assert(info.engine_mode == ops->engine_mode);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_fail_closed(void) {
    struct gem_i386_engine_ops broken;
    struct gem_i386_runtime_config config;
    struct gem_memory *memory = gem_memory_create();
    assert(memory != NULL);
    memset(&config, 0, sizeof(config));
    config.engine_mode = GEM_I386_ENGINE_JIT;
    assert(gem_i386_runtime_create_with_ops(memory, &config, NULL) == NULL);
    broken = gem_i386_blink_jit_ops;
    broken.abi_version = 0U;
    assert(gem_i386_runtime_create_with_ops(memory, &config, &broken) == NULL);
    broken = gem_i386_blink_jit_ops;
    broken.abi_version = GEM_I386_ENGINE_OPS_ABI_VERSION + 1U;
    assert(gem_i386_runtime_create_with_ops(memory, &config, &broken) == NULL);
    broken = gem_i386_blink_jit_ops;
    broken.run = NULL;
    assert(gem_i386_runtime_create_with_ops(memory, &config, &broken) == NULL);
    broken = gem_i386_blink_jit_ops;
    broken.engine_mode = GEM_I386_ENGINE_DEFAULT;
    assert(gem_i386_runtime_create_with_ops(memory, &config, &broken) == NULL);
    assert(gem_i386_runtime_create_with_ops(memory, &config, &gem_i386_blink_interpreter_ops) ==
           NULL);
    config.engine_mode = (enum gem_i386_engine_mode)7;
    assert(gem_i386_runtime_create(memory, &config) == NULL);
    gem_memory_destroy(memory);
}

int main(void) {
    exercise_bound_ops(GEM_I386_ENGINE_JIT, &gem_i386_blink_jit_ops);
    exercise_bound_ops(GEM_I386_ENGINE_INTERPRETER, &gem_i386_blink_interpreter_ops);
    exercise_public_create(GEM_I386_ENGINE_DEFAULT, &gem_i386_blink_jit_ops);
    exercise_public_create(GEM_I386_ENGINE_JIT, &gem_i386_blink_jit_ops);
    exercise_public_create(GEM_I386_ENGINE_INTERPRETER, &gem_i386_blink_interpreter_ops);
    exercise_fail_closed();
    return 0;
}
