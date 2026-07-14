// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

static struct gem_i386_context run(enum gem_i386_engine_mode mode,
                                   struct gem_i386_engine_info *info) {
    static const uint8_t code[] = {0xb8U, 0x78U, 0x56U, 0x34U, 0x12U, 0x83U, 0xc0U, 0x01U};
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    uint32_t code_address = UINT32_C(0x00400000);
    uint32_t stack_address = UINT32_C(0x00100000);
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &code_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, code_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, code_address, code, sizeof(code)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(code);
    config.max_budget = 2U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 2U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == UINT32_C(0x12345679));
    assert(context.eip == config.host_return_sentinel);
    memset(info, 0, sizeof(*info));
    info->abi_version = 1U;
    info->size = sizeof(*info);
    assert(gem_i386_runtime_engine_info(runtime, info));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

int main(void) {
    struct gem_i386_engine_info interpreter_info;
    struct gem_i386_engine_info jit_info;
    struct gem_i386_context interpreter = run(GEM_I386_ENGINE_INTERPRETER, &interpreter_info);
    struct gem_i386_context jit = run(GEM_I386_ENGINE_JIT, &jit_info);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    assert(interpreter_info.engine_mode == GEM_I386_ENGINE_INTERPRETER);
    assert(interpreter_info.jit_executions == 0U);
    assert(jit_info.engine_mode == GEM_I386_ENGINE_JIT);
    assert(jit_info.host_arch == GEM_I386_HOST_AARCH64);
    assert(jit_info.write_xor_execute == 1U);
    assert(jit_info.jit_compilations != 0U);
    assert(jit_info.jit_executions == 2U);
    assert(jit_info.jit_failures == 0U);
    return 0;
}
