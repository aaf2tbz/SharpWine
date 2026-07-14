// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <stdlib.h>
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

static struct gem_i386_context run_flags_branch(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0x00U, 0x00U, 0x00U, 0x00U, /* mov eax, 0 */
        0x83U, 0xf8U, 0x00U,               /* cmp eax, 0 */
        0x75U, 0x05U,                      /* jne failure */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U  /* mov ebx, 1 */
    };
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
    config.max_budget = 4U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 4U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_memory_flags_branch(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0x80U, 0x3dU, 0x00U, 0x01U, 0x40U, 0x00U, 0x01U, /* cmp byte [0x400100], 1 */
        0x75U, 0x05U,                                    /* jne success */
        0xbbU, 0x02U, 0x00U, 0x00U, 0x00U                /* mov ebx, 2 */
    };
    static const uint8_t zero = 0U;
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
    assert(gem_i386_memory_write(memory, code_address + UINT32_C(0x100), &zero, sizeof(zero)) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(code);
    config.max_budget = 3U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 3U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_near_jump(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xe9U, 0x05U, 0x00U, 0x00U, 0x00U, /* jmp success */
        0xbbU, 0x02U, 0x00U, 0x00U, 0x00U, /* mov ebx, 2 */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U  /* success: mov ebx, 1 */
    };
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
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_call_return(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0x78U, 0x56U, 0x34U, 0x12U, /* mov eax, 0x12345678 */
        0x50U,                             /* push eax */
        0xe8U, 0x07U, 0x00U, 0x00U, 0x00U, /* call callee */
        0x59U,                             /* pop ecx */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U, /* mov ebx, 1 */
        0xccU,                             /* host return sentinel */
        0x55U,                             /* callee: push ebp */
        0x89U, 0xe5U,                      /* mov ebp, esp */
        0x8bU, 0x45U, 0x08U,               /* mov eax, [ebp+8] */
        0xc9U,                             /* leave */
        0xc3U                              /* ret */
    };
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    uint32_t code_address = UINT32_C(0x00400000);
    uint32_t stack_address = UINT32_C(0x00100000);
    uint32_t initial_esp = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
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
    config.host_return_sentinel = code_address + 17U;
    config.max_budget = 10U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = initial_esp;
    assert(gem_i386_runtime_run(runtime, &context, 10U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == UINT32_C(0x12345678));
    assert(context.gpr[GEM_I386_EBX] == 1U);
    assert(context.gpr[GEM_I386_ECX] == UINT32_C(0x12345678));
    assert(context.gpr[GEM_I386_ESP] == initial_esp);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_pextrw_zero_extend(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0x00U, 0x00U, 0xadU, 0xdeU, /* mov eax, 0xdead0000 */
        0x66U, 0x0fU, 0xc5U, 0xc0U, 0x00U  /* pextrw eax, xmm0, 0 */
    };
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
    context.xmm[0].lo = UINT64_C(0x76);
    assert(gem_i386_runtime_run(runtime, &context, 2U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == UINT32_C(0x76));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_cmovne(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0x31U, 0xc0U,                      /* xor eax, eax */
        0xbbU, 0x00U, 0x00U, 0x05U, 0x00U, /* mov ebx, 0x50000 */
        0xb9U, 0x01U, 0x00U, 0x00U, 0x00U, /* mov ecx, 1 */
        0x85U, 0xc9U,                      /* test ecx, ecx */
        0x0fU, 0x45U, 0xc3U                /* cmovne eax, ebx */
    };
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
    config.max_budget = 5U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 5U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_lock_cmpxchg_branch(enum gem_i386_engine_mode mode,
                                                       uint32_t *value) {
    static const uint8_t code[] = {
        0xb8U, 0x00U, 0x00U, 0x00U, 0x00U,                      /* mov eax, 0 */
        0xb9U, 0x00U, 0x00U, 0x07U, 0x00U,                      /* mov ecx, 0x70000 */
        0xf0U, 0x0fU, 0xb1U, 0x0dU, 0x00U, 0x01U, 0x40U, 0x00U, /* lock cmpxchg [0x400100], ecx */
        0x75U, 0x05U,                                           /* jne failure */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U                       /* mov ebx, 1 */
    };
    static const uint32_t zero = 0U;
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
    assert(gem_i386_memory_write(memory, code_address + UINT32_C(0x100), &zero, sizeof(zero)) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(code);
    config.max_budget = 5U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 5U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_memory_read(memory, code_address + UINT32_C(0x100), value, sizeof(*value)) ==
           GEM_MEMORY_OK);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_external_absolute_store(enum gem_i386_engine_mode mode,
                                                           uint32_t *host_value) {
    static const uint8_t code[] = {
        0xb9U, 0x00U, 0x00U, 0x05U, 0x00U,        /* mov ecx, 0x50000 */
        0x89U, 0x0dU, 0x74U, 0xbeU, 0x66U, 0x7fU, /* mov [0x7f66be74], ecx */
        0x31U, 0xc9U,                             /* xor ecx, ecx */
        0x8bU, 0x0dU, 0x74U, 0xbeU, 0x66U, 0x7fU  /* mov ecx, [0x7f66be74] */
    };
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    uint32_t code_address = UINT32_C(0x00400000);
    uint32_t data_address = UINT32_C(0x7f66b000);
    uint32_t stack_address = UINT32_C(0x00100000);
    uint8_t *host_page = aligned_alloc(GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE);
    assert(memory != NULL);
    assert(host_page != NULL);
    memset(host_page, 0, GEM_GUEST_PAGE_SIZE);
    assert(gem_i386_memory_reserve(memory, &code_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, code_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, code_address, code, sizeof(code)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &data_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit_host(memory, data_address, host_page, GEM_GUEST_PAGE_SIZE,
                                       GEM_PAGE_WRITECOPY) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(code);
    config.max_budget = 4U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 4U) == GEM_STOP_HOST_RETURN);
    memcpy(host_value, host_page + UINT32_C(0xe74), sizeof(*host_value));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    free(host_page);
    return context;
}

static struct gem_i386_context run_fs_process_heap(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0x64U, 0xa1U, 0x18U, 0x00U, 0x00U, 0x00U, /* mov eax, fs:[0x18] */
        0x8bU, 0x40U, 0x30U,                      /* mov eax, [eax+0x30] */
        0x8bU, 0x40U, 0x18U                       /* mov eax, [eax+0x18] */
    };
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    uint32_t code_address = UINT32_C(0x00400000);
    uint32_t stack_address = UINT32_C(0x00100000);
    uint32_t teb_address = UINT32_C(0x7ffde000);
    const uint32_t peb_address = UINT32_C(0x7ffdf000);
    const uint32_t heap_address = UINT32_C(0x00050000);
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &code_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, code_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, code_address, code, sizeof(code)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &teb_address, 2U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, teb_address, 2U * GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, teb_address + UINT32_C(0x18), &teb_address,
                                 sizeof(teb_address)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, teb_address + UINT32_C(0x30), &peb_address,
                                 sizeof(peb_address)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, peb_address + UINT32_C(0x18), &heap_address,
                                 sizeof(heap_address)) == GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(code);
    config.max_budget = 3U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, teb_address);
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 3U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_backward_call(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0x78U, 0x56U, 0x34U, 0x12U, /* callee: mov eax, 0x12345678 */
        0xc3U,                             /* ret */
        0xe8U, 0xf5U, 0xffU, 0xffU, 0xffU, /* main: call callee */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U  /* mov ebx, 1 */
    };
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
    config.max_budget = 4U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address + 6U;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    assert(gem_i386_runtime_run(runtime, &context, 4U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return context;
}

static struct gem_i386_context run_relocated_heap_init(enum gem_i386_engine_mode mode,
                                                       uint32_t *host_heap) {
    static const uint8_t init_code[] = {
        0x55U,                                    /* push ebp */
        0x89U, 0xe5U,                             /* mov ebp, esp */
        0x64U, 0xa1U, 0x18U, 0x00U, 0x00U, 0x00U, /* mov eax, fs:[0x18] */
        0x8bU, 0x40U, 0x30U,                      /* mov eax, [eax+0x30] */
        0x8bU, 0x48U, 0x18U,                      /* mov ecx, [eax+0x18] */
        0x89U, 0x0dU, 0x74U, 0xbeU, 0x66U, 0x7fU, /* mov [0x7f66be74], ecx */
        0x31U, 0xc0U,                             /* xor eax, eax */
        0x85U, 0xc9U,                             /* test ecx, ecx */
        0x0fU, 0x95U, 0xc0U,                      /* setne al */
        0x5dU,                                    /* pop ebp */
        0xc3U                                     /* ret */
    };
    static const uint8_t caller_code[] = {
        0xe8U, 0x61U, 0xabU, 0xffU, 0xffU, /* call 0x7f5e3670 */
        0x89U, 0xc1U,                      /* mov ecx, eax */
        0x31U, 0xc0U,                      /* xor eax, eax */
        0x85U, 0xc9U,                      /* test ecx, ecx */
        0x74U, 0x05U,                      /* je done */
        0xbbU, 0x01U, 0x00U, 0x00U, 0x00U  /* mov ebx, 1 */
    };
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    uint32_t code_address = UINT32_C(0x7f5e3000);
    const uint32_t init_address = UINT32_C(0x7f5e3670);
    const uint32_t caller_address = UINT32_C(0x7f5e8b0a);
    uint32_t data_address = UINT32_C(0x7f66b000);
    uint32_t stack_address = UINT32_C(0x00100000);
    uint32_t teb_address = UINT32_C(0x7ffde000);
    const uint32_t peb_address = UINT32_C(0x7ffdf000);
    const uint32_t heap_address = UINT32_C(0x00050000);
    uint8_t *code_pages = aligned_alloc(GEM_GUEST_PAGE_SIZE, 6U * GEM_GUEST_PAGE_SIZE);
    uint8_t *data_page = aligned_alloc(GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE);
    unsigned int pass;
    assert(memory != NULL);
    assert(code_pages != NULL && data_page != NULL);
    memset(code_pages, 0xcc, 6U * GEM_GUEST_PAGE_SIZE);
    memset(data_page, 0, GEM_GUEST_PAGE_SIZE);
    memcpy(code_pages + (init_address - code_address), init_code, sizeof(init_code));
    memcpy(code_pages + (caller_address - code_address), caller_code, sizeof(caller_code));
    assert(gem_i386_memory_reserve(memory, &code_address, 6U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit_host(memory, code_address, code_pages, 6U * GEM_GUEST_PAGE_SIZE,
                                       GEM_PAGE_EXECUTE_READ) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &data_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit_host(memory, data_address, data_page, GEM_GUEST_PAGE_SIZE,
                                       GEM_PAGE_WRITECOPY) == GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, stack_address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, &teb_address, 2U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, teb_address, 2U * GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, teb_address + UINT32_C(0x18), &teb_address,
                                 sizeof(teb_address)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, teb_address + UINT32_C(0x30), &peb_address,
                                 sizeof(peb_address)) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, peb_address + UINT32_C(0x18), &heap_address,
                                 sizeof(heap_address)) == GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = caller_address + (uint32_t)sizeof(caller_code);
    config.max_budget = 32U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    for (pass = 0; pass < 2U; ++pass) {
        *(uint32_t *)(data_page + UINT32_C(0xe74)) = 0U;
        gem_i386_context_initialize(&context, teb_address);
        context.eip = caller_address;
        context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
        assert(gem_i386_runtime_run(runtime, &context, 32U) == GEM_STOP_HOST_RETURN);
        assert(*(const uint32_t *)(data_page + UINT32_C(0xe74)) == heap_address);
    }
    memcpy(host_heap, data_page + UINT32_C(0xe74), sizeof(*host_heap));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    free(data_page);
    free(code_pages);
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
    interpreter = run_flags_branch(GEM_I386_ENGINE_INTERPRETER);
    jit = run_flags_branch(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EBX] == 1U);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_memory_flags_branch(GEM_I386_ENGINE_INTERPRETER);
    jit = run_memory_flags_branch(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EBX] == 0U);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_near_jump(GEM_I386_ENGINE_INTERPRETER);
    jit = run_near_jump(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EBX] == 1U);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_call_return(GEM_I386_ENGINE_INTERPRETER);
    jit = run_call_return(GEM_I386_ENGINE_JIT);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_pextrw_zero_extend(GEM_I386_ENGINE_INTERPRETER);
    jit = run_pextrw_zero_extend(GEM_I386_ENGINE_JIT);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_cmovne(GEM_I386_ENGINE_INTERPRETER);
    jit = run_cmovne(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EAX] == UINT32_C(0x50000));
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    {
        uint32_t interpreter_value, jit_value;
        interpreter = run_lock_cmpxchg_branch(GEM_I386_ENGINE_INTERPRETER, &interpreter_value);
        jit = run_lock_cmpxchg_branch(GEM_I386_ENGINE_JIT, &jit_value);
        assert(interpreter.gpr[GEM_I386_EBX] == 1U);
        assert(interpreter_value == UINT32_C(0x00070000));
        assert(jit_value == interpreter_value);
        assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    }
    {
        uint32_t interpreter_value, jit_value;
        interpreter = run_external_absolute_store(GEM_I386_ENGINE_INTERPRETER, &interpreter_value);
        jit = run_external_absolute_store(GEM_I386_ENGINE_JIT, &jit_value);
        assert(interpreter.gpr[GEM_I386_ECX] == UINT32_C(0x50000));
        assert(interpreter_value == UINT32_C(0x50000));
        assert(jit_value == interpreter_value);
        assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    }
    interpreter = run_fs_process_heap(GEM_I386_ENGINE_INTERPRETER);
    jit = run_fs_process_heap(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EAX] == UINT32_C(0x50000));
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    interpreter = run_backward_call(GEM_I386_ENGINE_INTERPRETER);
    jit = run_backward_call(GEM_I386_ENGINE_JIT);
    assert(interpreter.gpr[GEM_I386_EAX] == UINT32_C(0x12345678));
    assert(interpreter.gpr[GEM_I386_EBX] == 1U);
    assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    {
        uint32_t interpreter_heap, jit_heap;
        interpreter = run_relocated_heap_init(GEM_I386_ENGINE_INTERPRETER, &interpreter_heap);
        jit = run_relocated_heap_init(GEM_I386_ENGINE_JIT, &jit_heap);
        assert(interpreter.gpr[GEM_I386_EBX] == 1U);
        assert(interpreter_heap == UINT32_C(0x50000));
        assert(jit_heap == interpreter_heap);
        assert(memcmp(&interpreter, &jit, sizeof(jit)) == 0);
    }
    return 0;
}
