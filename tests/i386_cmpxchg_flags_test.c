// SPDX-License-Identifier: Apache-2.0
/* Deterministic regression for the upstream Blink CMPXCHG flag operand order
 * defect (blink patch 0015): post-exchange flags must come from EAX - dest,
 * never dest - EAX.  Expected values are witnessed by the native Windows 11
 * ARM64 WoW64 oracle (Prism) and by Intel SDM hand computation. */
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)
#define DEFINED_FLAGS UINT32_C(0x8d5)

struct outcome {
    uint32_t flags;
    uint32_t eax;
    uint32_t memory;
};

static struct outcome run(enum gem_i386_engine_mode mode, const uint8_t *code, size_t code_size,
                          uint32_t eax, uint32_t ebx, uint32_t memory_value, uint32_t memory_size) {
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_memory *memory = gem_memory_create();
    struct outcome result;
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, code_size) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA + 64U, &memory_value, memory_size) == GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)code_size;
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
    context.gpr[GEM_I386_ESI] = DATA + 64U;
    context.gpr[GEM_I386_EAX] = eax;
    context.gpr[GEM_I386_EBX] = ebx;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    result.flags = context.eflags & DEFINED_FLAGS;
    result.eax = context.gpr[GEM_I386_EAX];
    result.memory = 0U;
    assert(gem_i386_memory_read(memory, DATA + 64U, &result.memory, memory_size) == GEM_MEMORY_OK);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return result;
}

static void expect_both_modes(const char *name, const uint8_t *code, size_t code_size, uint32_t eax,
                              uint32_t ebx, uint32_t memory_value, uint32_t memory_size,
                              uint32_t want_flags, uint32_t want_eax, uint32_t want_memory) {
    struct outcome interpreter;
    struct outcome jit;
    (void)name;
    interpreter =
        run(GEM_I386_ENGINE_INTERPRETER, code, code_size, eax, ebx, memory_value, memory_size);
    jit = run(GEM_I386_ENGINE_JIT, code, code_size, eax, ebx, memory_value, memory_size);
    assert(interpreter.flags == want_flags && interpreter.eax == want_eax &&
           interpreter.memory == want_memory);
    assert(jit.flags == want_flags && jit.eax == want_eax && jit.memory == want_memory);
}

int main(void) {
    static const uint8_t cmpxchg32[] = {0xf0U, 0x0fU, 0xb1U, 0x1eU}; /* lock cmpxchg [esi], ebx */
    static const uint8_t cmpxchg8[] = {0xf0U, 0x0fU, 0xb0U, 0x1eU};  /* lock cmpxchg [esi], bl */

    /* Windows 11 ARM64 WoW64 witness: EAX - [mem] gives PF+AF (0x14).
     * Unfixed Blink computed [mem] - EAX and produced CF+SF (0x81). */
    expect_both_modes("aligned-32 unequal", cmpxchg32, sizeof(cmpxchg32), UINT32_C(0xff8061b2),
                      UINT32_C(0x4f9f6aba), UINT32_C(0xca4e7c1f), 4U, UINT32_C(0x14),
                      UINT32_C(0xca4e7c1f), UINT32_C(0xca4e7c1f));

    /* EAX < [mem]: EAX - [mem] borrows and goes negative: CF+SF+PF (0x85).
     * Unfixed Blink produced PF alone (0x04). */
    expect_both_modes("aligned-32 borrow", cmpxchg32, sizeof(cmpxchg32), UINT32_C(0x10000000),
                      UINT32_C(0xdeadbeef), UINT32_C(0x20000000), 4U, UINT32_C(0x85),
                      UINT32_C(0x20000000), UINT32_C(0x20000000));

    /* 8-bit form: AL - [mem8] = 0x93 gives SF+PF+AF (0x94).
     * Unfixed Blink produced CF alone (0x01). */
    expect_both_modes("8-bit unequal", cmpxchg8, sizeof(cmpxchg8), UINT32_C(0xb2), UINT32_C(0x42),
                      UINT32_C(0x1f), 1U, UINT32_C(0x94), UINT32_C(0x1f), UINT32_C(0x1f));

    /* Equal operands exchange and produce ZF+PF (0x44) on both paths; this
     * guards the successful-exchange behavior the fix must not disturb. */
    expect_both_modes("aligned-32 equal", cmpxchg32, sizeof(cmpxchg32), UINT32_C(0x12345678),
                      UINT32_C(0xa5a5a5a5), UINT32_C(0x12345678), 4U, UINT32_C(0x44),
                      UINT32_C(0x12345678), UINT32_C(0xa5a5a5a5));
    expect_both_modes("8-bit equal", cmpxchg8, sizeof(cmpxchg8), UINT32_C(0x5a), UINT32_C(0x99),
                      UINT32_C(0x5a), 1U, UINT32_C(0x44), UINT32_C(0x5a), UINT32_C(0x99));
    return 0;
}
