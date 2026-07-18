// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)

struct fixture {
    struct gem_memory *memory;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
};

static struct fixture create_fixture(enum gem_i386_engine_mode mode, const uint8_t *code,
                                     size_t code_size, uint32_t code_address) {
    struct fixture fixture = {0};
    struct gem_i386_runtime_config config = {0};
    uint32_t address = CODE;
    fixture.memory = gem_memory_create();
    assert(fixture.memory != NULL);
    assert(gem_i386_memory_reserve(fixture.memory, &address, 2U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(address == CODE);
    assert(gem_i386_memory_commit(fixture.memory, CODE, 2U * GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(fixture.memory, code_address, code, code_size) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(fixture.memory, &address, 2U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(fixture.memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(fixture.memory, &address, 2U * GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(fixture.memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)code_size;
    config.max_budget = 8U;
    fixture.runtime = gem_i386_runtime_create(fixture.memory, &config);
    assert(fixture.runtime != NULL);
    gem_i386_context_initialize(&fixture.context, UINT32_C(0x7ffde000));
    fixture.context.eip = code_address;
    fixture.context.gpr[GEM_I386_ESP] = STACK + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    return fixture;
}

static void destroy_fixture(struct fixture *fixture) {
    gem_i386_runtime_destroy(fixture->runtime);
    gem_memory_destroy(fixture->memory);
}

static void expect_exception(enum gem_i386_engine_mode mode, const uint8_t *code, size_t code_size,
                             uint32_t eax, uint32_t edx, uint32_t ebx, uint32_t eflags,
                             uint32_t expected_status) {
    struct gem_i386_stop_info stop;
    struct fixture fixture = create_fixture(mode, code, code_size, CODE);
    const struct gem_i386_context before = fixture.context;
    fixture.context.gpr[GEM_I386_EAX] = eax;
    fixture.context.gpr[GEM_I386_EDX] = edx;
    fixture.context.gpr[GEM_I386_EBX] = ebx;
    fixture.context.eflags = eflags;
    assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
           GEM_STOP_WINDOWS_EXCEPTION);
    assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
    assert(stop.reason == GEM_STOP_WINDOWS_EXCEPTION);
    assert(stop.instructions_retired == 0U);
    if (stop.engine_status != expected_status)
        fprintf(stderr, "exception status %u, expected %u for %02x\n", stop.engine_status,
                expected_status, code[0]);
    assert(stop.engine_status == expected_status);
    assert(fixture.context.eip == before.eip);
    assert(fixture.context.gpr[GEM_I386_ESP] == before.gpr[GEM_I386_ESP]);
    assert(fixture.context.gpr[GEM_I386_EAX] == eax);
    assert(fixture.context.gpr[GEM_I386_EDX] == edx);
    assert(fixture.context.gpr[GEM_I386_EBX] == ebx);
    assert(fixture.context.eflags == eflags);
    destroy_fixture(&fixture);
}

static unsigned test_exceptions(void) {
    static const uint8_t div_bl[] = {0xf6U, 0xf3U};
    static const uint8_t idiv_bl[] = {0xf6U, 0xfbU};
    static const uint8_t div_bx[] = {0x66U, 0xf7U, 0xf3U};
    static const uint8_t idiv_bx[] = {0x66U, 0xf7U, 0xfbU};
    static const uint8_t div_ebx[] = {0xf7U, 0xf3U};
    static const uint8_t idiv_ebx[] = {0xf7U, 0xfbU};
    static const uint8_t ud2[] = {0x0fU, 0x0bU};
    static const uint8_t malformed[] = {0x0fU, 0xffU};
    static const uint8_t breakpoint[] = {0xccU};
    static const uint8_t into[] = {0xceU};
    unsigned checks = 0U;
    unsigned int mode_index, index;
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        const struct {
            const uint8_t *code;
            size_t size;
            uint32_t eax, edx, ebx;
        } divide_cases[] = {
            {div_bl, sizeof(div_bl), UINT32_C(0x1234), 0U, 0U},
            {idiv_bl, sizeof(idiv_bl), UINT32_C(0xff80), 0U, 0U},
            {div_bx, sizeof(div_bx), UINT32_C(0x1234), 0U, 0U},
            {idiv_bx, sizeof(idiv_bx), UINT32_C(0x8000), UINT32_MAX, 0U},
            {div_ebx, sizeof(div_ebx), UINT32_C(0x12345678), 0U, 0U},
            {idiv_ebx, sizeof(idiv_ebx), UINT32_C(0x80000000), UINT32_MAX, 0U},
            {div_bl, sizeof(div_bl), UINT32_C(0x0100), 0U, 1U},
            {idiv_bl, sizeof(idiv_bl), UINT32_C(0x8000), 0U, UINT32_MAX},
            {div_bx, sizeof(div_bx), 0U, 1U, 1U},
            {idiv_bx, sizeof(idiv_bx), UINT32_C(0x8000), UINT32_MAX, UINT32_MAX},
            {div_ebx, sizeof(div_ebx), 0U, 1U, 1U},
            {idiv_ebx, sizeof(idiv_ebx), UINT32_C(0x80000000), UINT32_MAX, UINT32_MAX},
        };
        for (index = 0U; index < sizeof(divide_cases) / sizeof(divide_cases[0]); ++index) {
            expect_exception(modes[mode_index], divide_cases[index].code, divide_cases[index].size,
                             divide_cases[index].eax, divide_cases[index].edx,
                             divide_cases[index].ebx, UINT32_C(0x202),
                             GEM_I386_EXCEPTION_INTEGER_DIVIDE_BY_ZERO);
            ++checks;
        }
        expect_exception(modes[mode_index], ud2, sizeof(ud2), 1U, 2U, 3U, UINT32_C(0x202),
                         GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION);
        ++checks;
        expect_exception(modes[mode_index], malformed, sizeof(malformed), 4U, 5U, 6U,
                         UINT32_C(0x202), GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION);
        ++checks;
        expect_exception(modes[mode_index], breakpoint, sizeof(breakpoint), 7U, 8U, 9U,
                         UINT32_C(0x202), GEM_I386_EXCEPTION_BREAKPOINT);
        ++checks;
        expect_exception(modes[mode_index], into, sizeof(into), 10U, 11U, 12U, UINT32_C(0xa02),
                         GEM_I386_EXCEPTION_INTEGER_OVERFLOW);
        ++checks;
    }
    assert(checks == 32U);
    return checks;
}

static unsigned test_fetch_boundaries(void) {
    static const uint8_t mov_eax[] = {0xb8U, 0x78U, 0x56U, 0x34U, 0x12U};
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    unsigned int mode_index, index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (index = 0U; index < 16U; ++index) {
            const uint32_t start = CODE + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U - (index & 3U);
            struct gem_i386_stop_info stop;
            struct fixture fixture =
                create_fixture(modes[mode_index], mov_eax, sizeof(mov_eax), start);
            uint32_t old_protection = 0U;
            assert(gem_i386_memory_protect(
                       fixture.memory, CODE + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                       (index & 1U) != 0U ? GEM_PAGE_READWRITE : GEM_PAGE_NOACCESS,
                       &old_protection) == GEM_MEMORY_OK);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_MEMORY_FAULT);
            assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
            assert(stop.reason == GEM_STOP_MEMORY_FAULT && stop.instructions_retired == 0U);
            assert(stop.access == GEM_I386_ACCESS_FETCH);
            assert(stop.memory_error == GEM_MEMORY_ACCESS_DENIED);
            assert(stop.fault_address >= CODE + GEM_GUEST_PAGE_SIZE);
            assert(fixture.context.eip == start);
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 32U);
    return checks;
}

static unsigned test_transaction_rollback(void) {
    static const uint8_t store_eax[] = {0x89U, 0x06U};
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    unsigned int mode_index, index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (index = 0U; index < 16U; ++index) {
            const uint32_t target = DATA + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U - (index & 1U);
            const uint8_t marker[] = {0x5aU, 0xa5U};
            uint8_t observed[2] = {0};
            const size_t retained = (size_t)(DATA + GEM_GUEST_PAGE_SIZE - target);
            struct gem_i386_stop_info stop;
            struct fixture fixture =
                create_fixture(modes[mode_index], store_eax, sizeof(store_eax), CODE);
            if (index % 3U != 0U)
                assert(gem_i386_memory_commit(
                           fixture.memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                           index % 3U == 1U ? GEM_PAGE_READONLY : GEM_PAGE_NOACCESS) ==
                       GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_EAX] = UINT32_C(0x12345678) ^ index;
            fixture.context.gpr[GEM_I386_ESI] = target;
            assert(gem_i386_memory_write(fixture.memory, target, marker, retained) ==
                   GEM_MEMORY_OK);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_MEMORY_FAULT);
            assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
            assert(stop.reason == GEM_STOP_MEMORY_FAULT && stop.instructions_retired == 0U);
            assert(stop.access == GEM_I386_ACCESS_WRITE);
            assert(stop.memory_error ==
                   (index % 3U == 0U ? GEM_MEMORY_NOT_COMMITTED : GEM_MEMORY_ACCESS_DENIED));
            assert(stop.fault_address >= DATA + GEM_GUEST_PAGE_SIZE);
            assert(fixture.context.eip == CODE);
            assert(gem_i386_memory_read(fixture.memory, target, observed, retained) ==
                   GEM_MEMORY_OK);
            assert(memcmp(marker, observed, retained) == 0);
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 32U);
    return checks;
}

static unsigned test_invalidation(void) {
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    unsigned int mode_index, index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (index = 0U; index < 16U; ++index) {
            uint8_t code[] = {0xb8U, (uint8_t)index, 0U, 0U, 0U};
            struct gem_i386_engine_info before = {.abi_version = 1U, .size = sizeof(before)};
            struct gem_i386_engine_info after = {.abi_version = 1U, .size = sizeof(after)};
            struct gem_i386_performance_info_v2 performance = {
                .abi_version = GEM_I386_PERFORMANCE_INFO_V2_ABI_VERSION,
                .size = sizeof(performance)};
            struct fixture fixture = create_fixture(modes[mode_index], code, sizeof(code), CODE);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(fixture.context.gpr[GEM_I386_EAX] == index);
            assert(gem_i386_runtime_engine_info(fixture.runtime, &before));
            code[1] = (uint8_t)(0x80U + index);
            assert(gem_i386_memory_write(fixture.memory, CODE, code, sizeof(code)) ==
                   GEM_MEMORY_OK);
            gem_i386_runtime_invalidate_code(fixture.runtime, CODE + (index & 3U), 1U);
            fixture.context.eip = CODE;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(fixture.context.gpr[GEM_I386_EAX] == (uint32_t)(0x80U + index));
            assert(gem_i386_runtime_engine_info(fixture.runtime, &after));
            assert(gem_i386_runtime_performance_info_v2(fixture.runtime, &performance));
            assert(performance.code_invalidations == 1U);
            if (modes[mode_index] == GEM_I386_ENGINE_JIT)
                assert(after.jit_compilations == before.jit_compilations + 1U &&
                       performance.jit_cache_hits ==
                           performance.jit_executions - performance.jit_compilations);
            else
                assert(after.jit_compilations == 0U);
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 32U);
    return checks;
}

static unsigned test_extended_coherency(void) {
    static const uint8_t store_eax[] = {0x89U, 0x06U};
    static const uint8_t mov_eax[] = {0xb8U, 0x11U, 0U, 0U, 0U};
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    unsigned int mode_index, index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (index = 0U; index < 4U; ++index) {
            const uint32_t target = DATA + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U - (index & 1U);
            const uint32_t value = UINT32_C(0x6a5b4c30) + index;
            uint32_t observed = 0U;
            struct fixture fixture =
                create_fixture(modes[mode_index], store_eax, sizeof(store_eax), CODE);
            assert(gem_i386_memory_commit(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                          GEM_GUEST_PAGE_SIZE,
                                          GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_EAX] = value;
            fixture.context.gpr[GEM_I386_ESI] = target;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(gem_i386_memory_read(fixture.memory, target, &observed, sizeof(observed)) ==
                   GEM_MEMORY_OK);
            assert(observed == value);
            destroy_fixture(&fixture);
            ++checks;
        }
        for (index = 0U; index < 4U; ++index) {
            const uint32_t target = DATA + (uint32_t)GEM_GUEST_PAGE_SIZE - 2U;
            const uint32_t value = UINT32_C(0xa55a0000) + index;
            uint32_t old_protection = 0U, observed = 0U;
            struct gem_i386_stop_info stop;
            struct fixture fixture =
                create_fixture(modes[mode_index], store_eax, sizeof(store_eax), CODE);
            assert(gem_i386_memory_commit(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                          GEM_GUEST_PAGE_SIZE,
                                          GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
            assert(gem_i386_memory_protect(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                           GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE | GEM_PAGE_GUARD,
                                           &old_protection) == GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_EAX] = value;
            fixture.context.gpr[GEM_I386_ESI] = target;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_MEMORY_FAULT);
            assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
            assert(stop.memory_error == GEM_MEMORY_GUARD_PAGE && stop.instructions_retired == 0U);
            assert(fixture.context.eip == CODE);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(gem_i386_memory_read(fixture.memory, target, &observed, sizeof(observed)) ==
                   GEM_MEMORY_OK);
            assert(observed == value);
            destroy_fixture(&fixture);
            ++checks;
        }
        for (index = 0U; index < 4U; ++index) {
            uint8_t changed[sizeof(mov_eax)];
            struct gem_i386_engine_info before = {.abi_version = 1U, .size = sizeof(before)};
            struct gem_i386_engine_info after = {.abi_version = 1U, .size = sizeof(after)};
            const uint32_t start = CODE + (uint32_t)GEM_GUEST_PAGE_SIZE - 1U;
            struct fixture fixture =
                create_fixture(modes[mode_index], mov_eax, sizeof(mov_eax), start);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(gem_i386_runtime_engine_info(fixture.runtime, &before));
            memcpy(changed, mov_eax, sizeof(changed));
            changed[1] = (uint8_t)(0x70U + index);
            assert(gem_i386_memory_write(fixture.memory, start, changed, sizeof(changed)) ==
                   GEM_MEMORY_OK);
            gem_i386_runtime_invalidate_code(fixture.runtime, CODE + GEM_GUEST_PAGE_SIZE, 1U);
            fixture.context.eip = start;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(fixture.context.gpr[GEM_I386_EAX] == (uint32_t)(0x70U + index));
            assert(gem_i386_runtime_engine_info(fixture.runtime, &after));
            if (modes[mode_index] == GEM_I386_ENGINE_JIT)
                assert(after.jit_compilations == before.jit_compilations + 1U);
            destroy_fixture(&fixture);
            ++checks;
        }
        for (index = 0U; index < 4U; ++index) {
            uint8_t target_code[] = {0xb8U, (uint8_t)(0x20U + index), 0U, 0U, 0U};
            uint8_t writer[] = {0xc6U, 0x05U, 0U, 0U, 0U, 0U, (uint8_t)(0x90U + index)};
            const uint32_t target = CODE + UINT32_C(0x100);
            struct fixture fixture =
                create_fixture(modes[mode_index], target_code, sizeof(target_code), target);
            memcpy(writer + 2U, &target, sizeof(target));
            ++writer[2U];
            assert(gem_i386_memory_write(fixture.memory, CODE, writer, sizeof(writer)) ==
                   GEM_MEMORY_OK);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(fixture.context.gpr[GEM_I386_EAX] == (uint32_t)(0x20U + index));
            fixture.context.eip = CODE;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_BUDGET_EXPIRED);
            fixture.context.eip = target;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            assert(fixture.context.gpr[GEM_I386_EAX] == (uint32_t)(0x90U + index));
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 32U);
    return checks;
}

struct crossing_opcode {
    const uint8_t *read_code;
    size_t read_code_size;
    const uint8_t *write_code;
    size_t write_code_size;
    size_t width;
};

static void assert_fault_state(const struct gem_i386_context *before,
                               const struct gem_i386_context *after) {
    assert(memcmp(before->gpr, after->gpr, sizeof(before->gpr)) == 0);
    assert(before->eip == after->eip);
    assert(before->eflags == after->eflags);
    assert(memcmp(before->xmm, after->xmm, sizeof(before->xmm)) == 0);
}

static unsigned test_crossing_widths(void) {
    static const uint8_t read2[] = {0x66U, 0x8bU, 0x06U};
    static const uint8_t write2[] = {0x66U, 0x89U, 0x06U};
    static const uint8_t read4[] = {0x8bU, 0x06U};
    static const uint8_t write4[] = {0x89U, 0x06U};
    static const uint8_t read8[] = {0xf3U, 0x0fU, 0x7eU, 0x06U};
    static const uint8_t write8[] = {0x66U, 0x0fU, 0xd6U, 0x06U};
    static const uint8_t read16[] = {0xf3U, 0x0fU, 0x6fU, 0x06U};
    static const uint8_t write16[] = {0xf3U, 0x0fU, 0x7fU, 0x06U};
    static const struct crossing_opcode operations[] = {
        {read2, sizeof(read2), write2, sizeof(write2), 2U},
        {read4, sizeof(read4), write4, sizeof(write4), 4U},
        {read8, sizeof(read8), write8, sizeof(write8), 8U},
        {read16, sizeof(read16), write16, sizeof(write16), 16U},
    };
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    const uint8_t value[16] = {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
                               0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xf0U, 0x0fU};
    unsigned checks = 0U;
    size_t mode_index, operation_index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (operation_index = 0U; operation_index < 4U; ++operation_index) {
            const struct crossing_opcode *operation = &operations[operation_index];
            const uint32_t target =
                DATA + (uint32_t)GEM_GUEST_PAGE_SIZE - (uint32_t)(operation->width / 2U);
            struct fixture fixture = create_fixture(modes[mode_index], operation->read_code,
                                                    operation->read_code_size, CODE);
            assert(gem_i386_memory_commit(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                          GEM_GUEST_PAGE_SIZE,
                                          GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
            assert(gem_i386_memory_write(fixture.memory, target, value, operation->width) ==
                   GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_ESI] = target;
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            if (operation->width == 2U)
                assert((fixture.context.gpr[GEM_I386_EAX] & UINT32_C(0xffff)) == UINT32_C(0x2211));
            else if (operation->width == 4U)
                assert(fixture.context.gpr[GEM_I386_EAX] == UINT32_C(0x44332211));
            else
                assert(memcmp(&fixture.context.xmm[0], value, operation->width) == 0);
            destroy_fixture(&fixture);
            ++checks;

            fixture = create_fixture(modes[mode_index], operation->read_code,
                                     operation->read_code_size, CODE);
            fixture.context.gpr[GEM_I386_ESI] = target;
            fixture.context.gpr[GEM_I386_EAX] = UINT32_C(0xa5a55a5a);
            fixture.context.xmm[0].lo = UINT64_C(0x1122334455667788);
            fixture.context.xmm[0].hi = UINT64_C(0x99aabbccddeeff00);
            {
                struct gem_i386_stop_info stop;
                const struct gem_i386_context before = fixture.context;
                assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                       GEM_STOP_MEMORY_FAULT);
                assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
                assert(stop.access == GEM_I386_ACCESS_READ);
                assert(stop.memory_error == GEM_MEMORY_NOT_COMMITTED);
                assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
                assert(stop.instructions_retired == 0U);
                assert_fault_state(&before, &fixture.context);
            }
            destroy_fixture(&fixture);
            ++checks;

            fixture = create_fixture(modes[mode_index], operation->write_code,
                                     operation->write_code_size, CODE);
            assert(gem_i386_memory_commit(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                          GEM_GUEST_PAGE_SIZE,
                                          GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_ESI] = target;
            memcpy(&fixture.context.xmm[0], value, sizeof(value));
            memcpy(&fixture.context.gpr[GEM_I386_EAX], value, sizeof(uint32_t));
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_HOST_RETURN);
            {
                uint8_t observed[16] = {0};
                assert(gem_i386_memory_read(fixture.memory, target, observed, operation->width) ==
                       GEM_MEMORY_OK);
                assert(memcmp(observed, value, operation->width) == 0);
            }
            destroy_fixture(&fixture);
            ++checks;

            fixture = create_fixture(modes[mode_index], operation->write_code,
                                     operation->write_code_size, CODE);
            fixture.context.gpr[GEM_I386_ESI] = target;
            memcpy(&fixture.context.xmm[0], value, sizeof(value));
            memcpy(&fixture.context.gpr[GEM_I386_EAX], value, sizeof(uint32_t));
            {
                struct gem_i386_stop_info stop;
                struct gem_i386_context before = fixture.context;
                uint8_t marker[8] = {0};
                uint8_t observed[8] = {0};
                const size_t retained = operation->width / 2U;
                memset(marker, 0x5a, retained);
                assert(gem_i386_memory_write(fixture.memory, target, marker, retained) ==
                       GEM_MEMORY_OK);
                assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                       GEM_STOP_MEMORY_FAULT);
                assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
                assert(stop.access == GEM_I386_ACCESS_WRITE);
                assert(stop.memory_error == GEM_MEMORY_NOT_COMMITTED);
                assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
                assert(stop.instructions_retired == 0U);
                assert_fault_state(&before, &fixture.context);
                assert(gem_i386_memory_read(fixture.memory, target, observed, retained) ==
                       GEM_MEMORY_OK);
                assert(memcmp(marker, observed, retained) == 0);
            }
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 32U);
    return checks;
}

static unsigned test_atomic_crossings(void) {
    static const uint8_t lock_xadd[] = {0xf0U, 0x0fU, 0xc1U, 0x06U};
    static const uint8_t lock_cmpxchg8b[] = {0xf0U, 0x0fU, 0xc7U, 0x0eU};
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    size_t mode_index, operation;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (operation = 0U; operation < 2U; ++operation) {
            const uint8_t *code = operation == 0U ? lock_xadd : lock_cmpxchg8b;
            const size_t code_size = operation == 0U ? sizeof(lock_xadd) : sizeof(lock_cmpxchg8b);
            const size_t width = operation == 0U ? 4U : 8U;
            const uint32_t target = DATA + (uint32_t)GEM_GUEST_PAGE_SIZE - (uint32_t)(width / 2U);
            const uint64_t initial = UINT64_C(0x0123456789abcdef);
            struct fixture fixture = create_fixture(modes[mode_index], code, code_size, CODE);
            assert(gem_i386_memory_commit(fixture.memory, DATA + GEM_GUEST_PAGE_SIZE,
                                          GEM_GUEST_PAGE_SIZE,
                                          GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
            fixture.context.gpr[GEM_I386_ESI] = target;
            if (operation == 0U) {
                const uint32_t word = 5U;
                uint32_t observed = 0U;
                fixture.context.gpr[GEM_I386_EAX] = 7U;
                assert(gem_i386_memory_write(fixture.memory, target, &word, sizeof(word)) ==
                       GEM_MEMORY_OK);
                assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                       GEM_STOP_HOST_RETURN);
                assert(gem_i386_memory_read(fixture.memory, target, &observed, sizeof(observed)) ==
                       GEM_MEMORY_OK);
                assert(observed == 12U && fixture.context.gpr[GEM_I386_EAX] == 5U);
            } else {
                uint64_t observed = 0U;
                const uint64_t replacement = UINT64_C(0xfedcba9876543210);
                fixture.context.gpr[GEM_I386_EAX] = (uint32_t)initial;
                fixture.context.gpr[GEM_I386_EDX] = (uint32_t)(initial >> 32U);
                fixture.context.gpr[GEM_I386_EBX] = (uint32_t)replacement;
                fixture.context.gpr[GEM_I386_ECX] = (uint32_t)(replacement >> 32U);
                assert(gem_i386_memory_write(fixture.memory, target, &initial, sizeof(initial)) ==
                       GEM_MEMORY_OK);
                assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                       GEM_STOP_HOST_RETURN);
                assert(gem_i386_memory_read(fixture.memory, target, &observed, sizeof(observed)) ==
                       GEM_MEMORY_OK);
                assert(observed == replacement);
            }
            destroy_fixture(&fixture);
            ++checks;

            fixture = create_fixture(modes[mode_index], code, code_size, CODE);
            fixture.context.gpr[GEM_I386_ESI] = target;
            fixture.context.gpr[GEM_I386_EAX] = UINT32_C(0x89abcdef);
            fixture.context.gpr[GEM_I386_EDX] = UINT32_C(0x01234567);
            fixture.context.gpr[GEM_I386_EBX] = UINT32_C(0x76543210);
            fixture.context.gpr[GEM_I386_ECX] = UINT32_C(0xfedcba98);
            {
                const size_t retained = width / 2U;
                uint8_t marker[4] = {0x5aU, 0xa5U, 0x3cU, 0xc3U};
                uint8_t observed[4] = {0};
                struct gem_i386_stop_info stop;
                const struct gem_i386_context before = fixture.context;
                assert(gem_i386_memory_write(fixture.memory, target, marker, retained) ==
                       GEM_MEMORY_OK);
                assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                       GEM_STOP_MEMORY_FAULT);
                assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
                assert(stop.access == GEM_I386_ACCESS_WRITE);
                assert(stop.memory_error == GEM_MEMORY_NOT_COMMITTED);
                assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
                assert(stop.instructions_retired == 0U);
                assert_fault_state(&before, &fixture.context);
                assert(gem_i386_memory_read(fixture.memory, target, observed, retained) ==
                       GEM_MEMORY_OK);
                assert(memcmp(marker, observed, retained) == 0);
            }
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 8U);
    return checks;
}

static unsigned test_stack_faults(void) {
    static const uint8_t push[] = {0x50U};
    static const uint8_t pop[] = {0x58U};
    static const uint8_t call[] = {0xe8U, 0U, 0U, 0U, 0U};
    static const uint8_t ret[] = {0xc3U};
    static const uint8_t pusha[] = {0x60U};
    static const uint8_t popa[] = {0x61U};
    const struct {
        const uint8_t *code;
        size_t code_size;
        uint32_t esp;
        enum gem_i386_memory_access access;
    } operations[] = {
        {push, sizeof(push), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE + 2U, GEM_I386_ACCESS_WRITE},
        {pop, sizeof(pop), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE - 2U, GEM_I386_ACCESS_READ},
        {call, sizeof(call), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE + 2U, GEM_I386_ACCESS_WRITE},
        {ret, sizeof(ret), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE - 2U, GEM_I386_ACCESS_READ},
        {pusha, sizeof(pusha), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE + 16U, GEM_I386_ACCESS_WRITE},
        {popa, sizeof(popa), STACK + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U, GEM_I386_ACCESS_READ},
    };
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    size_t mode_index, operation;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        for (operation = 0U; operation < sizeof(operations) / sizeof(operations[0]); ++operation) {
            struct gem_i386_stop_info stop;
            struct fixture fixture = create_fixture(modes[mode_index], operations[operation].code,
                                                    operations[operation].code_size, CODE);
            struct gem_i386_context before;
            uint8_t before_page[GEM_GUEST_PAGE_SIZE];
            uint8_t after_page[GEM_GUEST_PAGE_SIZE];
            fixture.context.gpr[GEM_I386_EAX] = UINT32_C(0x11223344);
            fixture.context.gpr[GEM_I386_EBX] = UINT32_C(0x55667788);
            fixture.context.gpr[GEM_I386_ESP] = operations[operation].esp;
            before = fixture.context;
            assert(gem_i386_memory_read(fixture.memory, STACK, before_page, sizeof(before_page)) ==
                   GEM_MEMORY_OK);
            assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
                   GEM_STOP_MEMORY_FAULT);
            assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
            if (stop.access != operations[operation].access)
                fprintf(stderr, "stack operation %zu access %u, expected %u\n", operation,
                        stop.access, operations[operation].access);
            assert(stop.access == operations[operation].access);
            if (stop.memory_error != GEM_MEMORY_NOT_COMMITTED)
                fprintf(stderr, "stack operation %zu memory error %u at %08x\n", operation,
                        stop.memory_error, stop.fault_address);
            assert(stop.memory_error == GEM_MEMORY_NOT_COMMITTED);
            assert(stop.fault_address == STACK + GEM_GUEST_PAGE_SIZE);
            assert(stop.instructions_retired == 0U);
            assert_fault_state(&before, &fixture.context);
            assert(gem_i386_memory_read(fixture.memory, STACK, after_page, sizeof(after_page)) ==
                   GEM_MEMORY_OK);
            assert(memcmp(before_page, after_page, sizeof(before_page)) == 0);
            destroy_fixture(&fixture);
            ++checks;
        }
    }
    assert(checks == 12U);
    return checks;
}

static unsigned test_invalidation_scope(void) {
    static const uint8_t code_a[] = {0xb8U, 0x11U, 0U, 0U, 0U};
    static const uint8_t code_b[] = {0xb8U, 0x22U, 0U, 0U, 0U};
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned checks = 0U;
    size_t mode_index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        uint8_t changed_a[sizeof(code_a)];
        uint32_t old_protection = 0U;
        struct gem_i386_engine_info warm = {.abi_version = 1U, .size = sizeof(warm)};
        struct gem_i386_engine_info after_b = {.abi_version = 1U, .size = sizeof(after_b)};
        struct gem_i386_engine_info after_a = {.abi_version = 1U, .size = sizeof(after_a)};
        struct gem_i386_stop_info stop;
        struct fixture fixture = create_fixture(modes[mode_index], code_a, sizeof(code_a), CODE);
        assert(gem_i386_memory_write(fixture.memory, CODE + GEM_GUEST_PAGE_SIZE, code_b,
                                     sizeof(code_b)) == GEM_MEMORY_OK);
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) == GEM_STOP_HOST_RETURN);
        fixture.context.eip = CODE + (uint32_t)GEM_GUEST_PAGE_SIZE;
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
               GEM_STOP_BUDGET_EXPIRED);
        assert(fixture.context.gpr[GEM_I386_EAX] == UINT32_C(0x22));
        assert(gem_i386_runtime_engine_info(fixture.runtime, &warm));

        memcpy(changed_a, code_a, sizeof(changed_a));
        changed_a[1] = 0x33U;
        assert(gem_i386_memory_write(fixture.memory, CODE, changed_a, sizeof(changed_a)) ==
               GEM_MEMORY_OK);
        gem_i386_runtime_invalidate_code(fixture.runtime, CODE + 1U, 1U);
        fixture.context.eip = CODE + (uint32_t)GEM_GUEST_PAGE_SIZE;
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
               GEM_STOP_BUDGET_EXPIRED);
        assert(fixture.context.gpr[GEM_I386_EAX] == UINT32_C(0x22));
        assert(gem_i386_runtime_engine_info(fixture.runtime, &after_b));
        assert(after_b.jit_compilations == warm.jit_compilations);
        ++checks;

        fixture.context.eip = CODE;
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) == GEM_STOP_HOST_RETURN);
        assert(fixture.context.gpr[GEM_I386_EAX] == UINT32_C(0x33));
        assert(gem_i386_runtime_engine_info(fixture.runtime, &after_a));
        if (modes[mode_index] == GEM_I386_ENGINE_JIT)
            assert(after_a.jit_compilations == warm.jit_compilations + 1U);
        ++checks;

        assert(gem_i386_memory_protect(fixture.memory, CODE, GEM_GUEST_PAGE_SIZE,
                                       GEM_PAGE_READWRITE, &old_protection) == GEM_MEMORY_OK);
        fixture.context.eip = CODE;
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) ==
               GEM_STOP_MEMORY_FAULT);
        assert(gem_i386_runtime_last_stop_info(fixture.runtime, &stop));
        assert(stop.access == GEM_I386_ACCESS_FETCH);
        assert(stop.memory_error == GEM_MEMORY_ACCESS_DENIED);
        assert(stop.fault_address == CODE);
        assert(stop.instructions_retired == 0U);
        ++checks;

        assert(gem_i386_memory_protect(fixture.memory, CODE, GEM_GUEST_PAGE_SIZE,
                                       GEM_PAGE_EXECUTE_READWRITE,
                                       &old_protection) == GEM_MEMORY_OK);
        changed_a[1] = 0x44U;
        assert(gem_i386_memory_write(fixture.memory, CODE, changed_a, sizeof(changed_a)) ==
               GEM_MEMORY_OK);
        fixture.context.eip = CODE;
        assert(gem_i386_runtime_run(fixture.runtime, &fixture.context, 1U) == GEM_STOP_HOST_RETURN);
        assert(fixture.context.gpr[GEM_I386_EAX] == UINT32_C(0x44));
        ++checks;
        destroy_fixture(&fixture);
    }
    assert(checks == 8U);
    return checks;
}

int main(void) {
    const unsigned checks =
        test_exceptions() + test_fetch_boundaries() + test_transaction_rollback() +
        test_invalidation() + test_extended_coherency() + test_crossing_widths() +
        test_atomic_crossings() + test_stack_faults() + test_invalidation_scope();
    assert(checks == 220U);
    printf("i386 phase 2: 110 deterministic scenarios, %u interpreter/JIT comparisons passed\n",
           checks);
    return 0;
}
