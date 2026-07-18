// SPDX-License-Identifier: Apache-2.0
#include "fixtures/i386_phase3_records.h"
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)

#ifndef MSWR_PHASE3_REFERENCE_PATH
#define MSWR_PHASE3_REFERENCE_PATH "tests/fixtures/i386_phase3_reference.bin"
#endif

static FILE *reference_file;
static int capture_reference;

struct execution {
    struct i386_phase3_record record;
    struct gem_i386_engine_info info;
};

static uint64_t hash_bytes(const uint8_t *data, size_t size) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void seed_context(struct gem_i386_context *context, uint32_t seed) {
    unsigned i;
    gem_i386_context_initialize(context, UINT32_C(0x7ffde000));
    context->eip = CODE;
    context->gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 32U;
    context->gpr[GEM_I386_EAX] = UINT32_C(0x10203040) ^ seed;
    context->gpr[GEM_I386_EBX] = UINT32_C(0x55667788) + seed;
    context->gpr[GEM_I386_ECX] = seed & 7U;
    context->gpr[GEM_I386_EDX] = UINT32_C(0x90abcdef) ^ (seed << 1U);
    context->fcw = (uint16_t)(UINT16_C(0x037f) | ((seed & 3U) << 10U));
    context->fsw = (uint16_t)((seed & 7U) << 11U);
    context->ftw = UINT16_C(0);
    context->fop = (uint16_t)seed;
    context->x87_environment.fip = UINT32_C(0x401000) + seed;
    context->x87_environment.fdp = DATA + 128U + seed;
    context->x87_environment.fcs = UINT16_C(0x23);
    context->x87_environment.fds = UINT16_C(0x2b);
    context->mxcsr = UINT32_C(0x1f80) | ((seed & 3U) << 13U);
    for (i = 0; i < 6U; ++i) {
        context->segment[i] = (uint16_t)(UINT16_C(0x20) + i * 8U + 3U);
        context->segment_base[i] = 0U;
        context->segment_limit[i] = UINT32_MAX;
        context->segment_attributes[i] =
            GEM_I386_SEGMENT_PRESENT | GEM_I386_SEGMENT_WRITABLE | GEM_I386_SEGMENT_DEFAULT_32;
    }
    context->segment_attributes[GEM_I386_CS] |= GEM_I386_SEGMENT_EXECUTABLE;
    for (i = 0; i < 8U; ++i) {
        context->xmm[i].lo = (UINT64_C(0x0102030405060708) * (i + 1U)) ^ seed;
        context->xmm[i].hi = (UINT64_C(0xf0e0d0c0b0a09080) - i) ^ ((uint64_t)seed << 32U);
        context->x87[i].lo = UINT64_C(0x8000000000000000) | ((uint64_t)seed << 16U) | i;
        context->x87[i].hi = UINT64_C(0x0000000000003fff);
    }
}

/* Project the current ABI v3 context into the pinned 448-byte Phase 3 record
 * layout.  The extension must be inert (zeroed) at this boundary, matching
 * ADR 0013's zeroed-v3 == v2-projection rule; anything else is a bug in the
 * state import/export path, not something to reinterpret. */
static void legacy_context_from_gem(struct i386_phase3_legacy_context *legacy,
                                    const struct gem_i386_context *context) {
    size_t i;
    assert(context->xcr0 == 0U && context->reserved1 == 0U);
    for (i = 0U; i < 8U; ++i)
        assert(context->ymm_upper[i].lo == 0U && context->ymm_upper[i].hi == 0U);
    memset(legacy, 0, sizeof(*legacy));
    memcpy(legacy, context, sizeof(*legacy));
    legacy->layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    legacy->context_size = GEM_I386_CONTEXT_SIZE_V2;
}

static struct execution execute_case(enum gem_i386_engine_mode mode, uint32_t case_id,
                                     enum i386_phase3_category category, const uint8_t *code,
                                     size_t code_size) {
    struct execution result;
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_context initial;
    struct gem_i386_context final;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint8_t bytes[512];
    uint32_t address = CODE;
    unsigned i;
    memset(&result, 0, sizeof(result));
    assert(memory != NULL && code_size <= sizeof(result.record.instruction));
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, code_size) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, 2U * GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    for (i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t)(i * 29U + case_id);
    assert(gem_i386_memory_write(memory, DATA, bytes, sizeof(bytes)) == GEM_MEMORY_OK);
    result.record.schema_version = I386_PHASE3_CORPUS_SCHEMA;
    result.record.case_id = case_id;
    result.record.category = category;
    memcpy(result.record.instruction, code, code_size);
    result.record.instruction_size = (uint8_t)code_size;
    seed_context(&initial, case_id);
    initial.gpr[GEM_I386_ESI] = DATA + 64U + (case_id & 31U);
    initial.gpr[GEM_I386_EDI] = DATA + 320U + (case_id & 31U);
    if (category == I386_PHASE3_REP_SEGMENT) {
        initial.gpr[GEM_I386_ECX] = case_id & 15U;
        if ((case_id & 1U) != 0U)
            initial.eflags |= UINT32_C(0x400);
    }
    if (category == I386_PHASE3_CPUID_CONTEXT) {
        switch (case_id % 3U) {
        case 0U:
            initial.gpr[GEM_I386_EAX] = 1U;
            break;
        case 1U:
            initial.gpr[GEM_I386_EAX] = 7U;
            initial.gpr[GEM_I386_ECX] = 0U;
            break;
        default:
            initial.gpr[GEM_I386_EAX] = UINT32_C(0x80000001);
            break;
        }
    }
    legacy_context_from_gem(&result.record.initial, &initial);
    result.record.memory_hash_before = hash_bytes(bytes, sizeof(bytes));
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)code_size;
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    final = initial;
    result.record.stop_reason = (uint32_t)gem_i386_runtime_run(runtime, &final, 1U);
    legacy_context_from_gem(&result.record.final, &final);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    result.record.exception_status = stop.engine_status;
    result.record.fault_address = stop.fault_address;
    result.record.access = (uint32_t)stop.access;
    result.record.memory_error = stop.memory_error;
    result.record.retired_count = stop.instructions_retired;
    assert(gem_i386_memory_read(memory, DATA, bytes, sizeof(bytes)) == GEM_MEMORY_OK);
    result.record.memory_hash_after = hash_bytes(bytes, sizeof(bytes));
    result.record.defined_context_mask = UINT64_MAX;
    result.info.abi_version = 1U;
    result.info.size = sizeof(result.info);
    assert(gem_i386_runtime_engine_info(runtime, &result.info));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return result;
}

static void compare_case(uint32_t case_id, enum i386_phase3_category category, const uint8_t *code,
                         size_t code_size) {
    const struct execution interpreter =
        execute_case(GEM_I386_ENGINE_INTERPRETER, case_id, category, code, code_size);
    const struct execution jit =
        execute_case(GEM_I386_ENGINE_JIT, case_id, category, code, code_size);
    if (memcmp(&interpreter.record.final, &jit.record.final, sizeof(interpreter.record.final)) != 0)
        fprintf(stderr, "Phase 3 context mismatch at case %u category %u\n", case_id,
                (unsigned)category);
    assert(memcmp(&interpreter.record.final, &jit.record.final, sizeof(interpreter.record.final)) ==
           0);
    assert(interpreter.record.stop_reason == jit.record.stop_reason);
    assert(interpreter.record.stop_reason == GEM_STOP_HOST_RETURN);
    assert(interpreter.record.exception_status == jit.record.exception_status);
    assert(interpreter.record.fault_address == jit.record.fault_address);
    assert(interpreter.record.memory_error == jit.record.memory_error);
    assert(interpreter.record.memory_hash_after == jit.record.memory_hash_after);
    assert(interpreter.info.jit_executions == 0U);
    assert(jit.info.jit_executions == 1U && jit.info.jit_failures == 0U);
    if (capture_reference) {
        assert(fwrite(&interpreter.record, sizeof(interpreter.record), 1U, reference_file) == 1U);
    } else {
        struct i386_phase3_record expected;
        assert(fread(&expected, sizeof(expected), 1U, reference_file) == 1U);
        assert(memcmp(&expected, &interpreter.record, sizeof(expected)) == 0);
    }
}

static uint32_t run_category(uint32_t first, uint32_t count, enum i386_phase3_category category,
                             const uint8_t *const *codes, const uint8_t *sizes, size_t code_count) {
    uint32_t i;
    for (i = 0; i < count; ++i)
        compare_case(first + i, category, codes[i % code_count], sizes[i % code_count]);
    return first + count;
}

static void verify_cpuid_profile(void) {
    static const uint8_t cpuid[] = {0x0fU, 0xa2U};
    struct execution leaf1 = execute_case(GEM_I386_ENGINE_INTERPRETER, 0U,
                                          I386_PHASE3_CPUID_CONTEXT, cpuid, sizeof(cpuid));
    struct execution leaf7 = execute_case(GEM_I386_ENGINE_INTERPRETER, 1U,
                                          I386_PHASE3_CPUID_CONTEXT, cpuid, sizeof(cpuid));
    struct execution ext = execute_case(GEM_I386_ENGINE_INTERPRETER, 2U, I386_PHASE3_CPUID_CONTEXT,
                                        cpuid, sizeof(cpuid));
    uint32_t ecx = leaf1.record.final.gpr[GEM_I386_ECX];
    uint32_t edx = leaf1.record.final.gpr[GEM_I386_EDX];
    assert((ecx &
            ((1U << 0U) | (1U << 1U) | (1U << 9U) | (1U << 12U) | (1U << 19U) | (1U << 20U) |
             (1U << 23U) | (1U << 25U) | (1U << 26U) | (1U << 27U) | (1U << 28U) | (1U << 30U))) ==
           ((1U << 0U) | (1U << 1U) | (1U << 9U) | (1U << 12U) | (1U << 19U) | (1U << 20U) |
            (1U << 23U) | (1U << 25U) | (1U << 26U) | (1U << 27U) | (1U << 28U) | (1U << 30U)));
    assert((ecx & (1U << 13U)) == 0U);
    assert((edx & ((1U << 0U) | (1U << 8U) | (1U << 15U) | (1U << 23U) | (1U << 24U) | (1U << 25U) |
                   (1U << 26U))) != 0U);
    assert(leaf7.record.final.gpr[GEM_I386_EBX] ==
           ((1U << 3U) | (1U << 5U) | (1U << 8U) | (1U << 9U) | (1U << 18U) | (1U << 19U)));
    assert(leaf7.record.final.gpr[GEM_I386_ECX] == (1U << 22U));
    assert((ext.record.final.gpr[GEM_I386_EDX] & (1U << 27U)) != 0U);
    assert((ext.record.final.gpr[GEM_I386_EDX] & ((1U << 11U) | (1U << 29U))) == 0U);
}

static uint32_t bmi1_flags(uint32_t result, uint32_t carry) {
    return carry | (result == 0U ? UINT32_C(0x40) : 0U) |
           (result & UINT32_C(0x80000000) ? UINT32_C(0x80) : 0U);
}

static void verify_bmi1_instructions(void) {
    static const uint8_t bmi1_andn[] = {0xc4U, 0xe2U, 0x60U, 0xf2U, 0xc2U};
    static const uint8_t bmi1_bextr[] = {0xc4U, 0xe2U, 0x60U, 0xf7U, 0xd0U};
    static const uint8_t bmi1_blsr[] = {0xc4U, 0xe2U, 0x40U, 0xf3U, 0xceU};
    static const uint8_t bmi1_blsmsk[] = {0xc4U, 0xe2U, 0x60U, 0xf3U, 0xd2U};
    static const uint8_t bmi1_blsi[] = {0xc4U, 0xe2U, 0x70U, 0xf3U, 0xd8U};
    static const uint8_t bmi1_tzcnt[] = {0xf3U, 0x0fU, 0xbcU, 0xc3U};
    const uint8_t *const code[] = {bmi1_andn,   bmi1_bextr, bmi1_blsr,
                                   bmi1_blsmsk, bmi1_blsi,  bmi1_tzcnt};
    const uint8_t size[] = {sizeof(bmi1_andn),   sizeof(bmi1_bextr), sizeof(bmi1_blsr),
                            sizeof(bmi1_blsmsk), sizeof(bmi1_blsi),  sizeof(bmi1_tzcnt)};
    uint32_t i;
    for (i = 0U; i < 6U; ++i) {
        const uint32_t case_id = UINT32_C(0x1200) + i;
        const struct execution interpreter =
            execute_case(GEM_I386_ENGINE_INTERPRETER, case_id, I386_PHASE3_SIMD, code[i], size[i]);
        const struct execution jit =
            execute_case(GEM_I386_ENGINE_JIT, case_id, I386_PHASE3_SIMD, code[i], size[i]);
        assert(memcmp(&interpreter.record.final, &jit.record.final,
                      sizeof(interpreter.record.final)) == 0);
        assert(interpreter.record.stop_reason == GEM_STOP_HOST_RETURN);
        assert(jit.record.stop_reason == GEM_STOP_HOST_RETURN);
        assert(interpreter.record.retired_count == 1U && jit.record.retired_count == 1U);
        assert(interpreter.info.jit_executions == 0U);
        assert(jit.info.jit_executions == 1U && jit.info.jit_failures == 0U);
        switch (i) {
        case 0U: {
            const uint32_t ebx = UINT32_C(0x55667788) + case_id;
            const uint32_t edx = UINT32_C(0x90abcdef) ^ (case_id << 1U);
            const uint32_t result = ~ebx & edx;
            assert(interpreter.record.final.gpr[GEM_I386_EAX] == result);
            assert((interpreter.record.final.eflags & UINT32_C(0x8c1)) == bmi1_flags(result, 0U));
            break;
        }
        case 1U:
            /* The seeded EBX control has a start index above 31. */
            assert(interpreter.record.final.gpr[GEM_I386_EDX] == 0U);
            assert((interpreter.record.final.eflags & UINT32_C(0x8d5)) == UINT32_C(0x40));
            break;
        case 2U: {
            const uint32_t esi = DATA + 64U + (case_id & 31U);
            const uint32_t result = esi & (esi - 1U);
            assert(interpreter.record.final.gpr[GEM_I386_EDI] == result);
            assert((interpreter.record.final.eflags & UINT32_C(0x8c1)) ==
                   bmi1_flags(result, esi == 0U));
            break;
        }
        case 3U: {
            const uint32_t edx = UINT32_C(0x90abcdef) ^ (case_id << 1U);
            const uint32_t result = edx ^ (edx - 1U);
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == result);
            assert((interpreter.record.final.eflags & UINT32_C(0x8c1)) ==
                   bmi1_flags(result, edx == 0U));
            break;
        }
        case 4U: {
            const uint32_t eax = UINT32_C(0x10203040) ^ case_id;
            const uint32_t result = eax & (0U - eax);
            assert(interpreter.record.final.gpr[GEM_I386_ECX] == result);
            assert((interpreter.record.final.eflags & UINT32_C(0x8c1)) ==
                   bmi1_flags(result, eax != 0U));
            break;
        }
        default: {
            const uint32_t ebx = UINT32_C(0x55667788) + case_id;
            uint32_t count = 0U;
            while (((ebx >> count) & 1U) == 0U)
                ++count;
            assert(interpreter.record.final.gpr[GEM_I386_EAX] == count);
            assert((interpreter.record.final.eflags & UINT32_C(0x41)) ==
                   (count == 0U ? UINT32_C(0x40) : 0U));
            break;
        }
        }
    }
}

static uint32_t bmi2_pdep(uint32_t source, uint32_t mask) {
    uint32_t bit = 1U;
    uint32_t result = 0U;
    while (mask != 0U) {
        const uint32_t lowest = mask & (0U - mask);
        if ((source & bit) != 0U)
            result |= lowest;
        mask &= mask - 1U;
        bit <<= 1U;
    }
    return result;
}

static uint32_t bmi2_pext(uint32_t source, uint32_t mask) {
    uint32_t bit = 1U;
    uint32_t result = 0U;
    while (mask != 0U) {
        const uint32_t lowest = mask & (0U - mask);
        if ((source & lowest) != 0U)
            result |= bit;
        mask &= mask - 1U;
        bit <<= 1U;
    }
    return result;
}

static void verify_bmi2_instructions(void) {
    static const uint8_t bmi2_bzhi[] = {0xc4U, 0xe2U, 0x70U, 0xf5U, 0xd8U};
    static const uint8_t bmi2_pdep_code[] = {0xc4U, 0xe2U, 0x7bU, 0xf5U, 0xd9U};
    static const uint8_t bmi2_pext_code[] = {0xc4U, 0xe2U, 0x7aU, 0xf5U, 0xd9U};
    static const uint8_t bmi2_mulx[] = {0xc4U, 0xe2U, 0x7bU, 0xf6U, 0xd9U};
    static const uint8_t bmi2_shlx[] = {0xc4U, 0xe2U, 0x71U, 0xf7U, 0xd8U};
    static const uint8_t bmi2_shrx[] = {0xc4U, 0xe2U, 0x73U, 0xf7U, 0xd8U};
    static const uint8_t bmi2_sarx[] = {0xc4U, 0xe2U, 0x72U, 0xf7U, 0xd8U};
    static const uint8_t bmi2_rorx[] = {0xc4U, 0xe3U, 0x7bU, 0xf0U, 0xd8U, 0x07U};
    const uint8_t *const code[] = {bmi2_bzhi, bmi2_pdep_code, bmi2_pext_code, bmi2_mulx,
                                   bmi2_shlx, bmi2_shrx,      bmi2_sarx,      bmi2_rorx};
    const uint8_t size[] = {sizeof(bmi2_bzhi), sizeof(bmi2_pdep_code), sizeof(bmi2_pext_code),
                            sizeof(bmi2_mulx), sizeof(bmi2_shlx),      sizeof(bmi2_shrx),
                            sizeof(bmi2_sarx), sizeof(bmi2_rorx)};
    uint32_t i;
    for (i = 0U; i < 8U; ++i) {
        const uint32_t case_id = UINT32_C(0x1300) + i;
        const struct execution interpreter =
            execute_case(GEM_I386_ENGINE_INTERPRETER, case_id, I386_PHASE3_SIMD, code[i], size[i]);
        const struct execution jit =
            execute_case(GEM_I386_ENGINE_JIT, case_id, I386_PHASE3_SIMD, code[i], size[i]);
        const uint32_t eax = UINT32_C(0x10203040) ^ case_id;
        const uint32_t ecx = case_id & 7U;
        const uint32_t edx = UINT32_C(0x90abcdef) ^ (case_id << 1U);
        assert(memcmp(&interpreter.record.final, &jit.record.final,
                      sizeof(interpreter.record.final)) == 0);
        assert(interpreter.record.stop_reason == GEM_STOP_HOST_RETURN);
        assert(jit.record.stop_reason == GEM_STOP_HOST_RETURN);
        assert(interpreter.record.retired_count == 1U && jit.record.retired_count == 1U);
        assert(interpreter.info.jit_executions == 0U);
        assert(jit.info.jit_executions == 1U && jit.info.jit_failures == 0U);
        switch (i) {
        case 0U: {
            const uint32_t result = ecx == 0U ? 0U : eax & ((1U << ecx) - 1U);
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == result);
            assert((interpreter.record.final.eflags & UINT32_C(0x8c1)) ==
                   (result == 0U ? UINT32_C(0x40) : 0U));
            break;
        }
        case 1U:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == bmi2_pdep(eax, ecx));
            break;
        case 2U:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == bmi2_pext(eax, ecx));
            break;
        case 3U: {
            const uint64_t product = (uint64_t)edx * ecx;
            assert(interpreter.record.final.gpr[GEM_I386_EAX] == (uint32_t)product);
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == (uint32_t)(product >> 32U));
            break;
        }
        case 4U:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == eax << ecx);
            break;
        case 5U:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == eax >> ecx);
            break;
        case 6U:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == (uint32_t)((int32_t)eax >> ecx));
            break;
        default:
            assert(interpreter.record.final.gpr[GEM_I386_EBX] == ((eax >> 7U) | (eax << 25U)));
            break;
        }
        if (i != 0U)
            assert((interpreter.record.final.eflags & UINT32_C(0x8d5)) ==
                   (interpreter.record.initial.eflags & UINT32_C(0x8d5)));
    }
}

static void verify_rdtscp_instruction(void) {
    static const uint8_t rdtscp[] = {0x66U, 0x0fU, 0x01U, 0xf9U};
    const uint32_t case_id = UINT32_C(0x1400);
    const struct execution interpreter = execute_case(GEM_I386_ENGINE_INTERPRETER, case_id,
                                                      I386_PHASE3_SIMD, rdtscp, sizeof(rdtscp));
    const struct execution jit =
        execute_case(GEM_I386_ENGINE_JIT, case_id, I386_PHASE3_SIMD, rdtscp, sizeof(rdtscp));
    assert(memcmp(&interpreter.record.final, &jit.record.final, sizeof(interpreter.record.final)) ==
           0);
    assert(interpreter.record.stop_reason == GEM_STOP_HOST_RETURN);
    assert(jit.record.stop_reason == GEM_STOP_HOST_RETURN);
    assert(interpreter.record.retired_count == 1U && jit.record.retired_count == 1U);
    assert(interpreter.record.final.gpr[GEM_I386_EAX] == 0U);
    assert(interpreter.record.final.gpr[GEM_I386_EDX] == 0U);
    assert(interpreter.record.final.gpr[GEM_I386_ECX] == 0U);
    assert((interpreter.record.final.eflags & UINT32_C(0x8d5)) ==
           (interpreter.record.initial.eflags & UINT32_C(0x8d5)));
    assert(interpreter.info.jit_executions == 0U);
    /* Adapter-owned serializing instructions deliberately terminate a Blink
     * path; the JIT still owns the decoded attempt and reports no fallback. */
    assert(jit.info.jit_executions == 0U && jit.info.jit_failures == 0U);
}

static void verify_legacy_state_semantics(void) {
    static const uint8_t nop[] = {0x90U};
    static const uint8_t pxor_mmx[] = {0x0fU, 0xefU, 0xc0U};
    static const uint8_t emms[] = {0x0fU, 0x77U};
    static const uint8_t movq_mmx[] = {0x0fU, 0x6fU, 0xc8U};
    static const uint8_t movq2dq[] = {0xf3U, 0x0fU, 0xd6U, 0xd1U};
    static const uint8_t movdq2q[] = {0xf2U, 0x0fU, 0xd6U, 0xdaU};
    struct execution roundtrip =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 3U, I386_PHASE3_CPUID_CONTEXT, nop, sizeof(nop));
    struct execution alias =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 4U, I386_PHASE3_MMX, pxor_mmx, sizeof(pxor_mmx));
    struct execution empty =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 5U, I386_PHASE3_MMX, emms, sizeof(emms));
    struct execution move =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 6U, I386_PHASE3_MMX, movq_mmx, sizeof(movq_mmx));
    struct execution to_xmm =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 7U, I386_PHASE3_MMX, movq2dq, sizeof(movq2dq));
    struct execution from_xmm =
        execute_case(GEM_I386_ENGINE_INTERPRETER, 8U, I386_PHASE3_MMX, movdq2q, sizeof(movdq2q));
    assert(memcmp(roundtrip.record.initial.x87, roundtrip.record.final.x87,
                  sizeof(roundtrip.record.initial.x87)) == 0);
    assert(roundtrip.record.final.x87_environment.fip ==
           roundtrip.record.initial.x87_environment.fip);
    assert(roundtrip.record.final.x87_environment.fdp ==
           roundtrip.record.initial.x87_environment.fdp);
    assert(roundtrip.record.final.x87_environment.fcs ==
           roundtrip.record.initial.x87_environment.fcs);
    assert(roundtrip.record.final.x87_environment.fds ==
           roundtrip.record.initial.x87_environment.fds);
    assert(alias.record.final.x87[0].lo == 0U);
    assert((alias.record.final.x87[0].hi & UINT64_C(0xffff)) == UINT64_C(0xffff));
    assert(empty.record.final.ftw == UINT16_MAX);
    assert(move.record.final.x87[1].lo == move.record.initial.x87[0].lo);
    assert(memcmp(move.record.final.xmm, move.record.initial.xmm, sizeof(move.record.final.xmm)) ==
           0);
    assert(to_xmm.record.final.xmm[2].lo == to_xmm.record.initial.x87[1].lo);
    assert(to_xmm.record.final.xmm[2].hi == 0U);
    assert(memcmp(to_xmm.record.final.x87, to_xmm.record.initial.x87,
                  sizeof(to_xmm.record.final.x87)) == 0);
    assert(from_xmm.record.final.x87[3].lo == from_xmm.record.initial.xmm[2].lo);
    assert(memcmp(from_xmm.record.final.xmm, from_xmm.record.initial.xmm,
                  sizeof(from_xmm.record.final.xmm)) == 0);
}

static void verify_restartable_rep(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {0xf3U, 0xa4U};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint8_t source[4] = {0x11U, 0x22U, 0x33U, 0x44U};
    uint8_t destination[4] = {0};
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA + 64U, source, sizeof(source)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_ESI] = DATA + 64U;
    context.gpr[GEM_I386_EDI] = DATA + GEM_GUEST_PAGE_SIZE - 4U;
    context.gpr[GEM_I386_ECX] = 8U;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.instructions_retired == 0U && stop.access == GEM_I386_ACCESS_WRITE);
    assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
    if (context.eip != CODE || context.gpr[GEM_I386_ECX] != 4U)
        fprintf(stderr,
                "restartable REP state mismatch: mode=%u eip=%08x ecx=%08x esi=%08x edi=%08x "
                "status=%u fault=%08x memory=%u\n",
                (unsigned)mode, context.eip, context.gpr[GEM_I386_ECX], context.gpr[GEM_I386_ESI],
                context.gpr[GEM_I386_EDI], stop.engine_status, stop.fault_address,
                stop.memory_error);
    assert(context.eip == CODE && context.gpr[GEM_I386_ECX] == 4U);
    assert(context.gpr[GEM_I386_ESI] == DATA + 68U);
    assert(context.gpr[GEM_I386_EDI] == DATA + GEM_GUEST_PAGE_SIZE);
    assert(gem_i386_memory_read(memory, DATA + GEM_GUEST_PAGE_SIZE - 4U, destination,
                                sizeof(destination)) == GEM_MEMORY_OK);
    assert(memcmp(source, destination, sizeof(source)) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_segment_limit(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {0x3eU, 0xa1U, 0x7fU, 0x00U, 0x00U, 0x00U};
    static const uint8_t write_code[] = {0x3eU, 0xa3U, 0x40U, 0x00U, 0x00U, 0x00U};
    static const uint8_t execute_code[] = {0x66U, 0x90U, 0x90U, 0x90U, 0x90U, 0x90U};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.segment_base[GEM_I386_DS] = DATA;
    context.segment_limit[GEM_I386_DS] = UINT32_C(0x80);
    context.segment_attributes[GEM_I386_DS] =
        GEM_I386_SEGMENT_PRESENT | GEM_I386_SEGMENT_WRITABLE | GEM_I386_SEGMENT_DEFAULT_32;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.instructions_retired == 0U && stop.access == GEM_I386_ACCESS_READ);
    assert(stop.fault_address == DATA + UINT32_C(0x81));
    assert(context.eip == CODE);
    assert(gem_i386_memory_write(memory, CODE, write_code, sizeof(write_code)) == GEM_MEMORY_OK);
    gem_i386_runtime_invalidate_code(runtime, CODE, sizeof(write_code));
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.segment_base[GEM_I386_DS] = DATA;
    context.segment_limit[GEM_I386_DS] = UINT32_MAX;
    context.segment_attributes[GEM_I386_DS] =
        GEM_I386_SEGMENT_PRESENT | GEM_I386_SEGMENT_DEFAULT_32;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    if (stop.access != GEM_I386_ACCESS_WRITE || stop.fault_address != DATA + 0x40U)
        fprintf(stderr, "segment write fault mismatch mode=%u access=%u address=%08x\n",
                (unsigned)mode, (unsigned)stop.access, stop.fault_address);
    assert(stop.access == GEM_I386_ACCESS_WRITE && stop.fault_address == DATA + 0x40U);
    assert(context.eip == CODE);
    assert(gem_i386_memory_write(memory, CODE, execute_code, sizeof(execute_code)) ==
           GEM_MEMORY_OK);
    gem_i386_runtime_invalidate_code(runtime, CODE, sizeof(execute_code));
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = 0U;
    context.segment_base[GEM_I386_CS] = CODE;
    context.segment_limit[GEM_I386_CS] = 0U;
    context.segment_attributes[GEM_I386_CS] =
        GEM_I386_SEGMENT_PRESENT | GEM_I386_SEGMENT_EXECUTABLE | GEM_I386_SEGMENT_DEFAULT_32;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.access == GEM_I386_ACCESS_FETCH && stop.fault_address == CODE + 1U);
    assert(context.eip == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_bmi1_cross_page(enum gem_i386_engine_mode mode, int commit_second_page) {
    static const uint8_t code[] = {0xc4U, 0xe2U, 0x60U, 0xf2U, 0x06U};
    static const uint8_t operand[] = {0x78U, 0x56U, 0x34U, 0x12U};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_context initial;
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA + GEM_GUEST_PAGE_SIZE - 2U, operand, 2U) ==
           GEM_MEMORY_OK);
    if (commit_second_page) {
        assert(gem_i386_memory_commit(memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                                      GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_write(memory, DATA + GEM_GUEST_PAGE_SIZE, operand + 2U, 2U) ==
               GEM_MEMORY_OK);
    }
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&initial, UINT32_C(0x7ffde000));
    initial.eip = CODE;
    initial.gpr[GEM_I386_EBX] = UINT32_C(0x0f0f0f0f);
    initial.gpr[GEM_I386_ESI] = DATA + GEM_GUEST_PAGE_SIZE - 2U;
    context = initial;
    if (commit_second_page) {
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(context.eip == CODE + sizeof(code));
        assert(context.gpr[GEM_I386_EAX] == (~initial.gpr[GEM_I386_EBX] & UINT32_C(0x12345678)));
    } else {
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
        assert(gem_i386_runtime_last_stop_info(runtime, &stop));
        assert(stop.instructions_retired == 0U && stop.access == GEM_I386_ACCESS_READ);
        assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
        assert(context.eip == initial.eip && context.eflags == initial.eflags);
        assert(memcmp(context.gpr, initial.gpr, sizeof(context.gpr)) == 0);
    }
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_bmi2_cross_page(enum gem_i386_engine_mode mode, int commit_second_page) {
    static const uint8_t code[] = {0xc4U, 0xe2U, 0x70U, 0xf5U, 0x1eU};
    static const uint8_t operand[] = {0x78U, 0x56U, 0x34U, 0x12U};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_context initial;
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA + GEM_GUEST_PAGE_SIZE - 2U, operand, 2U) ==
           GEM_MEMORY_OK);
    if (commit_second_page) {
        assert(gem_i386_memory_commit(memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                                      GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_write(memory, DATA + GEM_GUEST_PAGE_SIZE, operand + 2U, 2U) ==
               GEM_MEMORY_OK);
    }
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 1U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&initial, UINT32_C(0x7ffde000));
    initial.eip = CODE;
    initial.gpr[GEM_I386_ECX] = 16U;
    initial.gpr[GEM_I386_ESI] = DATA + GEM_GUEST_PAGE_SIZE - 2U;
    context = initial;
    if (commit_second_page) {
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(context.eip == CODE + sizeof(code));
        assert(context.gpr[GEM_I386_EBX] == UINT32_C(0x5678));
    } else {
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
        assert(gem_i386_runtime_last_stop_info(runtime, &stop));
        assert(stop.instructions_retired == 0U && stop.access == GEM_I386_ACCESS_READ);
        assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
        assert(context.eip == initial.eip && context.eflags == initial.eflags);
        assert(memcmp(context.gpr, initial.gpr, sizeof(context.gpr)) == 0);
    }
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_bmi2_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0x40U, 0x30U, 0x20U, 0x10U,       /* mov eax,0x10203040 */
        0xb9U, 0x07U, 0x00U, 0x00U, 0x00U,       /* mov ecx,7 */
        0xc4U, 0xe2U, 0x70U, 0xf5U, 0xd8U,       /* bzhi ecx,eax,ebx */
        0x83U, 0xfbU, 0x40U,                     /* cmp ebx,0x40 */
        0x75U, 0x03U,                            /* jne failure */
        0x31U, 0xc0U,                            /* xor eax,eax */
        0xc3U,                                   /* success return */
        0xb8U, 0x01U, 0x00U, 0x00U, 0x00U, 0xc3U /* failure return */
    };
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + 22U;
    config.max_budget = 6U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    assert(gem_i386_runtime_run(runtime, &context, 6U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.instructions_retired == 6U);
    assert(context.eip == CODE + 22U);
    assert(context.gpr[GEM_I386_EAX] == 0U);
    assert(context.gpr[GEM_I386_EBX] == UINT32_C(0x40));
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 6U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_avx_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xc5U, 0xfcU, 0x10U, 0x06U, /* vmovups ymm0,[esi] */
        0xc5U, 0xfcU, 0x58U, 0xc0U, /* vaddps ymm0,ymm0,ymm0 */
        0xc5U, 0xfcU, 0x11U, 0x07U  /* vmovups [edi],ymm0 */
    };
    static const float input[8] = {1.0F, 2.0F, 4.0F, 8.0F, 16.0F, 32.0F, 64.0F, 128.0F};
    static const float expected[8] = {2.0F, 4.0F, 8.0F, 16.0F, 32.0F, 64.0F, 128.0F, 256.0F};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    float output[8] = {0};
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA, input, sizeof(input)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 3U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_ESI] = DATA;
    context.gpr[GEM_I386_EDI] = DATA + 64U;
    context.xcr0 = GEM_I386_XCR0_SUPPORTED;
    reason = gem_i386_runtime_run(runtime, &context, 3U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    if (reason != GEM_STOP_HOST_RETURN)
        fprintf(stderr, "AVX guest program stopped: mode=%u reason=%u eip=%08x status=%08x\n",
                (unsigned)mode, (unsigned)reason, context.eip, stop.engine_status);
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 3U);
    assert(context.eip == CODE + sizeof(code));
    assert(gem_i386_memory_read(memory, DATA + 64U, output, sizeof(output)) == GEM_MEMORY_OK);
    assert(memcmp(output, expected, sizeof(output)) == 0);
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 3U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_avx2_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xc5U, 0xfeU, 0x6fU, 0x0eU,        /* vmovdqu ymm1,[esi] */
        0xc5U, 0xfeU, 0x6fU, 0x56U, 0x20U, /* vmovdqu ymm2,[esi+32] */
        0xc5U, 0xf5U, 0xfeU, 0xc2U,        /* vpaddd ymm0,ymm1,ymm2 */
        0xc5U, 0xfeU, 0x7fU, 0x07U         /* vmovdqu [edi],ymm0 */
    };
    static const uint32_t input[16] = {1U,  2U,  3U,  4U,  5U,  6U,  7U,  8U,
                                       10U, 20U, 30U, 40U, 50U, 60U, 70U, 80U};
    static const uint32_t expected[8] = {11U, 22U, 33U, 44U, 55U, 66U, 77U, 88U};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    uint32_t output[8] = {0};
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA, input, sizeof(input)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 5U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_ESI] = DATA;
    context.gpr[GEM_I386_EDI] = DATA + 128U;
    context.xcr0 = GEM_I386_XCR0_SUPPORTED;
    reason = gem_i386_runtime_run(runtime, &context, 5U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    if (reason != GEM_STOP_HOST_RETURN)
        fprintf(stderr,
                "AVX2 guest program stopped: mode=%u reason=%u eip=%08x status=%08x retired=%u\n",
                (unsigned)mode, (unsigned)reason, context.eip, stop.engine_status,
                stop.instructions_retired);
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 4U);
    assert(context.eip == CODE + sizeof(code));
    assert(gem_i386_memory_read(memory, DATA + 128U, output, sizeof(output)) == GEM_MEMORY_OK);
    assert(memcmp(output, expected, sizeof(output)) == 0);
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 4U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_fma_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xc5U, 0xfcU, 0x10U, 0x06U,        /* vmovups ymm0,[esi] */
        0xc5U, 0xfcU, 0x10U, 0x4eU, 0x20U, /* vmovups ymm1,[esi+32] */
        0xc5U, 0xfcU, 0x10U, 0x56U, 0x40U, /* vmovups ymm2,[esi+64] */
        0xc4U, 0xe2U, 0x75U, 0x98U, 0xc2U, /* vfmadd132ps ymm0,ymm1,ymm2 */
        0xc5U, 0xfcU, 0x11U, 0x07U         /* vmovups [edi],ymm0 */
    };
    static const float input[24] = {2.0F, 2.0F, 2.0F, 2.0F, 2.0F, 2.0F, 2.0F, 2.0F,
                                    3.0F, 3.0F, 3.0F, 3.0F, 3.0F, 3.0F, 3.0F, 3.0F,
                                    5.0F, 5.0F, 5.0F, 5.0F, 5.0F, 5.0F, 5.0F, 5.0F};
    static const float expected[8] = {13.0F, 13.0F, 13.0F, 13.0F, 13.0F, 13.0F, 13.0F, 13.0F};
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    float output[8] = {0};
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, DATA, input, sizeof(input)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 6U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_ESI] = DATA;
    context.gpr[GEM_I386_EDI] = DATA + 128U;
    context.xcr0 = GEM_I386_XCR0_SUPPORTED;
    reason = gem_i386_runtime_run(runtime, &context, 6U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    if (reason != GEM_STOP_HOST_RETURN)
        fprintf(stderr,
                "FMA guest program stopped: mode=%u reason=%u eip=%08x status=%08x retired=%u\n",
                (unsigned)mode, (unsigned)reason, context.eip, stop.engine_status,
                stop.instructions_retired);
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 5U);
    assert(context.eip == CODE + sizeof(code));
    assert(gem_i386_memory_read(memory, DATA + 128U, output, sizeof(output)) == GEM_MEMORY_OK);
    assert(memcmp(output, expected, sizeof(output)) == 0);
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 5U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_adx_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xb8U, 0xffU, 0xffU, 0xffU, 0xffU, /* mov eax,-1 */
        0x31U, 0xc9U,                      /* xor ecx,ecx */
        0x31U, 0xd2U,                      /* xor edx,edx */
        0xbbU, 0xffU, 0xffU, 0xffU, 0x7fU, /* mov ebx,0x7fffffff */
        0x83U, 0xc3U, 0x01U,               /* add ebx,1 (OF=1) */
        0xf9U,                             /* stc (CF=1, preserve OF) */
        0x66U, 0x0fU, 0x38U, 0xf6U, 0xc8U, /* adcx ecx,eax */
        0xf3U, 0x0fU, 0x38U, 0xf6U, 0xd0U  /* adox edx,eax */
    };
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 9U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    reason = gem_i386_runtime_run(runtime, &context, 9U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 8U);
    assert(context.eip == CODE + sizeof(code));
    assert(context.gpr[GEM_I386_ECX] == 0U && context.gpr[GEM_I386_EDX] == 0U);
    assert((context.eflags & (UINT32_C(0x001) | UINT32_C(0x800))) ==
           (UINT32_C(0x001) | UINT32_C(0x800)));
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 8U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_rdpid_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0xf3U, 0x0fU, 0xc7U, 0xf8U, /* rdpid eax */
        0x89U, 0x07U                /* mov [edi],eax */
    };
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    uint32_t output = UINT32_MAX;
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 3U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_EDI] = DATA;
    reason = gem_i386_runtime_run(runtime, &context, 3U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 2U);
    assert(context.eip == CODE + sizeof(code));
    assert(context.gpr[GEM_I386_EAX] == 0U);
    assert(gem_i386_memory_read(memory, DATA, &output, sizeof(output)) == GEM_MEMORY_OK);
    assert(output == 0U);
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 2U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void verify_random_guest_program(enum gem_i386_engine_mode mode) {
    static const uint8_t code[] = {
        0x0fU, 0xc7U, 0xf0U, /* rdrand eax */
        0x89U, 0x07U,        /* mov [edi],eax */
        0x0fU, 0xc7U, 0xf9U, /* rdseed ecx */
        0x89U, 0x4fU, 0x04U  /* mov [edi+4],ecx */
    };
    const uint32_t arithmetic_flags = UINT32_C(0x8d5);
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_context context;
    struct gem_i386_runtime *runtime;
    enum gem_stop_reason reason;
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, sizeof(code)) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)sizeof(code);
    config.max_budget = 5U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE;
    context.gpr[GEM_I386_EDI] = DATA;
    context.eflags |= arithmetic_flags;
    reason = gem_i386_runtime_run(runtime, &context, 5U);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(reason == GEM_STOP_HOST_RETURN);
    assert(stop.instructions_retired == 4U);
    assert(context.eip == CODE + sizeof(code));
    assert((context.eflags & arithmetic_flags) == UINT32_C(0x001));
    info.abi_version = 1U;
    info.size = sizeof(info);
    assert(gem_i386_runtime_engine_info(runtime, &info));
    if (mode == GEM_I386_ENGINE_JIT)
        assert(info.jit_executions == 4U && info.jit_failures == 0U);
    else
        assert(info.jit_executions == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void expect_masked_instruction(const uint8_t *code, size_t code_size) {
    const enum gem_i386_engine_mode modes[] = {GEM_I386_ENGINE_INTERPRETER, GEM_I386_ENGINE_JIT};
    unsigned int mode_index;
    for (mode_index = 0U; mode_index < 2U; ++mode_index) {
        struct gem_i386_runtime_config config = {0};
        struct gem_i386_context context;
        struct gem_i386_runtime *runtime;
        struct gem_memory *memory = gem_memory_create();
        uint32_t address = CODE;
        assert(memory != NULL);
        assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE,
                                      GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_write(memory, CODE, code, code_size) == GEM_MEMORY_OK);
        config.engine_mode = modes[mode_index];
        config.host_return_sentinel = CODE + (uint32_t)code_size;
        config.max_budget = 1U;
        runtime = gem_i386_runtime_create(memory, &config);
        assert(runtime != NULL);
        gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
        context.eip = CODE;
        context.gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
        {
            enum gem_stop_reason reason = gem_i386_runtime_run(runtime, &context, 1U);
            struct gem_i386_stop_info stop = {0};
            assert(gem_i386_runtime_last_stop_info(runtime, &stop));
            if (reason != GEM_STOP_UNSUPPORTED_INSTRUCTION &&
                !(reason == GEM_STOP_WINDOWS_EXCEPTION &&
                  stop.engine_status == GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION))
                fprintf(stderr, "masked instruction admitted: %02x %02x mode=%u reason=%u\n",
                        code[0], code_size > 1U ? code[1] : 0U, (unsigned)modes[mode_index],
                        (unsigned)reason);
            assert(reason == GEM_STOP_UNSUPPORTED_INSTRUCTION ||
                   (reason == GEM_STOP_WINDOWS_EXCEPTION &&
                    stop.engine_status == GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION));
        }
        assert(context.eip == CODE);
        gem_i386_runtime_destroy(runtime);
        gem_memory_destroy(memory);
    }
}

static void verify_masked_instructions(void) {
    static const uint8_t invalid_bmi2_prefix[] = {0xc4U, 0xe2U, 0x71U, 0xf5U, 0xd8U};
    static const uint8_t invalid_legacy_bmi2[] = {0x0fU, 0x38U, 0xf5U, 0xd8U};
    static const uint8_t fsgsbase[] = {0xf3U, 0x0fU, 0xaeU, 0xc0U};
    expect_masked_instruction(invalid_bmi2_prefix, sizeof(invalid_bmi2_prefix));
    expect_masked_instruction(invalid_legacy_bmi2, sizeof(invalid_legacy_bmi2));
    expect_masked_instruction(fsgsbase, sizeof(fsgsbase));
}

int main(void) {
    static const uint8_t x0[] = {0xd9U, 0xe8U}, x1[] = {0xd9U, 0xeeU};
    static const uint8_t x2[] = {0xd9U, 0xe0U}, x3[] = {0xdbU, 0xe3U};
    static const uint8_t x4[] = {0xd9U, 0xd0U}, x5[] = {0xd9U, 0xc0U};
    static const uint8_t *const x87[] = {x0, x1, x2, x3, x4, x5};
    static const uint8_t x87n[] = {sizeof(x0), sizeof(x1), sizeof(x2),
                                   sizeof(x3), sizeof(x4), sizeof(x5)};
    static const uint8_t m0[] = {0x0fU, 0xefU, 0xc0U}, m1[] = {0x0fU, 0xfcU, 0xc1U};
    static const uint8_t m2[] = {0x0fU, 0xd8U, 0xc1U}, m3[] = {0x0fU, 0x74U, 0xc1U};
    static const uint8_t m4[] = {0x0fU, 0x60U, 0xc1U}, m5[] = {0x0fU, 0xd5U, 0xc1U};
    static const uint8_t m6[] = {0x0fU, 0x77U};
    static const uint8_t *const mmx[] = {m0, m1, m2, m3, m4, m5, m6};
    static const uint8_t mmxn[] = {sizeof(m0), sizeof(m1), sizeof(m2), sizeof(m3),
                                   sizeof(m4), sizeof(m5), sizeof(m6)};
    static const uint8_t s0[] = {0x0fU, 0x57U, 0xc0U};
    static const uint8_t s1[] = {0x66U, 0x0fU, 0xefU, 0xc0U};
    static const uint8_t s2[] = {0x66U, 0x0fU, 0x38U, 0x00U, 0xc1U};
    static const uint8_t s3[] = {0x66U, 0x0fU, 0x38U, 0x39U, 0xc1U};
    static const uint8_t s4[] = {0xf2U, 0x0fU, 0x38U, 0xf1U, 0xc3U};
    static const uint8_t s5[] = {0x66U, 0x0fU, 0x3aU, 0x44U, 0xc1U, 0x00U};
    static const uint8_t s6[] = {0x66U, 0x0fU, 0x38U, 0xdcU, 0xc1U};
    static const uint8_t s7[] = {0x66U, 0x0fU, 0x38U, 0xddU, 0xc1U};
    static const uint8_t s8[] = {0x66U, 0x0fU, 0x38U, 0xdeU, 0xc1U};
    static const uint8_t s9[] = {0x66U, 0x0fU, 0x38U, 0xdfU, 0xc1U};
    static const uint8_t s10[] = {0x66U, 0x0fU, 0x38U, 0xdbU, 0xc1U};
    static const uint8_t s11[] = {0x66U, 0x0fU, 0x3aU, 0xdfU, 0xc1U, 0x01U};
    static const uint8_t s12[] = {0x66U, 0x0fU, 0x38U, 0x10U, 0xc1U};
    static const uint8_t s13[] = {0x66U, 0x0fU, 0x38U, 0x14U, 0xc1U};
    static const uint8_t s14[] = {0x66U, 0x0fU, 0x38U, 0x15U, 0xc1U};
    static const uint8_t s15[] = {0x66U, 0x0fU, 0x38U, 0x17U, 0xc1U};
    static const uint8_t s16[] = {0x66U, 0x0fU, 0x38U, 0x20U, 0xc1U};
    static const uint8_t s17[] = {0x66U, 0x0fU, 0x38U, 0x21U, 0xc1U};
    static const uint8_t s18[] = {0x66U, 0x0fU, 0x38U, 0x22U, 0xc1U};
    static const uint8_t s19[] = {0x66U, 0x0fU, 0x38U, 0x23U, 0xc1U};
    static const uint8_t s20[] = {0x66U, 0x0fU, 0x38U, 0x24U, 0xc1U};
    static const uint8_t s21[] = {0x66U, 0x0fU, 0x38U, 0x25U, 0xc1U};
    static const uint8_t s22[] = {0x66U, 0x0fU, 0x38U, 0x28U, 0xc1U};
    static const uint8_t s23[] = {0x66U, 0x0fU, 0x38U, 0x29U, 0xc1U};
    static const uint8_t s24[] = {0x66U, 0x0fU, 0x38U, 0x2bU, 0xc1U};
    static const uint8_t s25[] = {0x66U, 0x0fU, 0x38U, 0x30U, 0xc1U};
    static const uint8_t s26[] = {0x66U, 0x0fU, 0x38U, 0x31U, 0xc1U};
    static const uint8_t s27[] = {0x66U, 0x0fU, 0x38U, 0x32U, 0xc1U};
    static const uint8_t s28[] = {0x66U, 0x0fU, 0x38U, 0x33U, 0xc1U};
    static const uint8_t s29[] = {0x66U, 0x0fU, 0x38U, 0x34U, 0xc1U};
    static const uint8_t s30[] = {0x66U, 0x0fU, 0x38U, 0x35U, 0xc1U};
    static const uint8_t s31[] = {0x66U, 0x0fU, 0x38U, 0x37U, 0xc1U};
    static const uint8_t s32[] = {0x66U, 0x0fU, 0x38U, 0x41U, 0xc1U};
    static const uint8_t s33[] = {0x66U, 0x0fU, 0x3aU, 0x08U, 0xc1U, 0x02U};
    static const uint8_t s34[] = {0x66U, 0x0fU, 0x3aU, 0x09U, 0xc1U, 0x01U};
    static const uint8_t s35[] = {0x66U, 0x0fU, 0x3aU, 0x0aU, 0xc1U, 0x03U};
    static const uint8_t s36[] = {0x66U, 0x0fU, 0x3aU, 0x0bU, 0xc1U, 0x00U};
    static const uint8_t s37[] = {0x66U, 0x0fU, 0x3aU, 0x0cU, 0xc1U, 0xa5U};
    static const uint8_t s38[] = {0x66U, 0x0fU, 0x3aU, 0x0dU, 0xc1U, 0x03U};
    static const uint8_t s39[] = {0x66U, 0x0fU, 0x3aU, 0x0eU, 0xc1U, 0x5aU};
    static const uint8_t s40[] = {0x66U, 0x0fU, 0x3aU, 0x14U, 0xc1U, 0x07U};
    static const uint8_t s41[] = {0x66U, 0x0fU, 0x3aU, 0x15U, 0xc1U, 0x03U};
    static const uint8_t s42[] = {0x66U, 0x0fU, 0x3aU, 0x16U, 0xc1U, 0x02U};
    static const uint8_t s43[] = {0x66U, 0x0fU, 0x3aU, 0x17U, 0xc1U, 0x01U};
    static const uint8_t s44[] = {0x66U, 0x0fU, 0x3aU, 0x20U, 0xc1U, 0x05U};
    static const uint8_t s45[] = {0x66U, 0x0fU, 0x3aU, 0x21U, 0xc1U, 0x48U};
    static const uint8_t s46[] = {0x66U, 0x0fU, 0x3aU, 0x22U, 0xc1U, 0x02U};
    static const uint8_t s47[] = {0x66U, 0x0fU, 0x3aU, 0x40U, 0xc1U, 0xf1U};
    static const uint8_t s48[] = {0x66U, 0x0fU, 0x3aU, 0x41U, 0xc1U, 0x31U};
    static const uint8_t s49[] = {0x66U, 0x0fU, 0x3aU, 0x42U, 0xc1U, 0x05U};
    static const uint8_t s50[] = {0x66U, 0x0fU, 0x3aU, 0x60U, 0xc1U, 0x00U};
    static const uint8_t s51[] = {0x66U, 0x0fU, 0x3aU, 0x61U, 0xc1U, 0x41U};
    static const uint8_t s52[] = {0x66U, 0x0fU, 0x3aU, 0x62U, 0xc1U, 0x18U};
    static const uint8_t s53[] = {0x66U, 0x0fU, 0x3aU, 0x63U, 0xc1U, 0x79U};
    static const uint8_t *const simd[] = {
        s0,  s1,  s2,  s3,  s4,  s5,  s6,  s7,  s8,  s9,  s10, s11, s12, s13, s14, s15, s16, s17,
        s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35,
        s36, s37, s38, s39, s40, s41, s42, s43, s44, s45, s46, s47, s48, s49, s50, s51, s52, s53};
    static const uint8_t simdn[] = {
        sizeof(s0),  sizeof(s1),  sizeof(s2),  sizeof(s3),  sizeof(s4),  sizeof(s5),  sizeof(s6),
        sizeof(s7),  sizeof(s8),  sizeof(s9),  sizeof(s10), sizeof(s11), sizeof(s12), sizeof(s13),
        sizeof(s14), sizeof(s15), sizeof(s16), sizeof(s17), sizeof(s18), sizeof(s19), sizeof(s20),
        sizeof(s21), sizeof(s22), sizeof(s23), sizeof(s24), sizeof(s25), sizeof(s26), sizeof(s27),
        sizeof(s28), sizeof(s29), sizeof(s30), sizeof(s31), sizeof(s32), sizeof(s33), sizeof(s34),
        sizeof(s35), sizeof(s36), sizeof(s37), sizeof(s38), sizeof(s39), sizeof(s40), sizeof(s41),
        sizeof(s42), sizeof(s43), sizeof(s44), sizeof(s45), sizeof(s46), sizeof(s47), sizeof(s48),
        sizeof(s49), sizeof(s50), sizeof(s51), sizeof(s52), sizeof(s53)};
    static const uint8_t r0[] = {0xf3U, 0xa4U}, r1[] = {0xf3U, 0x66U, 0xa5U};
    static const uint8_t r2[] = {0xf3U, 0xa5U}, r3[] = {0xf3U, 0xaaU};
    static const uint8_t r4[] = {0xf3U, 0xabU}, r5[] = {0xf3U, 0xacU};
    static const uint8_t r6[] = {0xf3U, 0xa6U}, r7[] = {0xf2U, 0xaeU};
    static const uint8_t *const rep[] = {r0, r1, r2, r3, r4, r5, r6, r7};
    static const uint8_t repn[] = {sizeof(r0), sizeof(r1), sizeof(r2), sizeof(r3),
                                   sizeof(r4), sizeof(r5), sizeof(r6), sizeof(r7)};
    static const uint8_t c0[] = {0x0fU, 0xa2U}, c1[] = {0x90U};
    static const uint8_t c2[] = {0x0fU, 0xc7U, 0x0eU};
    static const uint8_t c3[] = {0x0fU, 0x44U, 0xc3U};
    static const uint8_t c4[] = {0xf3U, 0x0fU, 0xb8U, 0xc3U};
    static const uint8_t c5[] = {0x0fU, 0xaeU, 0x06U};
    static const uint8_t *const context[] = {c0, c1, c2, c3, c4, c5};
    static const uint8_t contextn[] = {sizeof(c0), sizeof(c1), sizeof(c2),
                                       sizeof(c3), sizeof(c4), sizeof(c5)};
    const char *capture_path = getenv("MSWR_PHASE3_CAPTURE_PATH");
    const struct i386_phase3_file_header header = {
        I386_PHASE3_REFERENCE_MAGIC, I386_PHASE3_CORPUS_SCHEMA,
        (uint32_t)sizeof(struct i386_phase3_record), I386_PHASE3_CASES};
    struct i386_phase3_file_header observed_header;
    uint32_t next = 0U;
    capture_reference = capture_path != NULL && capture_path[0] != '\0';
    reference_file = fopen(capture_reference ? capture_path : MSWR_PHASE3_REFERENCE_PATH,
                           capture_reference ? "wb" : "rb");
    assert(reference_file != NULL);
    if (capture_reference) {
        assert(fwrite(&header, sizeof(header), 1U, reference_file) == 1U);
    } else {
        assert(fread(&observed_header, sizeof(observed_header), 1U, reference_file) == 1U);
        assert(memcmp(&header, &observed_header, sizeof(header)) == 0);
    }
    next = run_category(next, I386_PHASE3_X87_CASES, I386_PHASE3_X87, x87, x87n, 6U);
    next = run_category(next, I386_PHASE3_MMX_CASES, I386_PHASE3_MMX, mmx, mmxn, 7U);
    next = run_category(next, I386_PHASE3_SIMD_CASES, I386_PHASE3_SIMD, simd, simdn, 54U);
    next =
        run_category(next, I386_PHASE3_REP_SEGMENT_CASES, I386_PHASE3_REP_SEGMENT, rep, repn, 8U);
    next = run_category(next, I386_PHASE3_CPUID_CONTEXT_CASES, I386_PHASE3_CPUID_CONTEXT, context,
                        contextn, 6U);
    assert(next == I386_PHASE3_CASES);
    verify_cpuid_profile();
    verify_bmi1_instructions();
    verify_bmi2_instructions();
    verify_rdtscp_instruction();
    verify_legacy_state_semantics();
    verify_restartable_rep(GEM_I386_ENGINE_INTERPRETER);
    verify_restartable_rep(GEM_I386_ENGINE_JIT);
    verify_segment_limit(GEM_I386_ENGINE_INTERPRETER);
    verify_segment_limit(GEM_I386_ENGINE_JIT);
    verify_bmi1_cross_page(GEM_I386_ENGINE_INTERPRETER, 1);
    verify_bmi1_cross_page(GEM_I386_ENGINE_JIT, 1);
    verify_bmi1_cross_page(GEM_I386_ENGINE_INTERPRETER, 0);
    verify_bmi1_cross_page(GEM_I386_ENGINE_JIT, 0);
    verify_bmi2_cross_page(GEM_I386_ENGINE_INTERPRETER, 1);
    verify_bmi2_cross_page(GEM_I386_ENGINE_JIT, 1);
    verify_bmi2_cross_page(GEM_I386_ENGINE_INTERPRETER, 0);
    verify_bmi2_cross_page(GEM_I386_ENGINE_JIT, 0);
    verify_bmi2_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_bmi2_guest_program(GEM_I386_ENGINE_JIT);
    verify_avx_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_avx_guest_program(GEM_I386_ENGINE_JIT);
    verify_avx2_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_avx2_guest_program(GEM_I386_ENGINE_JIT);
    verify_fma_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_fma_guest_program(GEM_I386_ENGINE_JIT);
    verify_adx_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_adx_guest_program(GEM_I386_ENGINE_JIT);
    verify_rdpid_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_rdpid_guest_program(GEM_I386_ENGINE_JIT);
    verify_random_guest_program(GEM_I386_ENGINE_INTERPRETER);
    verify_random_guest_program(GEM_I386_ENGINE_JIT);
    verify_masked_instructions();
    assert(capture_reference || fgetc(reference_file) == EOF);
    assert(fclose(reference_file) == 0);
    printf("Phase 3 corpus passed: %u cases, %u interpreter/JIT comparisons\n", I386_PHASE3_CASES,
           I386_PHASE3_COMPARISONS);
    return 0;
}
