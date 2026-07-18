// SPDX-License-Identifier: Apache-2.0
/* ADR 0013 W4 gate: protected-mode VEX decode, XGETBV, standard XSAVE/XRSTOR,
 * fail-closed XSAVEOPT, #GP mapping, and restartable cross-page operands. */
#include "blink/gem_embed.h"
#include "i386_engine_internal.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)
#define XSTATE_SIZE 832U

static const uint8_t xgetbv[] = {0x0fU, 0x01U, 0xd0U};
static const uint8_t xsetbv[] = {0x0fU, 0x01U, 0xd1U};
static const uint8_t xsave_esi[] = {0x0fU, 0xaeU, 0x26U};
static const uint8_t xrstor_esi[] = {0x0fU, 0xaeU, 0x2eU};
static const uint8_t xsaveopt_esi[] = {0x0fU, 0xaeU, 0x36U};
static const uint8_t vzeroupper[] = {0xc5U, 0xf8U, 0x77U};
static const uint8_t vzeroall[] = {0xc5U, 0xfcU, 0x77U};
static const uint8_t vaddps[] = {0xc5U, 0xf0U, 0x58U, 0xc2U};
static const uint8_t vaddss[] = {0xc5U, 0xf2U, 0x58U, 0xc2U};
static const uint8_t vaddps_ymm[] = {0xc5U, 0xf4U, 0x58U, 0xc2U};
static const uint8_t vaddps_ymm_esi[] = {0xc5U, 0xf4U, 0x58U, 0x06U};
static const uint8_t vmovups_ymm_store[] = {0xc5U, 0xfcU, 0x11U, 0x06U};
static const uint8_t vmovaps_ymm_store[] = {0xc5U, 0xfcU, 0x29U, 0x06U};
static const uint8_t vmovss_store[] = {0xc5U, 0xfaU, 0x11U, 0x06U};
static const uint8_t vpaddd_xmm[] = {0xc5U, 0xf1U, 0xfeU, 0xc2U};
static const uint8_t vmovhlps_xmm[] = {0xc5U, 0xf0U, 0x12U, 0xc2U};
static const uint8_t vpshufb_xmm[] = {0xc4U, 0xe2U, 0x71U, 0x00U, 0xc2U};
static const uint8_t vpmovsxbd_esi[] = {0xc4U, 0xe2U, 0x79U, 0x21U, 0x06U};
static const uint8_t vroundps_xmm[] = {0xc4U, 0xe3U, 0x79U, 0x08U, 0xc2U, 0x00U};
static const uint8_t vbroadcastss_ymm[] = {0xc4U, 0xe2U, 0x7dU, 0x18U, 0x06U};
static const uint8_t vpermilps_ymm_imm[] = {0xc4U, 0xe3U, 0x7dU, 0x04U, 0xc1U, 0x1bU};
static const uint8_t vpermilps_ymm_var[] = {0xc4U, 0xe2U, 0x75U, 0x0cU, 0xc2U};
static const uint8_t vperm2f128_ymm[] = {0xc4U, 0xe3U, 0x75U, 0x06U, 0xc2U, 0x21U};
static const uint8_t vinsertf128_ymm[] = {0xc4U, 0xe3U, 0x75U, 0x18U, 0xc2U, 0x01U};
static const uint8_t vextractf128_xmm[] = {0xc4U, 0xe3U, 0x7dU, 0x19U, 0xc2U, 0x01U};
static const uint8_t vtestps_ymm[] = {0xc4U, 0xe2U, 0x7dU, 0x0eU, 0xcaU};
static const uint8_t vblendvps_ymm[] = {0xc4U, 0xe3U, 0x75U, 0x4aU, 0xc2U, 0x30U};

static void put32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void put64(uint8_t *p, uint64_t value) {
    put32(p, (uint32_t)value);
    put32(p + 4, (uint32_t)(value >> 32));
}

static uint64_t get64(const uint8_t *p) {
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
           (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 | (uint64_t)p[6] << 48 |
           (uint64_t)p[7] << 56;
}

static struct gem_memory *make_memory(const uint8_t *code, size_t code_size,
                                      uint64_t committed_data) {
    struct gem_memory *memory = gem_memory_create();
    uint32_t address = CODE;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, CODE, code, code_size) == GEM_MEMORY_OK);
    address = DATA;
    assert(gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, DATA, committed_data, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    address = STACK;
    assert(gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    return memory;
}

static struct gem_i386_runtime *make_runtime(struct gem_memory *memory,
                                             enum gem_i386_engine_mode mode, size_t code_size) {
    struct gem_i386_runtime_config config;
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + (uint32_t)code_size;
    config.max_budget = 1U;
    return gem_i386_runtime_create(memory, &config);
}

static void initialize(struct gem_i386_context *context, uint32_t operand, uint32_t mask) {
    gem_i386_context_initialize(context, UINT32_C(0x7ffde000));
    context->eip = CODE;
    context->gpr[GEM_I386_ESP] = STACK + GEM_GUEST_PAGE_SIZE - 16U;
    context->gpr[GEM_I386_ESI] = operand;
    context->gpr[GEM_I386_EAX] = mask;
    context->xcr0 = GEM_I386_XCR0_SUPPORTED;
}

static void expect_protection(const uint8_t *code, size_t code_size, uint32_t operand,
                              uint32_t ecx) {
    struct gem_memory *memory = make_memory(code, code_size, GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, GEM_I386_ENGINE_INTERPRETER, code_size);
    struct gem_i386_context context;
    struct gem_i386_stop_info stop;
    assert(runtime != NULL);
    initialize(&context, operand, 7U);
    context.gpr[GEM_I386_ECX] = ecx;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_WINDOWS_EXCEPTION);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.engine_status == GEM_I386_EXCEPTION_GENERAL_PROTECTION);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_xgetbv(enum gem_i386_engine_mode mode) {
    struct gem_memory *memory = make_memory(xgetbv, sizeof(xgetbv), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(xgetbv));
    struct gem_i386_context context;
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == 7U && context.gpr[GEM_I386_EDX] == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_xsave(enum gem_i386_engine_mode mode) {
    struct gem_memory *memory = make_memory(xsave_esi, sizeof(xsave_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(xsave_esi));
    struct gem_i386_context context;
    uint8_t area[XSTATE_SIZE];
    uint32_t i;
    assert(runtime != NULL);
    initialize(&context, DATA, 7U);
    context.mxcsr = UINT32_C(0x1fa0);
    for (i = 0U; i < 8U; ++i) {
        context.xmm[i].lo = UINT64_C(0x1010101000000000) + i;
        context.xmm[i].hi = UINT64_C(0x2020202000000000) + i;
        context.ymm_upper[i].lo = UINT64_C(0xa0a0a0a000000000) + i;
        context.ymm_upper[i].hi = UINT64_C(0xb0b0b0b000000000) + i;
    }
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_memory_read(memory, DATA, area, sizeof(area)) == GEM_MEMORY_OK);
    assert(get64(area + 512) == 7U);
    assert(get64(area + 160) == UINT64_C(0x1010101000000000));
    assert(get64(area + 576) == UINT64_C(0xa0a0a0a000000000));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_xrstor(enum gem_i386_engine_mode mode) {
    struct gem_memory *memory = make_memory(xrstor_esi, sizeof(xrstor_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(xrstor_esi));
    struct gem_i386_context context;
    uint8_t area[XSTATE_SIZE];
    uint32_t i;
    assert(runtime != NULL);
    memset(area, 0, sizeof(area));
    put32(area + 24, UINT32_C(0x1fa0));
    put64(area + 512, 6U);
    for (i = 0U; i < 8U; ++i) {
        put64(area + 160U + i * 16U, UINT64_C(0x3030303000000000) + i);
        put64(area + 168U + i * 16U, UINT64_C(0x4040404000000000) + i);
        put64(area + 576U + i * 16U, UINT64_C(0xc0c0c0c000000000) + i);
        put64(area + 584U + i * 16U, UINT64_C(0xd0d0d0d000000000) + i);
    }
    assert(gem_i386_memory_write(memory, DATA, area, sizeof(area)) == GEM_MEMORY_OK);
    initialize(&context, DATA, 6U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(context.mxcsr == UINT32_C(0x1fa0));
    assert(context.xmm[7].lo == UINT64_C(0x3030303000000007));
    assert(context.xmm[7].hi == UINT64_C(0x4040404000000007));
    assert(context.ymm_upper[7].lo == UINT64_C(0xc0c0c0c000000007));
    assert(context.ymm_upper[7].hi == UINT64_C(0xd0d0d0d000000007));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_cross_page_retry(void) {
    const uint32_t operand = DATA + GEM_GUEST_PAGE_SIZE - 64U;
    struct gem_memory *memory = make_memory(xsave_esi, sizeof(xsave_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime =
        make_runtime(memory, GEM_I386_ENGINE_INTERPRETER, sizeof(xsave_esi));
    struct gem_i386_context context;
    uint8_t first[64];
    assert(runtime != NULL);
    initialize(&context, operand, 7U);
    memset(first, 0xa5, sizeof(first));
    assert(gem_i386_memory_write(memory, operand, first, sizeof(first)) == GEM_MEMORY_OK);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    memset(first, 0, sizeof(first));
    assert(gem_i386_memory_read(memory, operand, first, sizeof(first)) == GEM_MEMORY_OK);
    assert(first[0] == 0xa5U && first[63] == 0xa5U);
    assert(gem_i386_memory_commit(memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vzero(enum gem_i386_engine_mode mode, const uint8_t *code, size_t code_size,
                           int clear_all) {
    struct gem_memory *memory = make_memory(code, code_size, GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, code_size);
    struct gem_i386_context context;
    uint32_t i;
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    for (i = 0U; i < 8U; ++i) {
        context.xmm[i].lo = UINT64_C(0x1010101000000000) + i;
        context.xmm[i].hi = UINT64_C(0x2020202000000000) + i;
        context.ymm_upper[i].lo = UINT64_C(0xa0a0a0a000000000) + i;
        context.ymm_upper[i].hi = UINT64_C(0xb0b0b0b000000000) + i;
    }
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    for (i = 0U; i < 8U; ++i) {
        assert(context.ymm_upper[i].lo == 0U && context.ymm_upper[i].hi == 0U);
        if (clear_all)
            assert(context.xmm[i].lo == 0U && context.xmm[i].hi == 0U);
        else {
            assert(context.xmm[i].lo == UINT64_C(0x1010101000000000) + i);
            assert(context.xmm[i].hi == UINT64_C(0x2020202000000000) + i);
        }
    }
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vadd(enum gem_i386_engine_mode mode, const uint8_t *code, size_t code_size,
                          int scalar) {
    const float lhs[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    const float rhs[4] = {10.0f, 20.0f, 30.0f, 40.0f};
    const float expected_packed[4] = {11.0f, 22.0f, 33.0f, 44.0f};
    const float expected_scalar[4] = {11.0f, 2.0f, 3.0f, 4.0f};
    struct gem_memory *memory = make_memory(code, code_size, GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, code_size);
    struct gem_i386_context context;
    float actual[4];
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], lhs, sizeof(lhs));
    memcpy(&context.xmm[2], rhs, sizeof(rhs));
    context.ymm_upper[0].lo = UINT64_MAX;
    context.ymm_upper[0].hi = UINT64_MAX;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    memcpy(actual, &context.xmm[0], sizeof(actual));
    assert(memcmp(actual, scalar ? expected_scalar : expected_packed, sizeof(actual)) == 0);
    assert(context.ymm_upper[0].lo == 0U && context.ymm_upper[0].hi == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vadd256(enum gem_i386_engine_mode mode) {
    const float lhs[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    const float rhs[8] = {10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f};
    const float expected[8] = {11.0f, 22.0f, 33.0f, 44.0f, 55.0f, 66.0f, 77.0f, 88.0f};
    struct gem_memory *memory = make_memory(vaddps_ymm, sizeof(vaddps_ymm), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vaddps_ymm));
    struct gem_i386_context context;
    float actual[8];
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], lhs, 16U);
    memcpy(&context.ymm_upper[1], lhs + 4, 16U);
    memcpy(&context.xmm[2], rhs, 16U);
    memcpy(&context.ymm_upper[2], rhs + 4, 16U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    memcpy(actual, &context.xmm[0], 16U);
    memcpy(actual + 4, &context.ymm_upper[0], 16U);
    assert(memcmp(actual, expected, sizeof(actual)) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vadd256_cross_page(enum gem_i386_engine_mode mode) {
    const uint32_t operand = DATA + GEM_GUEST_PAGE_SIZE - 16U;
    const float source[8] = {10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f};
    const float lhs[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    struct gem_memory *memory =
        make_memory(vaddps_ymm_esi, sizeof(vaddps_ymm_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vaddps_ymm_esi));
    struct gem_i386_context context, before;
    struct gem_i386_stop_info stop;
    assert(runtime != NULL);
    initialize(&context, operand, 0U);
    memcpy(&context.xmm[1], lhs, 16U);
    memcpy(&context.ymm_upper[1], lhs + 4, 16U);
    context.xmm[0].lo = UINT64_C(0x1111111111111111);
    context.xmm[0].hi = UINT64_C(0x2222222222222222);
    context.ymm_upper[0].lo = UINT64_C(0x3333333333333333);
    context.ymm_upper[0].hi = UINT64_C(0x4444444444444444);
    before = context;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
    assert(context.eip == before.eip);
    assert(memcmp(&context.xmm[0], &before.xmm[0], sizeof(context.xmm[0])) == 0);
    assert(memcmp(&context.ymm_upper[0], &before.ymm_upper[0], sizeof(context.ymm_upper[0])) == 0);
    assert(gem_i386_memory_commit(memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, operand, source, sizeof(source)) == GEM_MEMORY_OK);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vmov256_store_cross_page(enum gem_i386_engine_mode mode) {
    const uint32_t operand = DATA + GEM_GUEST_PAGE_SIZE - 16U;
    const uint64_t source[4] = {UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222),
                                UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444)};
    uint8_t actual[32], first_page[16];
    struct gem_memory *memory =
        make_memory(vmovups_ymm_store, sizeof(vmovups_ymm_store), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vmovups_ymm_store));
    struct gem_i386_context context, before;
    struct gem_i386_stop_info stop;
    assert(runtime != NULL);
    memset(first_page, 0xa5, sizeof(first_page));
    assert(gem_i386_memory_write(memory, operand, first_page, sizeof(first_page)) == GEM_MEMORY_OK);
    initialize(&context, operand, 0U);
    memcpy(&context.xmm[0], source, 16U);
    memcpy(&context.ymm_upper[0], source + 2, 16U);
    before = context;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(gem_i386_runtime_last_stop_info(runtime, &stop));
    assert(stop.fault_address == DATA + GEM_GUEST_PAGE_SIZE);
    assert(context.eip == before.eip);
    assert(memcmp(&context.xmm[0], &before.xmm[0], sizeof(context.xmm[0])) == 0);
    assert(memcmp(&context.ymm_upper[0], &before.ymm_upper[0], sizeof(context.ymm_upper[0])) == 0);
    memset(first_page, 0, sizeof(first_page));
    assert(gem_i386_memory_read(memory, operand, first_page, sizeof(first_page)) == GEM_MEMORY_OK);
    for (size_t i = 0U; i < sizeof(first_page); ++i)
        assert(first_page[i] == 0xa5U);
    assert(gem_i386_memory_commit(memory, DATA + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_memory_read(memory, operand, actual, sizeof(actual)) == GEM_MEMORY_OK);
    assert(memcmp(actual, source, sizeof(source)) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vmov_store_shapes(enum gem_i386_engine_mode mode) {
    const uint32_t scalar_operand = DATA + GEM_GUEST_PAGE_SIZE - 4U;
    const uint32_t scalar = UINT32_C(0x7fc01234);
    struct gem_memory *memory =
        make_memory(vmovss_store, sizeof(vmovss_store), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vmovss_store));
    struct gem_i386_context context;
    uint32_t actual;
    assert(runtime != NULL);
    initialize(&context, scalar_operand, 0U);
    memcpy(&context.xmm[0], &scalar, sizeof(scalar));
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(gem_i386_memory_read(memory, scalar_operand, &actual, sizeof(actual)) == GEM_MEMORY_OK);
    assert(actual == scalar);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    memory = make_memory(vmovaps_ymm_store, sizeof(vmovaps_ymm_store), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vmovaps_ymm_store));
    assert(runtime != NULL);
    initialize(&context, DATA + 1U, 0U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_MEMORY_FAULT);
    assert(context.eip == CODE);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_avx_cross_lane(enum gem_i386_engine_mode mode) {
    const uint32_t broadcast = UINT32_C(0x3fa00000);
    const uint64_t first[4] = {UINT64_C(0x1111111111111111), UINT64_C(0x1212121212121212),
                               UINT64_C(0x1313131313131313), UINT64_C(0x1414141414141414)};
    const uint64_t second[4] = {UINT64_C(0x2121212121212121), UINT64_C(0x2222222222222222),
                                UINT64_C(0x2323232323232323), UINT64_C(0x2424242424242424)};
    const uint64_t permuted[4] = {UINT64_C(0x1313131313131313), UINT64_C(0x1414141414141414),
                                  UINT64_C(0x2121212121212121), UINT64_C(0x2222222222222222)};
    const uint64_t inserted[4] = {UINT64_C(0x1111111111111111), UINT64_C(0x1212121212121212),
                                  UINT64_C(0x2121212121212121), UINT64_C(0x2222222222222222)};
    struct gem_memory *memory;
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    uint32_t actual32[8];

    memory = make_memory(vbroadcastss_ymm, sizeof(vbroadcastss_ymm), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vbroadcastss_ymm));
    assert(runtime != NULL);
    assert(gem_i386_memory_write(memory, DATA + GEM_GUEST_PAGE_SIZE - 4U, &broadcast,
                                 sizeof(broadcast)) == GEM_MEMORY_OK);
    initialize(&context, DATA + GEM_GUEST_PAGE_SIZE - 4U, 0U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    memcpy(actual32, &context.xmm[0], 16U);
    memcpy(actual32 + 4, &context.ymm_upper[0], 16U);
    for (size_t i = 0U; i < 8U; ++i)
        assert(actual32[i] == broadcast);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    {
        const uint32_t values[8] = {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};
        const uint32_t control[8] = {1U, 0U, 3U, 2U, 2U, 3U, 0U, 1U};
        const uint32_t immediate_expected[8] = {3U, 2U, 1U, 0U, 7U, 6U, 5U, 4U};
        const uint32_t variable_expected[8] = {1U, 0U, 3U, 2U, 6U, 7U, 4U, 5U};
        memory = make_memory(vpermilps_ymm_imm, sizeof(vpermilps_ymm_imm), GEM_GUEST_PAGE_SIZE);
        runtime = make_runtime(memory, mode, sizeof(vpermilps_ymm_imm));
        assert(runtime != NULL);
        initialize(&context, DATA, 0U);
        memcpy(&context.xmm[1], values, 16U);
        memcpy(&context.ymm_upper[1], values + 4, 16U);
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(memcmp(&context.xmm[0], immediate_expected, 16U) == 0);
        assert(memcmp(&context.ymm_upper[0], immediate_expected + 4, 16U) == 0);
        gem_i386_runtime_destroy(runtime);
        gem_memory_destroy(memory);

        memory = make_memory(vpermilps_ymm_var, sizeof(vpermilps_ymm_var), GEM_GUEST_PAGE_SIZE);
        runtime = make_runtime(memory, mode, sizeof(vpermilps_ymm_var));
        assert(runtime != NULL);
        initialize(&context, DATA, 0U);
        memcpy(&context.xmm[1], values, 16U);
        memcpy(&context.ymm_upper[1], values + 4, 16U);
        memcpy(&context.xmm[2], control, 16U);
        memcpy(&context.ymm_upper[2], control + 4, 16U);
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(memcmp(&context.xmm[0], variable_expected, 16U) == 0);
        assert(memcmp(&context.ymm_upper[0], variable_expected + 4, 16U) == 0);
        gem_i386_runtime_destroy(runtime);
        gem_memory_destroy(memory);
    }

    memory = make_memory(vperm2f128_ymm, sizeof(vperm2f128_ymm), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vperm2f128_ymm));
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], first, 16U);
    memcpy(&context.ymm_upper[1], first + 2, 16U);
    memcpy(&context.xmm[2], second, 16U);
    memcpy(&context.ymm_upper[2], second + 2, 16U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[0], permuted, 16U) == 0);
    assert(memcmp(&context.ymm_upper[0], permuted + 2, 16U) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    memory = make_memory(vinsertf128_ymm, sizeof(vinsertf128_ymm), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vinsertf128_ymm));
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], first, 16U);
    memcpy(&context.ymm_upper[1], first + 2, 16U);
    memcpy(&context.xmm[2], second, 16U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[0], inserted, 16U) == 0);
    assert(memcmp(&context.ymm_upper[0], inserted + 2, 16U) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    memory = make_memory(vextractf128_xmm, sizeof(vextractf128_xmm), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vextractf128_xmm));
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[0], first, 16U);
    memcpy(&context.ymm_upper[0], first + 2, 16U);
    context.ymm_upper[2].lo = UINT64_MAX;
    context.ymm_upper[2].hi = UINT64_MAX;
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[2], first + 2, 16U) == 0);
    assert(context.ymm_upper[2].lo == 0U && context.ymm_upper[2].hi == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_avx_special_flags_and_blend(enum gem_i386_engine_mode mode) {
    const uint32_t first[8] = {UINT32_C(0x80000000), 1U, 1U, 1U, 1U, 1U, 1U, 1U};
    const uint32_t second[8] = {UINT32_C(0x80000000), 2U, 2U, 2U, 2U, 2U, 2U, 2U};
    const uint32_t mask[8] = {UINT32_C(0x80000000), 0U, UINT32_C(0x80000000), 0U,
                              UINT32_C(0x80000000), 0U, UINT32_C(0x80000000), 0U};
    const uint32_t expected[8] = {UINT32_C(0x80000000), 1U, 2U, 1U, 2U, 1U, 2U, 1U};
    struct gem_memory *memory = make_memory(vtestps_ymm, sizeof(vtestps_ymm), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vtestps_ymm));
    struct gem_i386_context context;
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], first, 16U);
    memcpy(&context.ymm_upper[1], first + 4, 16U);
    memcpy(&context.xmm[2], second, 16U);
    memcpy(&context.ymm_upper[2], second + 4, 16U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert((context.eflags & (1U << 6)) == 0U);
    assert((context.eflags & 1U) != 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    memory = make_memory(vblendvps_ymm, sizeof(vblendvps_ymm), GEM_GUEST_PAGE_SIZE);
    runtime = make_runtime(memory, mode, sizeof(vblendvps_ymm));
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], first, 16U);
    memcpy(&context.ymm_upper[1], first + 4, 16U);
    memcpy(&context.xmm[2], second, 16U);
    memcpy(&context.ymm_upper[2], second + 4, 16U);
    memcpy(&context.xmm[3], mask, 16U);
    memcpy(&context.ymm_upper[3], mask + 4, 16U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[0], expected, 16U) == 0);
    assert(memcmp(&context.ymm_upper[0], expected + 4, 16U) == 0);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_promoted128(enum gem_i386_engine_mode mode, const uint8_t *code,
                                 size_t code_size, unsigned operation) {
    struct gem_memory *memory = make_memory(code, code_size, GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, code_size);
    struct gem_i386_context context;
    uint32_t i;
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    context.ymm_upper[0].lo = UINT64_MAX;
    context.ymm_upper[0].hi = UINT64_MAX;
    if (operation == 0U) {
        const uint32_t lhs[4] = {1U, 2U, 3U, 4U};
        const uint32_t rhs[4] = {10U, 20U, 30U, 40U};
        const uint32_t expected[4] = {11U, 22U, 33U, 44U};
        memcpy(&context.xmm[1], lhs, sizeof(lhs));
        memcpy(&context.xmm[2], rhs, sizeof(rhs));
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(memcmp(&context.xmm[0], expected, sizeof(expected)) == 0);
    } else if (operation == 1U) {
        uint8_t source[16], control[16], expected[16];
        for (i = 0U; i < 16U; ++i) {
            source[i] = (uint8_t)i;
            control[i] = (uint8_t)(15U - i);
            expected[i] = (uint8_t)(15U - i);
        }
        memcpy(&context.xmm[1], source, sizeof(source));
        memcpy(&context.xmm[2], control, sizeof(control));
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(memcmp(&context.xmm[0], expected, sizeof(expected)) == 0);
    } else {
        const float source[4] = {1.4f, 1.5f, 2.5f, -1.5f};
        const float expected[4] = {1.0f, 2.0f, 2.0f, -2.0f};
        memcpy(&context.xmm[2], source, sizeof(source));
        assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
        assert(memcmp(&context.xmm[0], expected, sizeof(expected)) == 0);
    }
    assert(context.ymm_upper[0].lo == 0U && context.ymm_upper[0].hi == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vmovhlps(enum gem_i386_engine_mode mode) {
    const uint64_t lhs[2] = {UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222)};
    const uint64_t rhs[2] = {UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444)};
    const uint64_t expected[2] = {UINT64_C(0x4444444444444444), UINT64_C(0x2222222222222222)};
    struct gem_memory *memory =
        make_memory(vmovhlps_xmm, sizeof(vmovhlps_xmm), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vmovhlps_xmm));
    struct gem_i386_context context;
    assert(runtime != NULL);
    initialize(&context, DATA, 0U);
    memcpy(&context.xmm[1], lhs, sizeof(lhs));
    memcpy(&context.xmm[2], rhs, sizeof(rhs));
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[0], expected, sizeof(expected)) == 0);
    assert(context.ymm_upper[0].lo == 0U && context.ymm_upper[0].hi == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_vpmovsxbd_boundary(enum gem_i386_engine_mode mode) {
    const uint32_t operand = DATA + GEM_GUEST_PAGE_SIZE - 4U;
    const int8_t source[4] = {-1, 2, -3, 4};
    const int32_t expected[4] = {-1, 2, -3, 4};
    struct gem_memory *memory =
        make_memory(vpmovsxbd_esi, sizeof(vpmovsxbd_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime = make_runtime(memory, mode, sizeof(vpmovsxbd_esi));
    struct gem_i386_context context;
    assert(runtime != NULL);
    assert(gem_i386_memory_write(memory, operand, source, sizeof(source)) == GEM_MEMORY_OK);
    initialize(&context, operand, 0U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(memcmp(&context.xmm[0], expected, sizeof(expected)) == 0);
    assert(context.ymm_upper[0].lo == 0U && context.ymm_upper[0].hi == 0U);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

static void exercise_xsaveopt_gate(void) {
    struct gem_memory *memory =
        make_memory(xsaveopt_esi, sizeof(xsaveopt_esi), GEM_GUEST_PAGE_SIZE);
    struct gem_i386_runtime *runtime =
        make_runtime(memory, GEM_I386_ENGINE_INTERPRETER, sizeof(xsaveopt_esi));
    struct gem_i386_context context;
    assert(runtime != NULL);
    initialize(&context, DATA, 7U);
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
}

int main(void) {
    exercise_xgetbv(GEM_I386_ENGINE_INTERPRETER);
    exercise_xgetbv(GEM_I386_ENGINE_JIT);
    exercise_xsave(GEM_I386_ENGINE_INTERPRETER);
    exercise_xsave(GEM_I386_ENGINE_JIT);
    exercise_xrstor(GEM_I386_ENGINE_INTERPRETER);
    exercise_xrstor(GEM_I386_ENGINE_JIT);
    exercise_cross_page_retry();
    exercise_vzero(GEM_I386_ENGINE_INTERPRETER, vzeroupper, sizeof(vzeroupper), 0);
    exercise_vzero(GEM_I386_ENGINE_JIT, vzeroupper, sizeof(vzeroupper), 0);
    exercise_vzero(GEM_I386_ENGINE_INTERPRETER, vzeroall, sizeof(vzeroall), 1);
    exercise_vzero(GEM_I386_ENGINE_JIT, vzeroall, sizeof(vzeroall), 1);
    exercise_vadd(GEM_I386_ENGINE_INTERPRETER, vaddps, sizeof(vaddps), 0);
    exercise_vadd(GEM_I386_ENGINE_JIT, vaddps, sizeof(vaddps), 0);
    exercise_vadd(GEM_I386_ENGINE_INTERPRETER, vaddss, sizeof(vaddss), 1);
    exercise_vadd(GEM_I386_ENGINE_JIT, vaddss, sizeof(vaddss), 1);
    exercise_vadd256(GEM_I386_ENGINE_INTERPRETER);
    exercise_vadd256(GEM_I386_ENGINE_JIT);
    exercise_vadd256_cross_page(GEM_I386_ENGINE_INTERPRETER);
    exercise_vadd256_cross_page(GEM_I386_ENGINE_JIT);
    exercise_vmov256_store_cross_page(GEM_I386_ENGINE_INTERPRETER);
    exercise_vmov256_store_cross_page(GEM_I386_ENGINE_JIT);
    exercise_vmov_store_shapes(GEM_I386_ENGINE_INTERPRETER);
    exercise_vmov_store_shapes(GEM_I386_ENGINE_JIT);
    exercise_avx_cross_lane(GEM_I386_ENGINE_INTERPRETER);
    exercise_avx_cross_lane(GEM_I386_ENGINE_JIT);
    exercise_avx_special_flags_and_blend(GEM_I386_ENGINE_INTERPRETER);
    exercise_avx_special_flags_and_blend(GEM_I386_ENGINE_JIT);
    exercise_promoted128(GEM_I386_ENGINE_INTERPRETER, vpaddd_xmm, sizeof(vpaddd_xmm), 0U);
    exercise_promoted128(GEM_I386_ENGINE_JIT, vpaddd_xmm, sizeof(vpaddd_xmm), 0U);
    exercise_vmovhlps(GEM_I386_ENGINE_INTERPRETER);
    exercise_vmovhlps(GEM_I386_ENGINE_JIT);
    exercise_promoted128(GEM_I386_ENGINE_INTERPRETER, vpshufb_xmm, sizeof(vpshufb_xmm), 1U);
    exercise_promoted128(GEM_I386_ENGINE_JIT, vpshufb_xmm, sizeof(vpshufb_xmm), 1U);
    exercise_vpmovsxbd_boundary(GEM_I386_ENGINE_INTERPRETER);
    exercise_vpmovsxbd_boundary(GEM_I386_ENGINE_JIT);
    exercise_promoted128(GEM_I386_ENGINE_INTERPRETER, vroundps_xmm, sizeof(vroundps_xmm), 2U);
    exercise_promoted128(GEM_I386_ENGINE_JIT, vroundps_xmm, sizeof(vroundps_xmm), 2U);
    exercise_xsaveopt_gate();
    expect_protection(xsave_esi, sizeof(xsave_esi), DATA + 1U, 0U);
    expect_protection(xgetbv, sizeof(xgetbv), DATA, 1U);
    expect_protection(xsetbv, sizeof(xsetbv), DATA, 0U);
    return 0;
}
