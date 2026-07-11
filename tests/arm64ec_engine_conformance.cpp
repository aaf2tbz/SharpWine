// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/pe_arm64x.h"
#include "pe_arm64x_fixture_builder.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

namespace {

using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u64 kCode = 0x100000000ULL;
constexpr u64 kData = 0x100010000ULL;
constexpr u64 kLowCode = 0x20000ULL;
constexpr u64 kTebA = 0x700000010000ULL;
constexpr u64 kTebB = 0x700000020000ULL;
constexpr u64 kHostReturn = GEM_ARM64EC_DEFAULT_HOST_RETURN_SENTINEL;
constexpr u64 kTransition = GEM_ARM64EC_DEFAULT_ARCH_TRANSITION_SENTINEL;

constexpr u32 NOP = 0xd503201fU;
constexpr u32 RET = 0xd65f03c0U;
constexpr u32 ADD_X0_X0_1 = 0x91000400U;
constexpr u32 ADD_X2_X0_X1 = 0x8b010002U;
constexpr u32 SUB_X3_X2_5 = 0xd1001443U;
constexpr u32 AND_X4_X3_0xff = 0x92401c64U;
constexpr u32 LSL_X5_X4_4 = 0xd37cec85U;
constexpr u32 SUBS_X7_X0_X1 = 0xeb010007U;
constexpr u32 MOV_X0_X18 = 0xaa1203e0U;
constexpr u32 ADD_X1_X18_8 = 0x91002241U;
constexpr u32 MOV_X0_0x42 = 0xd2800840U;
constexpr u32 MOV_X2_1 = 0xd2800022U;
constexpr u32 MOV_X2_2 = 0xd2800042U;
constexpr u32 STR_X0_X1 = 0xf9000020U;
constexpr u32 LDR_W0_X1 = 0xb9400020U;
constexpr u32 ADD_V2_16B_V0_V1 = 0x4e218402U;
constexpr u32 MOV_V15_16B_V2 = 0x4ea21c4fU;
constexpr u32 FADD_D8_D6_D7 = 0x1e6728c8U;
constexpr u32 FRINTI_D9_D6 = 0x1e67c0c9U;
constexpr u32 FDIV_D10_D11_D12 = 0x1e6c196aU;
constexpr u32 LDAXR_X2_X0 = 0xc85f7c02U;
constexpr u32 ADD_X2_X2_1 = 0x91000442U;
constexpr u32 STLXR_W3_X2_X0 = 0xc8037c02U;
constexpr u32 SVC_0x123 = 0xd4002461U;
constexpr u32 BRK_0x456 = 0xd4208ac0U;
constexpr u32 UDF_0 = 0x00000000U;
constexpr u32 IC_IVAU_X0 = 0xd50b7520U;
constexpr u32 DC_CVAU_X0 = 0xd50b7b20U;
constexpr u32 DSB_ISH = 0xd5033b9fU;
constexpr u32 ISB = 0xd5033fdfU;
constexpr u32 BR_X0 = 0xd61f0000U;
constexpr u32 B_MINUS_4 = 0x17ffffffU;
constexpr u32 STR_W1_X0 = 0xb9000001U;

[[noreturn]] void Fail(const char *expression, const char *file, int line) {
    std::fprintf(stderr, "%s:%d: conformance assertion failed: %s\n", file, line, expression);
    std::abort();
}

#define EXPECT(expression)                                                                         \
    do {                                                                                           \
        if (!(expression))                                                                         \
            Fail(#expression, __FILE__, __LINE__);                                                 \
    } while (false)

u64 DoubleBits(double value) {
    u64 bits = 0;
    static_assert(sizeof(bits) == sizeof(value), "unexpected double size");
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

void StoreWord(std::array<std::uint8_t, 4> &bytes, u32 word) {
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>((word >> (index * 8U)) & 0xffU);
}

void WriteWords(gem_memory *memory, u64 address, std::initializer_list<u32> words) {
    std::array<std::uint8_t, 4096> bytes{};
    std::size_t offset = 0;
    EXPECT(words.size() * sizeof(u32) <= bytes.size());
    for (const u32 word : words) {
        for (std::size_t index = 0; index < sizeof(word); ++index)
            bytes[offset + index] = static_cast<std::uint8_t>((word >> (index * 8U)) & 0xffU);
        offset += sizeof(word);
    }
    EXPECT(gem_memory_write(memory, address, bytes.data(), offset) == GEM_MEMORY_OK);
}

void WriteWord(gem_memory *memory, u64 address, u32 word) {
    std::array<std::uint8_t, 4> bytes{};
    StoreWord(bytes, word);
    EXPECT(gem_memory_write(memory, address, bytes.data(), bytes.size()) == GEM_MEMORY_OK);
}

void MapCode(gem_memory *memory, u64 address, std::initializer_list<u32> words,
             u32 final_protection = GEM_PAGE_EXECUTE_READ) {
    u64 base = address;
    EXPECT(gem_memory_reserve(memory, &base, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    EXPECT(base == address);
    EXPECT(gem_memory_commit(memory, address, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    WriteWords(memory, address, words);
    EXPECT(gem_memory_protect(memory, address, GEM_GUEST_PAGE_SIZE, final_protection, nullptr) ==
           GEM_MEMORY_OK);
}

void MapData(gem_memory *memory, u64 address, u64 size = GEM_GUEST_PAGE_SIZE,
             u32 protection = GEM_PAGE_READWRITE) {
    u64 base = address;
    EXPECT(gem_memory_reserve(memory, &base, size) == GEM_MEMORY_OK);
    EXPECT(base == address);
    EXPECT(gem_memory_commit(memory, address, size, protection) == GEM_MEMORY_OK);
}

void WriteU64(gem_memory *memory, u64 address, u64 value) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU);
    EXPECT(gem_memory_write(memory, address, bytes.data(), bytes.size()) == GEM_MEMORY_OK);
}

u64 ReadU64(gem_memory *memory, u64 address) {
    std::array<std::uint8_t, 8> bytes{};
    u64 value = 0;
    EXPECT(gem_memory_read(memory, address, bytes.data(), bytes.size()) == GEM_MEMORY_OK);
    for (std::size_t index = 0; index < bytes.size(); ++index)
        value |= static_cast<u64>(bytes[index]) << (index * 8U);
    return value;
}

struct Fixture {
    Fixture() {
        memory = gem_memory_create();
        EXPECT(memory != nullptr);
        gem_arm64ec_runtime_config config{};
        config.host_return_sentinel = kHostReturn;
        config.arch_transition_sentinel = kTransition;
        config.max_budget = 100000;
        config.max_transitions = 64;
        runtime = gem_arm64ec_runtime_create(memory, &config);
        EXPECT(runtime != nullptr);
        EXPECT(gem_arm64ec_set_current_runtime(runtime));
    }

    ~Fixture() {
        gem_arm64ec_set_current_runtime(nullptr);
        gem_arm64ec_runtime_destroy(runtime);
        gem_memory_destroy(memory);
    }

    Fixture(const Fixture &) = delete;
    Fixture &operator=(const Fixture &) = delete;

    gem_memory *memory = nullptr;
    gem_arm64ec_runtime *runtime = nullptr;
};

void InitContext(gem_thread_context &context, u64 pc = kCode, u64 teb = kTebA) {
    gem_context_initialize(&context, teb, GEM_ISA_ARM64EC);
    context.pc = pc;
    context.x[30] = kHostReturn;
}

gem_stop_reason Run(Fixture &fixture, gem_thread_context &context, u64 budget) {
    const gem_stop_reason reason = gem_run_arm64ec(&context, budget);
    EXPECT(context.stop_reason == static_cast<u32>(reason));
    EXPECT(gem_context_is_valid(&context));
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.reason == reason);
    return reason;
}

void TestProvenance() {
    Fixture fixture;
    EXPECT(std::strcmp(gem_arm64ec_runtime_engine_name(fixture.runtime), "Dynarmic") == 0);
    EXPECT(std::strcmp(gem_arm64ec_runtime_engine_version(fixture.runtime), "6.7.0") == 0);
    EXPECT(std::strcmp(gem_arm64ec_runtime_engine_license(fixture.runtime), "ISC") == 0);
    EXPECT(std::strstr(gem_arm64ec_runtime_engine_provenance(fixture.runtime),
                       "a41c380246d3d9f9874f0f792d234dc0cc17c180") != nullptr);
}

void ExpectInvalidContextUnchanged(Fixture &fixture, gem_thread_context &context, u64 budget = 1) {
    const gem_thread_context before = context;
    EXPECT(gem_arm64ec_runtime_run(fixture.runtime, &context, budget) ==
           GEM_STOP_INVARIANT_VIOLATION);
    EXPECT(std::memcmp(&context, &before, sizeof(context)) == 0);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.reason == GEM_STOP_INVARIANT_VIOLATION);
    EXPECT(info.instructions_retired == 0U);
}

void TestInvalidContextAndBudgetZero() {
    Fixture fixture;
    gem_thread_context context{};
    ExpectInvalidContextUnchanged(fixture, context);

    gem_context_initialize(&context, kTebA, GEM_ISA_X64);
    ExpectInvalidContextUnchanged(fixture, context);

    gem_context_initialize(&context, kTebA, GEM_ISA_ARM64EC);
    context.layout_version += 1U;
    ExpectInvalidContextUnchanged(fixture, context);

    gem_context_initialize(&context, kTebA, GEM_ISA_ARM64EC);
    context.context_size -= 1U;
    ExpectInvalidContextUnchanged(fixture, context);

    gem_context_initialize(&context, kTebA, GEM_ISA_ARM64EC);
    context.teb = 0U;
    context.x[18] = 0U;
    ExpectInvalidContextUnchanged(fixture, context);

    gem_context_initialize(&context, kTebA, GEM_ISA_ARM64EC);
    context.x[18] = kTebB;
    ExpectInvalidContextUnchanged(fixture, context);

    MapCode(fixture.memory, kCode, {NOP, RET});
    InitContext(context);
    const u64 pc_before = context.pc;
    EXPECT(Run(fixture, context, 0) == GEM_STOP_BUDGET_EXPIRED);
    EXPECT(context.pc == pc_before);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 0);
}

void TestSingleStepAndBudgets() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {ADD_X0_X0_1, ADD_X0_X0_1, RET});
    gem_thread_context context{};
    InitContext(context);
    EXPECT(Run(fixture, context, 1) == GEM_STOP_BUDGET_EXPIRED);
    EXPECT(context.x[0] == 1);
    EXPECT(context.pc == kCode + 4U);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 1);

    EXPECT(Run(fixture, context, 1) == GEM_STOP_BUDGET_EXPIRED);
    EXPECT(context.x[0] == 2);
    EXPECT(context.pc == kCode + 8U);

    EXPECT(Run(fixture, context, 1) == GEM_STOP_HOST_RETURN);
    EXPECT(context.pc == kHostReturn);
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 1);
}

void TestGprAndNzcv() {
    Fixture fixture;
    MapCode(fixture.memory, kCode,
            {ADD_X2_X0_X1, SUB_X3_X2_5, AND_X4_X3_0xff, LSL_X5_X4_4, SUBS_X7_X0_X1, RET});
    gem_thread_context context{};
    InitContext(context);
    context.x[0] = 1;
    context.x[1] = 2;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 3);
    EXPECT(context.x[3] == UINT64_C(0xfffffffffffffffe));
    EXPECT(context.x[4] == 0xfeU);
    EXPECT(context.x[5] == 0xfe0U);
    EXPECT(context.x[7] == UINT64_C(0xffffffffffffffff));
    EXPECT((context.nzcv & 0xf0000000U) == 0x80000000U);
}

void TestSimdFpAndFpStatus() {
    Fixture fixture;
    MapCode(fixture.memory, kCode,
            {ADD_V2_16B_V0_V1, MOV_V15_16B_V2, FADD_D8_D6_D7, FRINTI_D9_D6, FDIV_D10_D11_D12, RET});
    gem_thread_context context{};
    InitContext(context);
    context.v[0].lo = UINT64_C(0x0101010101010101);
    context.v[0].hi = UINT64_C(0x0101010101010101);
    context.v[1].lo = UINT64_C(0x0202020202020202);
    context.v[1].hi = UINT64_C(0x0202020202020202);
    context.v[6].lo = DoubleBits(1.25);
    context.v[7].lo = DoubleBits(2.5);
    context.v[11].lo = DoubleBits(1.0);
    context.v[12].lo = DoubleBits(0.0);
    context.fpcr = UINT32_C(1) << 22;
    context.fpsr = 0;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
    EXPECT(context.v[2].lo == UINT64_C(0x0303030303030303));
    EXPECT(context.v[2].hi == UINT64_C(0x0303030303030303));
    EXPECT(context.v[15].lo == context.v[2].lo);
    EXPECT(context.v[15].hi == context.v[2].hi);
    EXPECT(context.v[8].lo == DoubleBits(3.75));
    EXPECT(context.v[9].lo == DoubleBits(2.0));
    EXPECT((context.fpcr & (UINT32_C(3) << 22)) == (UINT32_C(1) << 22));
    EXPECT((context.fpsr & (UINT32_C(1) << 1)) != 0U);
}

void TestAtomicsAndExclusives() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {LDAXR_X2_X0, ADD_X2_X2_1, STLXR_W3_X2_X0, RET});
    MapData(fixture.memory, kData);
    WriteU64(fixture.memory, kData, 41);
    gem_thread_context context{};
    InitContext(context);
    context.x[0] = kData;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 42);
    EXPECT(context.x[3] == 0);
    EXPECT(ReadU64(fixture.memory, kData) == 42);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWords(fixture.memory, kCode, {STLXR_W3_X2_X0, RET});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    WriteU64(fixture.memory, kData, 100);
    InitContext(context);
    context.x[0] = kData;
    context.x[2] = 101;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[3] != 0);
    EXPECT(ReadU64(fixture.memory, kData) == 100);
}

void TestX18ImportExport() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {MOV_X0_X18, ADD_X1_X18_8, RET});
#if defined(__aarch64__)
    u64 host_x18 = 0;
    __asm__ volatile("mov %0, x18" : "=r"(host_x18));
    EXPECT(host_x18 != kTebA);
    EXPECT(host_x18 != kTebB);
#endif
    gem_thread_context context{};
    InitContext(context, kCode, kTebA);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[0] == kTebA);
    EXPECT(context.x[1] == kTebA + 8U);
    EXPECT(context.x[18] == context.teb);

    InitContext(context, kCode, kTebB);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[0] == kTebB);
    EXPECT(context.x[1] == kTebB + 8U);

    InitContext(context, kCode, kTebA);
    context.x[18] = kTebB;
    EXPECT(gem_run_arm64ec(&context, 1) == GEM_STOP_INVARIANT_VIOLATION);
}

void TestLowAddresses() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {LDR_W0_X1, RET});
    const std::array<std::uint8_t, 4> kuser = {0x11U, 0x22U, 0x33U, 0x44U};
    EXPECT(gem_memory_write(fixture.memory, GEM_KUSER_CANONICAL_ADDRESS, kuser.data(),
                            kuser.size()) == GEM_MEMORY_OK);
    gem_thread_context context{};
    InitContext(context);
    context.x[1] = GEM_KUSER_SHARED_DATA_ADDRESS;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT((context.x[0] & 0xffffffffU) == 0x44332211U);

    MapCode(fixture.memory, kLowCode, {MOV_X0_0x42, RET});
    InitContext(context, kLowCode);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[0] == 0x42U);
}

void TestFaultsAndFourKiBProtections() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {STR_X0_X1, RET});
    MapData(fixture.memory, kData, GEM_GUEST_PAGE_SIZE * 2U);
    EXPECT(gem_memory_protect(fixture.memory, kData + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_NOACCESS, nullptr) == GEM_MEMORY_OK);
    const u64 faulting_store = kData + GEM_GUEST_PAGE_SIZE - 4U;
    const std::array<std::uint8_t, 4> before = {0xaaU, 0xbbU, 0xccU, 0xddU};
    EXPECT(gem_memory_write(fixture.memory, faulting_store, before.data(), before.size()) ==
           GEM_MEMORY_OK);
    gem_thread_context context{};
    InitContext(context);
    context.x[0] = UINT64_C(0x1122334455667788);
    context.x[1] = faulting_store;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_MEMORY_FAULT);
    EXPECT(context.pc == kCode);
    std::array<std::uint8_t, 4> after{};
    EXPECT(gem_memory_read(fixture.memory, faulting_store, after.data(), after.size()) ==
           GEM_MEMORY_OK);
    EXPECT(after == before);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.access == GEM_ARM64EC_ACCESS_WRITE);
    EXPECT(info.fault_address == faulting_store);

    Fixture fetch_fixture;
    u64 fetch_page = kCode;
    EXPECT(gem_memory_reserve(fetch_fixture.memory, &fetch_page, GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    EXPECT(gem_memory_commit(fetch_fixture.memory, fetch_page, GEM_GUEST_PAGE_SIZE,
                             GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    WriteWords(fetch_fixture.memory, fetch_page, {RET});
    InitContext(context, fetch_page);
    EXPECT(Run(fetch_fixture, context, 8) == GEM_STOP_MEMORY_FAULT);
    EXPECT(context.pc == fetch_page);
    EXPECT(gem_arm64ec_runtime_last_stop_info(fetch_fixture.runtime, &info));
    EXPECT(info.access == GEM_ARM64EC_ACCESS_FETCH);

    Fixture guard_fixture;
    MapCode(guard_fixture.memory, kCode, {RET});
    EXPECT(gem_memory_protect(guard_fixture.memory, kCode, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_EXECUTE_READ | GEM_PAGE_GUARD, nullptr) == GEM_MEMORY_OK);
    InitContext(context);
    EXPECT(Run(guard_fixture, context, 8) == GEM_STOP_MEMORY_FAULT);
    EXPECT(context.pc == kCode);
    EXPECT(gem_arm64ec_runtime_last_stop_info(guard_fixture.runtime, &info));
    EXPECT(info.access == GEM_ARM64EC_ACCESS_FETCH);
}

void TestBudgetedLoop() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {ADD_X0_X0_1, B_MINUS_4});
    gem_thread_context context{};
    InitContext(context);
    EXPECT(Run(fixture, context, 5) == GEM_STOP_BUDGET_EXPIRED);
    EXPECT(context.x[0] == 3);
    EXPECT(context.pc == kCode + 4U);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 5);
}

void TestStopReasons() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {SVC_0x123, RET});
    gem_thread_context context{};
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_SYSCALL);
    EXPECT(context.pc == kCode);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWords(fixture.memory, kCode, {BRK_0x456, RET});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_WINDOWS_EXCEPTION);
    EXPECT(context.pc == kCode);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWords(fixture.memory, kCode, {UDF_0, RET});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    EXPECT(context.pc == kCode);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWords(fixture.memory, kCode, {BR_X0, RET});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    InitContext(context);
    context.x[0] = kTransition;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_ARCH_TRANSITION);
    EXPECT(context.pc == kTransition);
}

void ExpectForbidden(Fixture &fixture, u32 instruction, gem_thread_context &context,
                     u64 expected_retired = 0) {
    const gem_thread_context before = context;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    gem_thread_context expected = before;
    expected.stop_reason = GEM_STOP_UNSUPPORTED_INSTRUCTION;
    EXPECT(std::memcmp(&context, &expected, sizeof(context)) == 0);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == expected_retired);
    EXPECT(info.fault_address == before.pc);
    EXPECT(info.access == GEM_ARM64EC_ACCESS_NONE);
    EXPECT(info.memory_error == GEM_MEMORY_OK);
    EXPECT(info.engine_status == instruction);
}

void TestMetadataCheckedX64Boundary() {
    Fixture fixture;
    pe_arm64x_fixture pe_fixture{};
    gem_pe_arm64x_image *image = nullptr;
    constexpr u64 image_base = PE_ARM64X_FIXTURE_IMAGE_BASE;
    constexpr u64 arm64_code = image_base + 0x1000U;
    constexpr u64 arm64ec_code = image_base + 0x1400U;
    constexpr u64 x64_target = image_base + 0x1901U;

    EXPECT(pe_arm64x_fixture_build(2U, &pe_fixture));
    EXPECT(gem_pe_arm64x_parse(pe_fixture.bytes, pe_fixture.size, nullptr, &image) == GEM_PE_OK);
    EXPECT(gem_arm64ec_runtime_attach_arm64x(fixture.runtime, image, image_base));
    gem_pe_arm64x_image_destroy(image);
    pe_arm64x_fixture_destroy(&pe_fixture);

    u64 code_page = image_base + 0x1000U;
    EXPECT(gem_memory_reserve(fixture.memory, &code_page, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    EXPECT(gem_memory_commit(fixture.memory, code_page, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    /* Native ARM64 metadata ranges may use registers that ARM64EC reserves. */
    constexpr u32 add_x0_x13_x2 = 0x8b000000U | (13U << 5U) | (2U << 16U);
    WriteWord(fixture.memory, arm64_code, add_x0_x13_x2);
    WriteWord(fixture.memory, arm64ec_code, BR_X0);
    EXPECT(gem_memory_protect(fixture.memory, code_page, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_thread_context context{};
    InitContext(context, arm64_code);
    context.x[13] = 40U;
    context.x[2] = 2U;
    EXPECT(Run(fixture, context, 1) == GEM_STOP_BUDGET_EXPIRED);
    EXPECT(context.x[0] == 42U && context.pc == arm64_code + sizeof(u32));

    InitContext(context, arm64ec_code);
    context.x[0] = x64_target;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_ARCH_TRANSITION);
    EXPECT(context.pc == x64_target);
    gem_arm64ec_stop_info info{};
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 1U);
    EXPECT(info.fault_address == x64_target);
    EXPECT(info.access == GEM_ARM64EC_ACCESS_NONE);

    /* The x64 target is intentionally unmapped. Metadata stops before either
     * the manual fetch or Dynarmic's code callback can request its bytes. */
    InitContext(context, x64_target);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_ARCH_TRANSITION);
    EXPECT(context.pc == x64_target);
    EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
    EXPECT(info.instructions_retired == 0U && info.fault_address == x64_target &&
           info.access == GEM_ARM64EC_ACCESS_NONE);

    InitContext(context, image_base + 0x2000U);
    const gem_thread_context before = context;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_INVARIANT_VIOLATION);
    gem_thread_context expected = before;
    expected.stop_reason = GEM_STOP_INVARIANT_VIOLATION;
    EXPECT(std::memcmp(&context, &expected, sizeof(context)) == 0);

    /* Metadata mode cannot escape through the unchecked legacy sentinel. */
    InitContext(context, kTransition);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_INVARIANT_VIOLATION);
    EXPECT(context.pc == kTransition);
}

void TestForbiddenRegisters() {
    constexpr std::array<u32, 5> forbidden_gprs = {13U, 14U, 23U, 24U, 28U};
    constexpr std::array<u32, 16> forbidden_vecs = {16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U,
                                                    24U, 25U, 26U, 27U, 28U, 29U, 30U, 31U};

    /* Data-processing source and destination forms cover every forbidden GPR. */
    for (const u32 reg : forbidden_gprs) {
        Fixture fixture;
        const u32 source = 0x8b000000U | (reg << 5U) | (2U << 16U);
        MapCode(fixture.memory, kCode, {source, RET});
        gem_thread_context context{};
        InitContext(context);
        ExpectForbidden(fixture, source, context);

        Fixture destination_fixture;
        const u32 destination = 0x8b000000U | reg | (1U << 5U) | (2U << 16U);
        MapCode(destination_fixture.memory, kCode, {destination, RET});
        InitContext(context);
        ExpectForbidden(destination_fixture, destination, context);
    }

    /* Base, index/accumulator, branch-target, and store roles are all Reg
     * arguments in the pinned decoder schema rather than opcode heuristics. */
    for (const u32 reg : forbidden_gprs) {
        Fixture fixture;
        const u32 madd_accumulator = 0x9b000000U | (reg << 10U) | (2U << 16U) | (1U << 5U);
        MapCode(fixture.memory, kCode, {madd_accumulator, RET});
        gem_thread_context context{};
        InitContext(context);
        ExpectForbidden(fixture, madd_accumulator, context);

        Fixture branch_fixture;
        const u32 branch = 0xd61f0000U | (reg << 5U);
        MapCode(branch_fixture.memory, kCode, {branch, RET});
        InitContext(context);
        ExpectForbidden(branch_fixture, branch, context);
    }

    /* Destination and source vector forms exercise each v16-v31 encoding. */
    constexpr u32 vector_add_base = 0x4e218402U & ~((31U << 16U) | (31U << 5U) | 31U);
    for (const u32 reg : forbidden_vecs) {
        Fixture fixture;
        const u32 destination = vector_add_base | (1U << 16U) | reg;
        MapCode(fixture.memory, kCode, {destination, RET});
        gem_thread_context context{};
        InitContext(context);
        ExpectForbidden(fixture, destination, context);

        Fixture source_fixture;
        const u32 source = vector_add_base | (reg << 16U) | 2U;
        MapCode(source_fixture.memory, kCode, {source, RET});
        InitContext(context);
        ExpectForbidden(source_fixture, source, context);
    }

    /* Scalar FP and SIMD load/store use distinct decoder operand families. */
    {
        Fixture fixture;
        const u32 scalar_source = (FADD_D8_D6_D7 & ~(31U << 5U)) | (20U << 5U);
        MapCode(fixture.memory, kCode, {scalar_source, RET});
        gem_thread_context context{};
        InitContext(context);
        ExpectForbidden(fixture, scalar_source, context);
    }
    {
        Fixture fixture;
        constexpr u32 vector_store = 0x3d800410U;
        MapCode(fixture.memory, kCode, {vector_store, RET});
        MapData(fixture.memory, kData);
        gem_thread_context context{};
        InitContext(context);
        context.x[0] = kData;
        const u64 data_before = ReadU64(fixture.memory, kData);
        ExpectForbidden(fixture, vector_store, context);
        EXPECT(ReadU64(fixture.memory, kData) == data_before);
    }

    /* Allowed operands and immediate bit patterns that resemble register
     * numbers remain executable, proving decoding is semantic. */
    {
        Fixture fixture;
        MapCode(fixture.memory, kCode, {0xd28001a0U, RET}); // mov x0, #13
        gem_thread_context context{};
        InitContext(context);
        EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
        EXPECT(context.x[0] == 13U);
    }
}

void TestForbiddenPriorityAndInvalidation() {
    constexpr u32 forbidden_store = 0xf9000017U; // str x23, [x0]
    {
        Fixture fixture;
        MapCode(fixture.memory, kCode, {forbidden_store, RET});
        gem_thread_context context{};
        InitContext(context);
        const gem_thread_context before = context;
        EXPECT(gem_arm64ec_runtime_run(fixture.runtime, &context, 8) ==
               GEM_STOP_UNSUPPORTED_INSTRUCTION);
        gem_thread_context expected = before;
        expected.stop_reason = GEM_STOP_UNSUPPORTED_INSTRUCTION;
        EXPECT(std::memcmp(&context, &expected, sizeof(context)) == 0);
        gem_arm64ec_stop_info info{};
        EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
        EXPECT(info.instructions_retired == 0U && info.fault_address == kCode &&
               info.access == GEM_ARM64EC_ACCESS_NONE && info.memory_error == GEM_MEMORY_OK);
    }
    {
        Fixture fixture;
        MapCode(fixture.memory, kCode, {forbidden_store, RET});
        gem_thread_context context{};
        InitContext(context);
        context.x[0] = kData; // deliberately unmapped: unsupported wins after fetch
        ExpectForbidden(fixture, forbidden_store, context);
    }
    {
        Fixture fixture;
        MapCode(fixture.memory, kCode, {forbidden_store}, GEM_PAGE_READWRITE);
        EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                                  nullptr) == GEM_MEMORY_OK);
        gem_thread_context context{};
        InitContext(context);
        EXPECT(Run(fixture, context, 8) == GEM_STOP_MEMORY_FAULT);
        gem_arm64ec_stop_info info{};
        EXPECT(gem_arm64ec_runtime_last_stop_info(fixture.runtime, &info));
        EXPECT(info.access == GEM_ARM64EC_ACCESS_FETCH);
    }
    {
        Fixture fixture;
        MapCode(fixture.memory, kCode, {ADD_X0_X0_1, RET}, GEM_PAGE_EXECUTE_READWRITE);
        gem_thread_context context{};
        InitContext(context);
        EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
        EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                                  nullptr) == GEM_MEMORY_OK);
        WriteWord(fixture.memory, kCode, forbidden_store);
        EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                                  nullptr) == GEM_MEMORY_OK);
        gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, 4);
        InitContext(context);
        ExpectForbidden(fixture, forbidden_store, context);
    }
}

struct BoundaryProbe {
    u64 address;
    unsigned calls;
};

gem_arm64ec_boundary_action BrokerBoundary(void *opaque, u64 pc, gem_thread_context *context,
                                           gem_arm64ec_boundary_kind *kind) {
    auto *probe = static_cast<BoundaryProbe *>(opaque);
    if (pc != probe->address)
        return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
    ++probe->calls;
    *kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
    context->x[9] = context->x[11];
    context->x[11] = context->x[10];
    context->pc = context->x[30];
    return GEM_ARM64EC_BOUNDARY_RESUME;
}

gem_arm64ec_boundary_action InvalidStopBoundary(void *, u64, gem_thread_context *context,
                                                gem_arm64ec_boundary_kind *kind) {
    *kind = GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
    context->x[18] ^= 1U;
    return GEM_ARM64EC_BOUNDARY_STOP;
}

void TestPrefetchBoundaryBroker() {
    Fixture fixture;
    constexpr u64 helper = 0x600000000000ULL;
    MapCode(fixture.memory, kCode, {BR_X0, RET});
    BoundaryProbe probe{helper, 0};
    EXPECT(gem_arm64ec_runtime_set_boundary_broker(fixture.runtime, BrokerBoundary, &probe));
    gem_thread_context context{};
    InitContext(context);
    context.x[0] = helper;
    context.x[10] = kCode + 4U;
    context.x[11] = 0x12345678U;
    context.x[30] = kHostReturn;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(probe.calls == 1U);
    EXPECT(context.x[9] == 0x12345678U && context.x[11] == kCode + 4U);
    EXPECT(gem_arm64ec_runtime_transition_count(fixture.runtime) == 1U);

    EXPECT(gem_arm64ec_runtime_set_boundary_broker(fixture.runtime, InvalidStopBoundary, nullptr));
    InitContext(context);
    const gem_thread_context before = context;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_INVARIANT_VIOLATION);
    gem_thread_context expected = before;
    expected.stop_reason = GEM_STOP_INVARIANT_VIOLATION;
    EXPECT(std::memcmp(&context, &expected, sizeof(context)) == 0);
    EXPECT(gem_arm64ec_runtime_transition_count(fixture.runtime) == 0U);
}

void TestMetadataBrokerResumeToHostReturn() {
    Fixture fixture;
    pe_arm64x_fixture pe_fixture{};
    gem_pe_arm64x_image *image = nullptr;
    constexpr u64 image_base = PE_ARM64X_FIXTURE_IMAGE_BASE;
    constexpr u64 helper = 0x600000000000ULL;
    EXPECT(pe_arm64x_fixture_build(2U, &pe_fixture));
    EXPECT(gem_pe_arm64x_parse(pe_fixture.bytes, pe_fixture.size, nullptr, &image) == GEM_PE_OK);
    EXPECT(gem_arm64ec_runtime_attach_arm64x(fixture.runtime, image, image_base));
    gem_pe_arm64x_image_destroy(image);
    pe_arm64x_fixture_destroy(&pe_fixture);

    BoundaryProbe probe{helper, 0};
    EXPECT(gem_arm64ec_runtime_set_boundary_broker(fixture.runtime, BrokerBoundary, &probe));
    gem_thread_context context{};
    InitContext(context, helper);
    context.x[30] = kHostReturn;
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.pc == kHostReturn);
    EXPECT(probe.calls == 1U);
    EXPECT(gem_arm64ec_runtime_transition_count(fixture.runtime) == 1U);
}

void TestSelfModifyingCodeAndCacheMaintenance() {
    Fixture fixture;
    MapCode(fixture.memory, kCode, {MOV_X2_1, RET}, GEM_PAGE_EXECUTE_READWRITE);
    gem_thread_context context{};
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 1);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWord(fixture.memory, kCode, MOV_X2_2);
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_EXECUTE_READWRITE, nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, 4);
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 2);

    constexpr u64 writer = kCode + 0x100U;
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWord(fixture.memory, kCode, MOV_X2_1);
    WriteWords(fixture.memory, writer, {STR_W1_X0, BR_X0});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE,
                              GEM_PAGE_EXECUTE_READWRITE, nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    InitContext(context);
    EXPECT(Run(fixture, context, 8) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 1);

    InitContext(context, writer);
    context.x[0] = kCode;
    context.x[1] = MOV_X2_2;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
    EXPECT(context.x[2] == 2);

    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE,
                              nullptr) == GEM_MEMORY_OK);
    WriteWords(fixture.memory, kCode, {IC_IVAU_X0, DC_CVAU_X0, DSB_ISH, ISB, RET});
    EXPECT(gem_memory_protect(fixture.memory, kCode, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READ,
                              nullptr) == GEM_MEMORY_OK);
    gem_arm64ec_runtime_invalidate_code(fixture.runtime, kCode, GEM_GUEST_PAGE_SIZE);
    InitContext(context);
    context.x[0] = kCode;
    EXPECT(Run(fixture, context, 16) == GEM_STOP_HOST_RETURN);
}

} // namespace

int main() {
    TestProvenance();
    TestInvalidContextAndBudgetZero();
    TestSingleStepAndBudgets();
    TestGprAndNzcv();
    TestSimdFpAndFpStatus();
    TestAtomicsAndExclusives();
    TestX18ImportExport();
    TestLowAddresses();
    TestFaultsAndFourKiBProtections();
    TestBudgetedLoop();
    TestStopReasons();
    TestMetadataCheckedX64Boundary();
    TestForbiddenRegisters();
    TestForbiddenPriorityAndInvalidation();
    TestPrefetchBoundaryBroker();
    TestMetadataBrokerResumeToHostReturn();
    TestSelfModifyingCodeAndCacheMaintenance();
    return 0;
}
