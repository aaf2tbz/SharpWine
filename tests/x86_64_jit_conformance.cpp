// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/x64_engine.h"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace {
constexpr std::uint64_t CODE = 0x10000;
constexpr std::uint64_t DATA = 0x20000;
constexpr std::uint64_t STACK = 0x30000;
constexpr std::uint64_t WINDOWS_SYSCALL = 0x40000;
constexpr std::uint64_t UNIX_CALL = 0x41000;
constexpr std::uint64_t CACHE_PAGES = 0x100000;

void map(gem_memory *memory, std::uint64_t address, std::uint32_t protection) {
    std::uint64_t requested = address;
    assert(gem_memory_reserve(memory, &requested, 4096) == GEM_MEMORY_OK);
    assert(gem_memory_commit(memory, address, 4096, protection) == GEM_MEMORY_OK);
}

void initialize(gem_thread_context &context) {
    gem_context_initialize(&context, UINT64_C(0x70000), GEM_ISA_X64);
    context.pc = CODE;
    context.sp = STACK + 4080;
    context.x64_rflags = 2;
    context.x64_mxcsr = 0x1f80;
    context.x64_fcw = 0x37f;
}

gem_x86_64_engine_info info(gem_x64_runtime *runtime) {
    gem_x86_64_engine_info result{};
    result.abi_version = 1U;
    result.size = sizeof(result);
    assert(gem_x64_runtime_engine_info(runtime, &result));
    return result;
}
} // namespace

int main() {
    gem_memory *memory = gem_memory_create();
    assert(memory);
    map(memory, CODE, GEM_PAGE_EXECUTE_READWRITE);
    map(memory, DATA, GEM_PAGE_READWRITE);
    map(memory, STACK, GEM_PAGE_READWRITE);

    gem_x64_runtime_config config{};
    config.max_budget = 16;
    config.windows_syscall_boundary = WINDOWS_SYSCALL;
    config.unix_call_boundary = UNIX_CALL;
    config.engine_mode = GEM_X86_64_ENGINE_JIT;
    gem_x64_runtime *jit = gem_x64_runtime_create(memory, &config);
    assert(jit);
    assert(std::strcmp(gem_x64_runtime_engine_name(jit), "GEM_x86_64 Blink AArch64 JIT") == 0);

    const std::uint8_t nop = 0x90;
    assert(gem_memory_write(memory, CODE, &nop, sizeof(nop)) == GEM_MEMORY_OK);
    gem_thread_context context{};
    initialize(context);
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.pc == CODE + 1);
    auto first = info(jit);
    assert(first.engine_mode == GEM_X86_64_ENGINE_JIT);
    assert(first.host_arch == GEM_X86_64_HOST_AARCH64);
    assert(first.write_xor_execute == 1U);
    assert(first.jit_compilations == 1U && first.jit_executions == 1U && first.jit_failures == 0U);

    context.pc = WINDOWS_SYSCALL;
    const auto syscall_before = context;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_SYSCALL);
    assert(context.pc == syscall_before.pc && context.stop_reason == GEM_STOP_SYSCALL);
    gem_x64_stop_info stop{};
    assert(gem_x64_runtime_last_stop_info(jit, &stop));
    assert(stop.reason == GEM_STOP_SYSCALL && stop.instructions_retired == 0U &&
           stop.engine_status == GEM_X64_BOUNDARY_WINDOWS_SYSCALL);
    assert(info(jit).jit_executions == first.jit_executions);

    context.pc = UNIX_CALL;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_SYSCALL);
    assert(gem_x64_runtime_last_stop_info(jit, &stop));
    assert(stop.reason == GEM_STOP_SYSCALL && stop.instructions_retired == 0U &&
           stop.engine_status == GEM_X64_BOUNDARY_UNIX_CALL);
    assert(info(jit).jit_executions == first.jit_executions);

    initialize(context);
    gem_x64_runtime_request_async_stop(jit);
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_ASYNC_REQUEST);
    assert(context.pc == CODE && context.stop_reason == GEM_STOP_ASYNC_REQUEST);
    assert(gem_x64_runtime_last_stop_info(jit, &stop));
    assert(stop.reason == GEM_STOP_ASYNC_REQUEST && stop.instructions_retired == 0U);
    assert(info(jit).jit_executions == first.jit_executions);

    const std::uint8_t mov_rax[] = {0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    assert(gem_memory_write(memory, CODE, mov_rax, sizeof(mov_rax)) == GEM_MEMORY_OK);
    gem_x64_runtime_invalidate_code(jit, CODE, sizeof(mov_rax));
    initialize(context);
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.pc == CODE + sizeof(mov_rax));
    assert(context.x[8] == UINT64_C(0x1122334455667788));
    auto second = info(jit);
    assert(second.jit_compilations == first.jit_compilations + 1U);
    assert(second.jit_executions == first.jit_executions + 1U);
    assert(second.jit_failures == 0U);

    initialize(context);
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.x[8] == UINT64_C(0x1122334455667788));
    auto cached = info(jit);
    assert(cached.jit_compilations == second.jit_compilations);
    assert(cached.jit_executions == second.jit_executions + 1U);

    const std::uint8_t load_rax[] = {0x48, 0x8b, 0x03};
    assert(gem_memory_write(memory, CODE, load_rax, sizeof(load_rax)) == GEM_MEMORY_OK);
    const std::uint64_t data_value = UINT64_C(0x1122334455667788);
    assert(gem_memory_write(memory, DATA, &data_value, sizeof(data_value)) == GEM_MEMORY_OK);
    gem_x64_runtime_invalidate_code(jit, CODE, sizeof(load_rax));
    std::uint32_t old_protection = 0;
    assert(gem_memory_protect(memory, DATA, 4096, GEM_PAGE_READWRITE | GEM_PAGE_GUARD,
                              &old_protection) == GEM_MEMORY_OK);
    initialize(context);
    context.x[27] = DATA;
    const auto guard_before = context;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_MEMORY_FAULT);
    assert(context.pc == guard_before.pc && context.x[8] == guard_before.x[8]);
    assert(gem_x64_runtime_last_stop_info(jit, &stop));
    assert(stop.memory_error == GEM_MEMORY_GUARD_PAGE && stop.fault_address == DATA);
    const auto guard_fault = info(jit);
    assert(guard_fault.jit_compilations == cached.jit_compilations + 1U);
    initialize(context);
    context.x[27] = DATA;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.x[8] == UINT64_C(0x1122334455667788));
    const auto guard_retry = info(jit);
    assert(guard_retry.jit_compilations == guard_fault.jit_compilations);
    assert(guard_retry.jit_executions == guard_fault.jit_executions + 1U);

    gem_x64_runtime_config oracle_config{};
    oracle_config.max_budget = 16;
    oracle_config.engine_mode = GEM_X86_64_ENGINE_INTERPRETER;
    gem_x64_runtime *oracle = gem_x64_runtime_create(memory, &oracle_config);
    assert(oracle);
    gem_thread_context oracle_context{};
    initialize(oracle_context);
    oracle_context.x[27] = DATA;
    assert(gem_x64_runtime_run(oracle, &oracle_context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(std::memcmp(&context, &oracle_context, sizeof(context)) == 0);

    /* Windows probes CPUID during process startup. Although Blink classifies
     * it as serializing, GEM must still compile one bounded transaction and
     * agree exactly with the explicit interpreter oracle. */
    const std::uint8_t cpuid[] = {0x0f, 0xa2};
    assert(gem_memory_write(memory, CODE, cpuid, sizeof(cpuid)) == GEM_MEMORY_OK);
    gem_x64_runtime_invalidate_code(jit, CODE, sizeof(cpuid));
    initialize(context);
    context.x[8] = 0U; /* EAX leaf */
    context.x[0] = 0U; /* ECX subleaf */
    initialize(oracle_context);
    oracle_context.x[8] = 0U;
    oracle_context.x[0] = 0U;
    const auto before_cpuid = info(jit);
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(gem_x64_runtime_run(oracle, &oracle_context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.pc == CODE + sizeof(cpuid));
    assert(std::memcmp(&context, &oracle_context, sizeof(context)) == 0);
    const auto after_cpuid = info(jit);
    assert(after_cpuid.jit_compilations == before_cpuid.jit_compilations + 1U);
    assert(after_cpuid.jit_executions == before_cpuid.jit_executions + 1U);
    assert(after_cpuid.jit_failures == before_cpuid.jit_failures);

    auto oracle_info = info(oracle);
    assert(oracle_info.engine_mode == GEM_X86_64_ENGINE_INTERPRETER);
    assert(oracle_info.jit_compilations == 0U && oracle_info.jit_executions == 0U &&
           oracle_info.jit_failures == 0U);

    /* Wine reaches more than 64 distinct pages during ntdll startup. Shadow
     * snapshots must evict deterministically instead of becoming a lifetime
     * working-set ceiling. Also prove that changing the second page of a
     * cross-page instruction invalidates the hook beginning on its predecessor. */
    for (std::uint64_t page = 0; page < 66U; ++page) {
        const std::uint64_t address = CACHE_PAGES + page * 4096U;
        map(memory, address, GEM_PAGE_EXECUTE_READWRITE);
        assert(gem_memory_write(memory, address, &nop, sizeof(nop)) == GEM_MEMORY_OK);
    }
    const std::uint64_t cross_pc = CACHE_PAGES + 4095U;
    std::uint8_t cross_page_mov[] = {0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    assert(gem_memory_write(memory, cross_pc, cross_page_mov, sizeof(cross_page_mov)) ==
           GEM_MEMORY_OK);
    initialize(context);
    context.pc = cross_pc;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.x[8] == UINT64_C(0x1122334455667788));
    const auto cross_first = info(jit);
    cross_page_mov[2] = 0x99;
    assert(gem_memory_write(memory, cross_pc, cross_page_mov, sizeof(cross_page_mov)) ==
           GEM_MEMORY_OK);
    gem_x64_runtime_invalidate_code(jit, CACHE_PAGES + 4096U, 1U);
    initialize(context);
    context.pc = cross_pc;
    assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(context.x[8] == UINT64_C(0x1122334455667799));
    assert(info(jit).jit_compilations == cross_first.jit_compilations + 1U);
    for (std::uint64_t page = 0; page < 66U; ++page) {
        initialize(context);
        context.pc = CACHE_PAGES + page * 4096U;
        assert(gem_x64_runtime_run(jit, &context, 1) == GEM_STOP_BUDGET_EXPIRED);
    }
    assert(info(jit).jit_failures == 0U);

    gem_x64_runtime_destroy(oracle);
    gem_x64_runtime_destroy(jit);
    gem_memory_destroy(memory);
    return 0;
}
