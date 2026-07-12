// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/x64_engine.h"
extern "C" {
#include "blink/gem_embed.h"
}
#include <cassert>
#include <cstdint>
#include <cstring>
static constexpr uint64_t CODE = 0x10000, DATA = 0x20000, STACK = 0x30000, TEB = 0x70000;
static void map(gem_memory *m, uint64_t a, uint64_t n, uint32_t p) {
    uint64_t x = a;
    assert(gem_memory_reserve(m, &x, n) == GEM_MEMORY_OK);
    assert(gem_memory_commit(m, a, n, p) == GEM_MEMORY_OK);
}
static uint32_t embedding_snapshot(void *, uint64_t, uint8_t[4096], uint32_t *) {
    return 0;
}
static uint32_t embedding_validate(void *, uint64_t, size_t, enum blink_gem_access) {
    return 0;
}
static uint32_t embedding_commit(void *, const struct blink_gem_write *, size_t, uint64_t *) {
    return 0;
}
static void test_embedding_abi() {
    assert(blink_gem_machine_create(nullptr, nullptr) == nullptr);
    blink_gem_callbacks callbacks{};
    callbacks.abi_version = BLINK_GEM_ABI_VERSION;
    callbacks.size = sizeof(callbacks);
    assert(blink_gem_machine_create(&callbacks, nullptr) == nullptr);
    callbacks.snapshot = embedding_snapshot;
    callbacks.validate = embedding_validate;
    callbacks.commit = embedding_commit;
    callbacks.abi_version++;
    assert(blink_gem_machine_create(&callbacks, nullptr) == nullptr);
    callbacks.abi_version = BLINK_GEM_ABI_VERSION;
    callbacks.size--;
    assert(blink_gem_machine_create(&callbacks, nullptr) == nullptr);
    callbacks.size = sizeof(callbacks);
    blink_gem_machine *machine = blink_gem_machine_create(&callbacks, nullptr);
    assert(machine);
    blink_gem_state state{};
    blink_gem_state output{};
    memset(&output, 0xa5, sizeof(output));
    const auto unchanged = output;
    state.abi_version = BLINK_GEM_ABI_VERSION + 1;
    state.size = sizeof(state);
    auto result = blink_gem_machine_step(machine, &state, &output);
    assert(result.outcome == BLINK_GEM_INVALID && !memcmp(&output, &unchanged, sizeof(output)));
    state.abi_version = BLINK_GEM_ABI_VERSION;
    state.size--;
    result = blink_gem_machine_step(machine, &state, &output);
    assert(result.outcome == BLINK_GEM_INVALID && !memcmp(&output, &unchanged, sizeof(output)));
    blink_gem_machine_destroy(machine);
}
static void init(gem_thread_context &c) {
    gem_context_initialize(&c, TEB, GEM_ISA_X64);
    c.pc = CODE;
    c.sp = STACK + 4080;
    c.x64_rflags = 2;
    c.x64_mxcsr = 0x1f80;
    c.x64_fcw = 0x37f;
    c.x64_fsw = 0x1234;
    for (unsigned i = 0; i < 31; ++i)
        if (i != 18)
            c.x[i] = UINT64_C(0x1000000000000000) + i;
    for (unsigned i = 0; i < 16; ++i) {
        c.v[i].lo = UINT64_C(0x2000000000000000) + i;
        c.v[i].hi = UINT64_C(0x3000000000000000) + i;
    }
    for (unsigned i = 0; i < 8; i++) {
        c.x87[i].lo = 0x11110000 + i;
        c.x87[i].hi = 0x22220000 + i;
    }
}
int main() {
    static_assert(sizeof(gem_thread_context) == 720);
    test_embedding_abi();
    gem_memory *m = gem_memory_create();
    assert(m);
    assert(gem_x64_runtime_create(nullptr, nullptr) == nullptr);
    gem_x64_stop_info null_info{};
    assert(!gem_x64_runtime_last_stop_info(nullptr, &null_info));
    map(m, CODE, 4096, GEM_PAGE_EXECUTE_READWRITE);
    map(m, DATA, 8192, GEM_PAGE_READWRITE);
    map(m, STACK, 4096, GEM_PAGE_READWRITE);
    gem_x64_runtime_config cfg{};
    cfg.max_budget = 100;
    gem_x64_runtime *r = gem_x64_runtime_create(m, &cfg);
    assert(r);
    assert(
        strstr(gem_x64_runtime_engine_provenance(r),
               "patch-sha256=5db0ef0f144fe0df014496fe521e0640659f7dd44cfbb3e79defa7fb503551a6") !=
        nullptr);
    gem_thread_context c{};
    init(c);
    uint8_t nop = 0x90;
    assert(gem_memory_write(m, CODE, &nop, 1) == GEM_MEMORY_OK);
    auto before = c;
    assert(gem_x64_runtime_run(r, &c, 0) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE);
    c.stop_reason = 0;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + 1);
    assert(!memcmp(c.x, before.x, sizeof(c.x)));
    assert(c.sp == before.sp && c.x64_mxcsr == before.x64_mxcsr && c.x64_fcw == before.x64_fcw &&
           c.x64_fsw == before.x64_fsw);
    assert(!memcmp(c.v, before.v, sizeof(c.v)));
    assert(!memcmp(c.x87, before.x87, sizeof(c.x87)));
    uint8_t program[] = {0x48, 0xb8, 3, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x83, 0xe8, 1, 0x75, 0xfa};
    assert(gem_memory_write(m, CODE, program, sizeof(program)) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 7) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.x[8] == 0 && c.pc == CODE + 16);
    uint64_t value = 0x8877665544332211;
    assert(gem_memory_write(m, DATA, &value, 8) == GEM_MEMORY_OK);
    uint8_t loadstore[] = {0x48, 0x8b, 0x03, 0x48, 0x89, 0x43, 0x08};
    assert(gem_memory_write(m, CODE, loadstore, sizeof(loadstore)) == GEM_MEMORY_OK);
    init(c);
    c.x[27] = DATA;
    assert(gem_x64_runtime_run(r, &c, 2) == GEM_STOP_BUDGET_EXPIRED);
    uint64_t out = 0;
    assert(gem_memory_read(m, DATA + 8, &out, 8) == GEM_MEMORY_OK && out == value);

    /* Pinned Blink's established opcode table decodes 0x50 as OpPushZvq.
     * It is intentionally absent from the reviewed handler manifest. */
    const uint8_t push_rax = 0x50;
    assert(gem_memory_write(m, CODE, &push_rax, 1) == GEM_MEMORY_OK);
    init(c);
    uint8_t stack_before[8]{};
    assert(gem_memory_read(m, c.sp - 8, stack_before, sizeof(stack_before)) == GEM_MEMORY_OK);
    auto unsupported_before = c;
    auto unsupported_expected = c;
    unsupported_expected.stop_reason = GEM_STOP_UNSUPPORTED_INSTRUCTION;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    assert(!memcmp(&c, &unsupported_expected, sizeof(c)));
    uint8_t stack_after[8]{};
    assert(gem_memory_read(m, unsupported_before.sp - 8, stack_after, sizeof(stack_after)) ==
           GEM_MEMORY_OK);
    assert(!memcmp(stack_before, stack_after, sizeof(stack_before)));

    assert(gem_memory_write(m, CODE, loadstore, 3) == GEM_MEMORY_OK);
    init(c);
    const uint64_t noncanonical_address = UINT64_C(0x0000800000000000);
    c.x[27] = noncanonical_address;
    auto noncanonical_expected = c;
    noncanonical_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
    uint8_t memory_before[8]{};
    assert(gem_memory_read(m, DATA, memory_before, sizeof(memory_before)) == GEM_MEMORY_OK);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
    assert(!memcmp(&c, &noncanonical_expected, sizeof(c)));
    uint8_t memory_after[8]{};
    assert(gem_memory_read(m, DATA, memory_after, sizeof(memory_after)) == GEM_MEMORY_OK);
    assert(!memcmp(memory_before, memory_after, sizeof(memory_before)));
    gem_x64_stop_info info{};
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.fault_address == noncanonical_address &&
           info.memory_error == GEM_MEMORY_NOT_RESERVED);

    uint32_t old = 0;
    uint64_t guard_value = 0U;
    assert(gem_memory_read(m, DATA, &guard_value, sizeof(guard_value)) == GEM_MEMORY_OK);
    assert(gem_memory_protect(m, DATA, 4096, GEM_PAGE_READWRITE | GEM_PAGE_GUARD, &old) ==
           GEM_MEMORY_OK);
    assert(gem_memory_write(m, CODE, loadstore, 3) == GEM_MEMORY_OK);
    init(c);
    c.x[27] = DATA;
    auto fault_before = c;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
    assert(c.pc == fault_before.pc && c.x[8] == fault_before.x[8]);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.memory_error == GEM_MEMORY_GUARD_PAGE);
    /* Windows guard protection is one-shot. CPU/data changes rolled back above,
     * but retrying the same instruction without re-protecting must succeed. */
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + 3U && c.x[8] == guard_value);
    uint8_t store[] = {0x48, 0x89, 0x03};
    assert(gem_memory_write(m, CODE, store, sizeof(store)) == GEM_MEMORY_OK);
    const uint64_t cross = DATA + 4092;
    uint8_t cross_before[8]{};
    assert(gem_memory_read(m, cross, cross_before, sizeof(cross_before)) == GEM_MEMORY_OK);
    assert(gem_memory_protect(m, DATA + 4096, 4096, GEM_PAGE_READONLY, &old) == GEM_MEMORY_OK);
    init(c);
    c.x[27] = cross;
    c.x[8] = UINT64_C(0x0102030405060708);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.fault_address == DATA + 4096 &&
           info.access == GEM_X64_ACCESS_WRITE && info.memory_error == GEM_MEMORY_ACCESS_DENIED);
    uint8_t cross_failed[8]{};
    assert(gem_memory_read(m, cross, cross_failed, sizeof(cross_failed)) == GEM_MEMORY_OK);
    assert(!memcmp(cross_before, cross_failed, sizeof(cross_before)));
    assert(gem_memory_protect(m, DATA + 4096, 4096, GEM_PAGE_READWRITE, &old) == GEM_MEMORY_OK);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(gem_memory_read(m, cross, &out, 8) == GEM_MEMORY_OK &&
           out == UINT64_C(0x0102030405060708));

    const uint64_t alias = 0x50000;
    const uint64_t alias_source = DATA;
    const uint64_t source_value = 0x44;
    assert(gem_memory_write(m, alias_source, &source_value, 8) == GEM_MEMORY_OK);
    assert(gem_memory_alias(m, alias, alias_source, 4096, GEM_PAGE_WRITECOPY) == GEM_MEMORY_OK);
    assert(gem_memory_write(m, CODE, store, sizeof(store)) == GEM_MEMORY_OK);
    init(c);
    c.x[27] = alias;
    c.x[8] = 0x55;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    uint64_t source_after = 0, alias_after = 0;
    assert(gem_memory_read(m, alias_source, &source_after, 8) == GEM_MEMORY_OK);
    assert(gem_memory_read(m, alias, &alias_after, 8) == GEM_MEMORY_OK);
    assert(source_after == source_value && alias_after == 0x55);
    /* The alias was materialized in Blink's shadow above. Releasing it must
     * remove that stale shadow without faulting an unrelated instruction. */
    assert(gem_memory_release(m, alias, 4096) == GEM_MEMORY_OK);
    assert(gem_memory_write(m, CODE, &nop, 1) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + 1 && gem_x64_runtime_last_stop_info(r, &info) &&
           info.reason == GEM_STOP_BUDGET_EXPIRED && info.instructions_retired == 1);

    const uint64_t kuser = UINT64_C(0xaabbccddeeff0011);
    assert(gem_memory_write(m, GEM_KUSER_CANONICAL_ADDRESS, &kuser, 8) == GEM_MEMORY_OK);
    assert(gem_memory_write(m, CODE, loadstore, 3) == GEM_MEMORY_OK);
    init(c);
    c.x[27] = GEM_KUSER_SHARED_DATA_ADDRESS;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED && c.x[8] == kuser);

    uint8_t mov_one[] = {0x48, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0};
    assert(gem_memory_write(m, CODE, mov_one, sizeof(mov_one)) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED && c.x[8] == 1);
    uint8_t two = 2;
    assert(gem_memory_write(m, CODE + 2, &two, 1) == GEM_MEMORY_OK);
    gem_x64_runtime_invalidate_code(r, CODE, sizeof(mov_one));
    c.pc = CODE;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED && c.x[8] == 2);

    uint8_t ret = 0xc3;
    uint64_t sentinel = GEM_X64_DEFAULT_HOST_RETURN_SENTINEL;
    assert(gem_memory_write(m, CODE, &ret, 1) == GEM_MEMORY_OK);
    init(c);
    assert(gem_memory_write(m, c.sp, &sentinel, 8) == GEM_MEMORY_OK);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_HOST_RETURN);

    assert(gem_memory_protect(m, CODE, 4096, GEM_PAGE_READWRITE, &old) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.access == GEM_X64_ACCESS_FETCH);
    assert(gem_memory_protect(m, CODE, 4096, GEM_PAGE_EXECUTE_READWRITE, &old) == GEM_MEMORY_OK);

    init(c);
    c.pc = 0x60000;
    fault_before = c;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
    assert(c.pc == fault_before.pc);
    assert(gem_x64_runtime_last_stop_info(r, &info) &&
           info.memory_error == GEM_MEMORY_NOT_RESERVED);

    uint8_t overlong[16];
    memset(overlong, 0x66, sizeof(overlong));
    assert(gem_memory_write(m, CODE, overlong, sizeof(overlong)) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    assert(c.pc == CODE);

    uint8_t x87[] = {0xd9, 0xe8};
    assert(gem_memory_write(m, CODE, x87, 2) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    assert(!memcmp(c.x87, before.x87, sizeof(c.x87)));
    uint8_t mmx[] = {0x0f, 0x6f, 0xc0};
    assert(gem_memory_write(m, CODE, mmx, sizeof(mmx)) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_UNSUPPORTED_INSTRUCTION);
    assert(!memcmp(c.x87, before.x87, sizeof(c.x87)));

    constexpr uint64_t chain = 0x100000;
    const uint8_t jump_page[] = {0xe9, 0xfb, 0x0f, 0, 0};
    for (unsigned i = 0; i < 64; ++i) {
        map(m, chain + i * 4096U, 4096, GEM_PAGE_EXECUTE_READWRITE);
        assert(gem_memory_write(m, chain + i * 4096U, jump_page, sizeof(jump_page)) ==
               GEM_MEMORY_OK);
    }
    init(c);
    c.pc = chain;
    assert(gem_x64_runtime_run(r, &c, 64) == GEM_STOP_INVARIANT_VIOLATION);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.engine_status == UINT32_MAX);

    auto malformed = c;
    malformed.layout_version = 99;
    auto copy = malformed;
    assert(gem_x64_runtime_run(r, &malformed, 1) == GEM_STOP_INVARIANT_VIOLATION);
    assert(!memcmp(&malformed, &copy, sizeof(copy)));
    init(c);
    copy = c;
    assert(gem_x64_runtime_run(r, &c, 101) == GEM_STOP_INVARIANT_VIOLATION);
    assert(!memcmp(&c, &copy, sizeof(c)));
    c.pc = UINT64_C(0x0000800000000000);
    copy = c;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_INVARIANT_VIOLATION);
    assert(!memcmp(&c, &copy, sizeof(c)));
    assert(gem_x64_runtime_run(nullptr, &c, 1) == GEM_STOP_INVARIANT_VIOLATION);
    assert(gem_x64_runtime_run(r, nullptr, 1) == GEM_STOP_INVARIANT_VIOLATION);
    gem_x64_runtime_destroy(r);
    gem_memory_destroy(m);
}
