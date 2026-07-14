// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/x64_engine.h"
#include "x64_engine_trace.h"
extern "C" {
#include "blink/gem_embed.h"
}
#include <array>
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
    cfg.engine_mode = GEM_X86_64_ENGINE_INTERPRETER;
    gem_x64_runtime *r = gem_x64_runtime_create(m, &cfg);
    assert(r);
    assert(
        strstr(gem_x64_runtime_engine_provenance(r),
               "patch-sha256=f921ab05bc911b8d3d50afd8426eea1e8c99b776e9abdb04434234cf78a91807") !=
        nullptr);
    gem_x86_64_engine_info engine_info{};
    engine_info.abi_version = 1U;
    engine_info.size = sizeof(engine_info);
    assert(gem_x64_runtime_engine_info(r, &engine_info));
    assert(engine_info.engine_mode == GEM_X86_64_ENGINE_INTERPRETER);
    assert(engine_info.host_arch == GEM_X86_64_HOST_AARCH64);
    assert(engine_info.jit_compilations == 0U && engine_info.jit_executions == 0U &&
           engine_info.jit_failures == 0U);
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

    /* Decoded user-mode instructions outside the stable diagnostic manifest
     * receive a deterministic mopcode-derived id and still retire through the
     * checked one-instruction transaction. */
    const uint8_t push_rax = 0x50;
    assert(gem_memory_write(m, CODE, &push_rax, 1) == GEM_MEMORY_OK);
    init(c);
    c.x[8] = UINT64_C(0x8877665544332211);
    const uint64_t push_sp = c.sp;
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + 1U && c.sp == push_sp - sizeof(uint64_t));
    uint64_t pushed = 0U;
    assert(gem_memory_read(m, c.sp, &pushed, sizeof(pushed)) == GEM_MEMORY_OK &&
           pushed == UINT64_C(0x8877665544332211));

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

    const uint8_t int3 = 0xcc;
    assert(gem_memory_write(m, CODE, &int3, 1) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_WINDOWS_EXCEPTION);
    assert(c.pc == CODE);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.reason == GEM_STOP_WINDOWS_EXCEPTION);

    uint8_t x87[] = {0xd9, 0xe8};
    assert(gem_memory_write(m, CODE, x87, 2) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + sizeof(x87));
    uint8_t mmx[] = {0x0f, 0x6f, 0xc0};
    assert(gem_memory_write(m, CODE, mmx, sizeof(mmx)) == GEM_MEMORY_OK);
    init(c);
    assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == CODE + sizeof(mmx));

    /* Transactional shadow pages are a bounded FIFO cache, not a process-wide
     * execution limit.  Crossing the 64-page capacity must keep running. */
    constexpr uint64_t chain = 0x100000;
    const uint8_t jump_page[] = {0xe9, 0xfb, 0x0f, 0, 0};
    for (unsigned i = 0; i < 66; ++i) {
        map(m, chain + i * 4096U, 4096, GEM_PAGE_EXECUTE_READWRITE);
        assert(gem_memory_write(m, chain + i * 4096U, jump_page, sizeof(jump_page)) ==
               GEM_MEMORY_OK);
    }
    init(c);
    c.pc = chain;
    assert(gem_x64_runtime_run(r, &c, 65) == GEM_STOP_BUDGET_EXPIRED);
    assert(c.pc == chain + 65 * 4096U);
    assert(gem_x64_runtime_last_stop_info(r, &info) && info.engine_status == 0);

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

    /* Decoder-owned handler trace: identity is Blink's own decode-dispatch
     * result, storage is bounded and reset-able, and exactly one entry is
     * appended per retired instruction (nothing for unsupported outcomes). */
    {
        uint32_t trace_count = 0xffffffffU;
        uint32_t trace_overflow = 0xffffffffU;
        uint64_t trace_rip = 0U;
        uint32_t trace_id = 0U;
        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow) &&
               trace_count == 0U && trace_overflow == 0U);
        assert(gem_memory_write(m, CODE, &nop, 1) == GEM_MEMORY_OK);
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow) &&
               trace_count == 1U && trace_overflow == 0U);
        assert(gem_x64_runtime_handler_trace_read(r, 0, &trace_rip, &trace_id) &&
               trace_rip == CODE && trace_id == BLINK_GEM_HANDLER_OP_NOP &&
               !strcmp(gem_x64_runtime_handler_name(trace_id), "OpNop"));
        assert(!gem_x64_runtime_handler_trace_read(r, 1, &trace_rip, &trace_id));

        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_memory_write(m, CODE, loadstore, 3) == GEM_MEMORY_OK);
        init(c);
        c.x[27] = DATA;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow) &&
               trace_count == 1U &&
               gem_x64_runtime_handler_trace_read(r, 0, &trace_rip, &trace_id) &&
               trace_id == BLINK_GEM_HANDLER_OP_MOV_GVQP_EVQP && trace_rip == CODE);

        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_memory_write(m, CODE, &push_rax, 1) == GEM_MEMORY_OK);
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow) &&
               trace_count == 1U && trace_overflow == 0U &&
               gem_x64_runtime_handler_trace_read(r, 0, &trace_rip, &trace_id) &&
               trace_rip == CODE && trace_id == BLINK_GEM_HANDLER_DECODED_BASE + 0x050U &&
               !strcmp(gem_x64_runtime_handler_name(trace_id), "OpPushZvq"));

        /* Determinism: identical repeated program yields an identical trace. */
        const uint8_t alu_then_mov[] = {0x48, 0x83, 0xc1, 0x02, 0x48, 0x8b, 0xc1};
        assert(gem_memory_write(m, CODE, alu_then_mov, sizeof(alu_then_mov)) == GEM_MEMORY_OK);
        uint32_t first_ids[2] = {0U, 0U};
        for (unsigned pass = 0; pass < 2U; ++pass) {
            gem_x64_runtime_handler_trace_reset(r);
            init(c);
            assert(gem_x64_runtime_run(r, &c, 2) == GEM_STOP_BUDGET_EXPIRED);
            assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow) &&
                   trace_count == 2U && trace_overflow == 0U);
            uint32_t ids[2] = {0U, 0U};
            uint64_t rip0 = 0U;
            uint64_t rip1 = 0U;
            assert(gem_x64_runtime_handler_trace_read(r, 0, &rip0, &ids[0]) &&
                   gem_x64_runtime_handler_trace_read(r, 1, &rip1, &ids[1]));
            assert(ids[0] == BLINK_GEM_HANDLER_OP_ALUI &&
                   ids[1] == BLINK_GEM_HANDLER_OP_MOV_GVQP_EVQP && rip0 == CODE &&
                   rip1 == CODE + 4U);
            if (pass == 0U) {
                first_ids[0] = ids[0];
                first_ids[1] = ids[1];
            } else {
                assert(ids[0] == first_ids[0] && ids[1] == first_ids[1]);
            }
        }
        /* An invalid trace-info request leaves the runtime state untouched. */
        assert(gem_x64_runtime_handler_name(0U) != nullptr &&
               !strcmp(gem_x64_runtime_handler_name(0U), "OpUnknown"));
        gem_x64_runtime_handler_trace_reset(nullptr);
        assert(!gem_x64_runtime_handler_trace_info(nullptr, &trace_count, &trace_overflow));
        assert(!gem_x64_runtime_handler_trace_read(nullptr, 0, &trace_rip, &trace_id));
    }

    /* Decoder-owned "last decode attempt" diagnostic: Blink's own
     * Mopcode()/DescribeMopcode() identity is surfaced verbatim, including for
     * denied opcodes outside the decoded user-mode policy.  Pre-decode
     * faults must leave valid=0 with an empty name.  The wrapper validates
     * abi_version/size on entry and copies Blink-owned storage into caller
     * storage; the returned name lifetime is bound to the runtime. */
    {
        uint32_t trace_count = 0U;
        uint32_t trace_overflow = 0U;
        blink_gem_decode_attempt attempt{};
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt);
        assert(!gem_x64_runtime_decode_attempt_info(nullptr, &attempt));
        assert(!gem_x64_runtime_decode_attempt_info(r, nullptr));

        /* Wrong abi_version/size must fail closed at the wrapper boundary. */
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION + 1U;
        attempt.size = sizeof(attempt);
        assert(!gem_x64_runtime_decode_attempt_info(r, &attempt));
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt) - 1U;
        assert(!gem_x64_runtime_decode_attempt_info(r, &attempt));
        attempt.size = sizeof(attempt);
        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(!attempt.valid && attempt.name[0] == '\0');

        /* Successful LoadInstruction with an admitted handler: identity is
         * Blink's own decode-dispatch result (handler_id != 0, name matches). */
        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_memory_write(m, CODE, &nop, 1) == GEM_MEMORY_OK);
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_NOP &&
               !strcmp(attempt.name, "OpNop") && attempt.rip == CODE);

        /* LEA retires with Blink's stable decoder-owned handler id. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t lea[] = {0x48, 0x8d, 0x05, 0x2a, 0x00, 0x00, 0x00};
        assert(gem_memory_write(m, CODE, lea, sizeof(lea)) == GEM_MEMORY_OK);
        init(c);
        const auto lea_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(lea));
        assert(!memcmp(c.x87, lea_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_LEA_GVQP_M &&
               !strcmp(attempt.name, "OpLeaGvqpM") && attempt.rip == CODE);

        /* The authentic direct path's register-register ADD uses Blink's
         * OpAluFlip implementation. It updates RAX/flags without touching raw
         * x87/MM state or guest memory. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t add_rax_rcx[] = {0x48, 0x03, 0xc1};
        assert(gem_memory_write(m, CODE, add_rax_rcx, sizeof(add_rax_rcx)) == GEM_MEMORY_OK);
        init(c);
        c.x[8] = 7U;
        c.x[0] = 5U;
        const auto add_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(add_rax_rcx) && c.x[8] == 12U && c.x[0] == 5U);
        assert(!memcmp(c.x87, add_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_ALU_FLIP &&
               !strcmp(attempt.name, "OpAluwFlip") && attempt.rip == CODE);

        /* The authentic x64 fixture also uses ADD EAX,ECX. The 32-bit form
         * shares the stable handler id and must zero-extend its result. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t add_eax_ecx[] = {0x03, 0xc1};
        assert(gem_memory_write(m, CODE, add_eax_ecx, sizeof(add_eax_ecx)) == GEM_MEMORY_OK);
        init(c);
        c.x[8] = UINT64_C(0xffffffff00000007);
        c.x[0] = 5U;
        const auto add32_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(add_eax_ecx) && c.x[8] == 12U && c.x[0] == 5U);
        assert(!memcmp(c.x87, add32_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_ALU_FLIP &&
               !strcmp(attempt.name, "OpAluwFlip") && attempt.rip == CODE);

        /* The authentic aggregate path combines two halves with OR RAX,RCX.
         * It shares OpAluFlip but has its own exact 64-bit register rule. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t or_rax_rcx[] = {0x48, 0x0b, 0xc1};
        assert(gem_memory_write(m, CODE, or_rax_rcx, sizeof(or_rax_rcx)) == GEM_MEMORY_OK);
        init(c);
        c.x[8] = UINT64_C(0x1234000000000000);
        c.x[0] = UINT64_C(0x0000000056789abc);
        const auto or_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(or_rax_rcx) && c.x[8] == UINT64_C(0x1234000056789abc) &&
               !memcmp(c.x87, or_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x00bU &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_ALU_FLIP &&
               !strcmp(attempt.name, "OpAluwFlip") && attempt.rip == CODE);

        /* The authentic variadic fixture zeros EAX with XOR EAX,EAX. Keep
         * that exact 32-bit register family and its required zero-extension. */
        const uint8_t xor_eax_eax[] = {0x33, 0xc0};
        assert(gem_memory_write(m, CODE, xor_eax_eax, sizeof(xor_eax_eax)) == GEM_MEMORY_OK);
        init(c);
        c.x[8] = UINT64_C(0xffffffffffffffff);
        const auto xor32_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(xor_eax_eax) && c.x[8] == 0U &&
               !memcmp(c.x87, xor32_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x033U &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_ALU_FLIP &&
               !strcmp(attempt.name, "OpAluwFlip"));

        /* The 64-bit XOR variant resolves to the shared handler and receives
         * the deterministic decoded-instruction id. */
        const uint8_t xor_rax_rcx[] = {0x48, 0x33, 0xc1};
        assert(gem_memory_write(m, CODE, xor_rax_rcx, sizeof(xor_rax_rcx)) == GEM_MEMORY_OK);
        init(c);
        c.x[8] = UINT64_C(0xf0f00ff00f0ff00f);
        c.x[0] = UINT64_C(0x0ff0f00ff0f00ff0);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(xor_rax_rcx) && c.x[8] == UINT64_C(0xff00ffffffffffff));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x033U &&
               attempt.handler_id == BLINK_GEM_HANDLER_DECODED_BASE + 0x033U &&
               !strcmp(attempt.name, "OpAluwFlip"));

        /* The authentic variadic path uses TEST ECX,ECX for its zero-count
         * branch. The 32-bit register form must preserve GPRs and set ZF. */
        const uint8_t test_ecx_ecx[] = {0x85, 0xc9};
        assert(gem_memory_write(m, CODE, test_ecx_ecx, sizeof(test_ecx_ecx)) == GEM_MEMORY_OK);
        init(c);
        c.x[0] = 0U;
        const auto test_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(test_ecx_ecx) && c.x[0] == 0U &&
               (c.x64_rflags & UINT64_C(0x40)) != 0U &&
               !memcmp(c.x87, test_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x085U &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_ALU_TEST &&
               !strcmp(attempt.name, "OpAluwTest"));

        /* MOVSXD RAX,dword ptr [RBX+8] models the fixture's signed variadic
         * load while exercising the stable checked-memory form. */
        const int32_t signed_value = -7;
        assert(gem_memory_write(m, DATA + 8U, &signed_value, sizeof(signed_value)) ==
               GEM_MEMORY_OK);
        const uint8_t movsxd_rax_rbx[] = {0x48, 0x63, 0x43, 0x08};
        assert(gem_memory_write(m, CODE, movsxd_rax_rbx, sizeof(movsxd_rax_rbx)) == GEM_MEMORY_OK);
        init(c);
        c.x[27] = DATA;
        const auto movsxd_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(movsxd_rax_rbx) && c.x[8] == UINT64_C(0xfffffffffffffff9) &&
               !memcmp(c.x87, movsxd_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x063U &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_MOVSL_GDQP_ED &&
               !strcmp(attempt.name, "OpMovsxdGdqpEd"));

        /* Preserve compiler alignment NOPs exactly, including the redundant
         * operand-size prefixes emitted by the authentic fixture. */
        const uint8_t nop_ev[] = {0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
        assert(gem_memory_write(m, CODE, nop_ev, sizeof(nop_ev)) == GEM_MEMORY_OK);
        init(c);
        const auto nop_ev_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(nop_ev));
        assert(!memcmp(c.x, nop_ev_before.x, sizeof(c.x)));
        assert(c.sp == nop_ev_before.sp);
        assert((c.x64_rflags & UINT64_C(0x8d5)) == (nop_ev_before.x64_rflags & UINT64_C(0x8d5)));
        assert(c.x64_mxcsr == nop_ev_before.x64_mxcsr);
        assert(c.x64_fcw == nop_ev_before.x64_fcw);
        assert(c.x64_fsw == nop_ev_before.x64_fsw);
        assert(!memcmp(c.v, nop_ev_before.v, sizeof(c.v)));
        assert(!memcmp(c.x87, nop_ev_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x11fU &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_NOP_EV &&
               !strcmp(attempt.name, "OpNopEv"));

        /* Alternate widths and checked-memory forms use the decoded policy. */
        const std::array<std::array<uint8_t, 3>, 2> decoded_adds = {
            {{0x66, 0x03, 0xc1}, {0x48, 0x03, 0x01}}};
        for (unsigned index = 0; index < decoded_adds.size(); ++index) {
            const auto &decoded_add = decoded_adds[index];
            gem_x64_runtime_handler_trace_reset(r);
            assert(gem_memory_write(m, CODE, decoded_add.data(), decoded_add.size()) ==
                   GEM_MEMORY_OK);
            init(c);
            c.x[8] = index ? 7U : UINT64_C(0x123456789abc0007);
            c.x[0] = index ? DATA : 5U;
            const uint64_t add_memory_value = 5U;
            if (index)
                assert(gem_memory_write(m, DATA, &add_memory_value, sizeof(add_memory_value)) ==
                       GEM_MEMORY_OK);
            assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
            assert(c.pc == CODE + decoded_add.size());
            assert(c.x[8] == (index ? 12U : UINT64_C(0x123456789abc000c)));
            assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
            assert(attempt.valid && attempt.mopcode == 0x003U &&
                   attempt.handler_id == BLINK_GEM_HANDLER_DECODED_BASE + 0x003U &&
                   !strcmp(attempt.name, "OpAluwFlip") && attempt.rip == CODE);
        }

        /* Authentic scalar-double arithmetic keeps XMM0's upper lane and all
         * unrelated SIMD/x87 state intact. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t addsd_xmm0_xmm0[] = {0xf2, 0x0f, 0x58, 0xc0};
        assert(gem_memory_write(m, CODE, addsd_xmm0_xmm0, sizeof(addsd_xmm0_xmm0)) ==
               GEM_MEMORY_OK);
        init(c);
        c.v[0].lo = UINT64_C(0x3ff8000000000000); /* 1.5 */
        const auto addsd_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(addsd_xmm0_xmm0) &&
               c.v[0].lo == UINT64_C(0x4008000000000000) && /* 3.0 */
               c.v[0].hi == addsd_before.v[0].hi && c.x64_mxcsr == addsd_before.x64_mxcsr &&
               !memcmp(c.x87, addsd_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_ADD_PSD &&
               !strcmp(attempt.name, "OpAddpsd") && attempt.rip == CODE);

        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t subsd_xmm0_rip[] = {0xf2, 0x0f, 0x5c, 0x05, 0xf8, 0xff, 0x00, 0x00};
        const uint64_t half = UINT64_C(0x3fe0000000000000); /* 0.5 */
        assert(gem_memory_write(m, CODE, subsd_xmm0_rip, sizeof(subsd_xmm0_rip)) == GEM_MEMORY_OK &&
               gem_memory_write(m, DATA, &half, sizeof(half)) == GEM_MEMORY_OK);
        init(c);
        c.v[0].lo = UINT64_C(0x4008000000000000); /* 3.0 */
        const auto subsd_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(subsd_xmm0_rip) &&
               c.v[0].lo == UINT64_C(0x4004000000000000) && /* 2.5 */
               c.v[0].hi == subsd_before.v[0].hi && c.x64_mxcsr == subsd_before.x64_mxcsr &&
               !memcmp(c.x87, subsd_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_SUB_PSD &&
               !strcmp(attempt.name, "OpSubpsd") && attempt.rip == CODE);

        for (const std::array<uint8_t, 4> decoded_sse :
             {std::array<uint8_t, 4>{0x66, 0x0f, 0x58, 0xc0},
              std::array<uint8_t, 4>{0xf3, 0x0f, 0x58, 0xc0}}) {
            assert(gem_memory_write(m, CODE, decoded_sse.data(), decoded_sse.size()) ==
                   GEM_MEMORY_OK);
            init(c);
            c.v[0].lo = 0U;
            c.v[0].hi = 0U;
            assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
            assert(c.pc == CODE + decoded_sse.size());
            assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
            assert(attempt.valid && attempt.mopcode == 0x158U &&
                   attempt.handler_id == BLINK_GEM_HANDLER_DECODED_BASE + 0x158U &&
                   !strcmp(attempt.name, "OpAddpsd"));
        }

        /* Reviewed relative CALL transactionally pushes its return address and
         * retires with Blink's decoder-owned handler id. */
        gem_x64_runtime_handler_trace_reset(r);
        const uint8_t call[] = {0xe8, 0x00, 0x00, 0x00, 0x00};
        assert(gem_memory_write(m, CODE, call, sizeof(call)) == GEM_MEMORY_OK);
        init(c);
        const auto call_before = c;
        const auto call_sp = c.sp;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(call) && c.sp == call_sp - sizeof(uint64_t));
        uint64_t call_return = 0U;
        assert(gem_memory_read(m, c.sp, &call_return, sizeof(call_return)) == GEM_MEMORY_OK);
        assert(call_return == CODE + sizeof(call));
        assert(!memcmp(c.x87, call_before.x87, sizeof(c.x87)));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.handler_id == BLINK_GEM_HANDLER_OP_CALL_JVDS &&
               !strcmp(attempt.name, "OpCallJvds") && attempt.rip == CODE);

        /* Windows ARM64X import thunks use RIP-relative FF /2 and FF /4.
         * Admission is based on Blink's decoded 0x0ff group and ModR/M
         * selector; GEM does not scan or reinterpret instruction bytes. */
        constexpr uint64_t indirect_slot = CODE + 0x100U;
        constexpr uint64_t indirect_target = CODE + 0x200U;
        const uint8_t indirect_call[] = {0xff, 0x15, 0xfa, 0x00, 0x00, 0x00};
        assert(gem_memory_write(m, CODE, indirect_call, sizeof(indirect_call)) == GEM_MEMORY_OK);
        assert(gem_memory_write(m, indirect_slot, &indirect_target, sizeof(indirect_target)) ==
               GEM_MEMORY_OK);
        gem_x64_runtime_handler_trace_reset(r);
        init(c);
        const auto indirect_call_sp = c.sp;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == indirect_target && c.sp == indirect_call_sp - sizeof(uint64_t) &&
               gem_x64_runtime_last_instruction_was_call(r));
        call_return = 0U;
        assert(gem_memory_read(m, c.sp, &call_return, sizeof(call_return)) == GEM_MEMORY_OK);
        assert(call_return == CODE + sizeof(indirect_call));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x0ffU &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_CALL_EQ &&
               !strcmp(attempt.name, "Op0ff") && attempt.rip == CODE);

        const uint8_t indirect_jump[] = {0xff, 0x25, 0xfa, 0x00, 0x00, 0x00};
        assert(gem_memory_write(m, CODE, indirect_jump, sizeof(indirect_jump)) == GEM_MEMORY_OK);
        gem_x64_runtime_handler_trace_reset(r);
        init(c);
        const auto indirect_jump_sp = c.sp;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == indirect_target && c.sp == indirect_jump_sp &&
               !gem_x64_runtime_last_instruction_was_call(r));
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x0ffU &&
               attempt.handler_id == BLINK_GEM_HANDLER_OP_JMP_EQ &&
               !strcmp(attempt.name, "Op0ff") && attempt.rip == CODE);

        /* GEM owns syscall delivery. Blink's Linux handler remains denied,
         * while the decoded instruction is surfaced as a Windows boundary. */
        const uint8_t denied_syscall[] = {0x0f, 0x05};
        assert(gem_memory_write(m, CODE, denied_syscall, sizeof(denied_syscall)) == GEM_MEMORY_OK);
        init(c);
        const auto denied_before = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_SYSCALL);
        assert(c.pc == denied_before.pc && c.sp == denied_before.sp);
        assert(gem_x64_runtime_last_stop_info(r, &info) &&
               info.engine_status == GEM_X64_BOUNDARY_WINDOWS_SYSCALL);
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(attempt.valid && attempt.mopcode == 0x105U && attempt.handler_id == 0U &&
               !strcmp(attempt.name, "OpSyscall"));

        /* CALL's return-record write is transactional on an unwritable stack. */
        assert(gem_memory_write(m, CODE, call, sizeof(call)) == GEM_MEMORY_OK);
        const std::array<uint8_t, 8> call_stack_pattern = {0x10, 0x21, 0x32, 0x43,
                                                           0x54, 0x65, 0x76, 0x87};
        assert(gem_memory_write(m, STACK + 4088U, call_stack_pattern.data(),
                                call_stack_pattern.size()) == GEM_MEMORY_OK);
        uint32_t stack_protection = 0U;
        assert(gem_memory_protect(m, STACK, 4096U, GEM_PAGE_READONLY, &stack_protection) ==
               GEM_MEMORY_OK);
        init(c);
        c.sp = STACK + 4096U;
        auto failed_call_expected = c;
        failed_call_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
        assert(!memcmp(&c, &failed_call_expected, sizeof(c)));
        gem_x64_stop_info call_fault{};
        assert(gem_x64_runtime_last_stop_info(r, &call_fault) &&
               call_fault.reason == GEM_STOP_MEMORY_FAULT &&
               call_fault.instructions_retired == 0U && call_fault.fault_address == STACK &&
               call_fault.access == GEM_X64_ACCESS_WRITE &&
               call_fault.memory_error == GEM_MEMORY_ACCESS_DENIED);
        std::array<uint8_t, 8> failed_call_stack{};
        assert(gem_memory_read(m, STACK + 4088U, failed_call_stack.data(),
                               failed_call_stack.size()) == GEM_MEMORY_OK);
        assert(failed_call_stack == call_stack_pattern);
        assert(gem_memory_protect(m, STACK, 4096U, stack_protection, &stack_protection) ==
               GEM_MEMORY_OK);

        /* The same runtime remains reusable after the failed transaction. */
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == CODE + sizeof(call) && c.sp == STACK + 4072U);
        /* RET identity also comes from Blink's retired decoder handler. */
        const uint8_t ret_instruction = 0xc3;
        const uint64_t ret_target = CODE + 1U;
        assert(gem_memory_write(m, CODE, &ret_instruction, sizeof(ret_instruction)) ==
               GEM_MEMORY_OK);
        assert(gem_memory_write(m, STACK + 4080U, &ret_target, sizeof(ret_target)) ==
               GEM_MEMORY_OK);
        init(c);
        c.sp = STACK + 4080U;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(c.pc == ret_target && c.sp == STACK + 4088U &&
               gem_x64_runtime_last_instruction_was_ret(r));
        assert(gem_memory_write(m, CODE, &nop, sizeof(nop)) == GEM_MEMORY_OK);
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_BUDGET_EXPIRED);
        assert(!gem_x64_runtime_last_instruction_was_ret(r));

        /* Pre-decode fault: a fetch outside mapped memory leaves valid=0 and
         * an empty name; canonical CPU state is unchanged. */
        gem_x64_runtime_handler_trace_reset(r);
        uint32_t code_protection = 0U;
        assert(gem_memory_protect(m, CODE, 4096U, GEM_PAGE_NOACCESS, &code_protection) ==
               GEM_MEMORY_OK);
        init(c);
        const auto prefault = c;
        assert(gem_x64_runtime_run(r, &c, 1) == GEM_STOP_MEMORY_FAULT);
        assert(c.pc == prefault.pc);
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(!attempt.valid && attempt.name[0] == '\0');
        uint32_t ignored_protection = 0U;
        assert(gem_memory_protect(m, CODE, 4096U, code_protection, &ignored_protection) ==
               GEM_MEMORY_OK);

        /* Reset is allowed mid-run only between steps; here it just clears the
         * decode-attempt record without disturbing the previously retired
         * trace.  Reading after an unsuccessful reset target keeps valid=0. */
        blink_gem_decode_attempt zero{};
        zero.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        zero.size = sizeof(zero);
        attempt = zero;
        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_x64_runtime_decode_attempt_info(r, &attempt));
        assert(!attempt.valid && attempt.name[0] == '\0');
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow));
        assert(trace_count == 0U && trace_overflow == 0U);
    }

    /* >256 instruction overflow test: prove the trace is sticky, non-wrapping,
     * retains the first BLINK_GEM_MAX_TRACE_ENTRIES entries, resets cleanly on
     * demand, and never alters guest execution, admission, or committed
     * architectural state.  We step the same NOP BLINK_GEM_MAX_TRACE_ENTRIES + 8
     * times through the x64 runtime: the trace must hold exactly 256 entries
     * with overflow=1, the first retired RIP must still be CODE, and the
     * retired CPU/IPC state must match a control runtime that never overflowed.
     */
    {
        constexpr unsigned kCapacity = BLINK_GEM_MAX_TRACE_ENTRIES;
        constexpr unsigned kOverflow = kCapacity + 8U;
        uint32_t trace_count = 0U;
        uint32_t trace_overflow = 0U;
        uint64_t trace_rip = 0U;
        uint32_t trace_id = 0U;

        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow));
        assert(trace_count == 0U && trace_overflow == 0U);

        std::array<uint8_t, kOverflow> overflow_nops{};
        overflow_nops.fill(nop);
        assert(gem_memory_write(m, CODE, overflow_nops.data(), overflow_nops.size()) ==
               GEM_MEMORY_OK);
        init(c);
        const auto overflow_before = c;
        /* Step every NOP in one-instruction runs so each retirement is observed
         * independently while the machine-owned trace remains cumulative. */
        for (unsigned step = 0; step < kOverflow; ++step) {
            assert(gem_x64_runtime_run(r, &c, 1U) == GEM_STOP_BUDGET_EXPIRED);
            c.stop_reason = GEM_STOP_NONE;
        }
        assert(c.pc == overflow_before.pc + kOverflow);
        const auto overflow_after = c;

        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow));
        assert(trace_count == kCapacity);
        assert(trace_overflow == 1U);
        /* Sticky / non-wrapping: first capacity entries are exactly the first
         * capacity retired RIPs; the 257th read must fail. */
        for (unsigned index = 0; index < kCapacity; ++index) {
            assert(gem_x64_runtime_handler_trace_read(r, index, &trace_rip, &trace_id));
            assert(trace_rip == overflow_before.pc + index && trace_id == BLINK_GEM_HANDLER_OP_NOP);
        }
        assert(!gem_x64_runtime_handler_trace_read(r, kCapacity, &trace_rip, &trace_id));

        /* Reset clears the trace and overflow flag, and the very next retired
         * instruction appends exactly one entry with overflow=0. */
        gem_x64_runtime_handler_trace_reset(r);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow));
        assert(trace_count == 0U && trace_overflow == 0U);
        init(c);
        assert(gem_x64_runtime_run(r, &c, 1U) == GEM_STOP_BUDGET_EXPIRED);
        assert(gem_x64_runtime_handler_trace_info(r, &trace_count, &trace_overflow));
        assert(trace_count == 1U && trace_overflow == 0U);
        assert(gem_x64_runtime_handler_trace_read(r, 0, &trace_rip, &trace_id) &&
               trace_rip == CODE && trace_id == BLINK_GEM_HANDLER_OP_NOP);

        /* No state effect: a control runtime (separate guest-memory image) that
         * never overflowed must agree on every touched CPU/register byte after
         * the exact same kOverflow NOPs; only the runtime's trace, not the
         * canonical CPU state, may differ. */
        gem_memory *ctrl_m = gem_memory_create();
        assert(ctrl_m);
        map(ctrl_m, CODE, 4096, GEM_PAGE_EXECUTE_READWRITE);
        map(ctrl_m, DATA, 8192, GEM_PAGE_READWRITE);
        map(ctrl_m, STACK, 4096, GEM_PAGE_READWRITE);
        gem_x64_runtime_config ctrl_cfg{};
        ctrl_cfg.max_budget = 100U;
        ctrl_cfg.engine_mode = GEM_X86_64_ENGINE_INTERPRETER;
        gem_x64_runtime *ctrl_r = gem_x64_runtime_create(ctrl_m, &ctrl_cfg);
        assert(ctrl_r);
        assert(gem_memory_write(ctrl_m, CODE, overflow_nops.data(), overflow_nops.size()) ==
               GEM_MEMORY_OK);
        gem_thread_context ctrl_c{};
        init(ctrl_c);
        for (unsigned step = 0; step < kOverflow; ++step) {
            gem_x64_runtime_handler_trace_reset(ctrl_r);
            assert(gem_x64_runtime_run(ctrl_r, &ctrl_c, 1U) == GEM_STOP_BUDGET_EXPIRED);
            ctrl_c.stop_reason = GEM_STOP_NONE;
        }
        /* The control resets diagnostics between steps and therefore never
         * overflows, while executing exactly the same guest instructions. */
        assert(gem_x64_runtime_handler_trace_info(ctrl_r, &trace_count, &trace_overflow));
        assert(trace_count == 1U && trace_overflow == 0U);
        /* CPU state must match the overflowed runtime exactly; the only
         * difference between the two runtimes is the diagnostic trace. */
        assert(overflow_after.pc == ctrl_c.pc);
        assert(!memcmp(overflow_after.x, ctrl_c.x, sizeof(ctrl_c.x)));
        assert(overflow_after.sp == ctrl_c.sp && overflow_after.x64_rflags == ctrl_c.x64_rflags &&
               overflow_after.x64_mxcsr == ctrl_c.x64_mxcsr &&
               overflow_after.x64_fcw == ctrl_c.x64_fcw &&
               overflow_after.x64_fsw == ctrl_c.x64_fsw);
        assert(!memcmp(overflow_after.v, ctrl_c.v, sizeof(ctrl_c.v)));
        assert(!memcmp(overflow_after.x87, ctrl_c.x87, sizeof(ctrl_c.x87)));
        gem_x64_runtime_destroy(ctrl_r);
        gem_memory_destroy(ctrl_m);
    }
    gem_x64_runtime_destroy(r);
    gem_memory_destroy(m);
}
