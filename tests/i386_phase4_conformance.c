// SPDX-License-Identifier: Apache-2.0
#include "fixtures/i386_phase4_execute.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void verify_generator(void) {
    struct i386_phase4_case first;
    struct i386_phase4_case second;
    uint32_t counts[7] = {0};
    uint32_t ordinal;
    for (ordinal = 0; ordinal < I386_PHASE4_CASES_PER_SHARD; ++ordinal) {
        assert(i386_phase4_generate(0U, ordinal, &first));
        assert(i386_phase4_generate(0U, ordinal, &second));
        assert(memcmp(&first, &second, sizeof(first)) == 0);
        assert(first.seed == i386_phase4_case_seed(0U, ordinal));
        if (!first.expected_negative)
            assert(first.instruction[0] != 0xc4U && first.instruction[0] != 0xc5U);
        ++counts[first.category];
    }
    assert(counts[I386_PHASE4_SCALAR] == 1024U);
    assert(counts[I386_PHASE4_MEMORY] == 768U);
    assert(counts[I386_PHASE4_X87_MMX] == 512U);
    assert(counts[I386_PHASE4_SIMD] == 768U);
    assert(counts[I386_PHASE4_SYSTEM] == 768U);
    assert(counts[I386_PHASE4_NEGATIVE] == 256U);
    assert(!i386_phase4_generate(I386_PHASE4_SHARDS, 0U, &first));
    assert(!i386_phase4_generate(0U, I386_PHASE4_CASES_PER_SHARD, &first));
    assert(i386_phase4_generate(0U, 0U, &first));
    first.instruction_size = 0U;
    assert(!i386_phase4_validate(&first));
    assert(i386_phase4_generate(0U, I386_PHASE4_CASES_PER_SHARD - 1U, &first));
    first.expected_negative = 0U;
    assert(!i386_phase4_validate(&first));
}

static void verify_x87_stack_overflow_regression(uint32_t ordinal, uint32_t template_id) {
    struct i386_phase4_case test;
    struct i386_phase4_record interpreter;
    struct i386_phase4_record jit;
    assert(i386_phase4_generate(0U, ordinal, &test));
    assert(test.template_id == template_id);
    assert(i386_phase4_execute(&test, GEM_I386_ENGINE_INTERPRETER, &interpreter));
    assert(i386_phase4_execute(&test, GEM_I386_ENGINE_JIT, &jit));
    assert(i386_phase4_records_match(&interpreter, &jit));
    assert(i386_phase4_sdm_expectation_met(&test, &interpreter));
    assert(i386_phase4_sdm_expectation_met(&test, &jit));
}

static void verify_scas_flag_regression(void) {
    struct i386_phase4_case test;
    struct i386_phase4_record interpreter;
    struct i386_phase4_record jit;
    assert(i386_phase4_generate(0U, 3080U, &test));
    assert(test.template_id == 504U);
    assert(i386_phase4_execute(&test, GEM_I386_ENGINE_INTERPRETER, &interpreter));
    assert(i386_phase4_execute(&test, GEM_I386_ENGINE_JIT, &jit));
    assert(i386_phase4_records_match(&interpreter, &jit));
    assert(interpreter.final.gpr[GEM_I386_ECX] == 0U);
    assert(interpreter.final.gpr[GEM_I386_EDI] == test.initial.gpr[GEM_I386_EDI] + 5U);
    assert((interpreter.final.eflags & test.defined.eflags_mask) == UINT32_C(0x94));
}

static void verify_bmi1_templates(void) {
    struct i386_phase4_case test;
    struct i386_phase4_record interpreter;
    struct i386_phase4_record jit;
    uint32_t i;
    for (i = 0U; i < 6U; ++i) {
        assert(i386_phase4_generate(I386_PHASE4_SHARDS - 1U, 1018U + i, &test));
        assert(test.template_id == 132U + i);
        assert(i386_phase4_execute(&test, GEM_I386_ENGINE_INTERPRETER, &interpreter));
        assert(i386_phase4_execute(&test, GEM_I386_ENGINE_JIT, &jit));
        assert(i386_phase4_records_match(&interpreter, &jit));
        assert(interpreter.classification == I386_PHASE4_PASS);
        assert(jit.classification == I386_PHASE4_PASS);
        assert(interpreter.retired_count == 1U && jit.retired_count == 1U);
        assert(interpreter.jit_executions == 0U);
        assert(jit.jit_executions == 1U && jit.jit_failures == 0U);
    }
}

static void verify_bmi2_templates(void) {
    struct i386_phase4_case test;
    struct i386_phase4_record interpreter;
    struct i386_phase4_record jit;
    uint32_t i;
    for (i = 0U; i < 8U; ++i) {
        assert(i386_phase4_generate(I386_PHASE4_SHARDS - 1U, 1010U + i, &test));
        assert(test.template_id == 138U + i);
        assert(i386_phase4_execute(&test, GEM_I386_ENGINE_INTERPRETER, &interpreter));
        assert(i386_phase4_execute(&test, GEM_I386_ENGINE_JIT, &jit));
        assert(i386_phase4_records_match(&interpreter, &jit));
        assert(interpreter.classification == I386_PHASE4_PASS);
        assert(jit.classification == I386_PHASE4_PASS);
        assert(interpreter.retired_count == 1U && jit.retired_count == 1U);
        assert(interpreter.jit_executions == 0U);
        assert(jit.jit_executions == 1U && jit.jit_failures == 0U);
    }
}

int main(void) {
    const char *full = getenv("MSWR_PHASE4_FULL");
    uint32_t shard_count = full && full[0] == '1' ? I386_PHASE4_SHARDS : 1U;
    uint32_t shard;
    uint32_t ordinal;
    uint64_t comparisons = 0;
    verify_generator();
    verify_x87_stack_overflow_regression(1792U, 300U);
    verify_x87_stack_overflow_regression(1806U, 301U);
    verify_scas_flag_regression();
    verify_bmi1_templates();
    verify_bmi2_templates();
    for (shard = 0; shard < shard_count; ++shard) {
        for (ordinal = 0; ordinal < I386_PHASE4_CASES_PER_SHARD; ++ordinal) {
            struct i386_phase4_case test;
            struct i386_phase4_record interpreter;
            struct i386_phase4_record jit;
            assert(i386_phase4_generate(shard, ordinal, &test));
            if (!i386_phase4_execute(&test, GEM_I386_ENGINE_INTERPRETER, &interpreter))
                fprintf(stderr, "Phase 4 execution failure shard=%u case=%u template=%u\n", shard,
                        ordinal, test.template_id);
            assert(interpreter.classification == I386_PHASE4_PASS);
            assert(i386_phase4_execute(&test, GEM_I386_ENGINE_JIT, &jit));
            if (!i386_phase4_records_match(&interpreter, &jit))
                fprintf(stderr, "Phase 4 mismatch shard=%u case=%u template=%u category=%s\n",
                        shard, ordinal, test.template_id, i386_phase4_category_name(test.category));
            assert(i386_phase4_records_match(&interpreter, &jit));
            assert(interpreter.jit_executions == 0U);
            assert(jit.jit_failures == 0U);
            if (!test.expected_negative)
                assert(jit.jit_executions == 1U);
            comparisons += 2U;
        }
    }
    printf("Phase 4 %s passed: %u cases, %llu native comparisons\n",
           shard_count == I386_PHASE4_SHARDS ? "qualification" : "smoke",
           shard_count * I386_PHASE4_CASES_PER_SHARD, (unsigned long long)comparisons);
    return 0;
}
