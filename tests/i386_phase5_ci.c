// SPDX-License-Identifier: Apache-2.0
#include "fixtures/i386_phase4_execute.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef MSWR_PHASE5_GOLDEN_PATH
#define MSWR_PHASE5_GOLDEN_PATH "tests/fixtures/i386_phase5_golden.bin"
#endif

#define PHASE5_CASES UINT32_C(65536)
#define PHASE5_FINAL_SHARD UINT32_C(15)
#define PHASE5_FINAL_ORDINAL UINT32_C(4095)

static uint32_t read_u32(FILE *file) {
    uint8_t bytes[4];
    assert(fread(bytes, sizeof(bytes), 1U, file) == 1U);
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) | ((uint32_t)bytes[2] << 16U) |
           ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(FILE *file) {
    uint64_t value = 0U;
    unsigned int i;
    for (i = 0U; i < 8U; ++i) {
        const int byte = fgetc(file);
        assert(byte != EOF);
        value |= (uint64_t)(uint8_t)byte << (i * 8U);
    }
    return value;
}

int main(int argc, char **argv) {
    static const uint8_t magic[8] = {'S', 'W', 'P', '5', 'G', 'L', 'D', '1'};
    enum gem_i386_engine_mode mode;
    uint8_t observed_magic[8];
    uint32_t index;
    FILE *file;
    assert(argc == 2);
    if (!strcmp(argv[1], "interpreter"))
        mode = GEM_I386_ENGINE_INTERPRETER;
    else {
        assert(!strcmp(argv[1], "jit"));
        mode = GEM_I386_ENGINE_JIT;
    }
    file = fopen(MSWR_PHASE5_GOLDEN_PATH, "rb");
    assert(file != NULL);
    assert(fread(observed_magic, sizeof(observed_magic), 1U, file) == 1U);
    assert(memcmp(observed_magic, magic, sizeof(magic)) == 0);
    assert(read_u32(file) == 1U);
    assert(read_u32(file) == PHASE5_CASES);
    assert(read_u32(file) == PHASE5_FINAL_SHARD);
    assert(read_u32(file) == PHASE5_FINAL_ORDINAL);
    assert(read_u64(file) == I386_PHASE4_MASTER_SEED);
    for (index = 0U; index < PHASE5_CASES; ++index) {
        struct i386_phase4_case test;
        struct i386_phase4_record record;
        const uint32_t shard = index / I386_PHASE4_CASES_PER_SHARD;
        const uint32_t ordinal = index % I386_PHASE4_CASES_PER_SHARD;
        const uint64_t expected = read_u64(file);
        assert(i386_phase4_generate(shard, ordinal, &test));
        assert(i386_phase4_execute(&test, mode, &record));
        if (i386_phase4_compatibility_hash(&record) != expected)
            fprintf(stderr, "Phase 5 golden mismatch mode=%s shard=%u case=%u template=%u\n",
                    argv[1], shard, ordinal, test.template_id);
        assert(i386_phase4_compatibility_hash(&record) == expected);
        assert(record.jit_failures == 0U);
        if (mode == GEM_I386_ENGINE_JIT && !test.expected_negative)
            assert(record.jit_executions == 1U);
    }
    assert(fgetc(file) == EOF);
    assert(fclose(file) == 0);
    printf("Phase 5 %s golden replay passed: %u cases\n", argv[1], PHASE5_CASES);
    return 0;
}
