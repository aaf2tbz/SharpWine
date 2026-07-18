// SPDX-License-Identifier: Apache-2.0
#include "i386_phase4_records.h"

#include <stddef.h>
#if defined(I386_PHASE4_FREESTANDING)
void *memcpy(void *target, const void *source, size_t size);
void *memset(void *target, int value, size_t size);
#else
#include <string.h>
#endif

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)

struct template_entry {
    uint8_t bytes[8];
    uint8_t size;
    uint8_t negative;
    enum i386_phase4_comparison_policy policy;
    uint32_t eflags_mask;
};

static const struct template_entry scalar_templates[] = {
    {{0x01, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x29, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x31, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
    {{0x40}, 1, 0, I386_PHASE4_COMPARE_EXACT, 0x8d4},
    {{0xf7, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x0f, 0xaf, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0x801},
    {{0xc1, 0xe0, 0x01}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
    {{0xf3, 0x0f, 0xb8, 0xc3}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x041},
    /* Phase 6 handler-coverage templates (W3d): application traces showed
     * these handlers with zero corpus coverage.  Straight-line, no ESP/EIP
     * redirection, so the unsandboxed native baseline executor stays safe. */
    {{0x0f, 0xb7, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x8d, 0x43, 0x40}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x3b, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x0b, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
    {{0x2b, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x23, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
    {{0xa8, 0x5a}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
    {{0x0f, 0xca}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x88, 0xd8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc6, 0xc0, 0x5a}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x42, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x43, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x45, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x46, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x47, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x48, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x49, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x4d, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x4e, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x4f, 0xc3}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x93, 0xc0}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x94, 0xc0}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x95, 0xc0}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xff, 0xc0}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d4},
    /* Phase 6 W5 BMI1 qualification templates.  Six reserved cases in shard
     * 15 select these entries explicitly so prior native-Windows records stay
     * stable.  The qualification VM has no i386 BMI1 capability, so its
     * attempted results are retained while SDM expectations and exact
     * interpreter/JIT parity provide the acceptance authority. */
    {{0xc4, 0xe2, 0x60, 0xf2, 0xc2}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8c1},
    {{0xc4, 0xe2, 0x60, 0xf7, 0xd0}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0xc4, 0xe2, 0x40, 0xf3, 0xce}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8c1},
    {{0xc4, 0xe2, 0x60, 0xf3, 0xd2}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8c1},
    {{0xc4, 0xe2, 0x70, 0xf3, 0xd8}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8c1},
    {{0xf3, 0x0f, 0xbc, 0xc3}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x041},
    /* Phase 6 W5 BMI2 qualification templates. SharpWine's native semantic
     * expectations and exact interpreter/JIT parity are authoritative when a
     * comparison runtime does not expose this family. */
    {{0xc4, 0xe2, 0x70, 0xf5, 0xd8}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0x8c1},
    {{0xc4, 0xe2, 0x7b, 0xf5, 0xd9}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x7a, 0xf5, 0xd9}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x7b, 0xf6, 0xd9}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x71, 0xf7, 0xd8}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x73, 0xf7, 0xd8}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x72, 0xf7, 0xd8}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe3, 0x7b, 0xf0, 0xd8, 0x07}, 6, 0, I386_PHASE4_COMPARE_EXACT, 0},
};
static const struct template_entry memory_templates[] = {
    {{0x8b, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x89, 0x07}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x03, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x87, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf0, 0x0f, 0xc1, 0x06}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0xf0, 0x0f, 0xb1, 0x1e}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    /* Phase 6 handler-coverage templates (W3d). */
    {{0x88, 0x1e}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc6, 0x06, 0x5a}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc7, 0x06, 0x78, 0x56, 0x34, 0x12}, 6, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x33, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8c5},
};
static const struct template_entry x87_mmx_templates[] = {
    {{0xd9, 0xe8}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xd9, 0xee}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xd9, 0xe0}, 2, 0, I386_PHASE4_COMPARE_X87_BINARY64, 0},
    {{0x0f, 0xef, 0xc0}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0xfc, 0xc1}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x77}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
};
static const struct template_entry simd_templates[] = {
    {{0x66, 0x0f, 0xef, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0xfe, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x38, 0x00, 0xc1}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x38, 0x39, 0xc1}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x38, 0xdc, 0xc1}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x3a, 0x44, 0xc1, 0x00}, 6, 0, I386_PHASE4_COMPARE_EXACT, 0},
    /* Phase 6 handler-coverage templates (W3d). */
    {{0x0f, 0x29, 0xc1}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0x11, 0xc1}, 3, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x62, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x6f, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x6c, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x6e, 0xc0}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0x7e, 0xc0}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0xd6, 0xc1}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x66, 0x0f, 0xc5, 0xc0, 0x01}, 5, 0, I386_PHASE4_COMPARE_EXACT, 0},
};
static const struct template_entry system_templates[] = {
    {{0xf3, 0xa4}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf3, 0xaa}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf3, 0xac}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf3, 0xa6}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0xf2, 0xae}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x90}, 1, 0, I386_PHASE4_COMPARE_EXACT, 0},
};
static const struct template_entry negative_templates[] = {
    {{0x0f, 0x0b}, 2, 1, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf3, 0x0f, 0xae, 0xc0}, 4, 1, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf3, 0x0f, 0xc7, 0xf0}, 4, 1, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x0f, 0xff}, 2, 1, I386_PHASE4_COMPARE_EXACT, 0},
};

uint64_t i386_phase4_splitmix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

uint64_t i386_phase4_case_seed(uint32_t shard, uint32_t ordinal) {
    uint64_t identity = ((uint64_t)shard << 32U) | ordinal;
    return i386_phase4_splitmix64(I386_PHASE4_MASTER_SEED ^ identity);
}

static uint64_t next_random(uint64_t *state) {
    *state = i386_phase4_splitmix64(*state);
    return *state;
}

static enum i386_phase4_category category_for_ordinal(uint32_t ordinal) {
    if (ordinal < 1024U)
        return I386_PHASE4_SCALAR;
    if (ordinal < 1792U)
        return I386_PHASE4_MEMORY;
    if (ordinal < 2304U)
        return I386_PHASE4_X87_MMX;
    if (ordinal < 3072U)
        return I386_PHASE4_SIMD;
    if (ordinal < 3840U)
        return I386_PHASE4_SYSTEM;
    return I386_PHASE4_NEGATIVE;
}

/* The hash-bound Phase 5 golden corpus pins shards 0-4 against the original
 * 36-template selection (entries[random % count]).  The Phase 6
 * handler-coverage templates appended above must not change any pinned case,
 * so shards below this bound keep selecting from the legacy prefix counts;
 * later shards select from the full tables.  Once the golden corpus is
 * regenerated against the expanded tables this gate can be removed. */
#define I386_PHASE4_LEGACY_GOLDEN_SHARDS 5U
#define I386_PHASE4_LEGACY_SCALAR_COUNT 8U
#define I386_PHASE4_LEGACY_MEMORY_COUNT 6U
#define I386_PHASE4_LEGACY_X87_MMX_COUNT 6U
#define I386_PHASE4_LEGACY_SIMD_COUNT 6U
#define I386_PHASE4_LEGACY_SYSTEM_COUNT 6U
#define I386_PHASE4_LEGACY_NEGATIVE_COUNT 4U
#define I386_PHASE4_SCALAR_RANDOM_COUNT 32U
#define I386_PHASE4_BMI1_FIRST_ORDINAL 1018U
#define I386_PHASE4_BMI1_TEMPLATE_FIRST 32U
#define I386_PHASE4_BMI2_FIRST_ORDINAL 1010U
#define I386_PHASE4_BMI2_TEMPLATE_FIRST 38U

static const struct template_entry *select_template(uint32_t shard, uint32_t ordinal,
                                                    enum i386_phase4_category category,
                                                    uint64_t random) {
    /* Divisors must stay compile-time constants: the freestanding baseline
     * fixture has no compiler runtime for a dynamic 64-bit modulo. */
    switch (category) {
    case I386_PHASE4_SCALAR:
        if (shard == I386_PHASE4_SHARDS - 1U && ordinal >= I386_PHASE4_BMI1_FIRST_ORDINAL)
            return &scalar_templates[I386_PHASE4_BMI1_TEMPLATE_FIRST + ordinal -
                                     I386_PHASE4_BMI1_FIRST_ORDINAL];
        if (shard == I386_PHASE4_SHARDS - 1U && ordinal >= I386_PHASE4_BMI2_FIRST_ORDINAL)
            return &scalar_templates[I386_PHASE4_BMI2_TEMPLATE_FIRST + ordinal -
                                     I386_PHASE4_BMI2_FIRST_ORDINAL];
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &scalar_templates[random % I386_PHASE4_LEGACY_SCALAR_COUNT]
                   : &scalar_templates[random % I386_PHASE4_SCALAR_RANDOM_COUNT];
    case I386_PHASE4_MEMORY:
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &memory_templates[random % I386_PHASE4_LEGACY_MEMORY_COUNT]
                   : &memory_templates[random %
                                       (sizeof(memory_templates) / sizeof(memory_templates[0]))];
    case I386_PHASE4_X87_MMX:
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &x87_mmx_templates[random % I386_PHASE4_LEGACY_X87_MMX_COUNT]
                   : &x87_mmx_templates[random %
                                        (sizeof(x87_mmx_templates) / sizeof(x87_mmx_templates[0]))];
    case I386_PHASE4_SIMD:
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &simd_templates[random % I386_PHASE4_LEGACY_SIMD_COUNT]
                   : &simd_templates[random % (sizeof(simd_templates) / sizeof(simd_templates[0]))];
    case I386_PHASE4_SYSTEM:
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &system_templates[random % I386_PHASE4_LEGACY_SYSTEM_COUNT]
                   : &system_templates[random %
                                       (sizeof(system_templates) / sizeof(system_templates[0]))];
    case I386_PHASE4_NEGATIVE:
        return shard < I386_PHASE4_LEGACY_GOLDEN_SHARDS
                   ? &negative_templates[random % I386_PHASE4_LEGACY_NEGATIVE_COUNT]
                   : &negative_templates[random % (sizeof(negative_templates) /
                                                   sizeof(negative_templates[0]))];
    }
    return NULL;
}

int i386_phase4_generate(uint32_t shard, uint32_t ordinal, struct i386_phase4_case *out) {
    const struct template_entry *entry;
    enum i386_phase4_category category;
    uint64_t state;
    uint32_t i;
    if (!out || shard >= I386_PHASE4_SHARDS || ordinal >= I386_PHASE4_CASES_PER_SHARD)
        return 0;
    memset(out, 0, sizeof(*out));
    out->schema_version = I386_PHASE4_SCHEMA;
    out->generator_version = I386_PHASE4_GENERATOR_VERSION;
    out->template_revision = I386_PHASE4_TEMPLATE_REVISION;
    out->shard = shard;
    out->ordinal = ordinal;
    out->seed = i386_phase4_case_seed(shard, ordinal);
    state = out->seed;
    category = category_for_ordinal(ordinal);
    entry = select_template(shard, ordinal, category, next_random(&state));
    if (!entry)
        return 0;
    out->category = category;
    out->template_id = (uint32_t)category * 100U +
                       (uint32_t)(entry - (category == I386_PHASE4_SCALAR    ? scalar_templates
                                           : category == I386_PHASE4_MEMORY  ? memory_templates
                                           : category == I386_PHASE4_X87_MMX ? x87_mmx_templates
                                           : category == I386_PHASE4_SIMD    ? simd_templates
                                           : category == I386_PHASE4_SYSTEM  ? system_templates
                                                                             : negative_templates));
    out->comparison_policy = entry->policy;
    out->instruction_size = entry->size;
    out->expected_negative = entry->negative;
    memcpy(out->instruction, entry->bytes, entry->size);
    memset(&out->initial, 0, sizeof(out->initial));
    out->initial.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    out->initial.context_size = GEM_I386_CONTEXT_SIZE_V2;
    out->initial.eflags = GEM_I386_EFLAGS_REQUIRED;
    out->initial.fcw = UINT16_C(0x037f);
    out->initial.mxcsr = UINT32_C(0x1f80);
    out->initial.teb = UINT32_C(0x7ffde000);
    out->initial.eip = CODE;
    out->initial.eflags |= (uint32_t)(next_random(&state) & UINT64_C(0x801));
    for (i = 0; i < 8U; ++i)
        out->initial.gpr[i] = (uint32_t)next_random(&state);
    out->initial.gpr[GEM_I386_ESP] = STACK + UINT32_C(0xfe0);
    out->initial.gpr[GEM_I386_ESI] = DATA + 64U;
    out->initial.gpr[GEM_I386_EDI] = DATA + 320U;
    out->initial.gpr[GEM_I386_ECX] &= 15U;
    out->initial.fcw = (uint16_t)(UINT16_C(0x037f) | ((state & 3U) << 10U));
    out->initial.mxcsr = UINT32_C(0x1f80) | ((uint32_t)(state & 3U) << 13U);
    for (i = 0; i < 8U; ++i) {
        out->initial.xmm[i].lo = next_random(&state);
        out->initial.xmm[i].hi = next_random(&state);
        out->initial.x87[i].lo = UINT64_C(0x8000000000000000) | (next_random(&state) >> 1U);
        out->initial.x87[i].lo &= ~UINT64_C(0x7ff);
        out->initial.x87[i].hi = UINT64_C(0x3fff);
    }
    for (i = 0; i < I386_PHASE4_MEMORY_SIZE; ++i)
        out->memory[i] = (uint8_t)next_random(&state);
    out->defined.gpr_mask = UINT32_C(0xff);
    out->defined.eflags_mask = entry->eflags_mask;
    out->defined.segment_mask = UINT32_C(0x3f);
    out->defined.x87_environment_mask = UINT32_C(0x0f);
    out->defined.xmm_byte_mask = UINT64_MAX;
    out->defined.x87_byte_mask = UINT64_MAX;
    out->defined.mxcsr_mask = UINT32_MAX;
    out->defined.memory_offset = 0U;
    out->defined.memory_size = I386_PHASE4_MEMORY_SIZE;
    out->defined.exception_mask = UINT32_MAX;
    return i386_phase4_validate(out);
}

int i386_phase4_validate(const struct i386_phase4_case *test) {
    if (!test || test->schema_version != I386_PHASE4_SCHEMA ||
        test->generator_version != I386_PHASE4_GENERATOR_VERSION ||
        test->template_revision != I386_PHASE4_TEMPLATE_REVISION ||
        test->shard >= I386_PHASE4_SHARDS || test->ordinal >= I386_PHASE4_CASES_PER_SHARD ||
        test->instruction_size == 0U || test->instruction_size > 15U ||
        test->seed != i386_phase4_case_seed(test->shard, test->ordinal) ||
        test->defined.memory_offset + test->defined.memory_size > I386_PHASE4_MEMORY_SIZE)
        return 0;
    if (test->category < I386_PHASE4_SCALAR || test->category > I386_PHASE4_NEGATIVE)
        return 0;
    return test->expected_negative == (test->category == I386_PHASE4_NEGATIVE);
}

const char *i386_phase4_category_name(enum i386_phase4_category category) {
    static const char *const names[] = {"invalid", "scalar", "memory",  "x87-mmx",
                                        "simd",    "system", "negative"};
    return category <= I386_PHASE4_NEGATIVE ? names[category] : names[0];
}
