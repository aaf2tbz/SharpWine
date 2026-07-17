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
};
static const struct template_entry memory_templates[] = {
    {{0x8b, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x89, 0x07}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0x03, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0x87, 0x06}, 2, 0, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xf0, 0x0f, 0xc1, 0x06}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
    {{0xf0, 0x0f, 0xb1, 0x1e}, 4, 0, I386_PHASE4_COMPARE_EXACT, 0x8d5},
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
    {{0xc5, 0xf8, 0x77}, 3, 1, I386_PHASE4_COMPARE_EXACT, 0},
    {{0xc4, 0xe2, 0x71, 0x98, 0xc1}, 5, 1, I386_PHASE4_COMPARE_EXACT, 0},
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

static const struct template_entry *select_template(enum i386_phase4_category category,
                                                    uint64_t random, uint32_t *count) {
    const struct template_entry *entries = NULL;
    switch (category) {
    case I386_PHASE4_SCALAR:
        entries = scalar_templates;
        *count = (uint32_t)(sizeof(scalar_templates) / sizeof(scalar_templates[0]));
        break;
    case I386_PHASE4_MEMORY:
        entries = memory_templates;
        *count = (uint32_t)(sizeof(memory_templates) / sizeof(memory_templates[0]));
        break;
    case I386_PHASE4_X87_MMX:
        entries = x87_mmx_templates;
        *count = (uint32_t)(sizeof(x87_mmx_templates) / sizeof(x87_mmx_templates[0]));
        break;
    case I386_PHASE4_SIMD:
        entries = simd_templates;
        *count = (uint32_t)(sizeof(simd_templates) / sizeof(simd_templates[0]));
        break;
    case I386_PHASE4_SYSTEM:
        entries = system_templates;
        *count = (uint32_t)(sizeof(system_templates) / sizeof(system_templates[0]));
        break;
    case I386_PHASE4_NEGATIVE:
        entries = negative_templates;
        *count = (uint32_t)(sizeof(negative_templates) / sizeof(negative_templates[0]));
        break;
    }
    return entries ? &entries[random % *count] : NULL;
}

int i386_phase4_generate(uint32_t shard, uint32_t ordinal, struct i386_phase4_case *out) {
    const struct template_entry *entry;
    enum i386_phase4_category category;
    uint64_t state;
    uint32_t count = 0;
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
    entry = select_template(category, next_random(&state), &count);
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
