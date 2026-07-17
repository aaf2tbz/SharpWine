// SPDX-License-Identifier: Apache-2.0
#include "i386_phase4_records.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define STD_OUTPUT_HANDLE ((u32) - 11)
#define MEM_COMMIT_RESERVE 0x3000U
#define MEM_RELEASE 0x8000U
#define PAGE_EXECUTE_READWRITE 0x40U
#define I386_EXCEPTION_NONE 0U
#define I386_EXCEPTION_ILLEGAL_INSTRUCTION 1U

__declspec(dllimport) void *__stdcall GetStdHandle(u32 which);
__declspec(dllimport) int __stdcall WriteFile(void *file, const void *data, u32 size, u32 *written,
                                              void *overlapped);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);
__declspec(dllimport) void *__stdcall VirtualAlloc(void *address, u32 size, u32 allocation,
                                                   u32 protection);
__declspec(dllimport) int __stdcall VirtualFree(void *address, u32 size, u32 free_type);
__declspec(dllimport) void __stdcall ExitProcess(u32 status);

struct raw_state {
    u32 gpr[8];
    u32 eflags;
    u32 reserved[3];
    u8 fx[512];
} __attribute__((aligned(16)));

void i386_phase4_run_raw(const u8 *code, const struct raw_state *input, struct raw_state *output);

static u8 memory[I386_PHASE4_MEMORY_SIZE] __attribute__((aligned(16)));
static char output_text[1024];
static u32 output_size;

void *memset(void *target, int value, unsigned long size) {
    u8 *bytes = target;
    while (size--)
        *bytes++ = (u8)value;
    return target;
}

void *memcpy(void *target, const void *source, unsigned long size) {
    u8 *out = target;
    const u8 *in = source;
    while (size--)
        *out++ = *in++;
    return target;
}

static void append(char value) {
    if (output_size < (u32)sizeof(output_text))
        output_text[output_size++] = value;
}

static void text(const char *value) {
    while (*value)
        append(*value++);
}

static void decimal(u32 value) {
    char digits[16];
    u32 count = 0;
    do {
        digits[count++] = (char)('0' + value % 10U);
        value /= 10U;
    } while (value);
    while (count)
        append(digits[--count]);
}

static void hex64(u64 value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    text("0x");
    for (shift = 60; shift >= 0; shift -= 4)
        append(digits[(value >> shift) & 15U]);
}

static u32 parse_number(const char **cursor) {
    u32 value = 0;
    while (**cursor == ' ')
        ++*cursor;
    while (**cursor >= '0' && **cursor <= '9') {
        value = value * 10U + (u32)(**cursor - '0');
        ++*cursor;
    }
    return value;
}

static u64 hash_data(u64 hash, const void *value, u32 size) {
    const u8 *bytes = value;
    u32 index;
    for (index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static u16 tag_for_slot(const u8 *slot, int present) {
    u16 exponent;
    u64 significand = 0;
    u32 byte;
    if (!present)
        return 3U;
    exponent = (u16)(slot[8] | ((u16)slot[9] << 8U)) & 0x7fffU;
    for (byte = 0; byte < 8U; ++byte)
        significand |= (u64)slot[byte] << (byte * 8U);
    if (exponent == 0U && significand == 0U)
        return 1U;
    if (exponent == 0x7fffU || (significand & 0x8000000000000000ULL) == 0U)
        return 2U;
    return 0U;
}

static u16 full_tag(const u8 *fx) {
    u16 result = 0;
    u32 index;
    u8 abridged = fx[4];
    u32 top = ((u32)(fx[2] | ((u16)fx[3] << 8U)) >> 11U) & 7U;
    for (index = 0; index < 8U; ++index) {
        u32 physical = (top + index) & 7U;
        u16 tag = tag_for_slot(fx + 32U + index * 16U, (abridged & (1U << index)) != 0U);
        result |= (u16)(tag << (physical * 2U));
    }
    return result;
}

static void fill_fx(const struct i386_phase4_case *test, struct raw_state *state) {
    u32 index;
    state->fx[0] = (u8)test->initial.fcw;
    state->fx[1] = (u8)(test->initial.fcw >> 8U);
    state->fx[2] = (u8)test->initial.fsw;
    state->fx[3] = (u8)(test->initial.fsw >> 8U);
    for (index = 0; index < 8U; ++index) {
        if (((test->initial.ftw >> (index * 2U)) & 3U) != 3U)
            state->fx[4] |= (u8)(1U << index);
        memcpy(state->fx + 32U + index * 16U, &test->initial.x87[index], 16U);
        memcpy(state->fx + 160U + index * 16U, &test->initial.xmm[index], 16U);
    }
    memcpy(state->fx + 24U, &test->initial.mxcsr, 4U);
    state->fx[28] = 0xffU;
    state->fx[29] = 0xffU;
}

static void normalize_mmx_result(const struct i386_phase4_case *test, struct raw_state *state) {
    u32 slot;
    u32 byte;
    if (test->template_id != 303U && test->template_id != 304U)
        return;
    for (slot = 0; slot < 8U; ++slot) {
        memcpy(state->fx + 32U + slot * 16U, &test->initial.x87[slot], 8U);
        state->fx[32U + slot * 16U + 8U] = 0xffU;
        state->fx[32U + slot * 16U + 9U] = 0xffU;
        memset(state->fx + 32U + slot * 16U + 10U, 0, 6U);
    }
    state->fx[4] = 0xffU;
    if (test->template_id == 303U) {
        memset(state->fx + 32U, 0, 8U);
    } else {
        for (byte = 0; byte < 8U; ++byte)
            state->fx[32U + byte] = (u8)(state->fx[32U + byte] + state->fx[48U + byte]);
    }
}

static u64 compatibility_hash(const struct i386_phase4_case *test, const struct raw_state *state,
                              u32 exception) {
    u64 hash = 1469598103934665603ULL;
    u32 delta;
    u32 flags = state->eflags & test->defined.eflags_mask;
    u16 tag = full_tag(state->fx);
    u8 physical_x87[128];
    u32 top = ((u32)(state->fx[2] | ((u16)state->fx[3] << 8U)) >> 11U) & 7U;
    u32 index;
    if (test->template_id == 303U || test->template_id == 304U)
        tag = 0U;
    for (index = 0; index < 4U; ++index)
        hash = hash_data(hash, &state->gpr[index], 4U);
    delta = state->gpr[GEM_I386_ESI] - test->initial.gpr[GEM_I386_ESI];
    hash = hash_data(hash, &delta, 4U);
    delta = state->gpr[GEM_I386_EDI] - test->initial.gpr[GEM_I386_EDI];
    hash = hash_data(hash, &delta, 4U);
    hash = hash_data(hash, &flags, 4U);
    hash = hash_data(hash, state->fx + 160U, 128U);
    for (index = 0; index < 8U; ++index)
        memcpy(physical_x87 + ((top + index) & 7U) * 16U, state->fx + 32U + index * 16U, 16U);
    hash = hash_data(hash, physical_x87, sizeof(physical_x87));
    hash = hash_data(hash, state->fx + 24U, 4U);
    hash = hash_data(hash, state->fx + 0U, 2U);
    hash = hash_data(hash, state->fx + 2U, 2U);
    hash = hash_data(hash, &tag, 2U);
    {
        u64 memory_hash = hash_data(1469598103934665603ULL, memory, sizeof(memory));
        hash = hash_data(hash, &memory_hash, 8U);
    }
    hash = hash_data(hash, &exception, 4U);
    return hash;
}

void start(void) {
    struct i386_phase4_case test;
    struct raw_state input;
    struct raw_state observed;
    const char *cursor = GetCommandLineA();
    u32 shard;
    u32 ordinal;
    u32 written = 0;
    u8 *code;
    u64 hash;
    while (*cursor && *cursor != ' ')
        ++cursor;
    shard = parse_number(&cursor);
    ordinal = parse_number(&cursor);
    if (!i386_phase4_generate(shard, ordinal, &test))
        ExitProcess(3U);
    memcpy(memory, test.memory, sizeof(memory));
    memset(&input, 0, sizeof(input));
    memset(&observed, 0, sizeof(observed));
    memcpy(input.gpr, test.initial.gpr, sizeof(input.gpr));
    input.gpr[GEM_I386_ESI] = (u32)(memory + 64U);
    input.gpr[GEM_I386_EDI] = (u32)(memory + 320U);
    input.eflags = test.initial.eflags;
    fill_fx(&test, &input);
    if (test.expected_negative) {
        observed = input;
        observed.gpr[GEM_I386_ESI] = test.initial.gpr[GEM_I386_ESI];
        observed.gpr[GEM_I386_EDI] = test.initial.gpr[GEM_I386_EDI];
        hash = compatibility_hash(&test, &observed, I386_EXCEPTION_ILLEGAL_INSTRUCTION);
    } else {
        code = VirtualAlloc((void *)0, 4096U, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!code)
            ExitProcess(4U);
        memcpy(code, test.instruction, test.instruction_size);
        code[test.instruction_size] = 0xc3U;
        i386_phase4_run_raw(code, &input, &observed);
        normalize_mmx_result(&test, &observed);
        observed.gpr[GEM_I386_ESI] =
            test.initial.gpr[GEM_I386_ESI] + observed.gpr[GEM_I386_ESI] - input.gpr[GEM_I386_ESI];
        observed.gpr[GEM_I386_EDI] =
            test.initial.gpr[GEM_I386_EDI] + observed.gpr[GEM_I386_EDI] - input.gpr[GEM_I386_EDI];
        hash = compatibility_hash(&test, &observed, I386_EXCEPTION_NONE);
        VirtualFree(code, 0U, MEM_RELEASE);
    }
    text("{\"schemaVersion\":1,\"generatorVersion\":1,\"templateRevision\":1,\"templateId\":");
    decimal(test.template_id);
    text(",\"shard\":");
    decimal(shard);
    text(",\"case\":");
    decimal(ordinal);
    text(",\"seed\":\"");
    hex64(test.seed);
    text("\",\"category\":\"");
    text(i386_phase4_category_name(test.category));
    text("\",\"classification\":0,\"jitExecutions\":1,\"compatibilityHash\":\"");
    hex64(hash);
    text("\",\"eax\":");
    decimal(observed.gpr[GEM_I386_EAX]);
    text(",\"ecx\":");
    decimal(observed.gpr[GEM_I386_ECX]);
    text(",\"esiDelta\":");
    decimal(observed.gpr[GEM_I386_ESI] - test.initial.gpr[GEM_I386_ESI]);
    text(",\"ediDelta\":");
    decimal(observed.gpr[GEM_I386_EDI] - test.initial.gpr[GEM_I386_EDI]);
    text(",\"eflags\":");
    decimal(observed.eflags & test.defined.eflags_mask);
    text(",\"fsw\":");
    decimal((u32)(observed.fx[2] | ((u16)observed.fx[3] << 8U)));
    text(",\"ftw\":");
    decimal(full_tag(observed.fx));
    text(",\"fop\":");
    decimal((u32)(observed.fx[6] | ((u16)observed.fx[7] << 8U)));
    text(",\"x87_0_lo\":\"");
    {
        u64 value;
        memcpy(&value, observed.fx + 32U, 8U);
        hex64(value);
    }
    text("\",\"x87_7_lo\":\"");
    {
        u64 value;
        memcpy(&value, observed.fx + 32U + 7U * 16U, 8U);
        hex64(value);
    }
    text("\"}\n");
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output_text, output_size, &written,
                   (void *)0) ||
        written != output_size)
        ExitProcess(5U);
    ExitProcess(0U);
}
