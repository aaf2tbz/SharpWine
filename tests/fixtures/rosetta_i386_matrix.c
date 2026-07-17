// SPDX-License-Identifier: Apache-2.0
typedef unsigned char u8;
typedef unsigned int u32;

struct matrix_input {
    u32 eax, ebx, ecx, edx, esi, edi, eflags;
    u32 xmm0[4];
};

struct matrix_record {
    u32 case_id;
    u32 eax, ebx, ecx, edx, esi, edi, eflags;
    u32 memory[8];
    u32 xmm0[4];
};

struct matrix_case {
    const char *name;
    const u8 *code;
    u32 code_size;
    struct matrix_input input;
    u32 memory[8];
    u32 use_memory_esi;
};

#include "rosetta_i386_matrix_cases.h"

#define STD_OUTPUT_HANDLE ((u32) - 11)
#define MEM_COMMIT_RESERVE 0x3000U
#define MEM_RELEASE 0x8000U
#define PAGE_EXECUTE_READWRITE 0x40U

__declspec(dllimport) void *__stdcall GetStdHandle(u32 which);
__declspec(dllimport) int __stdcall WriteFile(void *file, const void *data, u32 size, u32 *written,
                                              void *overlapped);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);
__declspec(dllimport) void *__stdcall VirtualAlloc(void *address, u32 size, u32 allocation,
                                                   u32 protection);
__declspec(dllimport) int __stdcall VirtualFree(void *address, u32 size, u32 free_type);
__declspec(dllimport) void __stdcall ExitProcess(u32 status);

void run_raw_i386_case(const u8 *code, const struct matrix_input *input,
                       struct matrix_record *record);

static char output[4096];
static u32 output_size;
static u32 memory[8] __attribute__((aligned(16)));

static void append_char(char value) {
    if (output_size < (u32)sizeof(output))
        output[output_size++] = value;
}

static void append_text(const char *text) {
    while (*text)
        append_char(*text++);
}

static void append_hex32(u32 value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    append_text("0x");
    for (shift = 28; shift >= 0; shift -= 4)
        append_char(digits[(value >> shift) & 15U]);
}

static void append_byte(u8 value) {
    static const char digits[] = "0123456789abcdef";
    append_char(digits[value >> 4]);
    append_char(digits[value & 15U]);
}

static void field(const char *name, u32 value, int last) {
    append_char('"');
    append_text(name);
    append_text("\":\"");
    append_hex32(value);
    append_char('"');
    append_char(last ? '}' : ',');
}

static u32 parse_index(const char *command_line) {
    const char *last = command_line;
    u32 value = 0;
    while (*command_line) {
        if (*command_line == ' ')
            last = command_line + 1;
        ++command_line;
    }
    while (*last >= '0' && *last <= '9')
        value = value * 10U + (u32)(*last++ - '0');
    return value;
}

static void copy_words(u32 *target, const u32 *source, u32 count) {
    u32 index;
    for (index = 0; index < count; ++index)
        target[index] = source[index];
}

static void emit(const struct matrix_case *test, const struct matrix_record *record) {
    u32 index;
    append_text("{\"schemaVersion\":1,\"name\":\"");
    append_text(test->name);
    append_text("\",\"encoding\":\"");
    for (index = 0; index < test->code_size; ++index)
        append_byte(test->code[index]);
    append_text("\",");
    field("case", record->case_id, 0);
    field("eax", record->eax, 0);
    field("ebx", record->ebx, 0);
    field("ecx", record->ecx, 0);
    field("edx", record->edx, 0);
    field("esiDelta", record->esi, 0);
    field("ediDelta", record->edi, 0);
    field("eflags", record->eflags, 0);
    for (index = 0; index < 8; ++index) {
        char name[] = "memory0";
        name[6] = (char)('0' + index);
        field(name, record->memory[index], 0);
    }
    for (index = 0; index < 4; ++index) {
        char name[] = "xmm0_0";
        name[5] = (char)('0' + index);
        field(name, record->xmm0[index], index == 3);
    }
    append_char('\n');
}

static void run_index(u32 index) {
    struct matrix_input input;
    struct matrix_record record = {0};
    u8 *code;
    u32 offset;
    u32 written = 0;
    input = matrix_cases[index].input;
    copy_words(memory, matrix_cases[index].memory, 8U);
    if (matrix_cases[index].use_memory_esi)
        input.esi = (u32)memory;
    code = (u8 *)VirtualAlloc((void *)0, 4096U, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code)
        ExitProcess(5U);
    for (offset = 0; offset < matrix_cases[index].code_size; ++offset)
        code[offset] = matrix_cases[index].code[offset];
    code[matrix_cases[index].code_size] = 0xc3U;
    record.case_id = index;
    run_raw_i386_case(code, &input, &record);
    record.esi -= input.esi;
    record.edi -= input.edi;
    copy_words(record.memory, memory, 8U);
    emit(&matrix_cases[index], &record);
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_size, &written, (void *)0) ||
        written != output_size)
        ExitProcess(6U);
    VirtualFree(code, 0U, MEM_RELEASE);
}

void start(void) {
    u32 index = parse_index(GetCommandLineA());
    u32 current;
    if (index > MATRIX_CASE_COUNT)
        ExitProcess(4U);
    if (index == MATRIX_CASE_COUNT) {
        for (current = 0; current < MATRIX_CASE_COUNT; ++current) {
            output_size = 0;
            run_index(current);
        }
    } else {
        run_index(index);
    }
    ExitProcess(0U);
}
