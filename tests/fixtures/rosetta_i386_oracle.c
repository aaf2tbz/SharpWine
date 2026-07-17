// SPDX-License-Identifier: Apache-2.0
#include "rosetta_i386_oracle.h"

#define STD_OUTPUT_HANDLE ((oracle_u32) - 11)

__declspec(dllimport) void *__stdcall GetStdHandle(oracle_u32 which);
__declspec(dllimport) int __stdcall WriteFile(void *file, const void *data, oracle_u32 size,
                                              oracle_u32 *written, void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(oracle_u32 status);

static char output[8192];
static oracle_u32 output_size;

static void append_char(char value) {
    if (output_size < (oracle_u32)sizeof(output))
        output[output_size++] = value;
}

static void append_text(const char *text) {
    while (*text != '\0')
        append_char(*text++);
}

static void append_hex(oracle_u32 value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    append_text("0x");
    for (shift = 28; shift >= 0; shift -= 4)
        append_char(digits[(value >> (oracle_u32)shift) & 15U]);
}

static void append_field(const char *name, oracle_u32 value, int last) {
    append_char('"');
    append_text(name);
    append_text("\":\"");
    append_hex(value);
    append_char('"');
    append_char(last ? '}' : ',');
}

static void emit(const struct oracle_record *record) {
    append_text("{\"schemaVersion\":1,");
    append_field("case", record->case_id, 0);
    append_field("eax", record->eax, 0);
    append_field("ebx", record->ebx, 0);
    append_field("ecx", record->ecx, 0);
    append_field("edx", record->edx, 0);
    append_field("esi", record->esi, 0);
    append_field("edi", record->edi, 0);
    append_field("ebp", record->ebp, 0);
    append_field("espDelta", record->esp_delta, 0);
    append_field("eflags", record->eflags, 0);
    append_field("memory0", record->memory[0], 0);
    append_field("memory1", record->memory[1], 0);
    append_field("xmm0_0", record->xmm0[0], 0);
    append_field("xmm0_1", record->xmm0[1], 0);
    append_field("xmm0_2", record->xmm0[2], 0);
    append_field("xmm0_3", record->xmm0[3], 0);
    append_field("x87_0", record->x87[0], 0);
    append_field("x87_1", record->x87[1], 1);
    append_char('\n');
}

void start(void) {
    static struct oracle_record records[5];
    oracle_u32 written = 0;
    oracle_u32 i;
    run_add32(&records[0]);
    run_shift32(&records[1]);
    run_memory32(&records[2]);
    run_sse2(&records[3]);
    run_x87(&records[4]);
    for (i = 0; i < 5U; ++i)
        emit(&records[i]);
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_size, &written, (void *)0) ||
        written != output_size)
        ExitProcess(2U);
    ExitProcess(0U);
}
