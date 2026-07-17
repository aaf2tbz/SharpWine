// SPDX-License-Identifier: Apache-2.0
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct matrix_input {
    u32 eax, ebx, ecx, edx, esi, edi, eflags;
    u32 xmm0[4];
};
struct matrix_record {
    u32 case_id, eax, ebx, ecx, edx, esi, edi, eflags;
    u32 memory[8], xmm0[4];
};
struct fault_case {
    const char *name;
    const u8 *code;
    u32 code_size;
    u32 eax, ebx, ecx, edx;
    u32 memory_offset;
};

#include "i386_phase2_fault_cases.h"

#define STD_OUTPUT_HANDLE ((u32) - 11)
#define MEM_COMMIT_RESERVE 0x3000U
#define PAGE_EXECUTE_READWRITE 0x40U
#define PAGE_NOACCESS 0x01U

typedef struct exception_record {
    u32 code, flags;
    struct exception_record *record;
    void *address;
    u32 parameter_count;
    u32 information[15];
} exception_record;
typedef struct floating_save_area {
    u32 control, status, tag, error_offset, error_selector, data_offset, data_selector;
    u8 register_area[80];
    u32 cr0_npx_state;
} floating_save_area;
typedef struct i386_context {
    u32 flags, dr0, dr1, dr2, dr3, dr6, dr7;
    floating_save_area float_save;
    u32 seg_gs, seg_fs, seg_es, seg_ds;
    u32 edi, esi, ebx, edx, ecx, eax;
    u32 ebp, eip, seg_cs, eflags, esp, seg_ss;
    u8 extended[512];
} i386_context;
typedef struct exception_pointers {
    exception_record *record;
    i386_context *context;
} exception_pointers;

__declspec(dllimport) void *__stdcall GetStdHandle(u32 which);
__declspec(dllimport) int __stdcall WriteFile(void *file, const void *data, u32 size, u32 *written,
                                              void *overlapped);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);
__declspec(dllimport) void *__stdcall VirtualAlloc(void *address, u32 size, u32 allocation,
                                                   u32 protection);
__declspec(dllimport) int __stdcall VirtualProtect(void *address, u32 size, u32 protection,
                                                   u32 *old_protection);
__declspec(dllimport) void *__stdcall SetUnhandledExceptionFilter(void *filter);
__declspec(dllimport) void __stdcall ExitProcess(u32 status);

void run_raw_i386_case(const u8 *code, const struct matrix_input *input,
                       struct matrix_record *record);

static char output[4096];
static u32 output_size;
static const struct fault_case *current;
static u8 *code_page;
static u8 *data_pages;
static u32 before_hash;

static void append_char(char value) {
    if (output_size < sizeof(output))
        output[output_size++] = value;
}
static void append_text(const char *text) {
    while (*text)
        append_char(*text++);
}
static void append_hex(u32 value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    append_text("0x");
    for (shift = 28; shift >= 0; shift -= 4)
        append_char(digits[(value >> shift) & 15U]);
}
static void field(const char *name, u32 value, int last) {
    append_char('"');
    append_text(name);
    append_text("\":\"");
    append_hex(value);
    append_char('"');
    append_char(last ? '}' : ',');
}
static u32 hash_page(const u8 *bytes) {
    u32 hash = 2166136261U, index;
    for (index = 0; index < 4096U; ++index)
        hash = (hash ^ bytes[index]) * 16777619U;
    return hash;
}
static void flush_and_exit(u32 status) {
    u32 written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_size, &written, (void *)0);
    ExitProcess(status);
}
static int __stdcall fault_filter(exception_pointers *pointers) {
    const exception_record *record = pointers->record;
    const i386_context *context = pointers->context;
    const u32 access_type = record->parameter_count > 0U ? record->information[0] : 0U;
    const u32 fault_address = record->parameter_count > 1U ? record->information[1] : 0U;
    const u32 initial_esi =
        current->memory_offset ? (u32)(data_pages + 4096U - current->memory_offset) : 0U;
    u32 index;
    append_text("{\"schemaVersion\":3,\"name\":\"");
    append_text(current->name);
    append_text("\",\"encoding\":\"");
    for (index = 0; index < current->code_size; ++index) {
        static const char digits[] = "0123456789abcdef";
        append_char(digits[current->code[index] >> 4]);
        append_char(digits[current->code[index] & 15U]);
    }
    append_text("\",");
    field("exceptionCode", record->code, 0);
    field("exceptionAddress", (u32)record->address, 0);
    field("parameterCount", record->parameter_count, 0);
    field("information0", access_type, 0);
    field("information1", fault_address, 0);
    field("accessType", access_type, 0);
    field("faultAddress", fault_address, 0);
    field("gemMemoryError", record->code == 0xc0000005U ? 7U : 0U, 0);
    field("retiredCount", 0U, 0);
    field("initialEip", (u32)code_page, 0);
    field("initialEax", current->eax, 0);
    field("initialEbx", current->ebx, 0);
    field("initialEcx", current->ecx, 0);
    field("initialEdx", current->edx, 0);
    field("initialEsi", initial_esi, 0);
    field("initialEdi", 0U, 0);
    field("initialEbp", context->ebp, 0);
    field("initialEsp", context->esp, 0);
    field("initialEflags", 0x202U, 0);
    field("finalEip", context->eip, 0);
    field("finalEax", context->eax, 0);
    field("finalEbx", context->ebx, 0);
    field("finalEcx", context->ecx, 0);
    field("finalEdx", context->edx, 0);
    field("finalEsi", context->esi, 0);
    field("finalEdi", context->edi, 0);
    field("finalEbp", context->ebp, 0);
    field("finalEsp", context->esp, 0);
    field("finalEflags", context->eflags, 0);
    field("beforeMemoryHash", before_hash, 0);
    field("afterMemoryHash", hash_page(data_pages), 1);
    append_char('\n');
    flush_and_exit(0U);
    return 1;
}
static u32 parse_index(const char *line) {
    const char *last = line;
    u32 value = 0;
    while (*line) {
        if (*line == ' ')
            last = line + 1;
        ++line;
    }
    while (*last >= '0' && *last <= '9')
        value = value * 10U + (u32)(*last++ - '0');
    return value;
}
void start(void) {
    const u32 index = parse_index(GetCommandLineA());
    struct matrix_input input = {0};
    struct matrix_record ignored = {0};
    u32 old_protection = 0, offset;
    if (index >= PHASE2_FAULT_CASE_COUNT)
        ExitProcess(4U);
    current = &phase2_fault_cases[index];
    code_page = VirtualAlloc((void *)0, 4096U, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
    data_pages = VirtualAlloc((void *)0, 8192U, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code_page || !data_pages)
        ExitProcess(5U);
    for (offset = 0; offset < 4096U; ++offset)
        data_pages[offset] = (u8)(offset * 29U + 7U);
    before_hash = hash_page(data_pages);
    if (!VirtualProtect(data_pages + 4096U, 4096U, PAGE_NOACCESS, &old_protection))
        ExitProcess(6U);
    for (offset = 0; offset < current->code_size; ++offset)
        code_page[offset] = current->code[offset];
    code_page[current->code_size] = 0xc3U;
    input.eax = current->eax;
    input.ebx = current->ebx;
    input.ecx = current->ecx;
    input.edx = current->edx;
    input.esi = current->memory_offset ? (u32)(data_pages + 4096U - current->memory_offset) : 0U;
    input.eflags = 0x202U;
    SetUnhandledExceptionFilter((void *)fault_filter);
    run_raw_i386_case(code_page, &input, &ignored);
    append_text("{\"schemaVersion\":2,\"status\":\"missing-fault\"}\n");
    flush_and_exit(7U);
}
