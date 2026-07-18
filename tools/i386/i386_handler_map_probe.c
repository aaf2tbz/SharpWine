// SPDX-License-Identifier: Apache-2.0
/* Handler-map probe: execute one raw i386 instruction byte sequence through
 * the pinned Blink interpreter and print the decoder-owned handler identity of
 * every retired instruction as "handler <id> <name>" lines, followed by
 * "stop <reason>" and "retired <count>" summaries.  This is the engine-backed
 * oracle for tools/i386/map_handler_coverage.py; it is not installed and never
 * changes guest semantics. */
#include "i386_engine_trace.h"
#include "metalsharp/gem/i386_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CODE_ADDRESS UINT32_C(0x00400000)
#define DATA_ADDRESS UINT32_C(0x00500000)
#define STACK_ADDRESS UINT32_C(0x00600000)
#define MAX_CODE_BYTES 64U

static int hex_digit(char digit) {
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F')
        return digit - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *text, uint8_t *bytes, size_t capacity) {
    size_t count = 0U;
    while (*text != '\0') {
        int high;
        int low;
        while (*text == ' ' || *text == ',' || *text == '\n' || *text == '\t')
            ++text;
        if (*text == '\0')
            break;
        high = hex_digit(text[0]);
        low = text[1] != '\0' ? hex_digit(text[1]) : -1;
        if (high < 0 || low < 0 || count == capacity)
            return 0U;
        bytes[count++] = (uint8_t)((high << 4) | low);
        text += 2;
    }
    return count;
}

int main(int argc, char **argv) {
    struct gem_i386_runtime_config config;
    struct gem_i386_context context;
    struct gem_i386_stop_info stop;
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory;
    uint8_t code[MAX_CODE_BYTES];
    uint32_t address;
    uint32_t count = 0U;
    uint32_t overflowed = 0U;
    size_t code_size;
    uint32_t i;
    enum gem_stop_reason reason;
    if (argc != 2)
        return 2;
    /* The drain must never consume the buffer this probe reads back. */
    unsetenv(GEM_I386_HANDLER_TRACE_ENV_VAR);
    unsetenv(GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR);
    code_size = parse_hex(argv[1], code, sizeof(code));
    if (code_size == 0U)
        return 2;
    memory = gem_memory_create();
    if (memory == NULL)
        return 1;
    address = CODE_ADDRESS;
    if (gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) != GEM_MEMORY_OK ||
        gem_i386_memory_commit(memory, CODE_ADDRESS, GEM_GUEST_PAGE_SIZE,
                               GEM_PAGE_EXECUTE_READWRITE) != GEM_MEMORY_OK ||
        gem_i386_memory_write(memory, CODE_ADDRESS, code, code_size) != GEM_MEMORY_OK)
        return 1;
    address = DATA_ADDRESS;
    if (gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) != GEM_MEMORY_OK ||
        gem_i386_memory_commit(memory, DATA_ADDRESS, 2U * GEM_GUEST_PAGE_SIZE,
                               GEM_PAGE_READWRITE) != GEM_MEMORY_OK)
        return 1;
    address = STACK_ADDRESS;
    if (gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) != GEM_MEMORY_OK ||
        gem_i386_memory_commit(memory, STACK_ADDRESS, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) !=
            GEM_MEMORY_OK)
        return 1;
    memset(&config, 0, sizeof(config));
    config.engine_mode = GEM_I386_ENGINE_INTERPRETER;
    config.host_return_sentinel = CODE_ADDRESS + (uint32_t)code_size;
    config.max_budget = 64U;
    runtime = gem_i386_runtime_create(memory, &config);
    if (runtime == NULL)
        return 1;
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = CODE_ADDRESS;
    context.gpr[GEM_I386_ESP] = STACK_ADDRESS + UINT32_C(0xfe0);
    context.gpr[GEM_I386_ESI] = DATA_ADDRESS + 64U;
    context.gpr[GEM_I386_EDI] = DATA_ADDRESS + 320U;
    context.gpr[GEM_I386_ECX] = 1U;
    gem_i386_runtime_handler_trace_reset(runtime);
    reason = gem_i386_runtime_run(runtime, &context, 64U);
    if (!gem_i386_runtime_handler_trace_info(runtime, &count, &overflowed))
        return 1;
    for (i = 0U; i < count; ++i) {
        uint64_t rip = 0U;
        uint32_t handler_id = 0U;
        if (!gem_i386_runtime_handler_trace_read(runtime, i, &rip, &handler_id))
            return 1;
        printf("handler %u %s\n", handler_id, gem_i386_runtime_handler_name(handler_id));
    }
    memset(&stop, 0, sizeof(stop));
    if (!gem_i386_runtime_last_stop_info(runtime, &stop))
        return 1;
    printf("stop %u\n", (unsigned int)reason);
    printf("retired %u\n", stop.instructions_retired);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    return 0;
}
