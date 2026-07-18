// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"
#include "i386_engine_trace.h"
#include "metalsharp/gem/i386_memory.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACE_OUTPUT_PATH "gem_i386_handler_trace_test.out"

static const uint8_t test_code[] = {
    0x90U,                             /* nop */
    0xb8U, 0x78U, 0x56U, 0x34U, 0x12U, /* mov eax, 0x12345678 */
    0x83U, 0xc0U, 0x01U,               /* add eax, 1 */
};
static const uint32_t expected_ids[] = {
    BLINK_GEM_HANDLER_OP_NOP, BLINK_GEM_HANDLER_OP_MOV_ZVQP_IVQP, BLINK_GEM_HANDLER_OP_ALUI};
static const uint64_t expected_rip_offsets[] = {0U, 1U, 6U};

static struct gem_memory *create_memory(uint32_t *code_address, uint32_t *stack_address) {
    struct gem_memory *memory = gem_memory_create();
    *code_address = UINT32_C(0x00400000);
    *stack_address = UINT32_C(0x00100000);
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, code_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, *code_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, *code_address, test_code, sizeof(test_code)) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(memory, stack_address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, *stack_address, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    return memory;
}

static struct gem_i386_context initial_context(uint32_t code_address, uint32_t stack_address) {
    struct gem_i386_context context;
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = code_address;
    context.gpr[GEM_I386_ESP] = stack_address + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    return context;
}

static struct gem_i386_runtime *
create_runtime(struct gem_memory *memory, enum gem_i386_engine_mode mode, uint32_t code_address) {
    struct gem_i386_runtime_config config;
    struct gem_i386_runtime *runtime;
    memset(&config, 0, sizeof(config));
    config.engine_mode = mode;
    config.host_return_sentinel = code_address + (uint32_t)sizeof(test_code);
    config.max_budget = 3U;
    runtime = gem_i386_runtime_create(memory, &config);
    assert(runtime != NULL);
    return runtime;
}

static void run_sequence(struct gem_i386_runtime *runtime, uint32_t code_address,
                         uint32_t stack_address) {
    struct gem_i386_context context = initial_context(code_address, stack_address);
    assert(gem_i386_runtime_run(runtime, &context, 3U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == UINT32_C(0x12345679));
    assert(context.eip == code_address + (uint32_t)sizeof(test_code));
}

static void exercise_accessors(void) {
    struct gem_i386_runtime *runtime;
    struct gem_memory *memory;
    struct blink_gem_decode_attempt attempt;
    uint32_t code_address;
    uint32_t stack_address;
    uint32_t count = 0U;
    uint32_t overflowed = 0U;
    uint32_t id = 0U;
    uint64_t rip = 0U;
    size_t i;
    memory = create_memory(&code_address, &stack_address);
    runtime = create_runtime(memory, GEM_I386_ENGINE_INTERPRETER, code_address);
    gem_i386_runtime_handler_trace_reset(NULL);
    assert(!gem_i386_runtime_handler_trace_info(NULL, &count, &overflowed));
    assert(!gem_i386_runtime_handler_trace_read(NULL, 0, &rip, &id));

    gem_i386_runtime_handler_trace_reset(runtime);
    assert(gem_i386_runtime_handler_trace_info(runtime, &count, &overflowed));
    assert(count == 0U && overflowed == 0U);
    run_sequence(runtime, code_address, stack_address);
    assert(gem_i386_runtime_handler_trace_info(runtime, &count, &overflowed));
    if (count != 3U || overflowed != 0U)
        fprintf(stderr, "trace info: count=%u overflowed=%u\n", count, overflowed);
    assert(count == 3U && overflowed == 0U);
    for (i = 0U; i < 3U; ++i) {
        assert(gem_i386_runtime_handler_trace_read(runtime, i, &rip, &id));
        if (id != expected_ids[i])
            fprintf(stderr, "trace[%zu]: rip=%llx id=0x%x (%s)\n", i, (unsigned long long)rip, id,
                    gem_i386_runtime_handler_name(id));
        assert(rip == (uint64_t)code_address + expected_rip_offsets[i]);
        assert(id == expected_ids[i]);
    }
    assert(!gem_i386_runtime_handler_trace_read(runtime, 3U, &rip, &id));

    /* Determinism: the identical program yields an identical trace. */
    gem_i386_runtime_handler_trace_reset(runtime);
    run_sequence(runtime, code_address, stack_address);
    for (i = 0U; i < 3U; ++i) {
        assert(gem_i386_runtime_handler_trace_read(runtime, i, &rip, &id));
        assert(id == expected_ids[i]);
    }

    assert(strcmp(gem_i386_runtime_handler_name(BLINK_GEM_HANDLER_OP_NOP), "OpNop") == 0);
    assert(strcmp(gem_i386_runtime_handler_name(BLINK_GEM_HANDLER_DECODED_BASE + 0x050U),
                  "OpPushZvq") == 0);
    assert(strcmp(gem_i386_runtime_handler_name(0U), "OpUnknown") == 0);

    memset(&attempt, 0, sizeof(attempt));
    attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
    attempt.size = sizeof(attempt);
    assert(!gem_i386_runtime_decode_attempt_info(NULL, &attempt));
    assert(!gem_i386_runtime_decode_attempt_info(runtime, NULL));
    attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION + 1U;
    assert(!gem_i386_runtime_decode_attempt_info(runtime, &attempt));
    attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
    attempt.size = sizeof(attempt) - 1U;
    assert(!gem_i386_runtime_decode_attempt_info(runtime, &attempt));
    attempt.size = sizeof(attempt);
    assert(gem_i386_runtime_decode_attempt_info(runtime, &attempt));
    assert(attempt.valid != 0U);
    assert(attempt.handler_id == BLINK_GEM_HANDLER_OP_ALUI);
    assert(strcmp(attempt.name, "OpAluwiReg") == 0);
    assert(attempt.rip == (uint64_t)code_address + 6U);

    /* The drain is off while MSWR_I386_HANDLER_TRACE_PATH is unset, so
     * destroying the runtime must not create the output file. */
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    assert(fopen(TRACE_OUTPUT_PATH, "r") == NULL);
}

static char *read_output(void) {
    static char contents[16384];
    FILE *file = fopen(TRACE_OUTPUT_PATH, "r");
    size_t length;
    assert(file != NULL);
    length = fread(contents, 1U, sizeof(contents) - 1U, file);
    contents[length] = '\0';
    fclose(file);
    return contents;
}

static void exercise_drain(void) {
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_i386_context output;
    struct gem_memory *memory;
    const char *contents;
    uint32_t code_address;
    uint32_t stack_address;
    uint32_t retired = 0U;
    assert(setenv(GEM_I386_HANDLER_TRACE_ENV_VAR, TRACE_OUTPUT_PATH, 1) == 0);
    memory = create_memory(&code_address, &stack_address);
    runtime = create_runtime(memory, GEM_I386_ENGINE_JIT, code_address);
    context = initial_context(code_address, stack_address);

    /* Step nop and mov through the bound ops; each step drains one entry. */
    runtime->transaction = gem_memory_transaction_begin(memory);
    assert(runtime->transaction != NULL);
    runtime->ops->sync(runtime);
    assert(runtime->ops->step(runtime, &context, &output, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    assert(runtime->ops->step(runtime, &output, &context, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    gem_memory_transaction_end(runtime->transaction);
    runtime->transaction = NULL;

    /* Run the final add through the engine's batched run path. */
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    assert(context.gpr[GEM_I386_EAX] == UINT32_C(0x12345679));
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    contents = read_output();
    assert(strstr(contents, "total_drained 3\n") != NULL);
    assert(strstr(contents, "overflow_events 0\n") != NULL);
    assert(strstr(contents, "out_of_range 0\n") != NULL);
    assert(strstr(contents, "handler 1 OpNop 1\n") != NULL);
    assert(strstr(contents, "handler 2 OpMovZvqpIvqp 1\n") != NULL);
    assert(strstr(contents, "handler 6 OpAlui 1\n") != NULL);

    /* A second drain-enabled runtime rewrites the file deterministically with
     * the cumulative process-wide histogram. */
    memory = create_memory(&code_address, &stack_address);
    runtime = create_runtime(memory, GEM_I386_ENGINE_INTERPRETER, code_address);
    run_sequence(runtime, code_address, stack_address);
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);

    contents = read_output();
    assert(strstr(contents, "total_drained 6\n") != NULL);
    assert(strstr(contents, "overflow_events 0\n") != NULL);
    assert(strstr(contents, "handler 1 OpNop 2\n") != NULL);
    assert(strstr(contents, "handler 2 OpMovZvqpIvqp 2\n") != NULL);
    assert(strstr(contents, "handler 6 OpAlui 2\n") != NULL);
}

static void exercise_periodic_flush(void) {
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct gem_i386_context output;
    struct gem_memory *memory;
    const char *contents;
    uint32_t code_address;
    uint32_t stack_address;
    uint32_t retired = 0U;
    assert(setenv(GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR, "2", 1) == 0);
    memory = create_memory(&code_address, &stack_address);
    runtime = create_runtime(memory, GEM_I386_ENGINE_JIT, code_address);
    context = initial_context(code_address, stack_address);

    /* The first step pushes the process-wide flush counter past the tiny
     * threshold, so the cumulative histogram is rewritten mid-run, before any
     * destroy: a killed process would still leave this evidence behind. */
    runtime->transaction = gem_memory_transaction_begin(memory);
    assert(runtime->transaction != NULL);
    runtime->ops->sync(runtime);
    assert(runtime->ops->step(runtime, &context, &output, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    contents = read_output();
    assert(strstr(contents, "total_drained 7\n") != NULL);
    assert(strstr(contents, "handler 1 OpNop 3\n") != NULL);
    assert(strstr(contents, "handler 2 OpMovZvqpIvqp 2\n") != NULL);

    /* One more entry stays below the threshold: no flush, file unchanged. */
    assert(runtime->ops->step(runtime, &output, &context, &retired) == GEM_STOP_NONE);
    assert(retired == 1U);
    contents = read_output();
    assert(strstr(contents, "total_drained 7\n") != NULL);
    gem_memory_transaction_end(runtime->transaction);
    runtime->transaction = NULL;

    /* Crossing the threshold again flushes the full cumulative histogram,
     * still without any destroy. */
    assert(gem_i386_runtime_run(runtime, &context, 1U) == GEM_STOP_HOST_RETURN);
    contents = read_output();
    assert(strstr(contents, "total_drained 9\n") != NULL);
    assert(strstr(contents, "handler 1 OpNop 3\n") != NULL);
    assert(strstr(contents, "handler 2 OpMovZvqpIvqp 3\n") != NULL);
    assert(strstr(contents, "handler 6 OpAlui 3\n") != NULL);

    /* Destroy still rewrites the same final state. */
    gem_i386_runtime_destroy(runtime);
    gem_memory_destroy(memory);
    contents = read_output();
    assert(strstr(contents, "total_drained 9\n") != NULL);
    assert(unsetenv(GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR) == 0);
    assert(remove(TRACE_OUTPUT_PATH) == 0);
}

int main(void) {
    assert(unsetenv(GEM_I386_HANDLER_TRACE_ENV_VAR) == 0);
    assert(unsetenv(GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR) == 0);
    remove(TRACE_OUTPUT_PATH);
    exercise_accessors();
    exercise_drain();
    exercise_periodic_flush();
    return 0;
}
