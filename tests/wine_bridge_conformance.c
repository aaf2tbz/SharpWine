// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/wine_bridge.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define CODE_OFFSET UINT64_C(0x100)
#define HOST_RETURN UINT64_C(0xfffffffffffffff0)
#define UNIX_DISPATCH UINT64_C(0x600000000000)
#define TEST_TEB UINT64_C(0x700000010000)

#define MOV_X0_X13 UINT32_C(0xaa0d03e0)
#define SVC_0X123 UINT32_C(0xd4002461)
#define BR_X1 UINT32_C(0xd61f0020)
#define LDR_X2_X0 UINT32_C(0xf9400002)
#define RET UINT32_C(0xd65f03c0)
#define B_SELF UINT32_C(0x14000000)

struct callback_state {
    uint32_t syscall_count;
    uint32_t unix_count;
    int corrupt_x18;
    int corrupt_reserved;
    int corrupt_version;
    int no_progress;
    int terminate;
    int exit_thread;
    atomic_int block_enabled;
    atomic_int callback_entered;
    atomic_int callback_release;
};

struct runner_state {
    struct gem_wine_thread *thread;
    struct gem_thread_context input;
    struct gem_thread_context output;
    struct gem_wine_run_result result;
    enum gem_wine_status status;
};

struct churn_state {
    struct gem_wine_process *process;
    size_t host_page;
    atomic_int failed;
};

static void store_word(uint8_t *memory, size_t offset, uint32_t word) {
    memory[offset] = (uint8_t)word;
    memory[offset + 1U] = (uint8_t)(word >> 8U);
    memory[offset + 2U] = (uint8_t)(word >> 16U);
    memory[offset + 3U] = (uint8_t)(word >> 24U);
}

static enum gem_wine_status boundary_callback(void *opaque,
                                              const struct gem_wine_boundary_request *request,
                                              struct gem_wine_boundary_response *response) {
    struct callback_state *state = (struct callback_state *)opaque;
    assert(request->version == GEM_WINE_BOUNDARY_ABI_VERSION);
    assert(request->struct_size == sizeof(*request));
    assert(request->context.x[18] == TEST_TEB);
    response->action = GEM_WINE_BOUNDARY_RESUME;
    response->context = request->context;
    response->context.stop_reason = GEM_STOP_NONE;

    if (atomic_load(&state->block_enabled) != 0) {
        atomic_store(&state->callback_entered, 1);
        while (atomic_load(&state->callback_release) == 0)
            (void)sched_yield();
    }
    if (state->exit_thread)
        pthread_exit(NULL);

    if (request->event == GEM_WINE_EVENT_SYSCALL) {
        assert(request->stop.engine_status == UINT32_C(0x123));
        assert(request->stop.reason == GEM_STOP_SYSCALL);
        assert(request->stop.access == GEM_WINE_ACCESS_NONE);
        assert(request->stop.reserved == 0U);
        assert(request->context.x[0] == UINT64_C(0x123456789abcdef0));
        ++state->syscall_count;
        response->context.x[0] = UINT64_C(0x42);
        response->context.pc += 4U;
    } else if (request->event == GEM_WINE_EVENT_UNIX_CALL) {
        assert(request->context.pc == UNIX_DISPATCH);
        ++state->unix_count;
        response->context.x[0] = UINT64_C(0x99);
        response->context.pc = response->context.x[30];
    } else {
        response->action = GEM_WINE_BOUNDARY_FAIL;
    }
    if (state->no_progress)
        response->context.pc = request->context.pc;
    if (state->terminate) {
        response->action = GEM_WINE_BOUNDARY_TERMINATE;
        response->exit_status = UINT32_C(0x77);
    }
    if (state->corrupt_x18)
        response->context.x[18] ^= 1U;
    if (state->corrupt_reserved)
        response->context.reserved0 = 1U;
    if (state->corrupt_version)
        ++response->version;
    return GEM_WINE_OK;
}

static void *run_thread(void *opaque) {
    struct runner_state *runner = (struct runner_state *)opaque;
    runner->status =
        gem_wine_thread_run(runner->thread, &runner->input, &runner->output, &runner->result);
    return NULL;
}

static void *churn_mappings(void *opaque) {
    struct churn_state *state = (struct churn_state *)opaque;
    unsigned int iteration;
    for (iteration = 0U; iteration < 32U; ++iteration) {
        uint8_t *host = mmap(NULL, state->host_page, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uint32_t old = 0U;
        if (host == MAP_FAILED ||
            gem_wine_process_reserve(state->process, (uint64_t)(uintptr_t)host, state->host_page) !=
                GEM_WINE_OK ||
            gem_wine_process_reserve(state->process, (uint64_t)(uintptr_t)host, state->host_page) !=
                GEM_WINE_CONFLICT ||
            gem_wine_process_commit_identity(
                state->process, (uint64_t)(uintptr_t)host, host + GEM_WINE_GUEST_PAGE_SIZE,
                state->host_page, GEM_WINE_PAGE_READWRITE) != GEM_WINE_INVALID_ARGUMENT ||
            gem_wine_process_commit_identity(state->process, (uint64_t)(uintptr_t)host, host,
                                             state->host_page,
                                             GEM_WINE_PAGE_READWRITE) != GEM_WINE_OK ||
            gem_wine_process_protect(state->process, (uint64_t)(uintptr_t)host, state->host_page,
                                     GEM_WINE_PAGE_WRITECOPY | GEM_WINE_PAGE_GUARD,
                                     &old) != GEM_WINE_OK ||
            old != GEM_WINE_PAGE_READWRITE ||
            gem_wine_process_decommit(state->process, (uint64_t)(uintptr_t)host,
                                      state->host_page) != GEM_WINE_OK ||
            gem_wine_process_commit_identity(state->process, (uint64_t)(uintptr_t)host, host,
                                             state->host_page,
                                             GEM_WINE_PAGE_EXECUTE_READWRITE) != GEM_WINE_OK ||
            gem_wine_process_invalidate_code(state->process, (uint64_t)(uintptr_t)host,
                                             state->host_page) != GEM_WINE_OK ||
            gem_wine_process_release(state->process, (uint64_t)(uintptr_t)host, state->host_page) !=
                GEM_WINE_OK ||
            munmap(host, state->host_page) != 0) {
            atomic_store(&state->failed, 1);
            return NULL;
        }
    }
    return NULL;
}

static void initialize_context(struct gem_thread_context *context, uint64_t pc) {
    memset(context, 0, sizeof(*context));
    context->layout_version = GEM_CONTEXT_LAYOUT_VERSION;
    context->context_size = GEM_THREAD_CONTEXT_EXPECTED_SIZE;
    context->teb = TEST_TEB;
    context->x[18] = TEST_TEB;
    context->isa = GEM_ISA_ARM64EC;
    context->pc = pc;
    context->x[30] = HOST_RETURN;
}

int main(void) {
    const long host_page_long = sysconf(_SC_PAGESIZE);
    const size_t host_page = (size_t)host_page_long;
    uint8_t *mapping;
    uint8_t *kuser = NULL;
    uint64_t code;
    uint32_t old_protection;
    uint32_t wait_count;
    struct gem_wine_process_config process_config;
    struct gem_wine_process_config invalid_process_config;
    struct gem_wine_thread_config thread_config;
    struct gem_wine_thread_config invalid_thread_config;
    struct gem_wine_process *process = NULL;
    struct gem_wine_thread *thread = NULL;
    struct callback_state callback = {0};
    struct runner_state runner;
    pthread_t runner_thread;
    pthread_t churn_threads[4];
    struct churn_state churn;
    unsigned int churn_index;
    struct gem_thread_context input;
    struct gem_thread_context output;
    struct gem_thread_context unchanged_output;
    struct gem_wine_run_result result;
    struct gem_wine_run_result unchanged_result;
    struct gem_u128 upper_simd[16];
    struct gem_u128 upper_simd_output[16];

    atomic_init(&callback.block_enabled, 0);
    atomic_init(&callback.callback_entered, 0);
    atomic_init(&callback.callback_release, 0);
    assert(gem_wine_bridge_abi_version() == GEM_WINE_BRIDGE_ABI_VERSION);
    assert(host_page_long > 0);
    mapping = mmap(NULL, host_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    assert((uint64_t)(uintptr_t)mapping >= UINT64_C(0x100000000));
    code = (uint64_t)(uintptr_t)mapping + CODE_OFFSET;

    memset(&process_config, 0, sizeof(process_config));
    process_config.version = GEM_WINE_PROCESS_CONFIG_VERSION;
    process_config.struct_size = (uint32_t)sizeof(process_config);
    process_config.segment_instruction_budget = 64U;
    process_config.total_instruction_budget = 256U;
    process_config.max_boundary_callbacks = 8U;
    process_config.host_return_sentinel = HOST_RETURN;
    process_config.unix_call_dispatcher = UNIX_DISPATCH;
    invalid_process_config = process_config;
    invalid_process_config.reserved[0] = 1U;
    assert(gem_wine_process_create(&invalid_process_config, &process) == GEM_WINE_INVALID_ARGUMENT);
    assert(process == NULL);
    invalid_process_config = process_config;
    invalid_process_config.struct_size -= 1U;
    assert(gem_wine_process_create(&invalid_process_config, &process) == GEM_WINE_INVALID_ARGUMENT);
    assert(process == NULL);
    invalid_process_config = process_config;
    invalid_process_config.unix_call_dispatcher = HOST_RETURN;
    assert(gem_wine_process_create(&invalid_process_config, &process) == GEM_WINE_INVALID_ARGUMENT);
    assert(process == NULL);
    assert(gem_wine_process_create(&process_config, &process) == GEM_WINE_OK);
    assert(process != NULL);
    assert(gem_wine_process_prepare_arm64ec(NULL) == GEM_WINE_INVALID_ARGUMENT);
    assert(gem_wine_process_prepare_arm64ec(process) == GEM_WINE_OK);
    assert(gem_wine_process_prepare_arm64ec(process) == GEM_WINE_OK);
    churn.process = process;
    churn.host_page = host_page;
    atomic_init(&churn.failed, 0);
    for (churn_index = 0U; churn_index < 4U; ++churn_index)
        assert(pthread_create(&churn_threads[churn_index], NULL, churn_mappings, &churn) == 0);
    for (churn_index = 0U; churn_index < 4U; ++churn_index)
        assert(pthread_join(churn_threads[churn_index], NULL) == 0);
    assert(atomic_load(&churn.failed) == 0);
    assert(gem_wine_process_reserve(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page) ==
           GEM_WINE_OK);
    assert(gem_wine_process_reserve(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page) ==
           GEM_WINE_CONFLICT);
    assert(gem_wine_process_commit_identity(process, (uint64_t)(uintptr_t)mapping, mapping,
                                            (uint64_t)host_page,
                                            GEM_WINE_PAGE_EXECUTE_READ) == GEM_WINE_OK);
    old_protection = 0U;
    assert(gem_wine_process_protect(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page,
                                    GEM_WINE_PAGE_READONLY, &old_protection) == GEM_WINE_OK);
    assert(old_protection == GEM_WINE_PAGE_EXECUTE_READ);
    assert(gem_wine_process_protect(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page,
                                    GEM_WINE_PAGE_EXECUTE_READ, &old_protection) == GEM_WINE_OK);
    assert(old_protection == GEM_WINE_PAGE_READONLY);
    assert(gem_wine_process_decommit(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page) ==
           GEM_WINE_OK);
    assert(gem_wine_process_protect(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page,
                                    GEM_WINE_PAGE_EXECUTE_READ,
                                    &old_protection) == GEM_WINE_MEMORY_ERROR);
    assert(gem_wine_process_commit_identity(process, (uint64_t)(uintptr_t)mapping, mapping,
                                            (uint64_t)host_page,
                                            GEM_WINE_PAGE_EXECUTE_READ) == GEM_WINE_OK);

    assert(posix_memalign((void **)&kuser, GEM_WINE_GUEST_PAGE_SIZE, GEM_WINE_GUEST_PAGE_SIZE) ==
           0);
    memset(kuser, 0, GEM_WINE_GUEST_PAGE_SIZE);
    assert(gem_wine_process_bind_kuser(process, kuser) == GEM_WINE_OK);
    *(uint64_t *)kuser = UINT64_C(0x1122334455667788);

    memset(&thread_config, 0, sizeof(thread_config));
    thread_config.version = GEM_WINE_THREAD_CONFIG_VERSION;
    thread_config.struct_size = (uint32_t)sizeof(thread_config);
    thread_config.teb = TEST_TEB;
    thread_config.boundary = boundary_callback;
    thread_config.opaque = &callback;
    invalid_thread_config = thread_config;
    invalid_thread_config.reserved[0] = 1U;
    assert(gem_wine_thread_create(process, &invalid_thread_config, &thread) ==
           GEM_WINE_INVALID_ARGUMENT);
    assert(thread == NULL);
    assert(gem_wine_thread_create(process, &thread_config, &thread) == GEM_WINE_OK);
    assert(thread != NULL);
    assert(gem_wine_process_prepare_arm64ec(process) == GEM_WINE_OK);
    for (churn_index = 0U; churn_index < 16U; ++churn_index) {
        upper_simd[churn_index].lo = UINT64_C(0x1111000000000000) + churn_index;
        upper_simd[churn_index].hi = UINT64_C(0xeeee000000000000) + churn_index;
    }
    assert(gem_wine_thread_set_native_upper_simd(thread, upper_simd) == GEM_WINE_OK);
    memset(upper_simd_output, 0, sizeof(upper_simd_output));
    assert(gem_wine_thread_get_native_upper_simd(thread, upper_simd_output) == GEM_WINE_OK);
    assert(memcmp(upper_simd, upper_simd_output, sizeof(upper_simd)) == 0);
    assert(gem_wine_process_destroy(process) == GEM_WINE_CONFLICT);

    initialize_context(&input, code);
    input.reserved0 = 1U;
    memset(&output, 0xa5, sizeof(output));
    memset(&result, 0x5a, sizeof(result));
    unchanged_output = output;
    unchanged_result = result;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_INVALID_ARGUMENT);
    assert(memcmp(&output, &unchanged_output, sizeof(output)) == 0);
    assert(memcmp(&result, &unchanged_result, sizeof(result)) == 0);

    store_word(mapping, CODE_OFFSET, MOV_X0_X13);
    store_word(mapping, CODE_OFFSET + 4U, SVC_0X123);
    store_word(mapping, CODE_OFFSET + 8U, BR_X1);
    initialize_context(&input, code);
    input.x[1] = UNIX_DISPATCH;
    input.x[13] = UINT64_C(0x123456789abcdef0);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(result.outcome == GEM_WINE_RUN_COMPLETE);
    assert(result.boundary_callbacks == 2U);
    assert(callback.syscall_count == 1U && callback.unix_count == 1U);
    assert(output.pc == HOST_RETURN && output.x[0] == UINT64_C(0x99));
    assert(output.x[18] == TEST_TEB);
    assert(gem_wine_thread_get_native_upper_simd(thread, upper_simd_output) == GEM_WINE_OK);
    assert(memcmp(upper_simd, upper_simd_output, sizeof(upper_simd)) == 0);

    store_word(mapping, CODE_OFFSET, LDR_X2_X0);
    store_word(mapping, CODE_OFFSET + 4U, RET);
    assert(gem_wine_process_invalidate_code(process, code, 8U) == GEM_WINE_OK);
    initialize_context(&input, code);
    input.x[0] = GEM_WINE_KUSER_SHARED_DATA_ADDRESS;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(output.x[2] == UINT64_C(0x1122334455667788));

    store_word(mapping, CODE_OFFSET, SVC_0X123);
    assert(gem_wine_process_invalidate_code(process, code, 4U) == GEM_WINE_OK);
    initialize_context(&input, code);
    input.x[0] = UINT64_C(0x123456789abcdef0);
    callback.corrupt_x18 = 1;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_CALLBACK_ERROR);
    assert(result.outcome == GEM_WINE_RUN_FAILED);
    assert(output.x[18] == TEST_TEB);
    callback.corrupt_x18 = 0;

    callback.corrupt_reserved = 1;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_CALLBACK_ERROR);
    assert(result.outcome == GEM_WINE_RUN_FAILED);
    assert(output.reserved0 == 0U);
    callback.corrupt_reserved = 0;

    callback.corrupt_version = 1;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_CALLBACK_ERROR);
    assert(result.outcome == GEM_WINE_RUN_FAILED);
    callback.corrupt_version = 0;

    callback.no_progress = 1;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_CALLBACK_ERROR);
    assert(result.outcome == GEM_WINE_RUN_FAILED);
    callback.no_progress = 0;

    callback.terminate = 1;
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_TERMINATED);
    assert(result.outcome == GEM_WINE_RUN_TERMINATED);
    assert(result.exit_status == UINT32_C(0x77));
    assert(output.pc == code);
    callback.terminate = 0;

    store_word(mapping, CODE_OFFSET, B_SELF);
    assert(gem_wine_process_invalidate_code(process, code, 4U) == GEM_WINE_OK);
    initialize_context(&input, code);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_BUDGET_EXPIRED);
    assert(result.outcome == GEM_WINE_RUN_BUDGET_EXPIRED);
    assert(result.instructions_retired == process_config.total_instruction_budget);
    assert(result.stop.reason == GEM_STOP_BUDGET_EXPIRED);

    store_word(mapping, CODE_OFFSET, SVC_0X123);
    store_word(mapping, CODE_OFFSET + 4U, RET);
    assert(gem_wine_process_invalidate_code(process, code, 8U) == GEM_WINE_OK);
    memset(&runner, 0, sizeof(runner));
    runner.thread = thread;
    initialize_context(&runner.input, code);
    runner.input.x[0] = UINT64_C(0x123456789abcdef0);
    atomic_store(&callback.callback_entered, 0);
    atomic_store(&callback.callback_release, 0);
    atomic_store(&callback.block_enabled, 1);
    assert(pthread_create(&runner_thread, NULL, run_thread, &runner) == 0);
    for (wait_count = 0U;
         wait_count < UINT32_C(1000000) && atomic_load(&callback.callback_entered) == 0;
         ++wait_count)
        (void)sched_yield();
    assert(atomic_load(&callback.callback_entered) != 0);
    assert(gem_wine_thread_run(thread, &runner.input, &output, &result) == GEM_WINE_CONFLICT);
    assert(gem_wine_thread_destroy(thread) == GEM_WINE_CONFLICT);
    assert(gem_wine_process_destroy(process) == GEM_WINE_CONFLICT);
    atomic_store(&callback.callback_release, 1);
    assert(pthread_join(runner_thread, NULL) == 0);
    atomic_store(&callback.block_enabled, 0);
    assert(runner.status == GEM_WINE_OK);
    assert(runner.result.outcome == GEM_WINE_RUN_COMPLETE);
    assert(runner.output.pc == HOST_RETURN);

    memset(&runner, 0, sizeof(runner));
    runner.thread = thread;
    initialize_context(&runner.input, code);
    callback.exit_thread = 1;
    assert(pthread_create(&runner_thread, NULL, run_thread, &runner) == 0);
    assert(pthread_join(runner_thread, NULL) == 0);
    callback.exit_thread = 0;
    /* pthread_exit() from a Wine boundary must release the bridge run lock so
     * a joined guest thread can be destroyed without leaking its runtime. */
    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    thread = NULL;
    thread_config.boundary = NULL;
    thread_config.opaque = NULL;
    assert(gem_wine_thread_create(process, &thread_config, &thread) == GEM_WINE_OK);
    store_word(mapping, CODE_OFFSET, SVC_0X123);
    assert(gem_wine_process_invalidate_code(process, code, 4U) == GEM_WINE_OK);
    initialize_context(&input, code);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_STOPPED);
    assert(result.outcome == GEM_WINE_RUN_UNHANDLED_STOP);
    assert(result.last_event == GEM_WINE_EVENT_SYSCALL);
    assert(result.boundary_callbacks == 0U);
    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    assert(gem_wine_process_release(process, (uint64_t)(uintptr_t)mapping, (uint64_t)host_page) ==
           GEM_WINE_OK);
    assert(gem_wine_process_destroy(process) == GEM_WINE_OK);
    free(kuser);
    assert(munmap(mapping, host_page) == 0);
    assert(strcmp(gem_wine_status_name(GEM_WINE_OK), "ok") == 0);
    return 0;
}
