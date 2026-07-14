// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/wine_bridge.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define HOST_RETURN UINT64_C(0xfffffffffffffff0)
#define TEST_TEB UINT64_C(0x700000020000)

struct callback_state {
    uint64_t resume_pc;
    uint32_t expected_event;
    uint32_t expected_reason;
    uint32_t expected_engine_status;
    uint32_t expected_retired;
    uint32_t calls;
    uint32_t pop_return;
};

static void put16(uint8_t *bytes, size_t offset, uint16_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static void put32(uint8_t *bytes, size_t offset, uint32_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static void make_pe32_plus(uint8_t *image, size_t image_size) {
    const size_t pe = 0x80U;
    memset(image, 0, image_size);
    put16(image, 0, UINT16_C(0x5a4d));
    put32(image, 0x3c, (uint32_t)pe);
    put32(image, pe, UINT32_C(0x00004550));
    put16(image, pe + 4U, UINT16_C(0x8664));
    put16(image, pe + 6U, UINT16_C(1));
    put16(image, pe + 20U, UINT16_C(0x00f0));
    put16(image, pe + 24U, UINT16_C(0x020b));
    put32(image, pe + 24U + 56U, (uint32_t)image_size);
    put32(image, pe + 24U + 60U, UINT32_C(0x200));
}

static enum gem_wine_status boundary(void *opaque, const struct gem_wine_boundary_request *request,
                                     struct gem_wine_boundary_response *response) {
    struct callback_state *state = opaque;
    assert(request->context.isa == GEM_ISA_X64);
    assert(request->context.teb == TEST_TEB && request->context.x[18] == TEST_TEB);
    assert(request->event == state->expected_event);
    assert(request->stop.reason == state->expected_reason);
    assert(request->stop.engine_status == state->expected_engine_status);
    assert(request->stop.instructions_retired == state->expected_retired);
    ++state->calls;
    response->action = GEM_WINE_BOUNDARY_RESUME;
    response->context = request->context;
    if (state->pop_return) {
        memcpy(&response->context.pc, (const void *)(uintptr_t)response->context.sp,
               sizeof(response->context.pc));
        response->context.sp += sizeof(response->context.pc);
    } else {
        response->context.pc = state->resume_pc;
    }
    response->context.stop_reason = GEM_STOP_NONE;
    return GEM_WINE_OK;
}

static void initialize_context(struct gem_thread_context *context, uint64_t pc, uint64_t stack) {
    memset(context, 0, sizeof(*context));
    context->layout_version = GEM_CONTEXT_LAYOUT_VERSION;
    context->context_size = GEM_THREAD_CONTEXT_EXPECTED_SIZE;
    context->teb = TEST_TEB;
    context->x[18] = TEST_TEB;
    context->isa = GEM_ISA_X64;
    context->pc = pc;
    context->sp = stack;
    context->x64_rflags = UINT64_C(2);
    context->x64_mxcsr = UINT32_C(0x1f80);
    context->x64_fcw = UINT16_C(0x37f);
}

static void run_case(uint8_t *image, size_t image_size, uint64_t flags) {
    const uint64_t base = (uint64_t)(uintptr_t)image;
    const uint64_t code = base + UINT64_C(0x200);
    const uint64_t windows_boundary = base + UINT64_C(0x300);
    const uint64_t unix_boundary = base + UINT64_C(0x400);
    const uint64_t stack = base + UINT64_C(0x800);
    struct gem_wine_process_config process_config = {0};
    struct gem_wine_x86_64_config x64_config = {0};
    struct gem_wine_x86_64_config conflict_config;
    struct gem_wine_thread_config thread_config = {0};
    struct gem_wine_process *process = NULL;
    struct gem_wine_thread *thread = NULL;
    struct callback_state callback = {code + UINT64_C(7), 0, 0, 0, 0, 0, 0};
    struct gem_thread_context input, output;
    struct gem_wine_run_result result;

    memset(image, 0, image_size);

    process_config.version = GEM_WINE_PROCESS_CONFIG_VERSION;
    process_config.struct_size = sizeof(process_config);
    process_config.segment_instruction_budget = 8U;
    process_config.total_instruction_budget = 32U;
    process_config.max_boundary_callbacks = 4U;
    process_config.host_return_sentinel = HOST_RETURN;
    process_config.unix_call_dispatcher = UINT64_C(0x600000000000);
    assert(gem_wine_process_create(&process_config, &process) == GEM_WINE_OK);
    assert(gem_wine_process_reserve(process, base, image_size) == GEM_WINE_OK);
    assert(gem_wine_process_commit_identity(process, base, image, image_size,
                                            GEM_WINE_PAGE_EXECUTE_READWRITE) == GEM_WINE_OK);

    x64_config.version = GEM_WINE_X86_64_CONFIG_VERSION;
    x64_config.struct_size = sizeof(x64_config);
    x64_config.loaded_base = base;
    x64_config.image_size = image_size;
    x64_config.windows_syscall_boundary = windows_boundary;
    x64_config.unix_call_boundary = unix_boundary;
    x64_config.flags = flags;
    assert(gem_wine_process_prepare_x86_64(process, &x64_config) == GEM_WINE_INVALID_ARGUMENT);
    make_pe32_plus(image, image_size);
    memcpy(image + 0x200, "\xff\x14\x25\x00\x10\xfe\x7f\xc3", 8U); /* CALL *0x7ffe1000; RET */
    assert(gem_wine_process_prepare_x86_64(process, &x64_config) == GEM_WINE_OK);
    assert(gem_wine_process_prepare_x86_64(process, &x64_config) == GEM_WINE_OK);
    conflict_config = x64_config;
    conflict_config.unix_call_boundary += 1U;
    assert(gem_wine_process_prepare_x86_64(process, &conflict_config) == GEM_WINE_CONFLICT);
    assert(gem_wine_process_prepare_arm64ec(process) == GEM_WINE_CONFLICT);

    thread_config.version = GEM_WINE_THREAD_CONFIG_VERSION;
    thread_config.struct_size = sizeof(thread_config);
    thread_config.teb = TEST_TEB;
    thread_config.boundary = boundary;
    thread_config.opaque = &callback;
    assert(gem_wine_thread_create(process, &thread_config, &thread) == GEM_WINE_OK);

    memcpy(image + 0x800, &(uint64_t){HOST_RETURN}, sizeof(uint64_t));
    callback.expected_event = GEM_WINE_EVENT_SYSCALL;
    callback.expected_reason = GEM_STOP_SYSCALL;
    callback.expected_engine_status = GEM_WINE_X86_64_BOUNDARY_WINDOWS_SYSCALL;
    callback.expected_retired = 1U;
    callback.pop_return = 1U;
    initialize_context(&input, code, stack);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(callback.calls == 1U && result.last_event == GEM_WINE_EVENT_SYSCALL);
    assert(result.instructions_retired == 2U && output.pc == HOST_RETURN);

    memcpy(image + 0x800, &(uint64_t){HOST_RETURN}, sizeof(uint64_t));
    callback.expected_event = GEM_WINE_EVENT_UNIX_CALL;
    callback.expected_reason = GEM_STOP_SYSCALL;
    callback.expected_engine_status = GEM_WINE_X86_64_BOUNDARY_UNIX_CALL;
    callback.expected_retired = 0U;
    callback.pop_return = 0U;
    initialize_context(&input, unix_boundary, stack);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(callback.calls == 2U && result.last_event == GEM_WINE_EVENT_UNIX_CALL);
    assert(result.instructions_retired == 1U && output.pc == HOST_RETURN);

    image[0x200] = 0xcc; /* INT3 is a Windows exception boundary. */
    image[0x201] = 0xc3;
    memcpy(image + 0x800, &(uint64_t){HOST_RETURN}, sizeof(uint64_t));
    callback.expected_event = GEM_WINE_EVENT_WINDOWS_EXCEPTION;
    callback.expected_reason = GEM_STOP_WINDOWS_EXCEPTION;
    callback.expected_engine_status = 0U;
    callback.expected_retired = 0U;
    callback.resume_pc = code + 1U;
    callback.pop_return = 0U;
    initialize_context(&input, code, stack);
    assert(gem_wine_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(callback.calls == 3U && result.last_event == GEM_WINE_EVENT_WINDOWS_EXCEPTION);
    assert(result.instructions_retired == 1U && output.pc == HOST_RETURN);

    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    assert(gem_wine_process_destroy(process) == GEM_WINE_OK);
}

int main(void) {
    const long page_size_long = sysconf(_SC_PAGESIZE);
    const size_t image_size = (size_t)page_size_long;
    uint8_t *image;
    assert(page_size_long >= 4096);
    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(image != MAP_FAILED && (uint64_t)(uintptr_t)image >= UINT64_C(0x100000000));
    run_case(image, image_size, 0U);
    run_case(image, image_size, GEM_WINE_X86_64_FLAG_INTERPRETER_ORACLE);
    assert(munmap(image, image_size) == 0);
    return 0;
}
