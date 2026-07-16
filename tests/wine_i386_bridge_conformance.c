// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/wine_bridge.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IMAGE_BASE UINT32_C(0x00400000)
#define IMAGE_SIZE UINT32_C(0x00004000)
#define CODE_ADDRESS (IMAGE_BASE + UINT32_C(0x1000))
#define HOST_RETURN (CODE_ADDRESS + UINT32_C(8))
#define TEST_TEB UINT32_C(0x7ffde000)

struct boundary_state {
    uint32_t calls;
    uint32_t expected_event;
    uint32_t expected_engine_status;
    uint32_t expected_access;
    uint32_t resume_bytes;
};

static enum gem_wine_status boundary(void *opaque,
                                     const struct gem_wine_i386_boundary_request *request,
                                     struct gem_wine_i386_boundary_response *response) {
    struct boundary_state *state = opaque;
    assert(request->version == GEM_WINE_BOUNDARY_ABI_VERSION);
    assert(request->struct_size == sizeof(*request));
    assert(request->event == state->expected_event);
    if (state->expected_engine_status != 0U)
        assert(request->stop.engine_status == state->expected_engine_status);
    if (state->expected_access != 0U)
        assert(request->stop.access == state->expected_access);
    ++state->calls;
    response->context = request->context;
    response->context.stop_reason = GEM_STOP_NONE;
    if (state->resume_bytes != 0U) {
        response->context.eip += state->resume_bytes;
        response->action = GEM_WINE_BOUNDARY_RESUME;
    } else {
        response->action = GEM_WINE_BOUNDARY_TERMINATE;
        response->exit_status = UINT32_C(0x52);
    }
    return GEM_WINE_OK;
}

static void put16(uint8_t *bytes, size_t offset, uint16_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static void put32(uint8_t *bytes, size_t offset, uint32_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static void make_pe32(uint8_t *image, uint16_t machine) {
    const size_t pe = 0x80U;
    memset(image, 0, IMAGE_SIZE);
    put16(image, 0U, UINT16_C(0x5a4d));
    put32(image, 0x3cU, (uint32_t)pe);
    put32(image, pe, UINT32_C(0x00004550));
    put16(image, pe + 4U, machine);
    put16(image, pe + 6U, UINT16_C(1));
    put16(image, pe + 20U, UINT16_C(0x00e0));
    put16(image, pe + 24U, UINT16_C(0x010b));
    put32(image, pe + 24U + 56U, IMAGE_SIZE);
    put32(image, pe + 24U + 60U, UINT32_C(0x200));
    memcpy(image + 0x1000U, "\xb8\x78\x56\x34\x12\x83\xc0\x01", 8U);
}

int main(void) {
    struct gem_wine_process_config process_config = {0};
    struct gem_wine_i386_config i386_config = {0};
    struct gem_wine_i386_thread_config thread_config = {0};
    struct gem_wine_process *process = NULL;
    struct gem_wine_thread *thread = NULL;
    struct gem_i386_context input, output;
    struct gem_wine_run_result result;
    struct boundary_state boundary_state = {0};
    const size_t host_page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *image = aligned_alloc(host_page, IMAGE_SIZE);
    assert(image != NULL);

    process_config.version = GEM_WINE_PROCESS_CONFIG_VERSION;
    process_config.struct_size = sizeof(process_config);
    process_config.segment_instruction_budget = 2U;
    process_config.total_instruction_budget = 8U;
    process_config.max_boundary_callbacks = 2U;
    process_config.host_return_sentinel = UINT64_C(0xfffffffffffffff0);
    assert(gem_wine_process_create(&process_config, &process) == GEM_WINE_OK);
    assert(gem_wine_process_reserve(process, IMAGE_BASE, IMAGE_SIZE) == GEM_WINE_OK);
    assert(gem_wine_process_commit_i386_host(process, IMAGE_BASE, image, IMAGE_SIZE,
                                             GEM_WINE_PAGE_EXECUTE_READWRITE) == GEM_WINE_OK);

    i386_config.version = GEM_WINE_I386_CONFIG_VERSION;
    i386_config.struct_size = sizeof(i386_config);
    i386_config.loaded_base = IMAGE_BASE;
    i386_config.image_size = IMAGE_SIZE;
    i386_config.windows_syscall_boundary = UINT32_C(0x7ffe1000);
    i386_config.unix_call_boundary = UINT32_C(0x7ffe1010);
    i386_config.host_return_sentinel = HOST_RETURN;
    make_pe32(image, UINT16_C(0x8664));
    assert(gem_wine_process_prepare_i386(process, &i386_config) == GEM_WINE_INVALID_ARGUMENT);
    make_pe32(image, UINT16_C(0x014c));
    i386_config.unix_call_boundary = i386_config.windows_syscall_boundary;
    assert(gem_wine_process_prepare_i386(process, &i386_config) == GEM_WINE_INVALID_ARGUMENT);
    i386_config.unix_call_boundary = UINT32_C(0x7ffe1010);
    assert(gem_wine_process_prepare_i386(process, &i386_config) == GEM_WINE_OK);
    assert(gem_wine_process_prepare_i386(process, &i386_config) == GEM_WINE_OK);
    assert(gem_wine_process_reserve(process, UINT64_C(0x100000000), GEM_WINE_GUEST_PAGE_SIZE) ==
           GEM_WINE_INVALID_ARGUMENT);

    thread_config.version = GEM_WINE_I386_THREAD_CONFIG_VERSION;
    thread_config.struct_size = sizeof(thread_config);
    thread_config.teb = TEST_TEB;
    thread_config.boundary = boundary;
    thread_config.opaque = &boundary_state;
    assert(gem_wine_i386_thread_create(process, &thread_config, &thread) == GEM_WINE_OK);
    memset(&input, 0, sizeof(input));
    input.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION;
    input.context_size = sizeof(input);
    input.eflags = GEM_I386_EFLAGS_REQUIRED;
    input.mxcsr = UINT32_C(0x1f80);
    input.fcw = UINT16_C(0x037f);
    input.teb = TEST_TEB;
    input.eip = CODE_ADDRESS;
    input.gpr[GEM_I386_ESP] = IMAGE_BASE + IMAGE_SIZE - UINT32_C(0x10);
    assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
    assert(result.outcome == GEM_WINE_RUN_COMPLETE);
    assert(result.instructions_retired == 2U);
    assert(output.gpr[GEM_I386_EAX] == UINT32_C(0x12345679));
    assert(output.eip == HOST_RETURN);

    {
        static const uint8_t breakpoint_code[] = {0xccU, 0xb8U, 0xefU, 0xbeU,
                                                  0xadU, 0xdeU, 0x90U, 0x90U};
        memcpy(image + 0x1000U, breakpoint_code, sizeof(breakpoint_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS, sizeof(breakpoint_code)) ==
               GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_WINDOWS_EXCEPTION;
        boundary_state.expected_engine_status = GEM_I386_EXCEPTION_BREAKPOINT;
        boundary_state.expected_access = 0U;
        boundary_state.resume_bytes = 1U;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
        assert(boundary_state.calls == 1U);
        assert(result.outcome == GEM_WINE_RUN_COMPLETE);
        assert(output.gpr[GEM_I386_EAX] == UINT32_C(0xdeadbeef));
        assert(output.eip == HOST_RETURN);
    }
    {
        static const uint8_t divide_code[] = {0xf7U, 0xf3U};
        memcpy(image + 0x1000U, divide_code, sizeof(divide_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS, sizeof(divide_code)) ==
               GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        input.gpr[GEM_I386_EBX] = 0U;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_WINDOWS_EXCEPTION;
        boundary_state.expected_engine_status = GEM_I386_EXCEPTION_INTEGER_DIVIDE_BY_ZERO;
        boundary_state.resume_bytes = 0U;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_TERMINATED);
        assert(boundary_state.calls == 1U);
        assert(result.outcome == GEM_WINE_RUN_TERMINATED && result.exit_status == 0x52U);
    }
    {
        static const uint8_t load_code[] = {0xa1U, 0x00U, 0x00U, 0x50U, 0x00U};
        memcpy(image + 0x1000U, load_code, sizeof(load_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS, sizeof(load_code)) ==
               GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_MEMORY_FAULT;
        boundary_state.expected_engine_status = 0U;
        boundary_state.expected_access = GEM_I386_ACCESS_READ;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_TERMINATED);
        assert(boundary_state.calls == 1U);
        assert(result.stop.fault_address == UINT32_C(0x00500000));
        assert(result.stop.memory_error == GEM_MEMORY_NOT_RESERVED);
    }

    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    assert(gem_wine_process_release(process, IMAGE_BASE, IMAGE_SIZE) == GEM_WINE_OK);
    assert(gem_wine_process_destroy(process) == GEM_WINE_OK);
    free(image);
    return 0;
}
