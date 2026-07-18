// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/wine_bridge.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <sys/mman.h>
#endif
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
    uint32_t mutate_v2;
    uint32_t mutate_v3;
    uint32_t respond_v1;
};

static enum gem_wine_status boundary(void *opaque,
                                     const struct gem_wine_i386_boundary_request *request,
                                     struct gem_wine_i386_boundary_response *response) {
    struct boundary_state *state = opaque;
    assert(request->version == GEM_WINE_I386_BOUNDARY_ABI_VERSION);
    assert(request->struct_size == sizeof(*request));
    if (request->event != state->expected_event)
        fprintf(stderr,
                "i386 boundary event mismatch: expected=%u actual=%u status=%u access=%u "
                "eip=%08x fault=%08llx memory=%u\n",
                state->expected_event, request->event, request->stop.engine_status,
                request->stop.access, request->context.eip,
                (unsigned long long)request->stop.fault_address, request->stop.memory_error);
    assert(request->event == state->expected_event);
    if (state->expected_engine_status != 0U)
        assert(request->stop.engine_status == state->expected_engine_status);
    if (state->expected_access != 0U)
        assert(request->stop.access == state->expected_access);
    ++state->calls;
    response->context = request->context;
    response->context.stop_reason = GEM_STOP_NONE;
    if (state->mutate_v2 != 0U) {
        unsigned int i;
        response->context.eflags ^= UINT32_C(0x400);
        response->context.mxcsr = UINT32_C(0x3f80);
        response->context.fcw = UINT16_C(0x027f);
        response->context.fsw = UINT16_C(0x2800);
        response->context.ftw = UINT16_C(0x00ff);
        response->context.fop = UINT16_C(0x345);
        response->context.x87_environment.fip = UINT32_C(0x11223344);
        response->context.x87_environment.fdp = UINT32_C(0x55667788);
        response->context.x87_environment.fcs = UINT16_C(0x23);
        response->context.x87_environment.fds = UINT16_C(0x2b);
        for (i = 0U; i < 6U; ++i) {
            response->context.segment[i] = (uint16_t)(UINT16_C(0x43) + i * 8U);
            response->context.segment_base[i] = i == GEM_I386_CS ? 0U : UINT32_C(0x10000) * i;
            response->context.segment_limit[i] = UINT32_MAX - i;
            response->context.segment_attributes[i] =
                GEM_I386_SEGMENT_PRESENT | GEM_I386_SEGMENT_DEFAULT_32 |
                (i == GEM_I386_CS ? GEM_I386_SEGMENT_EXECUTABLE : GEM_I386_SEGMENT_WRITABLE);
        }
        for (i = 0U; i < 8U; ++i) {
            response->context.xmm[i].lo = UINT64_C(0x11110000) + i;
            response->context.xmm[i].hi = UINT64_C(0x22220000) + i;
            response->context.x87[i].lo = UINT64_C(0x8000000000000000) + i;
            response->context.x87[i].hi = UINT64_C(0x3fff);
        }
    }
    if (state->mutate_v3 != 0U) {
        unsigned int i;
        response->context.xcr0 = GEM_I386_XCR0_SUPPORTED;
        for (i = 0U; i < 8U; ++i) {
            response->context.ymm_upper[i].lo = UINT64_C(0x33330000) + i;
            response->context.ymm_upper[i].hi = UINT64_C(0x44440000) + i;
        }
    }
    if (state->respond_v1 != 0U) {
        response->version = GEM_WINE_I386_BOUNDARY_ABI_VERSION_V1;
        response->struct_size = GEM_WINE_I386_BOUNDARY_RESPONSE_SIZE_V1;
        response->context.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
        response->context.context_size = GEM_I386_CONTEXT_SIZE_V2;
        memset(response->context.ymm_upper, 0, sizeof(response->context.ymm_upper));
        response->context.xcr0 = 0U;
        response->context.reserved1 = 0U;
    }
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
    struct gem_i386_diagnostics diagnostics = {.abi_version = GEM_I386_DIAGNOSTICS_ABI_VERSION,
                                               .size = sizeof(diagnostics)};
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
    assert(gem_wine_i386_thread_diagnostics(thread, &diagnostics) == GEM_WINE_OK);
    assert(diagnostics.engine_mode == GEM_I386_ENGINE_JIT);
    assert(diagnostics.jit_executions != 0U && diagnostics.jit_failures == 0U);
    assert(diagnostics.interpreter_fallbacks == 0U);

    {
        static const uint8_t breakpoint_code[] = {0xccU, 0xb8U, 0xefU, 0xbeU,
                                                  0xadU, 0xdeU, 0x90U, 0x90U};
        enum gem_wine_status run_status;
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
        boundary_state.mutate_v2 = 1U;
        boundary_state.mutate_v3 = 1U;
        run_status = gem_wine_i386_thread_run(thread, &input, &output, &result);
        if (run_status != GEM_WINE_OK)
            fprintf(stderr, "i386 v2 resume failed: status=%u outcome=%u stop=%u callbacks=%u\n",
                    run_status, result.outcome, result.stop_reason,
                    (unsigned)result.boundary_callbacks);
        assert(run_status == GEM_WINE_OK);
        assert(boundary_state.calls == 1U);
        assert(result.outcome == GEM_WINE_RUN_COMPLETE);
        assert(output.gpr[GEM_I386_EAX] == UINT32_C(0xdeadbeef));
        assert(output.eip == HOST_RETURN);
        assert((output.eflags & UINT32_C(0x400)) != 0U);
        assert(output.mxcsr == UINT32_C(0x3f80));
        assert(output.fcw == UINT16_C(0x027f) && output.fsw == UINT16_C(0x2800));
        assert(output.x87_environment.fip == UINT32_C(0x11223344) &&
               output.x87_environment.fdp == UINT32_C(0x55667788));
        assert(output.x87_environment.fcs == UINT16_C(0x23) &&
               output.x87_environment.fds == UINT16_C(0x2b));
        assert(output.xmm[7].hi == UINT64_C(0x22220007));
        assert(output.x87[7].lo == UINT64_C(0x8000000000000007));
        assert(output.xcr0 == GEM_I386_XCR0_SUPPORTED);
        assert(output.ymm_upper[7].lo == UINT64_C(0x33330007));
        assert(output.ymm_upper[7].hi == UINT64_C(0x44440007));
        assert(output.segment[5] == UINT16_C(0x6b));
        assert(output.segment_base[GEM_I386_CS] == 0U);
        assert(output.segment_base[GEM_I386_FS] == UINT32_C(0x40000));
        boundary_state.mutate_v2 = 0U;
        boundary_state.mutate_v3 = 0U;
    }
    {
        static const uint8_t breakpoint_code[] = {0xccU, 0xb8U, 0x34U, 0x12U,
                                                  0x00U, 0x00U, 0x90U, 0x90U};
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
        boundary_state.respond_v1 = 1U;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
        assert(boundary_state.calls == 1U && result.outcome == GEM_WINE_RUN_COMPLETE);
        assert(output.layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V2);
        assert(output.context_size == GEM_I386_CONTEXT_SIZE_V2);
        assert(output.gpr[GEM_I386_EAX] == UINT32_C(0x1234));
        boundary_state.respond_v1 = 0U;
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
        static const uint8_t xsetbv_code[] = {0x0fU, 0x01U, 0xd1U};
        memcpy(image + 0x1000U, xsetbv_code, sizeof(xsetbv_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS, sizeof(xsetbv_code)) ==
               GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_WINDOWS_EXCEPTION;
        boundary_state.expected_engine_status = GEM_I386_EXCEPTION_GENERAL_PROTECTION;
        boundary_state.expected_access = 0U;
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
    {
        static const uint8_t unsupported_code[] = {0x0fU, 0xaeU, 0x36U};
        memcpy(image + 0x1000U, unsupported_code, sizeof(unsupported_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS, sizeof(unsupported_code)) ==
               GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_UNSUPPORTED_INSTRUCTION;
        boundary_state.expected_engine_status = 0U;
        boundary_state.expected_access = 0U;
        boundary_state.resume_bytes = 0U;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_TERMINATED);
        assert(boundary_state.calls == 1U);
        diagnostics.abi_version = GEM_I386_DIAGNOSTICS_ABI_VERSION;
        diagnostics.size = sizeof(diagnostics);
        assert(gem_wine_i386_thread_diagnostics(thread, &diagnostics) == GEM_WINE_OK);
        assert(diagnostics.unsupported_instructions == 1U);
        assert(diagnostics.last_unsupported_eip == CODE_ADDRESS);
        assert(diagnostics.last_unsupported_length == sizeof(unsupported_code));
        assert(strcmp(diagnostics.last_unsupported_name, "Op1ae") == 0);
        assert(diagnostics.code_invalidations != 0U);
        assert(diagnostics.interpreter_fallbacks == 0U);
    }

#if defined(__APPLE__)
    {
        static const uint8_t external_load_code[] = {
            0xa1U, 0x00U, 0x00U, 0x60U, 0x00U, /* mov eax,[0x00600000] */
            0x83U, 0xc0U, 0x01U                /* add eax,1 */
        };
        const uint32_t external_data = UINT32_C(0x00600000);
        uint32_t *host = mmap(NULL, host_page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANON, -1, 0);
        assert(host != MAP_FAILED);
        *host = UINT32_C(1);
        assert(gem_wine_process_reserve(process, external_data, GEM_WINE_GUEST_PAGE_SIZE) ==
               GEM_WINE_OK);
        assert(gem_wine_process_commit_i386_host(process, external_data, host,
                                                 GEM_WINE_GUEST_PAGE_SIZE,
                                                 GEM_WINE_PAGE_READWRITE) == GEM_WINE_OK);
        memcpy(image + 0x1000U, external_load_code, sizeof(external_load_code));
        assert(gem_wine_process_invalidate_code(process, CODE_ADDRESS,
                                                sizeof(external_load_code)) == GEM_WINE_OK);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
        assert(result.outcome == GEM_WINE_RUN_COMPLETE);
        assert(output.gpr[GEM_I386_EAX] == UINT32_C(2));

        /* Host callbacks may mutate writable external pages without going
         * through the guest memory API.  The next checked run must refresh
         * that data while retaining the separately invalidated code page. */
        *host = UINT32_C(41);
        input.eip = CODE_ADDRESS;
        input.stop_reason = GEM_STOP_NONE;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_OK);
        assert(result.outcome == GEM_WINE_RUN_COMPLETE);
        assert(output.gpr[GEM_I386_EAX] == UINT32_C(42));
        assert(gem_wine_process_release(process, external_data, GEM_WINE_GUEST_PAGE_SIZE) ==
               GEM_WINE_OK);
        assert(munmap(host, host_page) == 0);
    }
    {
        const uint32_t stale_code = UINT32_C(0x00600000);
        uint8_t *host =
            mmap(NULL, host_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        assert(host != MAP_FAILED);
        host[0] = 0x90U;
        assert(gem_wine_process_reserve(process, stale_code, GEM_WINE_GUEST_PAGE_SIZE) ==
               GEM_WINE_OK);
        assert(gem_wine_process_commit_i386_host(process, stale_code, host,
                                                 GEM_WINE_GUEST_PAGE_SIZE,
                                                 GEM_WINE_PAGE_EXECUTE_READWRITE) == GEM_WINE_OK);
        assert(munmap(host, host_page) == 0);
        input.eip = stale_code;
        input.stop_reason = GEM_STOP_NONE;
        boundary_state.calls = 0U;
        boundary_state.expected_event = GEM_WINE_EVENT_MEMORY_FAULT;
        boundary_state.expected_engine_status = 0U;
        boundary_state.expected_access = GEM_I386_ACCESS_FETCH;
        boundary_state.resume_bytes = 0U;
        assert(gem_wine_i386_thread_run(thread, &input, &output, &result) == GEM_WINE_TERMINATED);
        assert(boundary_state.calls == 1U);
        assert(result.stop.fault_address == stale_code);
        if (result.stop.memory_error != GEM_MEMORY_NOT_COMMITTED)
            fprintf(stderr, "stale external page memory error: %u\n", result.stop.memory_error);
        assert(result.stop.memory_error == GEM_MEMORY_NOT_COMMITTED);
        assert(gem_wine_process_release(process, stale_code, GEM_WINE_GUEST_PAGE_SIZE) ==
               GEM_WINE_OK);
    }
#endif

    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    assert(gem_wine_process_release(process, IMAGE_BASE, IMAGE_SIZE) == GEM_WINE_OK);
    assert(gem_wine_process_destroy(process) == GEM_WINE_OK);
    free(image);
    return 0;
}
