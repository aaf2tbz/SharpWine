// SPDX-License-Identifier: Apache-2.0
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

    assert(gem_wine_thread_destroy(thread) == GEM_WINE_OK);
    assert(gem_wine_process_release(process, IMAGE_BASE, IMAGE_SIZE) == GEM_WINE_OK);
    assert(gem_wine_process_destroy(process) == GEM_WINE_OK);
    free(image);
    return 0;
}
