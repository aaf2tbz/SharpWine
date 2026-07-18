// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_context.h"

#include <assert.h>
#include <string.h>

int main(void) {
    struct gem_i386_context context;
    struct gem_i386_context v2;
    size_t i;
    gem_i386_context_initialize(&context, UINT32_C(0x7ffdf000));
    assert(sizeof(context) == GEM_I386_CONTEXT_SIZE_V3);
    assert(context.layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V3);
    assert(context.context_size == GEM_I386_CONTEXT_SIZE_V3);
    assert(context.gpr[GEM_I386_ESP] == 0U);
    assert(context.eflags == GEM_I386_EFLAGS_REQUIRED);
    assert(context.fcw == UINT16_C(0x037f));
    assert(context.mxcsr == UINT32_C(0x1f80));
    for (i = 0U; i < 8U; ++i) {
        assert(context.ymm_upper[i].lo == 0U && context.ymm_upper[i].hi == 0U);
        assert(context.xmm[i].lo == 0U && context.xmm[i].hi == 0U);
    }
    assert(context.xcr0 == 0U);
    assert(context.reserved1 == 0U);
    assert(gem_i386_context_is_valid(&context));

    /* v3 accepts the x87 environment, full supported XCR0, and nothing else. */
    context.x87_environment.fip = UINT32_C(0x401000);
    context.x87_environment.fdp = UINT32_C(0x402000);
    context.x87_environment.fcs = UINT16_C(0x23);
    context.x87_environment.fds = UINT16_C(0x2b);
    context.xcr0 = GEM_I386_XCR0_SUPPORTED;
    assert(gem_i386_context_is_valid(&context));
    context.xcr0 = GEM_I386_XCR0_SUPPORTED | UINT64_C(0x8);
    assert(!gem_i386_context_is_valid(&context));
    context.xcr0 = UINT64_C(0x100);
    assert(!gem_i386_context_is_valid(&context));
    context.xcr0 = 0U;
    context.reserved1 = 1U;
    assert(!gem_i386_context_is_valid(&context));
    context.reserved1 = 0U;
    context.x87_environment.reserved[1] = 1U;
    assert(!gem_i386_context_is_valid(&context));
    context.x87_environment.reserved[1] = 0U;
    context.context_size = GEM_I386_CONTEXT_SIZE_V2;
    assert(!gem_i386_context_is_valid(&context));
    context.context_size = GEM_I386_CONTEXT_SIZE_V3;
    context.layout_version = 99U;
    assert(!gem_i386_context_is_valid(&context));
    context.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V3;
    context.eflags = 0U;
    assert(!gem_i386_context_is_valid(&context));
    context.eflags = GEM_I386_EFLAGS_REQUIRED;
    assert(gem_i386_context_is_valid(&context));

    /* v2 and v1 callers with the pinned 448-byte layout stay valid. */
    memset(&v2, 0, sizeof(v2));
    v2.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    v2.context_size = GEM_I386_CONTEXT_SIZE_V2;
    v2.eflags = GEM_I386_EFLAGS_REQUIRED;
    v2.teb = UINT32_C(0x7ffdf000);
    v2.x87_environment.fip = UINT32_C(0x401000);
    v2.x87_environment.fds = UINT16_C(0x2b);
    assert(gem_i386_context_is_valid(&v2));
    v2.context_size = GEM_I386_CONTEXT_SIZE_V3;
    assert(!gem_i386_context_is_valid(&v2));
    v2.context_size = GEM_I386_CONTEXT_SIZE_V2;
    v2.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V1;
    assert(!gem_i386_context_is_valid(&v2));
    memset(v2.reserved, 0, sizeof(v2.reserved));
    assert(gem_i386_context_is_valid(&v2));

    memset(&context, 0, sizeof(context));
    assert(!gem_i386_context_is_valid(&context));
    return 0;
}
