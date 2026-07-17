// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_context.h"

#include <assert.h>
#include <string.h>

int main(void) {
    struct gem_i386_context context;
    gem_i386_context_initialize(&context, UINT32_C(0x7ffdf000));
    assert(sizeof(context) == GEM_I386_CONTEXT_SIZE_V1);
    assert(context.layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V2);
    assert(context.gpr[GEM_I386_ESP] == 0U);
    assert(context.eflags == GEM_I386_EFLAGS_REQUIRED);
    assert(context.fcw == UINT16_C(0x037f));
    assert(context.mxcsr == UINT32_C(0x1f80));
    assert(gem_i386_context_is_valid(&context));
    context.x87_environment.reserved[1] = 1U;
    assert(!gem_i386_context_is_valid(&context));
    context.x87_environment.reserved[1] = 0U;
    context.x87_environment.fip = UINT32_C(0x401000);
    context.x87_environment.fdp = UINT32_C(0x402000);
    context.x87_environment.fcs = UINT16_C(0x23);
    context.x87_environment.fds = UINT16_C(0x2b);
    assert(gem_i386_context_is_valid(&context));
    context.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V1;
    assert(!gem_i386_context_is_valid(&context));
    memset(context.reserved, 0, sizeof(context.reserved));
    assert(gem_i386_context_is_valid(&context));
    context.layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION_V2;
    context.eflags = 0U;
    assert(!gem_i386_context_is_valid(&context));
    memset(&context, 0, sizeof(context));
    assert(!gem_i386_context_is_valid(&context));
    return 0;
}
