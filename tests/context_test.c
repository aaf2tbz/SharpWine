// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context.h"

#include <assert.h>
#include <string.h>

int main(void) {
    const uint64_t teb = UINT64_C(0x00007ffefeff8000);
    struct gem_thread_context context;

    gem_context_initialize(&context, teb, GEM_ISA_ARM64EC);
    assert(gem_context_is_valid(&context));
    assert(context.x[18] == teb);
    assert(context.teb == teb);
    assert(strcmp(gem_stop_reason_name(GEM_STOP_ARCH_TRANSITION), "architecture-transition") == 0);

    context.x[18] = 0;
    assert(!gem_context_is_valid(&context));
    context.x[18] = teb;
    context.isa = GEM_ISA_INVALID;
    assert(!gem_context_is_valid(&context));
    assert(strcmp(gem_stop_reason_name((enum gem_stop_reason)999), "invalid") == 0);
    return 0;
}
