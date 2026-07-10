// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context.h"

#include <string.h>

void gem_context_initialize(struct gem_thread_context *context, uint64_t teb, enum gem_isa isa) {
    memset(context, 0, sizeof(*context));
    context->teb = teb;
    context->x[18] = teb;
    context->isa = (uint32_t)isa;
}

bool gem_context_is_valid(const struct gem_thread_context *context) {
    if (context == NULL || context->teb == 0 || context->x[18] != context->teb)
        return false;
    return context->isa == GEM_ISA_ARM64EC || context->isa == GEM_ISA_X64;
}

const char *gem_stop_reason_name(enum gem_stop_reason reason) {
    static const char *const names[] = {
        "none",
        "syscall",
        "architecture-transition",
        "host-return",
        "memory-fault",
        "windows-exception",
        "async-request",
        "unsupported",
        "budget-expired",
        "invariant-violation",
    };

    if ((unsigned int)reason >= sizeof(names) / sizeof(names[0]))
        return "invalid";
    return names[reason];
}
