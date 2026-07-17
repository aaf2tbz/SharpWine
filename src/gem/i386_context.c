// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_context.h"

#include <string.h>

void gem_i386_context_initialize(struct gem_i386_context *context, uint32_t teb) {
    if (context == NULL)
        return;
    memset(context, 0, sizeof(*context));
    context->layout_version = GEM_I386_CONTEXT_LAYOUT_VERSION;
    context->context_size = GEM_I386_CONTEXT_SIZE_V2;
    context->eflags = GEM_I386_EFLAGS_REQUIRED;
    context->fcw = UINT16_C(0x037f);
    context->mxcsr = UINT32_C(0x1f80);
    context->teb = teb;
}

bool gem_i386_context_is_valid(const struct gem_i386_context *context) {
    size_t i;
    if (context == NULL ||
        (context->layout_version != GEM_I386_CONTEXT_LAYOUT_VERSION_V1 &&
         context->layout_version != GEM_I386_CONTEXT_LAYOUT_VERSION_V2) ||
        context->context_size != GEM_I386_CONTEXT_SIZE_V1 || context->teb == 0U ||
        (context->eflags & GEM_I386_EFLAGS_REQUIRED) == 0U || context->reserved0 != 0U)
        return false;
    if (context->layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V1) {
        for (i = 0; i < sizeof(context->reserved) / sizeof(context->reserved[0]); ++i)
            if (context->reserved[i] != 0U)
                return false;
    } else {
        for (i = 0; i < sizeof(context->x87_environment.reserved) /
                            sizeof(context->x87_environment.reserved[0]);
             ++i)
            if (context->x87_environment.reserved[i] != 0U)
                return false;
    }
    return context->stop_reason <= (uint32_t)GEM_STOP_INVARIANT_VIOLATION;
}
