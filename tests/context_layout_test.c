// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context.h"
#include "metalsharp/gem/i386_context.h"

#include <assert.h>
#include <stddef.h>

int main(void) {
    struct gem_thread_context context;

    assert(GEM_CONTEXT_LAYOUT_VERSION == 1U);
    assert(GEM_CONTEXT_SERIALIZATION_VERSION == 1U);
    assert(GEM_THREAD_CONTEXT_SIZE_V1 == 720U);
    assert(GEM_THREAD_CONTEXT_ALIGNMENT_V1 == 8U);
    assert(GEM_THREAD_CONTEXT_EXPECTED_SIZE == GEM_THREAD_CONTEXT_SIZE_V1);
    assert(sizeof(struct gem_u128) == 16U);
    assert(sizeof(struct gem_thread_context) == GEM_THREAD_CONTEXT_SIZE_V1);
    assert(offsetof(struct gem_thread_context, layout_version) == 0U);
    assert(offsetof(struct gem_thread_context, context_size) == 4U);
    assert(offsetof(struct gem_thread_context, x) == 8U);
    assert(offsetof(struct gem_thread_context, sp) == 256U);
    assert(offsetof(struct gem_thread_context, pc) == 264U);
    assert(offsetof(struct gem_thread_context, nzcv) == 272U);
    assert(offsetof(struct gem_thread_context, fpcr) == 276U);
    assert(offsetof(struct gem_thread_context, fpsr) == 280U);
    assert(offsetof(struct gem_thread_context, reserved0) == 284U);
    assert(offsetof(struct gem_thread_context, v) == 288U);
    assert(offsetof(struct gem_thread_context, x64_rflags) == 544U);
    assert(offsetof(struct gem_thread_context, x64_mxcsr) == 552U);
    assert(offsetof(struct gem_thread_context, x64_fcw) == 556U);
    assert(offsetof(struct gem_thread_context, x64_fsw) == 558U);
    assert(offsetof(struct gem_thread_context, x87) == 560U);
    assert(offsetof(struct gem_thread_context, teb) == 688U);
    assert(offsetof(struct gem_thread_context, original_x64_sp) == 696U);
    assert(offsetof(struct gem_thread_context, transition_cookie) == 704U);
    assert(offsetof(struct gem_thread_context, isa) == 712U);
    assert(offsetof(struct gem_thread_context, stop_reason) == 716U);

    gem_context_initialize(&context, UINT64_C(0x00007ffefeff8000), GEM_ISA_X64);
    assert(context.layout_version == GEM_CONTEXT_LAYOUT_VERSION);
    assert(context.context_size == GEM_THREAD_CONTEXT_EXPECTED_SIZE);
    assert(gem_context_is_valid(&context));

    {
        struct gem_i386_context i386;
        assert(GEM_I386_CONTEXT_LAYOUT_VERSION == GEM_I386_CONTEXT_LAYOUT_VERSION_V3);
        assert(GEM_I386_CONTEXT_SIZE_V1 == 448U);
        assert(GEM_I386_CONTEXT_SIZE_V2 == 448U);
        assert(GEM_I386_CONTEXT_SIZE_V3 == 592U);
        assert(sizeof(struct gem_i386_context) == GEM_I386_CONTEXT_SIZE_V3);
        assert(offsetof(struct gem_i386_context, ymm_upper) == 448U);
        assert(offsetof(struct gem_i386_context, xcr0) == 576U);
        assert(offsetof(struct gem_i386_context, reserved1) == 584U);
        gem_i386_context_initialize(&i386, UINT32_C(0x7ffde000));
        assert(i386.layout_version == GEM_I386_CONTEXT_LAYOUT_VERSION_V3);
        assert(i386.context_size == GEM_I386_CONTEXT_SIZE_V3);
        assert(gem_i386_context_is_valid(&i386));
    }

    return 0;
}
