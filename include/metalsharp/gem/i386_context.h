// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_CONTEXT_H
#define METALSHARP_GEM_I386_CONTEXT_H

#include "metalsharp/gem/context.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_I386_CONTEXT_LAYOUT_VERSION_V1 UINT32_C(1)
#define GEM_I386_CONTEXT_LAYOUT_VERSION_V2 UINT32_C(2)
#define GEM_I386_CONTEXT_LAYOUT_VERSION GEM_I386_CONTEXT_LAYOUT_VERSION_V2
#define GEM_I386_CONTEXT_SERIALIZATION_VERSION UINT32_C(1)
#define GEM_I386_CONTEXT_SIZE_V1 UINT32_C(448)
#define GEM_I386_CONTEXT_SIZE_V2 UINT32_C(448)
#define GEM_I386_CONTEXT_ALIGNMENT_V1 UINT32_C(8)
#define GEM_I386_EFLAGS_REQUIRED UINT32_C(0x00000002)

enum gem_i386_segment_attribute {
    GEM_I386_SEGMENT_PRESENT = 1U << 0,
    GEM_I386_SEGMENT_WRITABLE = 1U << 1,
    GEM_I386_SEGMENT_EXECUTABLE = 1U << 2,
    GEM_I386_SEGMENT_EXPAND_DOWN = 1U << 3,
    GEM_I386_SEGMENT_DEFAULT_32 = 1U << 4
};

enum gem_i386_gpr {
    GEM_I386_EAX = 0,
    GEM_I386_ECX = 1,
    GEM_I386_EDX = 2,
    GEM_I386_EBX = 3,
    GEM_I386_ESP = 4,
    GEM_I386_EBP = 5,
    GEM_I386_ESI = 6,
    GEM_I386_EDI = 7,
};

enum gem_i386_segment {
    GEM_I386_ES = 0,
    GEM_I386_CS = 1,
    GEM_I386_SS = 2,
    GEM_I386_DS = 3,
    GEM_I386_FS = 4,
    GEM_I386_GS = 5,
};

struct gem_i386_x87_environment {
    uint32_t fip;
    uint32_t fdp;
    uint16_t fcs;
    uint16_t fds;
    uint32_t reserved[2];
};

/* Dedicated PE32 architectural state. It is deliberately not a union member
 * of gem_thread_context v1: widening or reinterpreting that accepted ABI would
 * make ARM64EC/x64 state depend on the new architecture. */
struct gem_i386_context {
    uint32_t layout_version;
    uint32_t context_size;
    uint32_t gpr[8];
    uint32_t eip;
    uint32_t eflags;
    uint16_t segment[6];
    uint32_t segment_base[6];
    uint32_t segment_limit[6];
    uint32_t segment_attributes[6];
    struct gem_u128 xmm[8];
    struct gem_u128 x87[8];
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t fsw;
    uint16_t ftw;
    uint16_t fop;
    uint32_t teb;
    uint32_t reserved0;
    uint64_t transition_cookie;
    uint32_t stop_reason;
    union {
        uint32_t reserved[5];
        struct gem_i386_x87_environment x87_environment;
    };
};

#if defined(__cplusplus)
#define GEM_I386_STATIC_ASSERT(condition, message) static_assert((condition), message)
#define GEM_I386_ALIGNOF(type) alignof(type)
#else
#define GEM_I386_STATIC_ASSERT(condition, message) _Static_assert((condition), message)
#define GEM_I386_ALIGNOF(type) _Alignof(type)
#endif

GEM_I386_STATIC_ASSERT(sizeof(struct gem_i386_context) == GEM_I386_CONTEXT_SIZE_V1,
                       "gem_i386_context v1 size changed");
GEM_I386_STATIC_ASSERT(GEM_I386_ALIGNOF(struct gem_i386_context) == GEM_I386_CONTEXT_ALIGNMENT_V1,
                       "gem_i386_context v1 alignment changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, gpr) == 8U, "i386 gpr offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, eip) == 40U, "i386 eip offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, segment) == 48U,
                       "i386 segment offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, xmm) == 136U, "i386 xmm offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, x87) == 264U, "i386 x87 offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, transition_cookie) == 416U,
                       "i386 transition cookie offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, stop_reason) == 424U,
                       "i386 stop reason offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, x87_environment.fip) == 428U,
                       "i386 x87 instruction pointer offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, x87_environment.fdp) == 432U,
                       "i386 x87 data pointer offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, x87_environment.fcs) == 436U,
                       "i386 x87 code selector offset changed");
GEM_I386_STATIC_ASSERT(offsetof(struct gem_i386_context, x87_environment.fds) == 438U,
                       "i386 x87 data selector offset changed");

#undef GEM_I386_ALIGNOF
#undef GEM_I386_STATIC_ASSERT

void gem_i386_context_initialize(struct gem_i386_context *context, uint32_t teb);
bool gem_i386_context_is_valid(const struct gem_i386_context *context);

#ifdef __cplusplus
}
#endif

#endif
