// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_CONTEXT_H
#define METALSHARP_GEM_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gem_isa {
    GEM_ISA_INVALID = 0,
    GEM_ISA_ARM64EC = 1,
    GEM_ISA_X64 = 2,
};

enum gem_stop_reason {
    GEM_STOP_NONE = 0,
    GEM_STOP_SYSCALL,
    GEM_STOP_ARCH_TRANSITION,
    GEM_STOP_HOST_RETURN,
    GEM_STOP_MEMORY_FAULT,
    GEM_STOP_WINDOWS_EXCEPTION,
    GEM_STOP_ASYNC_REQUEST,
    GEM_STOP_UNSUPPORTED_INSTRUCTION,
    GEM_STOP_BUDGET_EXPIRED,
    GEM_STOP_INVARIANT_VIOLATION,
};

struct gem_u128 {
    uint64_t lo;
    uint64_t hi;
};

struct gem_thread_context {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint32_t nzcv;
    uint32_t fpcr;
    uint32_t fpsr;
    uint32_t reserved0;
    struct gem_u128 v[16];

    uint64_t x64_rflags;
    uint32_t x64_mxcsr;
    uint16_t x64_fcw;
    uint16_t x64_fsw;
    struct gem_u128 x87[8];

    uint64_t teb;
    uint64_t original_x64_sp;
    uint64_t transition_cookie;
    uint32_t isa;
    uint32_t stop_reason;
};

void gem_context_initialize(struct gem_thread_context *context, uint64_t teb, enum gem_isa isa);
bool gem_context_is_valid(const struct gem_thread_context *context);
const char *gem_stop_reason_name(enum gem_stop_reason reason);

#ifdef __cplusplus
}
#endif

#endif
