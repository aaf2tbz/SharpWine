// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_CONTEXT_CONVERSION_H
#define METALSHARP_GEM_CONTEXT_CONVERSION_H

#include "metalsharp/gem/context.h"

#ifdef __cplusplus
extern "C" {
#endif

enum gem_x64_gpr {
    GEM_X64_RAX,
    GEM_X64_RCX,
    GEM_X64_RDX,
    GEM_X64_RBX,
    GEM_X64_RSP,
    GEM_X64_RBP,
    GEM_X64_RSI,
    GEM_X64_RDI,
    GEM_X64_R8,
    GEM_X64_R9,
    GEM_X64_R10,
    GEM_X64_R11,
    GEM_X64_R12,
    GEM_X64_R13,
    GEM_X64_R14,
    GEM_X64_R15,
    GEM_X64_GPR_COUNT
};

/* A host-independent x64 view.  It contains no emulator or host registers. */
struct gem_x64_context {
    uint64_t gpr[GEM_X64_GPR_COUNT];
    uint64_t rip;
    uint64_t rflags;
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t fsw;
    struct gem_u128 xmm[16];
    struct gem_u128 x87[8];
    uint64_t teb;
};

/* These functions only materialize architectural state; they do not execute code. */
bool gem_context_arm64ec_to_x64(const struct gem_thread_context *source,
                                struct gem_x64_context *destination);
bool gem_context_x64_to_arm64ec(const struct gem_x64_context *source,
                                struct gem_thread_context *destination);
enum gem_arithmetic_mode {
    GEM_ARITHMETIC_LOGICAL = 0,
    GEM_ARITHMETIC_ADD = 1,
    GEM_ARITHMETIC_SUBTRACT = 2
};
/* Subtraction materializes ARM C (not-borrow) as inverted x64 CF. */
uint64_t gem_rflags_from_nzcv(uint32_t nzcv, uint64_t preserved_rflags);
uint64_t gem_rflags_from_nzcv_for_arithmetic(uint32_t nzcv, uint64_t preserved_rflags,
                                             enum gem_arithmetic_mode mode);
uint32_t gem_nzcv_from_rflags(uint64_t rflags, uint32_t preserved_nzcv);
uint32_t gem_nzcv_from_rflags_for_arithmetic(uint64_t rflags, uint32_t preserved_nzcv,
                                             enum gem_arithmetic_mode mode);
/* DAZ has no ARM64 FPCR equivalent and is explicitly rejected by the checked form. */
bool gem_fp_from_mxcsr_checked(uint32_t mxcsr, uint32_t *fpcr, uint32_t *fpsr);
uint32_t gem_mxcsr_from_fp(uint32_t fpcr, uint32_t fpsr);
void gem_fp_from_mxcsr(uint32_t mxcsr, uint32_t *fpcr, uint32_t *fpsr);

#ifdef __cplusplus
}
#endif
#endif
