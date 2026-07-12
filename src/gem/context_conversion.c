// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context_conversion.h"

#include <string.h>

#define RFLAGS_NZCV_MASK UINT64_C(0x8c1)
#define NZCV_MASK UINT32_C(0xf0000000)
#define FPCR_MXCSR_MASK                                                                            \
    ((UINT32_C(0x1f) << 8) | (UINT32_C(1) << 15) | (UINT32_C(3) << 22) | (UINT32_C(1) << 24))
#define FPSR_MXCSR_MASK UINT32_C(0x9f)

uint64_t gem_rflags_from_nzcv_for_arithmetic(uint32_t nzcv, uint64_t preserved_rflags,
                                             enum gem_arithmetic_mode mode) {
    uint64_t result = preserved_rflags & ~RFLAGS_NZCV_MASK;
    if (((nzcv & (UINT32_C(1) << 29)) != 0U) != (mode == GEM_ARITHMETIC_SUBTRACT))
        result |= UINT64_C(1) << 0;
    if ((nzcv & UINT32_C(1) << 30) != 0U)
        result |= UINT64_C(1) << 6;
    if ((nzcv & UINT32_C(1) << 31) != 0U)
        result |= UINT64_C(1) << 7;
    if ((nzcv & UINT32_C(1) << 28) != 0U)
        result |= UINT64_C(1) << 11;
    return result;
}
uint64_t gem_rflags_from_nzcv(uint32_t nzcv, uint64_t preserved_rflags) {
    return gem_rflags_from_nzcv_for_arithmetic(nzcv, preserved_rflags, GEM_ARITHMETIC_LOGICAL);
}

uint32_t gem_nzcv_from_rflags_for_arithmetic(uint64_t rflags, uint32_t preserved_nzcv,
                                             enum gem_arithmetic_mode mode) {
    uint32_t result = preserved_nzcv & ~NZCV_MASK;
    if (((rflags & (UINT64_C(1) << 0)) != 0U) != (mode == GEM_ARITHMETIC_SUBTRACT))
        result |= UINT32_C(1) << 29;
    if ((rflags & (UINT64_C(1) << 6)) != 0U)
        result |= UINT32_C(1) << 30;
    if ((rflags & (UINT64_C(1) << 7)) != 0U)
        result |= UINT32_C(1) << 31;
    if ((rflags & (UINT64_C(1) << 11)) != 0U)
        result |= UINT32_C(1) << 28;
    return result;
}
uint32_t gem_nzcv_from_rflags(uint64_t rflags, uint32_t preserved_nzcv) {
    return gem_nzcv_from_rflags_for_arithmetic(rflags, preserved_nzcv, GEM_ARITHMETIC_LOGICAL);
}

/* ARM IOC/IDC/DZC/OFC/UFC/IXC map to x86 IE/DE/ZE/OE/UE/PE respectively. */
uint32_t gem_mxcsr_from_fp(uint32_t fpcr, uint32_t fpsr) {
    static const unsigned arm_status[] = {0, 7, 1, 2, 3, 4};
    static const unsigned x86_status[] = {0, 1, 2, 3, 4, 5};
    uint32_t result = 0U;
    unsigned i, arm_round, x86_round;
    for (i = 0; i < 6; ++i)
        if ((fpsr & (UINT32_C(1) << arm_status[i])) != 0U)
            result |= UINT32_C(1) << x86_status[i];
    /* ARM enable bits IOC,DZC,OFC,UFC,IXC,IDE are inverse of MXCSR masks. */
    for (i = 0; i < 6; ++i)
        if ((fpcr & (UINT32_C(1) << (i == 1 ? 15 : 8 + (i > 1 ? i - 1 : i)))) == 0U)
            result |= UINT32_C(1) << (7 + i);
    arm_round = (fpcr >> 22) & 3U;
    x86_round = arm_round == 1U ? 2U : arm_round == 2U ? 1U : arm_round;
    result |= x86_round << 13;
    result |= ((fpcr >> 24) & 1U) << 15;
    return result;
}
bool gem_fp_from_mxcsr_checked(uint32_t mxcsr, uint32_t *fpcr, uint32_t *fpsr) {
    static const unsigned arm_status[] = {0, 7, 1, 2, 3, 4};
    static const unsigned x86_status[] = {0, 1, 2, 3, 4, 5};
    uint32_t control = 0U, status = 0U, x86_round, arm_round;
    unsigned i;
    if ((mxcsr & (UINT32_C(1) << 6)) != 0U)
        return false; /* DAZ is x86-only. */
    for (i = 0; i < 6; ++i) {
        if ((mxcsr & (UINT32_C(1) << x86_status[i])) != 0U)
            status |= UINT32_C(1) << arm_status[i];
        if ((mxcsr & (UINT32_C(1) << (7 + i))) == 0U)
            control |= UINT32_C(1) << (i == 1 ? 15 : 8 + (i > 1 ? i - 1 : i));
    }
    x86_round = (mxcsr >> 13) & 3U;
    arm_round = x86_round == 1U ? 2U : x86_round == 2U ? 1U : x86_round;
    control |= arm_round << 22;
    control |= ((mxcsr >> 15) & 1U) << 24;
    if (fpcr != NULL)
        *fpcr = control;
    if (fpsr != NULL)
        *fpsr = status;
    return true;
}
void gem_fp_from_mxcsr(uint32_t mxcsr, uint32_t *fpcr, uint32_t *fpsr) {
    (void)gem_fp_from_mxcsr_checked(mxcsr, fpcr, fpsr);
}

bool gem_context_x64_materialize(const struct gem_thread_context *source,
                                 struct gem_x64_context *destination) {
    if (!gem_context_is_valid(source) || source->isa != GEM_ISA_X64 || destination == NULL)
        return false;
    memset(destination, 0, sizeof(*destination));
    destination->gpr[GEM_X64_RAX] = source->x[8];
    destination->gpr[GEM_X64_RCX] = source->x[0];
    destination->gpr[GEM_X64_RDX] = source->x[1];
    destination->gpr[GEM_X64_RBX] = source->x[27];
    destination->gpr[GEM_X64_RSP] = source->sp;
    destination->gpr[GEM_X64_RBP] = source->x[29];
    destination->gpr[GEM_X64_RSI] = source->x[25];
    destination->gpr[GEM_X64_RDI] = source->x[26];
    destination->gpr[GEM_X64_R8] = source->x[2];
    destination->gpr[GEM_X64_R9] = source->x[3];
    destination->gpr[GEM_X64_R10] = source->x[4];
    destination->gpr[GEM_X64_R11] = source->x[5];
    destination->gpr[GEM_X64_R12] = source->x[19];
    destination->gpr[GEM_X64_R13] = source->x[20];
    destination->gpr[GEM_X64_R14] = source->x[21];
    destination->gpr[GEM_X64_R15] = source->x[22];
    destination->rip = source->pc;
    destination->rflags = source->x64_rflags;
    destination->mxcsr = source->x64_mxcsr;
    destination->fcw = source->x64_fcw;
    destination->fsw = source->x64_fsw;
    memcpy(destination->xmm, source->v, sizeof(destination->xmm));
    memcpy(destination->x87, source->x87, sizeof(destination->x87));
    destination->teb = source->teb;
    return true;
}

bool gem_context_x64_commit(const struct gem_x64_context *source,
                            struct gem_thread_context *destination) {
    struct gem_thread_context result;
    if (source == NULL || !gem_context_is_valid(destination) || destination->isa != GEM_ISA_X64 ||
        source->teb != destination->teb)
        return false;
    result = *destination;
    result.x[8] = source->gpr[GEM_X64_RAX];
    result.x[0] = source->gpr[GEM_X64_RCX];
    result.x[1] = source->gpr[GEM_X64_RDX];
    result.x[27] = source->gpr[GEM_X64_RBX];
    result.sp = source->gpr[GEM_X64_RSP];
    result.x[29] = source->gpr[GEM_X64_RBP];
    result.x[25] = source->gpr[GEM_X64_RSI];
    result.x[26] = source->gpr[GEM_X64_RDI];
    result.x[2] = source->gpr[GEM_X64_R8];
    result.x[3] = source->gpr[GEM_X64_R9];
    result.x[4] = source->gpr[GEM_X64_R10];
    result.x[5] = source->gpr[GEM_X64_R11];
    result.x[19] = source->gpr[GEM_X64_R12];
    result.x[20] = source->gpr[GEM_X64_R13];
    result.x[21] = source->gpr[GEM_X64_R14];
    result.x[22] = source->gpr[GEM_X64_R15];
    result.pc = source->rip;
    result.x64_rflags = source->rflags;
    result.x64_mxcsr = source->mxcsr;
    result.x64_fcw = source->fcw;
    result.x64_fsw = source->fsw;
    memcpy(result.v, source->xmm, sizeof(result.v));
    memcpy(result.x87, source->x87, sizeof(result.x87));
    result.x[18] = result.teb;
    if (!gem_context_is_valid(&result))
        return false;
    *destination = result;
    return true;
}

bool gem_context_arm64ec_to_x64(const struct gem_thread_context *source,
                                struct gem_x64_context *destination) {
    if (!gem_context_is_valid(source) || source->isa != GEM_ISA_ARM64EC || destination == NULL)
        return false;
    memset(destination, 0, sizeof(*destination));
    destination->gpr[GEM_X64_RAX] = source->x[8];
    destination->gpr[GEM_X64_RCX] = source->x[0];
    destination->gpr[GEM_X64_RDX] = source->x[1];
    destination->gpr[GEM_X64_RBX] = source->x[27];
    destination->gpr[GEM_X64_RSP] = source->sp;
    destination->gpr[GEM_X64_RBP] = source->x[29];
    destination->gpr[GEM_X64_RSI] = source->x[25];
    destination->gpr[GEM_X64_RDI] = source->x[26];
    destination->gpr[GEM_X64_R8] = source->x[2];
    destination->gpr[GEM_X64_R9] = source->x[3];
    destination->gpr[GEM_X64_R10] = source->x[4];
    destination->gpr[GEM_X64_R11] = source->x[5];
    destination->gpr[GEM_X64_R12] = source->x[19];
    destination->gpr[GEM_X64_R13] = source->x[20];
    destination->gpr[GEM_X64_R14] = source->x[21];
    destination->gpr[GEM_X64_R15] = source->x[22];
    destination->rip = source->pc;
    destination->rflags = gem_rflags_from_nzcv(source->nzcv, source->x64_rflags);
    destination->mxcsr = gem_mxcsr_from_fp(source->fpcr, source->fpsr);
    destination->fcw = source->x64_fcw;
    destination->fsw = source->x64_fsw;
    memcpy(destination->xmm, source->v, sizeof(destination->xmm));
    memcpy(destination->x87, source->x87, sizeof(destination->x87));
    destination->teb = source->teb;
    return true;
}

bool gem_context_x64_to_arm64ec(const struct gem_x64_context *source,
                                struct gem_thread_context *destination) {
    if (source == NULL || destination == NULL || source->teb == 0U ||
        !gem_fp_from_mxcsr_checked(source->mxcsr, NULL, NULL))
        return false;
    if (gem_context_is_valid(destination) && destination->isa != GEM_ISA_ARM64EC)
        return false;
    if (!gem_context_is_valid(destination))
        gem_context_initialize(destination, source->teb, GEM_ISA_ARM64EC);
    if (destination->teb != source->teb)
        return false;
    destination->x[8] = source->gpr[GEM_X64_RAX];
    destination->x[0] = source->gpr[GEM_X64_RCX];
    destination->x[1] = source->gpr[GEM_X64_RDX];
    destination->x[27] = source->gpr[GEM_X64_RBX];
    destination->sp = source->gpr[GEM_X64_RSP];
    destination->x[29] = source->gpr[GEM_X64_RBP];
    destination->x[25] = source->gpr[GEM_X64_RSI];
    destination->x[26] = source->gpr[GEM_X64_RDI];
    destination->x[2] = source->gpr[GEM_X64_R8];
    destination->x[3] = source->gpr[GEM_X64_R9];
    destination->x[4] = source->gpr[GEM_X64_R10];
    destination->x[5] = source->gpr[GEM_X64_R11];
    destination->x[19] = source->gpr[GEM_X64_R12];
    destination->x[20] = source->gpr[GEM_X64_R13];
    destination->x[21] = source->gpr[GEM_X64_R14];
    destination->x[22] = source->gpr[GEM_X64_R15];
    destination->pc = source->rip;
    destination->x64_rflags = source->rflags;
    destination->nzcv = gem_nzcv_from_rflags(source->rflags, destination->nzcv);
    {
        uint32_t converted_fpcr = 0U;
        uint32_t converted_fpsr = 0U;
        gem_fp_from_mxcsr(source->mxcsr, &converted_fpcr, &converted_fpsr);
        /* x64 has no representation for ARM-only state such as DN and QC. */
        destination->fpcr = (destination->fpcr & ~FPCR_MXCSR_MASK) | converted_fpcr;
        destination->fpsr = (destination->fpsr & ~FPSR_MXCSR_MASK) | converted_fpsr;
    }
    destination->x64_mxcsr = source->mxcsr;
    destination->x64_fcw = source->fcw;
    destination->x64_fsw = source->fsw;
    memcpy(destination->v, source->xmm, sizeof(destination->v));
    memcpy(destination->x87, source->x87, sizeof(destination->x87));
    destination->x[18] = destination->teb;
    destination->isa = GEM_ISA_ARM64EC;
    return true;
}
