// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/context_conversion.h"

#include <assert.h>
#include <string.h>

int main(void) {
    struct gem_thread_context arm;
    struct gem_x64_context x64;
    uint32_t flags;
    uint32_t fpcr;
    uint32_t fpsr;
    unsigned int i;
    static const unsigned int arm_gpr[] = {8, 0, 1, 27, 29, 25, 26, 2, 3, 4, 5, 19, 20, 21, 22};
    static const enum gem_x64_gpr x64_gpr[] = {GEM_X64_RAX, GEM_X64_RCX, GEM_X64_RDX, GEM_X64_RBX,
                                               GEM_X64_RBP, GEM_X64_RSI, GEM_X64_RDI, GEM_X64_R8,
                                               GEM_X64_R9,  GEM_X64_R10, GEM_X64_R11, GEM_X64_R12,
                                               GEM_X64_R13, GEM_X64_R14, GEM_X64_R15};
    gem_context_initialize(&arm, UINT64_C(0x12345000), GEM_ISA_ARM64EC);
    for (i = 0U; i < 16U; ++i) {
        arm.v[i].lo = i;
        arm.v[i].hi = ~UINT64_C(0) - i;
    }
    for (i = 0U; i < 8U; ++i) {
        arm.x87[i].lo = UINT64_C(0x100) + i;
        arm.x87[i].hi = UINT64_C(0x200) + i;
    }
    for (i = 0U; i < sizeof(arm_gpr) / sizeof(arm_gpr[0]); ++i)
        arm.x[arm_gpr[i]] = UINT64_C(0x1000) + i;
    arm.sp = UINT64_C(0x2000);
    arm.pc = UINT64_C(0x3000);
    arm.nzcv = UINT32_C(0xf0000000);
    arm.x64_rflags = UINT64_C(0x404);
    assert(gem_context_arm64ec_to_x64(&arm, &x64));
    for (i = 0U; i < sizeof(arm_gpr) / sizeof(arm_gpr[0]); ++i)
        assert(x64.gpr[x64_gpr[i]] == UINT64_C(0x1000) + i);
    assert(x64.gpr[GEM_X64_RSP] == UINT64_C(0x2000) && x64.rip == UINT64_C(0x3000));
    assert(memcmp(x64.xmm, arm.v, sizeof(x64.xmm)) == 0);
    assert(memcmp(x64.x87, arm.x87, sizeof(x64.x87)) == 0);
    assert((x64.rflags & UINT64_C(0x8c1)) == UINT64_C(0x8c1));
    assert(gem_context_x64_to_arm64ec(&x64, &arm));
    assert(arm.x[18] == arm.teb && arm.isa == GEM_ISA_ARM64EC);
    for (flags = 0U; flags < 16U; ++flags) {
        uint32_t nzcv = flags << 28;
        assert(gem_nzcv_from_rflags(gem_rflags_from_nzcv(nzcv, 0U), 0U) == nzcv);
    }
    /* Exhaust every status × mask × rounding × FZ combination. */
    for (flags = 0U; flags < 64U; ++flags) {
        uint32_t masks;
        for (masks = 0U; masks < 64U; ++masks) {
            uint32_t rounding;
            for (rounding = 0U; rounding < 4U; ++rounding) {
                uint32_t fz;
                for (fz = 0U; fz < 2U; ++fz) {
                    uint32_t mx = flags | (masks << 7) | (rounding << 13) | (fz << 15);
                    gem_fp_from_mxcsr(mx, &fpcr, &fpsr);
                    assert((gem_mxcsr_from_fp(fpcr, fpsr) & UINT32_C(0xffbf)) == mx);
                }
            }
        }
    }
    assert(!gem_fp_from_mxcsr_checked(UINT32_C(0x40), &fpcr, &fpsr));
    assert((gem_rflags_from_nzcv_for_arithmetic(UINT32_C(0x20000000), 0, GEM_ARITHMETIC_SUBTRACT) &
            1U) == 0U);
    assert((gem_nzcv_from_rflags_for_arithmetic(0, 0, GEM_ARITHMETIC_SUBTRACT) &
            UINT32_C(0x20000000)) != 0U);
    arm.isa = GEM_ISA_X64;
    assert(!gem_context_arm64ec_to_x64(&arm, &x64));
    arm.isa = GEM_ISA_ARM64EC;
    memset(&x64, 0, sizeof(x64));
    assert(!gem_context_x64_to_arm64ec(&x64, &arm));

    gem_context_initialize(&arm, UINT64_C(0x12345000), GEM_ISA_ARM64EC);
    arm.fpcr = UINT32_C(1) << 25; /* ARM-only default-NaN state. */
    arm.fpsr = UINT32_C(1) << 27; /* ARM-only cumulative saturation state. */
    memset(&x64, 0, sizeof(x64));
    x64.teb = arm.teb;
    x64.mxcsr = UINT32_C(0x1f80);
    assert(gem_context_x64_to_arm64ec(&x64, &arm));
    assert((arm.fpcr & (UINT32_C(1) << 25)) != 0U);
    assert((arm.fpsr & (UINT32_C(1) << 27)) != 0U);
    return 0;
}
