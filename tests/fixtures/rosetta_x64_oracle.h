// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_ROSETTA_X64_ORACLE_H
#define METALSHARP_ROSETTA_X64_ORACLE_H

#include <stdint.h>

struct rosetta_x64_record {
    uint32_t case_id;
    uint32_t reserved;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rflags;
    uint32_t memory[2];
    uint32_t xmm0[4];
    uint32_t ymm0[8];
};

extern const unsigned char rosetta_x64_add_start[];
extern const unsigned char rosetta_x64_add_end[];
extern const unsigned char rosetta_x64_shift_start[];
extern const unsigned char rosetta_x64_shift_end[];
extern const unsigned char rosetta_x64_memory_start[];
extern const unsigned char rosetta_x64_memory_end[];
extern const unsigned char rosetta_x64_sse2_start[];
extern const unsigned char rosetta_x64_sse2_end[];
extern const unsigned char rosetta_x64_avx2_start[];
extern const unsigned char rosetta_x64_avx2_end[];

#endif
