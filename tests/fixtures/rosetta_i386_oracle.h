// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_ROSETTA_I386_ORACLE_H
#define METALSHARP_ROSETTA_I386_ORACLE_H

typedef unsigned int oracle_u32;

struct oracle_record {
    oracle_u32 case_id;
    oracle_u32 eax;
    oracle_u32 ebx;
    oracle_u32 ecx;
    oracle_u32 edx;
    oracle_u32 esi;
    oracle_u32 edi;
    oracle_u32 ebp;
    oracle_u32 esp_delta;
    oracle_u32 eflags;
    oracle_u32 memory[2];
    oracle_u32 xmm0[4];
    oracle_u32 x87[2];
};

void run_add32(struct oracle_record *record);
void run_shift32(struct oracle_record *record);
void run_memory32(struct oracle_record *record);
void run_sse2(struct oracle_record *record);
void run_x87(struct oracle_record *record);

#endif
