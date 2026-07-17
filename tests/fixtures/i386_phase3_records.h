// SPDX-License-Identifier: Apache-2.0
#ifndef SHARPWINE_I386_PHASE3_RECORDS_H
#define SHARPWINE_I386_PHASE3_RECORDS_H

#include "metalsharp/gem/i386_context.h"

#include <stdint.h>

#define I386_PHASE3_CORPUS_SCHEMA UINT32_C(1)
#define I386_PHASE3_X87_CASES UINT32_C(256)
#define I386_PHASE3_MMX_CASES UINT32_C(128)
#define I386_PHASE3_SIMD_CASES UINT32_C(384)
#define I386_PHASE3_REP_SEGMENT_CASES UINT32_C(160)
#define I386_PHASE3_CPUID_CONTEXT_CASES UINT32_C(96)
#define I386_PHASE3_CASES UINT32_C(1024)
#define I386_PHASE3_COMPARISONS UINT32_C(2048)
#define I386_PHASE3_REFERENCE_MAGIC UINT32_C(0x334d4547)

struct i386_phase3_file_header {
    uint32_t magic;
    uint32_t schema_version;
    uint32_t record_size;
    uint32_t record_count;
};

enum i386_phase3_category {
    I386_PHASE3_X87 = 1,
    I386_PHASE3_MMX = 2,
    I386_PHASE3_SIMD = 3,
    I386_PHASE3_REP_SEGMENT = 4,
    I386_PHASE3_CPUID_CONTEXT = 5
};

/* A replay record contains every Phase 3 architectural output. The defined
 * mask makes compatibility-tolerance decisions explicit instead of comparing
 * host padding or undefined flags. Memory hashes cover both source and
 * destination regions before and after execution. */
struct i386_phase3_record {
    uint32_t schema_version;
    uint32_t case_id;
    enum i386_phase3_category category;
    uint8_t instruction[16];
    uint8_t instruction_size;
    uint8_t reserved[3];
    struct gem_i386_context initial;
    struct gem_i386_context final;
    uint64_t defined_context_mask;
    uint64_t memory_hash_before;
    uint64_t memory_hash_after;
    uint32_t stop_reason;
    uint32_t exception_status;
    uint32_t fault_address;
    uint32_t access;
    uint32_t memory_error;
    uint32_t retired_count;
    uint32_t reserved1;
};

#if defined(__cplusplus)
static_assert(sizeof(struct i386_phase3_file_header) == 16U, "Phase 3 file header drift");
static_assert(sizeof(struct i386_phase3_record) == 984U, "Phase 3 record layout drift");
#else
_Static_assert(sizeof(struct i386_phase3_file_header) == 16U, "Phase 3 file header drift");
_Static_assert(sizeof(struct i386_phase3_record) == 984U, "Phase 3 record layout drift");
#endif

#endif
