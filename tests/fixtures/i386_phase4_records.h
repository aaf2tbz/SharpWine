// SPDX-License-Identifier: Apache-2.0
#ifndef SHARPWINE_I386_PHASE4_RECORDS_H
#define SHARPWINE_I386_PHASE4_RECORDS_H

#include <stdint.h>

#if defined(I386_PHASE4_FREESTANDING)
#define GEM_I386_CONTEXT_LAYOUT_VERSION_V2 UINT32_C(2)
#define GEM_I386_CONTEXT_SIZE_V2 UINT32_C(448)
#define GEM_I386_EFLAGS_REQUIRED UINT32_C(2)
enum gem_i386_gpr {
    GEM_I386_EAX,
    GEM_I386_ECX,
    GEM_I386_EDX,
    GEM_I386_EBX,
    GEM_I386_ESP,
    GEM_I386_EBP,
    GEM_I386_ESI,
    GEM_I386_EDI
};
struct gem_u128 {
    uint64_t lo, hi;
};
struct gem_i386_x87_environment {
    uint32_t fip, fdp;
    uint16_t fcs, fds;
    uint32_t reserved[2];
};
struct gem_i386_context {
    uint32_t layout_version, context_size, gpr[8], eip, eflags;
    uint16_t segment[6];
    uint32_t segment_base[6], segment_limit[6], segment_attributes[6];
    struct gem_u128 xmm[8], x87[8];
    uint32_t mxcsr;
    uint16_t fcw, fsw, ftw, fop;
    uint32_t teb, reserved0;
    uint64_t transition_cookie;
    uint32_t stop_reason;
    union {
        uint32_t reserved[5];
        struct gem_i386_x87_environment x87_environment;
    };
};
#else
#include "metalsharp/gem/i386_context.h"
#endif

#define I386_PHASE4_SCHEMA UINT32_C(1)
#define I386_PHASE4_GENERATOR_VERSION UINT32_C(1)
#define I386_PHASE4_TEMPLATE_REVISION UINT32_C(1)
#define I386_PHASE4_MASTER_SEED UINT64_C(0x534841525057494e)
#define I386_PHASE4_SHARDS UINT32_C(16)
#define I386_PHASE4_CASES_PER_SHARD UINT32_C(4096)
#define I386_PHASE4_CASES UINT32_C(65536)
#define I386_PHASE4_NATIVE_COMPARISONS UINT32_C(131072)
#define I386_PHASE4_PARITY_COMPARISONS UINT32_C(65536)
#define I386_PHASE4_MEMORY_SIZE UINT32_C(512)

enum i386_phase4_category {
    I386_PHASE4_SCALAR = 1,
    I386_PHASE4_MEMORY = 2,
    I386_PHASE4_X87_MMX = 3,
    I386_PHASE4_SIMD = 4,
    I386_PHASE4_SYSTEM = 5,
    I386_PHASE4_NEGATIVE = 6
};

enum i386_phase4_comparison_policy {
    I386_PHASE4_COMPARE_EXACT = 0,
    I386_PHASE4_COMPARE_X87_BINARY64 = 1,
    I386_PHASE4_COMPARE_SIMD_ONE_ULP = 2
};

enum i386_phase4_classification {
    I386_PHASE4_PASS = 0,
    I386_PHASE4_SEMANTIC_MISMATCH = 1,
    I386_PHASE4_UNSUPPORTED_ADVERTISED = 2,
    I386_PHASE4_JIT_FALLBACK = 3,
    I386_PHASE4_TIMEOUT = 4,
    I386_PHASE4_CRASH = 5,
    I386_PHASE4_NONZERO_EXIT = 6,
    I386_PHASE4_MALFORMED_RECORD = 7,
    I386_PHASE4_INFRASTRUCTURE_FAILURE = 8
};

struct i386_phase4_defined_state {
    uint32_t gpr_mask;
    uint32_t eflags_mask;
    uint32_t segment_mask;
    uint32_t x87_environment_mask;
    uint64_t xmm_byte_mask;
    uint64_t x87_byte_mask;
    uint32_t mxcsr_mask;
    uint32_t memory_offset;
    uint32_t memory_size;
    uint32_t exception_mask;
};

struct i386_phase4_case {
    uint32_t schema_version;
    uint32_t generator_version;
    uint32_t template_revision;
    uint32_t template_id;
    uint32_t shard;
    uint32_t ordinal;
    uint64_t seed;
    enum i386_phase4_category category;
    enum i386_phase4_comparison_policy comparison_policy;
    uint8_t instruction[16];
    uint8_t instruction_size;
    uint8_t expected_negative;
    uint8_t reserved[2];
    struct gem_i386_context initial;
    struct i386_phase4_defined_state defined;
    uint8_t memory[I386_PHASE4_MEMORY_SIZE];
};

struct i386_phase4_record {
    uint32_t schema_version;
    uint32_t template_id;
    uint32_t shard;
    uint32_t ordinal;
    uint64_t seed;
    enum i386_phase4_category category;
    enum i386_phase4_classification classification;
    uint8_t instruction[16];
    uint8_t instruction_size;
    uint8_t reserved[3];
    struct gem_i386_context initial;
    struct gem_i386_context final;
    struct i386_phase4_defined_state defined;
    uint64_t memory_hash_before;
    uint64_t memory_hash_after;
    uint32_t stop_reason;
    uint32_t exception_status;
    uint32_t fault_address;
    uint32_t access;
    uint32_t memory_error;
    uint32_t retired_count;
    uint64_t jit_compilations;
    uint64_t jit_executions;
    uint64_t jit_failures;
};

uint64_t i386_phase4_splitmix64(uint64_t value);
uint64_t i386_phase4_case_seed(uint32_t shard, uint32_t ordinal);
int i386_phase4_generate(uint32_t shard, uint32_t ordinal, struct i386_phase4_case *out);
int i386_phase4_validate(const struct i386_phase4_case *test);
const char *i386_phase4_category_name(enum i386_phase4_category category);

#endif
