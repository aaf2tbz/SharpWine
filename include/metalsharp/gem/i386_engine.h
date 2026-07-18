// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_ENGINE_H
#define METALSHARP_GEM_I386_ENGINE_H

#include "metalsharp/gem/i386_context.h"
#include "metalsharp/gem/memory.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_I386_DEFAULT_HOST_RETURN_SENTINEL UINT32_C(0xfffffff0)
#define GEM_I386_BOUNDARY_WINDOWS_SYSCALL UINT32_C(1)
#define GEM_I386_BOUNDARY_UNIX_CALL UINT32_C(2)

/* Stable Windows-visible exception identities reported in
 * gem_i386_stop_info.engine_status when reason is
 * GEM_STOP_WINDOWS_EXCEPTION.  These values are part of the i386 engine ABI;
 * Blink-private halt values must never cross this boundary. */
#define GEM_I386_EXCEPTION_NONE UINT32_C(0)
#define GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION UINT32_C(1)
#define GEM_I386_EXCEPTION_BREAKPOINT UINT32_C(2)
#define GEM_I386_EXCEPTION_INTEGER_DIVIDE_BY_ZERO UINT32_C(3)
#define GEM_I386_EXCEPTION_INTEGER_OVERFLOW UINT32_C(4)
#define GEM_I386_EXCEPTION_STACK_OVERFLOW UINT32_C(5)
#define GEM_I386_EXCEPTION_GENERAL_PROTECTION UINT32_C(6)
#define GEM_I386_PERFORMANCE_INFO_ABI_VERSION UINT32_C(1)
#define GEM_I386_PERFORMANCE_INFO_V2_ABI_VERSION UINT32_C(2)
#define GEM_I386_DIAGNOSTICS_ABI_VERSION UINT32_C(1)
#define GEM_I386_DIAGNOSTIC_TEXT_BYTES UINT32_C(32)
#define GEM_I386_BLOCK_INFO_ABI_VERSION UINT32_C(1)

struct gem_i386_runtime;

enum gem_i386_engine_mode {
    GEM_I386_ENGINE_DEFAULT = 0,
    GEM_I386_ENGINE_JIT = 1,
    GEM_I386_ENGINE_INTERPRETER = 2,
};

enum gem_i386_host_arch {
    GEM_I386_HOST_UNKNOWN = 0,
    GEM_I386_HOST_AARCH64 = 1,
};

enum gem_i386_memory_access {
    GEM_I386_ACCESS_NONE = 0,
    GEM_I386_ACCESS_FETCH = 1,
    GEM_I386_ACCESS_READ = 2,
    GEM_I386_ACCESS_WRITE = 3,
};

struct gem_i386_runtime_config {
    uint32_t host_return_sentinel;
    uint32_t windows_syscall_boundary;
    uint32_t unix_call_boundary;
    enum gem_i386_engine_mode engine_mode;
    uint64_t max_budget;
    uint64_t max_generated_code_bytes;
    uint32_t reserved[4];
};

struct gem_i386_engine_info {
    uint32_t abi_version;
    uint32_t size;
    enum gem_i386_engine_mode engine_mode;
    enum gem_i386_host_arch host_arch;
    uint64_t jit_compilations;
    uint64_t jit_executions;
    uint64_t jit_failures;
    uint32_t write_xor_execute;
    uint32_t reserved;
};

struct gem_i386_stop_info {
    enum gem_stop_reason reason;
    uint32_t instructions_retired;
    uint32_t fault_address;
    enum gem_i386_memory_access access;
    uint32_t memory_error;
    uint32_t engine_status;
    uint32_t reserved;
};

struct gem_i386_performance_info {
    uint32_t abi_version;
    uint32_t size;
    uint64_t retired_instructions;
    uint64_t quanta;
    uint64_t retries;
    uint64_t page_snapshots;
    uint64_t bytes_copied;
    uint64_t bytes_committed;
    uint64_t state_imports;
    uint64_t state_exports;
    uint64_t decode_resets;
    uint64_t lock_wait_nanoseconds;
};

/* Versioned extension; the v1 query and its 88-byte layout remain unchanged. */
struct gem_i386_performance_info_v2 {
    uint32_t abi_version;
    uint32_t size;
    uint64_t retired_instructions;
    uint64_t quanta;
    uint64_t retries;
    uint64_t page_snapshots;
    uint64_t bytes_copied;
    uint64_t bytes_committed;
    uint64_t state_imports;
    uint64_t state_exports;
    uint64_t decode_resets;
    uint64_t lock_wait_nanoseconds;
    uint64_t jit_compilations;
    uint64_t jit_executions;
    uint64_t jit_cache_hits;
    uint64_t jit_failures;
    uint64_t code_invalidations;
};

/* Fixed-size, process-local evidence for app traces and support reports.  The
 * CPUID values are the exact deterministic legacy profile exposed to guests;
 * tests execute CPUID and compare the result to this snapshot so the report
 * cannot silently drift from implemented capability. */
struct gem_i386_diagnostics {
    uint32_t abi_version;
    uint32_t size;
    enum gem_i386_engine_mode engine_mode;
    enum gem_i386_host_arch host_arch;
    uint32_t cpuid_leaf1_ecx;
    uint32_t cpuid_leaf1_edx;
    uint32_t cpuid_leaf7_ebx;
    uint32_t cpuid_leaf7_ecx;
    uint32_t cpuid_extended1_edx;
    uint32_t last_unsupported_eip;
    uint32_t last_unsupported_mopcode;
    uint32_t last_unsupported_length;
    uint64_t jit_compilations;
    uint64_t jit_executions;
    uint64_t jit_cache_hits;
    uint64_t jit_failures;
    uint64_t code_invalidations;
    uint64_t interpreter_fallbacks;
    uint64_t unsupported_instructions;
    char engine_name[GEM_I386_DIAGNOSTIC_TEXT_BYTES];
    char engine_version[GEM_I386_DIAGNOSTIC_TEXT_BYTES];
    char last_unsupported_name[GEM_I386_DIAGNOSTIC_TEXT_BYTES];
    uint64_t blocks_created;
    uint64_t block_cache_hits;
    uint64_t direct_link_hits;
    uint64_t call_predictions;
    uint64_t return_predictions;
    uint64_t return_prediction_hits;
    uint64_t block_invalidations;
};

struct gem_i386_block_info {
    uint32_t abi_version;
    uint32_t size;
    uint64_t blocks_created;
    uint64_t block_lookups;
    uint64_t block_cache_hits;
    uint64_t direct_link_hits;
    uint64_t call_predictions;
    uint64_t return_predictions;
    uint64_t return_prediction_hits;
    uint64_t return_prediction_misses;
    uint64_t block_invalidations;
};

struct gem_i386_runtime *gem_i386_runtime_create(struct gem_memory *memory,
                                                 const struct gem_i386_runtime_config *config);
void gem_i386_runtime_destroy(struct gem_i386_runtime *runtime);
enum gem_stop_reason gem_i386_runtime_run(struct gem_i386_runtime *runtime,
                                          struct gem_i386_context *context, uint64_t budget);
bool gem_i386_runtime_last_stop_info(const struct gem_i386_runtime *runtime,
                                     struct gem_i386_stop_info *out);
bool gem_i386_runtime_engine_info(const struct gem_i386_runtime *runtime,
                                  struct gem_i386_engine_info *out);
bool gem_i386_runtime_performance_info(const struct gem_i386_runtime *runtime,
                                       struct gem_i386_performance_info *out);
bool gem_i386_runtime_performance_info_v2(const struct gem_i386_runtime *runtime,
                                          struct gem_i386_performance_info_v2 *out);
bool gem_i386_runtime_diagnostics(const struct gem_i386_runtime *runtime,
                                  struct gem_i386_diagnostics *out);
bool gem_i386_runtime_block_info(const struct gem_i386_runtime *runtime,
                                 struct gem_i386_block_info *out);
void gem_i386_runtime_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                      uint64_t size);
void gem_i386_runtime_invalidate_memory(struct gem_i386_runtime *runtime, uint32_t address,
                                        uint64_t size);
bool gem_i386_runtime_set_precise_host_dirty(struct gem_i386_runtime *runtime, bool enabled);
void gem_i386_runtime_request_async_stop(struct gem_i386_runtime *runtime);
const char *gem_i386_runtime_engine_name(const struct gem_i386_runtime *runtime);
const char *gem_i386_runtime_engine_version(const struct gem_i386_runtime *runtime);
const char *gem_i386_runtime_engine_license(const struct gem_i386_runtime *runtime);
const char *gem_i386_runtime_engine_provenance(const struct gem_i386_runtime *runtime);

#ifdef __cplusplus
}
#endif

#endif
