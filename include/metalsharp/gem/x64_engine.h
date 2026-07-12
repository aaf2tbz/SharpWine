// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_X64_ENGINE_H
#define METALSHARP_GEM_X64_ENGINE_H
#include "metalsharp/gem/context.h"
#include "metalsharp/gem/memory.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define GEM_X64_DEFAULT_HOST_RETURN_SENTINEL UINT64_C(0xfffffffffffffff0)
struct gem_x64_runtime;
enum gem_x64_memory_access {
    GEM_X64_ACCESS_NONE = 0,
    GEM_X64_ACCESS_FETCH = 1,
    GEM_X64_ACCESS_READ = 2,
    GEM_X64_ACCESS_WRITE = 3
};
struct gem_x64_runtime_config {
    uint64_t host_return_sentinel, max_budget;
};
struct gem_x64_stop_info {
    enum gem_stop_reason reason;
    uint64_t instructions_retired, fault_address;
    enum gem_x64_memory_access access;
    uint32_t memory_error, engine_status;
};
#if defined(__cplusplus)
static_assert(sizeof(struct gem_x64_stop_info) == 40U, "gem_x64_stop_info ABI changed");
#else
_Static_assert(sizeof(struct gem_x64_stop_info) == 40U, "gem_x64_stop_info ABI changed");
#endif
/* Runtime and associated memory are thread-confined. Calls made while a run is
 * active fail closed; GEM remains the sole canonical owner. */
struct gem_x64_runtime *gem_x64_runtime_create(struct gem_memory *,
                                               const struct gem_x64_runtime_config *);
void gem_x64_runtime_destroy(struct gem_x64_runtime *);
enum gem_stop_reason gem_x64_runtime_run(struct gem_x64_runtime *, struct gem_thread_context *,
                                         uint64_t);
bool gem_x64_runtime_last_stop_info(const struct gem_x64_runtime *, struct gem_x64_stop_info *);
/* The interpreter-only backend refreshes its transient page shadow before
 * every instruction and owns no translated-code cache, so invalidation is a
 * documented no-op. A future cache/JIT backend must replace this contract and
 * prove process-serialized generation plus cache maintenance before use. */
void gem_x64_runtime_invalidate_code(struct gem_x64_runtime *, uint64_t, uint64_t);
const char *gem_x64_runtime_engine_name(const struct gem_x64_runtime *);
const char *gem_x64_runtime_engine_version(const struct gem_x64_runtime *);
const char *gem_x64_runtime_engine_license(const struct gem_x64_runtime *);
const char *gem_x64_runtime_engine_provenance(const struct gem_x64_runtime *);
#ifdef __cplusplus
}
#endif
#endif
