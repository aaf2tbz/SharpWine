// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_HYBRID_RUNTIME_H
#define METALSHARP_GEM_HYBRID_RUNTIME_H

#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/arm64ec_target.h"
#include "metalsharp/gem/x64_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_HYBRID_RUNTIME_CONFIG_VERSION UINT32_C(1)

struct gem_hybrid_runtime_config {
    uint32_t version;
    uint32_t reserved;
    uint64_t loaded_base;
    uint64_t checker_helper;
    uint64_t dispatch_call_helper;
    uint64_t dispatch_ret_helper;
    uint64_t x64_return_sentinel;
    uint64_t host_return_sentinel;
    uint64_t max_budget;
};

struct gem_hybrid_roundtrip_stats {
    uint64_t arm64ec_instructions_retired;
    uint64_t x64_instructions_retired;
    uint64_t checker_boundaries;
    uint64_t dispatch_call_boundaries;
    uint64_t x64_to_arm64ec_boundaries;
    uint64_t descriptor_resolutions;
    uint64_t dispatch_ret_boundaries;
    uint64_t frame_pushes;
    uint64_t frame_pops;
    uint32_t maximum_frame_depth;
    uint32_t final_frame_depth;
};

struct gem_hybrid_runtime;

/* Phase-3 integer proof coordinator. It owns one bounded sidecar frame and two
 * transient engines over the caller's single GEM memory. The context remains
 * the sole canonical CPU state and must enter as ARM64EC with a clear cookie.
 * A failed run restores the entry context and any broker-inserted stack record,
 * clears the sidecar frame, and remains reusable. Successfully retired guest
 * instructions remain individually committed to GEM memory; one-shot guard
 * consumption is likewise not reversed. */
struct gem_hybrid_runtime *
gem_hybrid_runtime_create(struct gem_memory *memory, const struct gem_pe_arm64x_image *image,
                          const struct gem_hybrid_runtime_config *config);
void gem_hybrid_runtime_destroy(struct gem_hybrid_runtime *runtime);
enum gem_stop_reason gem_hybrid_runtime_run_integer_roundtrip(
    struct gem_hybrid_runtime *runtime, struct gem_thread_context *context, uint64_t caller_va,
    uint64_t finish_va, uint64_t budget, struct gem_hybrid_roundtrip_stats *stats);

#ifdef __cplusplus
}
#endif
#endif
