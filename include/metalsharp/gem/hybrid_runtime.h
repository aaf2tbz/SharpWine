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

enum gem_hybrid_return_mode {
    GEM_HYBRID_RETURN_NORMAL = 1,
    GEM_HYBRID_RETURN_TAIL = 2,
};

struct gem_hybrid_return_control {
    enum gem_hybrid_return_mode mode;
    uint32_t reserved;
    uint64_t requested_start_va;
    uint64_t expected_resolved_start_va;
    uint64_t expected_x64_target_va;
};

struct gem_hybrid_nested_control {
    uint32_t version;
    uint32_t reserved;
    uint64_t requested_start_va;
    uint64_t expected_resolved_start_va;
    uint64_t outer_x64_target_va;
    uint64_t callback_va;
    uint64_t outer_resume_va;
    uint64_t inner_x64_target_va;
};

#define GEM_HYBRID_NESTED_CONTROL_VERSION UINT32_C(1)

enum gem_hybrid_stop_source {
    GEM_HYBRID_STOP_SOURCE_BROKER = 0,
    GEM_HYBRID_STOP_SOURCE_ARM64EC = 1,
    GEM_HYBRID_STOP_SOURCE_X64 = 2,
};

/* Exact engine stop details from the most recent run. The source selects the
 * valid engine member. Broker-generated invariant failures have source BROKER
 * and zeroed engine details. This sidecar does not change the canonical
 * 720-byte thread-context ABI. */
struct gem_hybrid_stop_info {
    enum gem_stop_reason reason;
    enum gem_hybrid_stop_source source;
    struct gem_arm64ec_stop_info arm64ec;
    struct gem_x64_stop_info x64;
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
/* Coordinates an authentic ARM64EC exit thunk, x64 RET, and return through
 * the incoming ARM64EC LR. Control addresses are checked against ARM64X
 * metadata before execution. */
enum gem_stop_reason
gem_hybrid_runtime_run_integer_return(struct gem_hybrid_runtime *runtime,
                                      struct gem_thread_context *context,
                                      const struct gem_hybrid_return_control *control,
                                      uint64_t budget, struct gem_hybrid_roundtrip_stats *stats);
/* Runs only the bounded x64 CALL -> ARM64EC callback -> x64 resumption segment.
 * The CALL-owned return record remains committed on both success and later
 * failure; canonical CPU state is restored on failure. */
enum gem_stop_reason gem_hybrid_runtime_run_integer_callback_resume(
    struct gem_hybrid_runtime *runtime, struct gem_thread_context *context, uint64_t callback_va,
    uint64_t expected_resume_va, uint64_t budget, struct gem_hybrid_roundtrip_stats *stats);
/* Executes the evidenced depth-2 integer path ARM64EC -> x64 -> ARM64EC ->
 * x64 -> ARM64EC. The outer and inner broker records are bounded, checked,
 * restored independently, and never become part of the 720-byte context ABI. */
enum gem_stop_reason
gem_hybrid_runtime_run_integer_nested(struct gem_hybrid_runtime *runtime,
                                      struct gem_thread_context *context,
                                      const struct gem_hybrid_nested_control *control,
                                      uint64_t budget, struct gem_hybrid_roundtrip_stats *stats);
bool gem_hybrid_runtime_last_stop_info(const struct gem_hybrid_runtime *runtime,
                                       struct gem_hybrid_stop_info *out_info);

#ifdef __cplusplus
}
#endif
#endif
