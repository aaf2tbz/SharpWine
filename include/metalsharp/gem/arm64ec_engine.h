// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_ARM64EC_ENGINE_H
#define METALSHARP_GEM_ARM64EC_ENGINE_H

#include "metalsharp/gem/context.h"
#include "metalsharp/gem/memory.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_ARM64EC_DEFAULT_HOST_RETURN_SENTINEL UINT64_C(0xfffffffffffffff0)
#define GEM_ARM64EC_DEFAULT_ARCH_TRANSITION_SENTINEL UINT64_C(0xffffffffffffffe0)

struct gem_arm64ec_runtime;
struct gem_pe_arm64x_image;

enum gem_arm64ec_boundary_kind {
    GEM_ARM64EC_BOUNDARY_CHECK_ICALL = 1,
    GEM_ARM64EC_BOUNDARY_CHECK_ICALL_CFG = 2,
    GEM_ARM64EC_BOUNDARY_DISPATCH_CALL = 3,
    GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN = 4,
};

enum gem_arm64ec_boundary_action {
    GEM_ARM64EC_BOUNDARY_NOT_HANDLED = 0,
    GEM_ARM64EC_BOUNDARY_RESUME = 1,
    GEM_ARM64EC_BOUNDARY_STOP = 2,
    GEM_ARM64EC_BOUNDARY_FAIL = 3,
};

/* Invoked immediately before a guest instruction fetch. The callback may
 * broker only an address it recognizes. RESUME must change context->pc;
 * STOP leaves the approved boundary unfetched; FAIL is fail-closed. */
typedef enum gem_arm64ec_boundary_action (*gem_arm64ec_boundary_fn)(
    void *opaque, uint64_t pc, struct gem_thread_context *context,
    enum gem_arm64ec_boundary_kind *out_kind);

enum gem_arm64ec_memory_access {
    GEM_ARM64EC_ACCESS_NONE = 0,
    GEM_ARM64EC_ACCESS_FETCH = 1,
    GEM_ARM64EC_ACCESS_READ = 2,
    GEM_ARM64EC_ACCESS_WRITE = 3,
};

enum gem_arm64ec_execution_profile {
    /* Checked ARM64EC rules, including the forbidden architectural-register
     * operand decoder, remain the default for zero-initialized configs. */
    GEM_ARM64EC_PROFILE_STRICT = 0,
    /* Native Windows ARM64 code still runs under GEM, keeps x18 equal to the
     * canonical TEB after every instruction, and never executes on the host.
     * It is not valid for an attached ARM64X metadata map. */
    GEM_ARM64EC_PROFILE_NATIVE_ARM64 = 1,
};

struct gem_arm64ec_runtime_config {
    uint64_t host_return_sentinel;
    uint64_t arch_transition_sentinel;
    uint64_t max_budget;
    uint64_t max_transitions;
    enum gem_arm64ec_execution_profile execution_profile;
    uint32_t reserved;
};

struct gem_arm64ec_stop_info {
    enum gem_stop_reason reason;
    uint64_t instructions_retired;
    uint64_t fault_address;
    enum gem_arm64ec_memory_access access;
    uint32_t memory_error;
    uint32_t engine_status;
};

#if defined(__cplusplus)
static_assert(sizeof(enum gem_arm64ec_memory_access) == sizeof(int),
              "gem_arm64ec_memory_access ABI changed");
static_assert(sizeof(enum gem_arm64ec_execution_profile) == sizeof(int),
              "gem_arm64ec_execution_profile ABI changed");
static_assert(sizeof(struct gem_arm64ec_runtime_config) == 40U,
              "gem_arm64ec_runtime_config ABI changed");
static_assert(sizeof(struct gem_arm64ec_stop_info) == 40U, "gem_arm64ec_stop_info ABI changed");
#else
_Static_assert(sizeof(enum gem_arm64ec_memory_access) == sizeof(int),
               "gem_arm64ec_memory_access ABI changed");
_Static_assert(sizeof(enum gem_arm64ec_execution_profile) == sizeof(int),
               "gem_arm64ec_execution_profile ABI changed");
_Static_assert(sizeof(struct gem_arm64ec_runtime_config) == 40U,
               "gem_arm64ec_runtime_config ABI changed");
_Static_assert(sizeof(struct gem_arm64ec_stop_info) == 40U, "gem_arm64ec_stop_info ABI changed");
#endif

struct gem_arm64ec_runtime *
gem_arm64ec_runtime_create(struct gem_memory *memory,
                           const struct gem_arm64ec_runtime_config *config);
void gem_arm64ec_runtime_destroy(struct gem_arm64ec_runtime *runtime);

/* Attaches an immutable metadata clone. Runtime execution is then restricted
 * to checked ARM64/ARM64EC ranges and stops before metadata-classified x64.
 * This API is thread-confined and rejects replacement while a run is active. */
bool gem_arm64ec_runtime_attach_arm64x(struct gem_arm64ec_runtime *runtime,
                                       const struct gem_pe_arm64x_image *image,
                                       uint64_t loaded_image_base);

enum gem_stop_reason gem_arm64ec_runtime_run(struct gem_arm64ec_runtime *runtime,
                                             struct gem_thread_context *context, uint64_t budget);

/* Requests a bounded GEM_STOP_ASYNC_REQUEST from another thread or a signal
 * handler.  The request does not acquire GEM memory or runtime locks. */
void gem_arm64ec_runtime_request_async_stop(struct gem_arm64ec_runtime *runtime);

bool gem_arm64ec_runtime_last_stop_info(const struct gem_arm64ec_runtime *runtime,
                                        struct gem_arm64ec_stop_info *out_info);

/* Native Windows ARM64 has 32 architectural SIMD registers while the fixed
 * ARM64EC context ABI carries v0-v15.  The native profile keeps v16-v31 in a
 * runtime-owned sidecar so bounded stops and Wine callbacks do not lose
 * state without changing the 720-byte public context. */
bool gem_arm64ec_runtime_set_native_upper_simd(struct gem_arm64ec_runtime *runtime,
                                               const struct gem_u128 vectors[16]);
bool gem_arm64ec_runtime_get_native_upper_simd(const struct gem_arm64ec_runtime *runtime,
                                               struct gem_u128 vectors[16]);

bool gem_arm64ec_runtime_set_boundary_broker(struct gem_arm64ec_runtime *runtime,
                                             gem_arm64ec_boundary_fn broker, void *opaque);
uint64_t gem_arm64ec_runtime_transition_count(const struct gem_arm64ec_runtime *runtime);

void gem_arm64ec_runtime_invalidate_code(struct gem_arm64ec_runtime *runtime, uint64_t address,
                                         uint64_t size);

const char *gem_arm64ec_runtime_engine_name(const struct gem_arm64ec_runtime *runtime);
const char *gem_arm64ec_runtime_engine_version(const struct gem_arm64ec_runtime *runtime);
const char *gem_arm64ec_runtime_engine_license(const struct gem_arm64ec_runtime *runtime);
const char *gem_arm64ec_runtime_engine_provenance(const struct gem_arm64ec_runtime *runtime);

bool gem_arm64ec_set_current_runtime(struct gem_arm64ec_runtime *runtime);

enum gem_stop_reason gem_run_arm64ec(struct gem_thread_context *context, uint64_t budget);

#ifdef __cplusplus
}
#endif

#endif
