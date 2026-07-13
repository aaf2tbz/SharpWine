// SPDX-License-Identifier: Apache-2.0
#include "arm64ec_engine_internal.h"

#include <stdlib.h>
#include <string.h>

#if !defined(MSWR_ARM64EC_DYNARMIC_ENABLED)
bool gem_arm64ec_dynarmic_create(struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
    return false;
}
void gem_arm64ec_dynarmic_destroy(struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
}
enum gem_stop_reason gem_arm64ec_dynarmic_run(struct gem_arm64ec_runtime *runtime,
                                              struct gem_thread_context *context, uint64_t budget) {
    (void)runtime;
    (void)context;
    (void)budget;
    return GEM_STOP_INVARIANT_VIOLATION;
}
void gem_arm64ec_dynarmic_invalidate_code(struct gem_arm64ec_runtime *runtime, uint64_t address,
                                          uint64_t size) {
    (void)runtime;
    (void)address;
    (void)size;
}
const char *gem_arm64ec_dynarmic_engine_name(void) {
    return "unavailable";
}
const char *gem_arm64ec_dynarmic_engine_version(void) {
    return "unavailable";
}
const char *gem_arm64ec_dynarmic_engine_license(void) {
    return "unavailable";
}
const char *gem_arm64ec_dynarmic_engine_provenance(void) {
    return "unavailable";
}
#endif

static _Thread_local struct gem_arm64ec_runtime *gem_current_runtime;

static void reset_stop(struct gem_arm64ec_runtime *runtime, enum gem_stop_reason reason) {
    if (runtime != NULL) {
        memset(&runtime->last_stop, 0, sizeof(runtime->last_stop));
        runtime->last_stop.reason = reason;
    }
}

static enum gem_stop_reason finish_stop(struct gem_arm64ec_runtime *runtime,
                                        struct gem_thread_context *context,
                                        enum gem_stop_reason reason) {
    if (context != NULL)
        context->stop_reason = (uint32_t)reason;
    if (runtime != NULL)
        runtime->last_stop.reason = reason;
    return reason;
}

static bool context_is_arm64ec_valid(const struct gem_thread_context *context) {
    return gem_context_is_valid(context) && context->isa == (uint32_t)GEM_ISA_ARM64EC;
}

struct gem_arm64ec_runtime *
gem_arm64ec_runtime_create(struct gem_memory *memory,
                           const struct gem_arm64ec_runtime_config *config) {
    struct gem_arm64ec_runtime *runtime;

    if (memory == NULL)
        return NULL;
    runtime = calloc(1, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;

    runtime->memory = memory;
    if (config != NULL)
        runtime->config = *config;
    if (runtime->config.execution_profile < GEM_ARM64EC_PROFILE_STRICT ||
        runtime->config.execution_profile > GEM_ARM64EC_PROFILE_NATIVE_ARM64 ||
        runtime->config.reserved != 0U) {
        free(runtime);
        return NULL;
    }
    if (runtime->config.host_return_sentinel == 0U)
        runtime->config.host_return_sentinel = GEM_ARM64EC_DEFAULT_HOST_RETURN_SENTINEL;
    if (runtime->config.arch_transition_sentinel == 0U)
        runtime->config.arch_transition_sentinel = GEM_ARM64EC_DEFAULT_ARCH_TRANSITION_SENTINEL;

    reset_stop(runtime, GEM_STOP_NONE);
    if (!gem_arm64ec_dynarmic_create(runtime)) {
        free(runtime);
        return NULL;
    }
    return runtime;
}

void gem_arm64ec_runtime_destroy(struct gem_arm64ec_runtime *runtime) {
    if (runtime != NULL) {
        if (gem_current_runtime == runtime)
            gem_current_runtime = NULL;
        gem_arm64ec_dynarmic_destroy(runtime);
        gem_arm64ec_target_map_destroy(runtime->target_map);
        free(runtime);
    }
}

bool gem_arm64ec_runtime_attach_arm64x(struct gem_arm64ec_runtime *runtime,
                                       const struct gem_pe_arm64x_image *image,
                                       uint64_t loaded_image_base) {
    struct gem_arm64ec_target_map *map = NULL;
    if (runtime == NULL || image == NULL || runtime->running ||
        runtime->config.execution_profile != GEM_ARM64EC_PROFILE_STRICT)
        return false;
    if (gem_arm64ec_target_map_create(image, loaded_image_base, &map) != GEM_ARM64EC_TARGET_OK)
        return false;
    gem_arm64ec_target_map_destroy(runtime->target_map);
    runtime->target_map = map;
    gem_arm64ec_dynarmic_invalidate_code(runtime, loaded_image_base, UINT64_MAX);
    return true;
}

enum gem_stop_reason gem_arm64ec_runtime_run(struct gem_arm64ec_runtime *runtime,
                                             struct gem_thread_context *context, uint64_t budget) {
    enum gem_stop_reason reason;

    if (runtime == NULL)
        return GEM_STOP_INVARIANT_VIOLATION;
    reset_stop(runtime, GEM_STOP_NONE);
    runtime->transition_count = 0U;
    /* Validate the complete public context contract before changing any of its
     * 720 bytes. Rejection is observable through the return value and runtime
     * stop information, never by partially canonicalizing invalid input. */
    if (!context_is_arm64ec_valid(context)) {
        runtime->last_stop.reason = GEM_STOP_INVARIANT_VIOLATION;
        return GEM_STOP_INVARIANT_VIOLATION;
    }
    if (runtime->config.max_budget != 0U && budget > runtime->config.max_budget) {
        runtime->last_stop.reason = GEM_STOP_INVARIANT_VIOLATION;
        return GEM_STOP_INVARIANT_VIOLATION;
    }
    if (budget == 0U) {
        runtime->last_stop.instructions_retired = 0U;
        return finish_stop(runtime, context, GEM_STOP_BUDGET_EXPIRED);
    }

    if (runtime->running) {
        runtime->last_stop.reason = GEM_STOP_INVARIANT_VIOLATION;
        return GEM_STOP_INVARIANT_VIOLATION;
    }
    runtime->running = true;
    reason = gem_arm64ec_dynarmic_run(runtime, context, budget);
    runtime->running = false;
    if (!context_is_arm64ec_valid(context)) {
        runtime->last_stop.instructions_retired = 0U;
        reason = GEM_STOP_INVARIANT_VIOLATION;
    }
    return finish_stop(runtime, context, reason);
}

void gem_arm64ec_runtime_request_async_stop(struct gem_arm64ec_runtime *runtime) {
    if (runtime != NULL)
        gem_arm64ec_dynarmic_request_async_stop(runtime);
}

bool gem_arm64ec_runtime_last_stop_info(const struct gem_arm64ec_runtime *runtime,
                                        struct gem_arm64ec_stop_info *out_info) {
    if (runtime == NULL || out_info == NULL)
        return false;
    *out_info = runtime->last_stop;
    return true;
}

bool gem_arm64ec_runtime_set_native_upper_simd(struct gem_arm64ec_runtime *runtime,
                                               const struct gem_u128 vectors[16]) {
    if (runtime == NULL || vectors == NULL || runtime->running ||
        runtime->config.execution_profile != GEM_ARM64EC_PROFILE_NATIVE_ARM64)
        return false;
    memcpy(runtime->native_upper_simd, vectors, sizeof(runtime->native_upper_simd));
    return true;
}

bool gem_arm64ec_runtime_get_native_upper_simd(const struct gem_arm64ec_runtime *runtime,
                                               struct gem_u128 vectors[16]) {
    if (runtime == NULL || vectors == NULL || runtime->running ||
        runtime->config.execution_profile != GEM_ARM64EC_PROFILE_NATIVE_ARM64)
        return false;
    memcpy(vectors, runtime->native_upper_simd, sizeof(runtime->native_upper_simd));
    return true;
}

bool gem_arm64ec_runtime_set_boundary_broker(struct gem_arm64ec_runtime *runtime,
                                             gem_arm64ec_boundary_fn broker, void *opaque) {
    if (runtime == NULL || runtime->running)
        return false;
    runtime->boundary_broker = broker;
    runtime->boundary_opaque = opaque;
    return true;
}

uint64_t gem_arm64ec_runtime_transition_count(const struct gem_arm64ec_runtime *runtime) {
    return runtime != NULL ? runtime->transition_count : 0U;
}

void gem_arm64ec_runtime_invalidate_code(struct gem_arm64ec_runtime *runtime, uint64_t address,
                                         uint64_t size) {
    if (runtime != NULL && size != 0U)
        gem_arm64ec_dynarmic_invalidate_code(runtime, address, size);
}

const char *gem_arm64ec_runtime_engine_name(const struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
    return gem_arm64ec_dynarmic_engine_name();
}

const char *gem_arm64ec_runtime_engine_version(const struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
    return gem_arm64ec_dynarmic_engine_version();
}

const char *gem_arm64ec_runtime_engine_license(const struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
    return gem_arm64ec_dynarmic_engine_license();
}

const char *gem_arm64ec_runtime_engine_provenance(const struct gem_arm64ec_runtime *runtime) {
    (void)runtime;
    return gem_arm64ec_dynarmic_engine_provenance();
}

bool gem_arm64ec_set_current_runtime(struct gem_arm64ec_runtime *runtime) {
    gem_current_runtime = runtime;
    return true;
}

enum gem_stop_reason gem_run_arm64ec(struct gem_thread_context *context, uint64_t budget) {
    if (gem_current_runtime == NULL)
        return GEM_STOP_INVARIANT_VIOLATION;
    return gem_arm64ec_runtime_run(gem_current_runtime, context, budget);
}
