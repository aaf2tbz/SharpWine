// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_ARM64EC_ENGINE_INTERNAL_H
#define METALSHARP_GEM_ARM64EC_ENGINE_INTERNAL_H

#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/arm64ec_target.h"

#ifdef __cplusplus
extern "C" {
#endif

struct gem_arm64ec_runtime {
    struct gem_memory *memory;
    struct gem_arm64ec_runtime_config config;
    struct gem_arm64ec_stop_info last_stop;
    struct gem_arm64ec_target_map *target_map;
    gem_arm64ec_boundary_fn boundary_broker;
    void *boundary_opaque;
    uint64_t transition_count;
    struct gem_u128 native_upper_simd[16];
    bool running;
    void *backend;
};

bool gem_arm64ec_dynarmic_create(struct gem_arm64ec_runtime *runtime);
void gem_arm64ec_dynarmic_destroy(struct gem_arm64ec_runtime *runtime);
enum gem_stop_reason gem_arm64ec_dynarmic_run(struct gem_arm64ec_runtime *runtime,
                                              struct gem_thread_context *context, uint64_t budget);
void gem_arm64ec_dynarmic_request_async_stop(struct gem_arm64ec_runtime *runtime);
void gem_arm64ec_dynarmic_invalidate_code(struct gem_arm64ec_runtime *runtime, uint64_t address,
                                          uint64_t size);
const char *gem_arm64ec_dynarmic_engine_name(void);
const char *gem_arm64ec_dynarmic_engine_version(void);
const char *gem_arm64ec_dynarmic_engine_license(void);
const char *gem_arm64ec_dynarmic_engine_provenance(void);

#ifdef __cplusplus
}
#endif

#endif
