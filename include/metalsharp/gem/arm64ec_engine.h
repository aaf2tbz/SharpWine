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

enum gem_arm64ec_memory_access {
    GEM_ARM64EC_ACCESS_NONE = 0,
    GEM_ARM64EC_ACCESS_FETCH = 1,
    GEM_ARM64EC_ACCESS_READ = 2,
    GEM_ARM64EC_ACCESS_WRITE = 3,
};

struct gem_arm64ec_runtime_config {
    uint64_t host_return_sentinel;
    uint64_t arch_transition_sentinel;
    uint64_t max_budget;
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
static_assert(sizeof(struct gem_arm64ec_stop_info) == 40U, "gem_arm64ec_stop_info ABI changed");
#else
_Static_assert(sizeof(enum gem_arm64ec_memory_access) == sizeof(int),
               "gem_arm64ec_memory_access ABI changed");
_Static_assert(sizeof(struct gem_arm64ec_stop_info) == 40U, "gem_arm64ec_stop_info ABI changed");
#endif

struct gem_arm64ec_runtime *
gem_arm64ec_runtime_create(struct gem_memory *memory,
                           const struct gem_arm64ec_runtime_config *config);
void gem_arm64ec_runtime_destroy(struct gem_arm64ec_runtime *runtime);

enum gem_stop_reason gem_arm64ec_runtime_run(struct gem_arm64ec_runtime *runtime,
                                             struct gem_thread_context *context, uint64_t budget);

bool gem_arm64ec_runtime_last_stop_info(const struct gem_arm64ec_runtime *runtime,
                                        struct gem_arm64ec_stop_info *out_info);

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
