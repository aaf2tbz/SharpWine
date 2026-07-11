// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_ARM64EC_TARGET_H
#define METALSHARP_GEM_ARM64EC_TARGET_H

#include "metalsharp/gem/context.h"
#include "metalsharp/gem/memory.h"
#include "metalsharp/gem/pe_arm64x.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gem_arm64ec_target_map;

enum gem_arm64ec_target_status {
    GEM_ARM64EC_TARGET_OK = 0,
    GEM_ARM64EC_TARGET_INVALID_ARGUMENT = 1,
    GEM_ARM64EC_TARGET_OVERFLOW = 2,
    GEM_ARM64EC_TARGET_OUTSIDE_IMAGE = 3,
    GEM_ARM64EC_TARGET_NOT_EXECUTABLE = 4,
    GEM_ARM64EC_TARGET_MALFORMED_METADATA = 5,
    GEM_ARM64EC_TARGET_MISALIGNED = 6,
    GEM_ARM64EC_TARGET_MEMORY_FAULT = 7,
    GEM_ARM64EC_TARGET_CFG_DENIED = 8,
    GEM_ARM64EC_TARGET_DESCRIPTOR_UNSUPPORTED = 9,
    GEM_ARM64EC_TARGET_RELOCATION_UNSUPPORTED = 10,
};

enum gem_arm64ec_target_kind {
    GEM_ARM64EC_TARGET_ARM64 = 1,
    GEM_ARM64EC_TARGET_ARM64EC = 2,
    GEM_ARM64EC_TARGET_X64_BOUNDARY = 3,
};

struct gem_arm64ec_target_result {
    uint64_t requested_va;
    uint64_t resolved_va;
    uint32_t requested_rva;
    uint32_t resolved_rva;
    enum gem_arm64ec_target_kind kind;
    uint32_t redirection_hops;
};

/* CFG authorization is intentionally independent of ISA classification. A
 * missing policy denies an indirect target; it never changes target kind. */
typedef bool (*gem_arm64ec_cfg_authorize_fn)(void *opaque, uint64_t target_va);
struct gem_arm64ec_cfg_policy {
    gem_arm64ec_cfg_authorize_fn authorize;
    void *opaque;
};

/* The map owns an immutable clone of image and translates checked RVAs at the
 * supplied loaded base. It does not load bytes or apply PE relocations; callers
 * must not execute a nonpreferred image until a checked loader has done so. */
enum gem_arm64ec_target_status
gem_arm64ec_target_map_create(const struct gem_pe_arm64x_image *image, uint64_t loaded_image_base,
                              struct gem_arm64ec_target_map **out_map);
void gem_arm64ec_target_map_destroy(struct gem_arm64ec_target_map *map);

enum gem_arm64ec_target_status
gem_arm64ec_target_resolve(const struct gem_arm64ec_target_map *map, uint64_t requested_va,
                           struct gem_arm64ec_target_result *out_result);

enum gem_arm64ec_target_status
gem_arm64ec_cfg_authorize(const struct gem_arm64ec_cfg_policy *policy, uint64_t target_va);

/* Applies the documented x9/x10/x11 checker contract transactionally. ISA
 * classification and optional CFG authorization are independent. For an x64
 * target x9 receives the original target and x11 receives the checked
 * ARM64EC exit thunk; an ARM64/ARM64EC target leaves both registers intact. */
enum gem_arm64ec_target_status
gem_arm64ec_checker_dispatch(const struct gem_arm64ec_target_map *map,
                             const struct gem_arm64ec_cfg_policy *policy, bool require_cfg,
                             struct gem_thread_context *context,
                             struct gem_arm64ec_target_result *out_target);

/* Resolves the documented four-byte entry-thunk descriptor transactionally.
 * descriptor_va is function_va - 4; the little-endian displacement has its
 * low two tag bits cleared and is added to function_va with checked arithmetic. */
enum gem_arm64ec_target_status
gem_arm64ec_descriptor_resolve(const struct gem_arm64ec_target_map *map, struct gem_memory *memory,
                               uint64_t descriptor_va, const struct gem_arm64ec_cfg_policy *policy,
                               struct gem_arm64ec_target_result *out_result);

const char *gem_arm64ec_target_status_name(enum gem_arm64ec_target_status status);

#ifdef __cplusplus
}
#endif
#endif
