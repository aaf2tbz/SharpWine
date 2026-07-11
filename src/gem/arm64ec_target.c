// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/arm64ec_target.h"

#include <stdlib.h>
#include <string.h>

struct gem_arm64ec_target_map {
    struct gem_pe_arm64x_image *image;
    struct gem_pe_arm64x_summary summary;
    uint64_t loaded_base;
    uint64_t loaded_end;
};

static bool add_u64(uint64_t left, uint64_t right, uint64_t *out) {
    if (left > UINT64_MAX - right)
        return false;
    *out = left + right;
    return true;
}

enum gem_arm64ec_target_status
gem_arm64ec_target_map_create(const struct gem_pe_arm64x_image *image, uint64_t loaded_image_base,
                              struct gem_arm64ec_target_map **out_map) {
    struct gem_arm64ec_target_map *map = NULL;
    enum gem_pe_status pe_status;

    if (image == NULL || out_map == NULL)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    *out_map = NULL;
    map = (struct gem_arm64ec_target_map *)calloc(1U, sizeof(*map));
    if (map == NULL)
        return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    pe_status = gem_pe_arm64x_get_summary(image, &map->summary);
    if (pe_status != GEM_PE_OK || map->summary.size_of_image == 0U ||
        !add_u64(loaded_image_base, map->summary.size_of_image, &map->loaded_end)) {
        free(map);
        return pe_status == GEM_PE_OK ? GEM_ARM64EC_TARGET_OVERFLOW
                                      : GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    }
    pe_status = gem_pe_arm64x_image_clone(image, &map->image);
    if (pe_status != GEM_PE_OK) {
        free(map);
        return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    }
    map->loaded_base = loaded_image_base;
    *out_map = map;
    return GEM_ARM64EC_TARGET_OK;
}

void gem_arm64ec_target_map_destroy(struct gem_arm64ec_target_map *map) {
    if (map != NULL) {
        gem_pe_arm64x_image_destroy(map->image);
        free(map);
    }
}

static enum gem_arm64ec_target_status classify_terminal(const struct gem_arm64ec_target_map *map,
                                                        uint32_t rva,
                                                        struct gem_arm64ec_target_result *result) {
    struct gem_pe_arm64x_rva_info info;
    enum gem_pe_status status = gem_pe_arm64x_classify_rva(map->image, rva, &info);
    if (status != GEM_PE_OK)
        return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    if (info.classification == GEM_PE_RVA_INVALID)
        return rva >= map->summary.size_of_image ? GEM_ARM64EC_TARGET_OUTSIDE_IMAGE
                                                 : GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
    if (!info.executable_section)
        return GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
    switch (info.classification) {
    case GEM_PE_RVA_ARM64:
        result->kind = GEM_ARM64EC_TARGET_ARM64;
        break;
    case GEM_PE_RVA_ARM64EC:
        result->kind = GEM_ARM64EC_TARGET_ARM64EC;
        break;
    case GEM_PE_RVA_X64:
        result->kind = GEM_ARM64EC_TARGET_X64_BOUNDARY;
        break;
    case GEM_PE_RVA_THUNK:
        /* Entry-range membership describes the thunk role, not its ISA. The
         * checked code map remains authoritative for whether Dynarmic may
         * execute the bytes or must stop at an x64 boundary. */
        if (info.code_map_isa == GEM_PE_RVA_ARM64EC)
            result->kind = GEM_ARM64EC_TARGET_ARM64EC;
        else if (info.code_map_isa == GEM_PE_RVA_ARM64)
            result->kind = GEM_ARM64EC_TARGET_ARM64;
        else if (info.code_map_isa == GEM_PE_RVA_X64)
            result->kind = GEM_ARM64EC_TARGET_X64_BOUNDARY;
        else
            return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
        break;
    default:
        return GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
    }
    if (result->kind != GEM_ARM64EC_TARGET_X64_BOUNDARY &&
        (result->resolved_va & UINT64_C(3)) != 0U)
        return GEM_ARM64EC_TARGET_MISALIGNED;
    return GEM_ARM64EC_TARGET_OK;
}

enum gem_arm64ec_target_status
gem_arm64ec_target_resolve(const struct gem_arm64ec_target_map *map, uint64_t requested_va,
                           struct gem_arm64ec_target_result *out_result) {
    struct gem_arm64ec_target_result result;
    uint32_t rva;
    size_t hop;
    size_t hop_limit;

    if (map == NULL || out_result == NULL)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    if (requested_va < map->loaded_base || requested_va >= map->loaded_end)
        return GEM_ARM64EC_TARGET_OUTSIDE_IMAGE;
    memset(&result, 0, sizeof(result));
    result.requested_va = requested_va;
    result.requested_rva = (uint32_t)(requested_va - map->loaded_base);
    rva = result.requested_rva;
    hop_limit = gem_pe_arm64x_redirection_count(map->image) + 1U;

    for (hop = 0; hop < hop_limit; ++hop) {
        struct gem_pe_arm64x_rva_info info;
        enum gem_pe_status pe_status = gem_pe_arm64x_classify_rva(map->image, rva, &info);
        if (pe_status != GEM_PE_OK)
            return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
        if (!info.has_redirection)
            break;
        rva = info.redirection_destination_rva;
        result.redirection_hops += 1U;
    }
    if (hop == hop_limit)
        return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    result.resolved_rva = rva;
    if (!add_u64(map->loaded_base, rva, &result.resolved_va))
        return GEM_ARM64EC_TARGET_OVERFLOW;
    {
        enum gem_arm64ec_target_status status = classify_terminal(map, rva, &result);
        if (status != GEM_ARM64EC_TARGET_OK)
            return status;
    }
    *out_result = result;
    return GEM_ARM64EC_TARGET_OK;
}

enum gem_arm64ec_target_status
gem_arm64ec_cfg_authorize(const struct gem_arm64ec_cfg_policy *policy, uint64_t target_va) {
    if (policy == NULL || policy->authorize == NULL ||
        !policy->authorize(policy->opaque, target_va))
        return GEM_ARM64EC_TARGET_CFG_DENIED;
    return GEM_ARM64EC_TARGET_OK;
}

enum gem_arm64ec_target_status
gem_arm64ec_checker_dispatch(const struct gem_arm64ec_target_map *map,
                             const struct gem_arm64ec_cfg_policy *policy, bool require_cfg,
                             struct gem_thread_context *context,
                             struct gem_arm64ec_target_result *out_target) {
    struct gem_arm64ec_target_result target;
    struct gem_arm64ec_target_result exit_thunk;
    enum gem_arm64ec_target_status status;
    uint64_t original_target;

    if (map == NULL || context == NULL || out_target == NULL || !gem_context_is_valid(context) ||
        context->isa != (uint32_t)GEM_ISA_ARM64EC)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    original_target = context->x[11];
    status = gem_arm64ec_target_resolve(map, original_target, &target);
    if (status != GEM_ARM64EC_TARGET_OK)
        return status;
    if (require_cfg) {
        status = gem_arm64ec_cfg_authorize(policy, original_target);
        if (status != GEM_ARM64EC_TARGET_OK)
            return status;
    }
    if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
        status = gem_arm64ec_target_resolve(map, context->x[10], &exit_thunk);
        if (status != GEM_ARM64EC_TARGET_OK)
            return status;
        if (exit_thunk.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY)
            return GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
    }

    /* Commit only after target, policy, and exit-thunk checks have succeeded. */
    if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
        context->x[9] = original_target;
        context->x[11] = exit_thunk.resolved_va;
    }
    *out_target = target;
    return GEM_ARM64EC_TARGET_OK;
}

enum gem_arm64ec_target_status
gem_arm64ec_descriptor_resolve(const struct gem_arm64ec_target_map *map, struct gem_memory *memory,
                               uint64_t descriptor_va, const struct gem_arm64ec_cfg_policy *policy,
                               struct gem_arm64ec_target_result *out_result) {
    uint8_t descriptor[4];
    uint32_t encoded;
    uint64_t function_va;
    uint64_t thunk_va;
    struct gem_arm64ec_target_result result;
    enum gem_arm64ec_target_status status;
    enum gem_memory_error error;
    if (map == NULL || memory == NULL || out_result == NULL)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    if (descriptor_va > UINT64_MAX - sizeof(descriptor))
        return GEM_ARM64EC_TARGET_OVERFLOW;
    error = gem_memory_read(memory, descriptor_va, descriptor, sizeof(descriptor));
    if (error != GEM_MEMORY_OK)
        return GEM_ARM64EC_TARGET_MEMORY_FAULT;
    encoded = (uint32_t)descriptor[0] | ((uint32_t)descriptor[1] << 8U) |
              ((uint32_t)descriptor[2] << 16U) | ((uint32_t)descriptor[3] << 24U);
    function_va = descriptor_va + sizeof(descriptor);
    if (!add_u64(function_va, encoded & ~UINT32_C(3), &thunk_va))
        return GEM_ARM64EC_TARGET_OVERFLOW;
    status = gem_arm64ec_target_resolve(map, thunk_va, &result);
    if (status != GEM_ARM64EC_TARGET_OK)
        return status;
    if (result.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY)
        return GEM_ARM64EC_TARGET_NOT_EXECUTABLE;
    if (policy != NULL) {
        status = gem_arm64ec_cfg_authorize(policy, result.resolved_va);
        if (status != GEM_ARM64EC_TARGET_OK)
            return status;
    }
    *out_result = result;
    return GEM_ARM64EC_TARGET_OK;
}

const char *gem_arm64ec_target_status_name(enum gem_arm64ec_target_status status) {
    static const char *const names[] = {"ok",
                                        "invalid-argument",
                                        "overflow",
                                        "outside-image",
                                        "not-executable",
                                        "malformed-metadata",
                                        "misaligned",
                                        "memory-fault",
                                        "cfg-denied",
                                        "descriptor-unsupported",
                                        "relocation-unsupported"};
    if ((unsigned int)status >= sizeof(names) / sizeof(names[0]))
        return "invalid";
    return names[status];
}
