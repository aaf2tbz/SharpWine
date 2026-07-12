// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_PE_ARM64X_LOADER_H
#define METALSHARP_GEM_PE_ARM64X_LOADER_H

#include "metalsharp/gem/memory.h"
#include "metalsharp/gem/pe_arm64x.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_PE_ARM64X_MATERIALIZE_OPTIONS_VERSION UINT32_C(1)
#define GEM_PE_ARM64X_MAX_BINDINGS UINT32_C(32)

struct gem_pe_arm64x_binding {
    uint32_t slot_rva;
    uint64_t value;
};

struct gem_pe_arm64x_materialize_options {
    uint32_t version;
    uint32_t reserved;
    uint64_t image_base;
    const struct gem_pe_arm64x_binding *bindings;
    size_t binding_count;
};

enum gem_pe_materialize_status {
    GEM_PE_MATERIALIZE_OK = 0,
    GEM_PE_MATERIALIZE_INVALID_ARGUMENT,
    GEM_PE_MATERIALIZE_PARSE_ERROR,
    GEM_PE_MATERIALIZE_RELOCATION_REQUIRED,
    GEM_PE_MATERIALIZE_OVERFLOW,
    GEM_PE_MATERIALIZE_CONFLICT,
    GEM_PE_MATERIALIZE_BAD_SECTION,
    GEM_PE_MATERIALIZE_PERMISSION_CONFLICT,
    GEM_PE_MATERIALIZE_BAD_BINDING,
    GEM_PE_MATERIALIZE_MEMORY_ERROR
};

struct gem_pe_arm64x_materialized_image;

/*
 * Materializes only at the checked preferred base. Headers and file-backed
 * sections are copied into one caller-owned GEM address space; virtual tails
 * remain zero. No import, TLS, initializer, exception, or loader callback is
 * executed. Exact evidence-provided helper slots may be bound before final
 * page permissions are applied. Any failure releases the complete reservation.
 */
enum gem_pe_materialize_status
gem_pe_arm64x_materialize_preferred(struct gem_memory *memory, const uint8_t *bytes,
                                    size_t byte_count,
                                    const struct gem_pe_arm64x_materialize_options *options,
                                    struct gem_pe_arm64x_materialized_image **out_image);
void gem_pe_arm64x_materialized_image_destroy(struct gem_pe_arm64x_materialized_image *image);
const struct gem_pe_arm64x_image *
gem_pe_arm64x_materialized_metadata(const struct gem_pe_arm64x_materialized_image *image);
uint64_t gem_pe_arm64x_materialized_base(const struct gem_pe_arm64x_materialized_image *image);
uint64_t gem_pe_arm64x_materialized_size(const struct gem_pe_arm64x_materialized_image *image);
const char *gem_pe_materialize_status_name(enum gem_pe_materialize_status status);

#ifdef __cplusplus
}
#endif
#endif
