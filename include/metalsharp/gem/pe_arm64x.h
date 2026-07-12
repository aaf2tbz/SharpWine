// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_PE_ARM64X_H
#define METALSHARP_GEM_PE_ARM64X_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_PE_ARM64X_PARSE_OPTIONS_VERSION UINT32_C(1)
#define GEM_PE_ARM64X_DEFAULT_MAX_SECTIONS UINT32_C(96)
#define GEM_PE_ARM64X_DEFAULT_MAX_CODE_RANGES UINT32_C(4096)
#define GEM_PE_ARM64X_DEFAULT_MAX_ENTRY_RANGES UINT32_C(65536)
#define GEM_PE_ARM64X_DEFAULT_MAX_REDIRECTIONS UINT32_C(65536)
#define GEM_PE_ARM64X_DEFAULT_MAX_METADATA_BYTES UINT32_C(8388608)

enum gem_pe_status {
    GEM_PE_OK = 0,
    GEM_PE_ERROR_INVALID_ARGUMENT = 1,
    GEM_PE_ERROR_UNSUPPORTED_FORMAT = 2,
    GEM_PE_ERROR_TRUNCATED = 3,
    GEM_PE_ERROR_OVERFLOW = 4,
    GEM_PE_ERROR_LIMIT_EXCEEDED = 5,
    GEM_PE_ERROR_BAD_DOS_HEADER = 6,
    GEM_PE_ERROR_BAD_PE_SIGNATURE = 7,
    GEM_PE_ERROR_BAD_COFF_HEADER = 8,
    GEM_PE_ERROR_BAD_OPTIONAL_HEADER = 9,
    GEM_PE_ERROR_BAD_SECTION_TABLE = 10,
    GEM_PE_ERROR_BAD_RVA = 11,
    GEM_PE_ERROR_BAD_LOAD_CONFIG = 12,
    GEM_PE_ERROR_NO_CHPE_METADATA = 13,
    GEM_PE_ERROR_BAD_CHPE_METADATA = 14,
    GEM_PE_ERROR_UNSUPPORTED_CHPE_VERSION = 15,
    GEM_PE_ERROR_UNSORTED_RANGES = 16,
    GEM_PE_ERROR_OVERLAPPING_RANGES = 17,
};

enum gem_pe_rva_class {
    GEM_PE_RVA_INVALID = 0,
    GEM_PE_RVA_DATA = 1,
    GEM_PE_RVA_ARM64 = 2,
    GEM_PE_RVA_ARM64EC = 3,
    GEM_PE_RVA_X64 = 4,
    GEM_PE_RVA_THUNK = 5,
    GEM_PE_RVA_FAST_FORWARD = 6,
};

struct gem_pe_arm64x_parse_options {
    uint32_t version;
    uint32_t max_sections;
    uint32_t max_code_ranges;
    uint32_t max_entry_ranges;
    uint32_t max_redirections;
};

struct gem_pe_arm64x_image;

struct gem_pe_arm64x_summary {
    uint16_t machine;
    uint16_t section_count;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t address_of_entry_point;
    uint32_t load_config_rva;
    uint32_t load_config_size;
    uint32_t chpe_metadata_rva;
    uint32_t chpe_metadata_version;
    size_t code_range_count;
    size_t entry_range_count;
    size_t redirection_count;
};

struct gem_pe_arm64x_section {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t characteristics;
};

struct gem_pe_arm64x_code_range {
    uint32_t start_rva;
    uint32_t end_rva;
    enum gem_pe_rva_class isa;
};

struct gem_pe_arm64x_entry_range {
    uint32_t start_rva;
    uint32_t end_rva;
    uint32_t entry_point_rva;
};

struct gem_pe_arm64x_redirection {
    uint32_t source_rva;
    uint32_t destination_rva;
};

struct gem_pe_arm64x_rva_info {
    enum gem_pe_rva_class classification;
    enum gem_pe_rva_class code_map_isa;
    uint32_t rva;
    uint32_t containing_range_start_rva;
    uint32_t containing_range_end_rva;
    uint32_t entry_point_rva;
    uint32_t redirection_destination_rva;
    uint32_t section_index;
    bool has_entry_point;
    bool has_redirection;
    bool executable_section;
};

const char *gem_pe_status_name(enum gem_pe_status status);
const char *gem_pe_rva_class_name(enum gem_pe_rva_class classification);

void gem_pe_arm64x_default_parse_options(struct gem_pe_arm64x_parse_options *options);

/* The parser copies all returned metadata; bytes remains caller-owned and may
 * be changed or freed after this function returns GEM_PE_OK. */
enum gem_pe_status gem_pe_arm64x_parse(const uint8_t *bytes, size_t byte_count,
                                       const struct gem_pe_arm64x_parse_options *options,
                                       struct gem_pe_arm64x_image **out_image);
void gem_pe_arm64x_image_destroy(struct gem_pe_arm64x_image *image);
/* Produces an independent immutable metadata copy. */
enum gem_pe_status gem_pe_arm64x_image_clone(const struct gem_pe_arm64x_image *image,
                                             struct gem_pe_arm64x_image **out_image);

enum gem_pe_status gem_pe_arm64x_get_summary(const struct gem_pe_arm64x_image *image,
                                             struct gem_pe_arm64x_summary *out_summary);
size_t gem_pe_arm64x_section_count(const struct gem_pe_arm64x_image *image);
size_t gem_pe_arm64x_code_range_count(const struct gem_pe_arm64x_image *image);
size_t gem_pe_arm64x_entry_range_count(const struct gem_pe_arm64x_image *image);
size_t gem_pe_arm64x_redirection_count(const struct gem_pe_arm64x_image *image);

enum gem_pe_status gem_pe_arm64x_get_section(const struct gem_pe_arm64x_image *image, size_t index,
                                             struct gem_pe_arm64x_section *out_section);
enum gem_pe_status gem_pe_arm64x_get_code_range(const struct gem_pe_arm64x_image *image,
                                                size_t index,
                                                struct gem_pe_arm64x_code_range *out_range);
enum gem_pe_status gem_pe_arm64x_get_entry_range(const struct gem_pe_arm64x_image *image,
                                                 size_t index,
                                                 struct gem_pe_arm64x_entry_range *out_range);
enum gem_pe_status gem_pe_arm64x_get_redirection(const struct gem_pe_arm64x_image *image,
                                                 size_t index,
                                                 struct gem_pe_arm64x_redirection *out_redirection);

enum gem_pe_status gem_pe_arm64x_classify_rva(const struct gem_pe_arm64x_image *image, uint32_t rva,
                                              struct gem_pe_arm64x_rva_info *out_info);
enum gem_pe_status gem_pe_arm64x_rva_to_file_offset(const struct gem_pe_arm64x_image *image,
                                                    uint32_t rva, uint32_t size,
                                                    size_t *out_offset);

#ifdef __cplusplus
}
#endif

#endif
