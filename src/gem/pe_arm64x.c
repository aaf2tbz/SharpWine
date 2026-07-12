// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/pe_arm64x.h"

#include <stdlib.h>
#include <string.h>
#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
#include <stdio.h>
#endif

#define PE_DOS_HEADER_MIN_SIZE ((size_t)64)
#define PE_SIGNATURE UINT32_C(0x00004550)
#define PE_MACHINE_ARM64X UINT16_C(0xA64E)
#define PE_MACHINE_ARM64 UINT16_C(0xAA64)
#define PE_OPTIONAL_MAGIC_PE32_PLUS UINT16_C(0x020B)
#define PE_DIRECTORY_LOAD_CONFIG UINT32_C(10)
#define PE32_PLUS_DATA_DIRECTORY_OFFSET UINT32_C(112)
#define PE_DATA_DIRECTORY_SIZE UINT32_C(8)
#define PE_SECTION_HEADER_SIZE UINT32_C(40)
#define PE_COFF_HEADER_SIZE UINT32_C(20)
#define PE_LOAD_CONFIG_CHPE_POINTER_OFFSET UINT32_C(0xC8)
#define PE_LOAD_CONFIG_CHPE_POINTER_END UINT32_C(0xD0)
/* LLVM's COFF chpe_metadata layout defines a 20-dword v1 prefix and adds
 * three dwords in v2. Wine's IMAGE_ARM64EC_METADATA is a newer 29-dword
 * superset; accepting it requires the complete versioned minimum, not merely
 * the fields consumed below. */
#define PE_CHPE_METADATA_V1_SIZE UINT32_C(80)
#define PE_CHPE_METADATA_V2_SIZE UINT32_C(92)
#define PE_CHPE_CODE_MAP_RECORD_SIZE UINT32_C(8)
#define PE_CHPE_ENTRY_RECORD_SIZE UINT32_C(12)
#define PE_CHPE_REDIRECTION_RECORD_SIZE UINT32_C(8)
#define PE_SECTION_MEM_EXECUTE UINT32_C(0x20000000)
#define PE_SECTION_MEM_READ UINT32_C(0x40000000)

enum chpe_range_type {
    CHPE_RANGE_ARM64 = 0,
    CHPE_RANGE_ARM64EC = 1,
    CHPE_RANGE_AMD64 = 2,
};

struct pe_section {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t raw_pointer;
    uint32_t characteristics;
};

struct gem_pe_arm64x_image {
    struct gem_pe_arm64x_summary summary;
    size_t byte_count;
    uint32_t size_of_headers;
    struct pe_section *sections;
    struct gem_pe_arm64x_code_range *code_ranges;
    struct gem_pe_arm64x_entry_range *entry_ranges;
    struct gem_pe_arm64x_redirection *redirections;
};

struct parser_state {
    const uint8_t *bytes;
    size_t byte_count;
    struct gem_pe_arm64x_parse_options options;
    struct gem_pe_arm64x_image *image;
};

struct chpe_metadata_fields {
    uint32_t version;
    uint32_t code_map_rva;
    uint32_t code_map_count;
    uint32_t entry_ranges_rva;
    uint32_t redirections_rva;
    uint32_t entry_range_count;
    uint32_t redirection_count;
};

static bool checked_add_size(size_t a, size_t b, size_t *out) {
    if (a > SIZE_MAX - b)
        return false;
    *out = a + b;
    return true;
}

static bool checked_mul_size(size_t a, size_t b, size_t *out) {
    if (a != 0U && b > SIZE_MAX / a)
        return false;
    *out = a * b;
    return true;
}

static bool checked_add_u32(uint32_t a, uint32_t b, uint32_t *out) {
    if (a > UINT32_MAX - b)
        return false;
    *out = a + b;
    return true;
}

static bool file_span_fits(size_t byte_count, size_t offset, size_t size) {
    size_t end = 0;
    return checked_add_size(offset, size, &end) && end <= byte_count;
}

static enum gem_pe_status require_file_span(const struct parser_state *state, size_t offset,
                                            size_t size) {
    return file_span_fits(state->byte_count, offset, size) ? GEM_PE_OK : GEM_PE_ERROR_TRUNCATED;
}

static uint16_t read_u16le_unchecked(const uint8_t *bytes, size_t offset) {
    return (uint16_t)((uint16_t)bytes[offset] | ((uint16_t)bytes[offset + 1U] << 8U));
}

static uint32_t read_u32le_unchecked(const uint8_t *bytes, size_t offset) {
    return (uint32_t)bytes[offset] | ((uint32_t)bytes[offset + 1U] << 8U) |
           ((uint32_t)bytes[offset + 2U] << 16U) | ((uint32_t)bytes[offset + 3U] << 24U);
}

static uint64_t read_u64le_unchecked(const uint8_t *bytes, size_t offset) {
    const uint32_t lo = read_u32le_unchecked(bytes, offset);
    const uint32_t hi = read_u32le_unchecked(bytes, offset + 4U);
    return (uint64_t)lo | ((uint64_t)hi << 32U);
}

static uint32_t section_virtual_extent(const struct pe_section *section) {
    return section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
}

static bool section_is_executable(const struct pe_section *section) {
    return (section->characteristics & PE_SECTION_MEM_EXECUTE) != 0U;
}

static bool rva_add_fits_image(uint32_t rva, uint32_t size, uint32_t size_of_image) {
    uint32_t end = 0;
    return checked_add_u32(rva, size, &end) && end <= size_of_image;
}

static bool section_contains_span(const struct pe_section *section, uint32_t rva, uint32_t size) {
    uint32_t end = 0;
    uint32_t section_end = 0;
    const uint32_t extent = section_virtual_extent(section);
    return checked_add_u32(rva, size, &end) &&
           checked_add_u32(section->virtual_address, extent, &section_end) &&
           rva >= section->virtual_address && end <= section_end;
}

static const struct pe_section *find_section_for_span(const struct gem_pe_arm64x_image *image,
                                                      uint32_t rva, uint32_t size,
                                                      size_t *out_index) {
    size_t i = 0;
    for (i = 0; i < image->summary.section_count; ++i) {
        if (section_contains_span(&image->sections[i], rva, size)) {
            if (out_index != NULL)
                *out_index = i;
            return &image->sections[i];
        }
    }
    return NULL;
}

static enum gem_pe_status rva_to_file_offset_internal(const struct gem_pe_arm64x_image *image,
                                                      uint32_t rva, uint32_t size,
                                                      size_t *out_offset) {
    uint32_t header_end = 0;
    size_t section_index = 0;
    const struct pe_section *section = NULL;

    if (size == 0U)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    if (!rva_add_fits_image(rva, size, image->summary.size_of_image))
        return GEM_PE_ERROR_BAD_RVA;
    if (checked_add_u32(rva, size, &header_end) && rva < image->size_of_headers &&
        header_end <= image->size_of_headers && (size_t)header_end <= image->byte_count) {
        *out_offset = (size_t)rva;
        return GEM_PE_OK;
    }

    section = find_section_for_span(image, rva, size, &section_index);
    (void)section_index;
    if (section == NULL)
        return GEM_PE_ERROR_BAD_RVA;

    {
        const uint32_t offset_in_section = rva - section->virtual_address;
        uint32_t raw_end = 0;
        size_t file_offset = 0;
        if (!checked_add_u32(offset_in_section, size, &raw_end) || raw_end > section->raw_size)
            return GEM_PE_ERROR_BAD_RVA;
        if (!checked_add_size((size_t)section->raw_pointer, (size_t)offset_in_section,
                              &file_offset) ||
            !file_span_fits(image->byte_count, file_offset, (size_t)size))
            return GEM_PE_ERROR_BAD_RVA;
        *out_offset = file_offset;
    }
    return GEM_PE_OK;
}

static enum gem_pe_rva_class code_type_to_class(uint32_t type) {
    if (type == (uint32_t)CHPE_RANGE_ARM64)
        return GEM_PE_RVA_ARM64;
    if (type == (uint32_t)CHPE_RANGE_ARM64EC)
        return GEM_PE_RVA_ARM64EC;
    if (type == (uint32_t)CHPE_RANGE_AMD64)
        return GEM_PE_RVA_X64;
    return GEM_PE_RVA_INVALID;
}

static const struct gem_pe_arm64x_code_range *
find_code_range(const struct gem_pe_arm64x_image *image, uint32_t rva) {
    size_t i = 0;
    for (i = 0; i < image->summary.code_range_count; ++i) {
        const struct gem_pe_arm64x_code_range *range = &image->code_ranges[i];
        if (rva < range->start_rva)
            return NULL;
        if (rva < range->end_rva)
            return range;
    }
    return NULL;
}

static const struct gem_pe_arm64x_entry_range *
find_entry_range(const struct gem_pe_arm64x_image *image, uint32_t rva) {
    size_t i = 0;
    for (i = 0; i < image->summary.entry_range_count; ++i) {
        const struct gem_pe_arm64x_entry_range *range = &image->entry_ranges[i];
        if (rva < range->start_rva)
            return NULL;
        if (rva < range->end_rva)
            return range;
    }
    return NULL;
}

static const struct gem_pe_arm64x_redirection *
find_redirection(const struct gem_pe_arm64x_image *image, uint32_t rva) {
    size_t i = 0;
    for (i = 0; i < image->summary.redirection_count; ++i) {
        const struct gem_pe_arm64x_redirection *redirection = &image->redirections[i];
        if (rva < redirection->source_rva)
            return NULL;
        if (rva == redirection->source_rva)
            return redirection;
    }
    return NULL;
}

static bool code_range_contains_class(const struct gem_pe_arm64x_image *image, uint32_t start,
                                      uint32_t end, enum gem_pe_rva_class isa) {
    const struct gem_pe_arm64x_code_range *range = find_code_range(image, start);
    return range != NULL && range->isa == isa && end <= range->end_rva;
}

static enum gem_pe_status copy_options(const struct gem_pe_arm64x_parse_options *options,
                                       struct gem_pe_arm64x_parse_options *out_options) {
    if (options == NULL) {
        gem_pe_arm64x_default_parse_options(out_options);
        return GEM_PE_OK;
    }
    if (options->version != GEM_PE_ARM64X_PARSE_OPTIONS_VERSION || options->max_sections == 0U ||
        options->max_code_ranges == 0U || options->max_entry_ranges == 0U ||
        options->max_redirections == 0U)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_options = *options;
    return GEM_PE_OK;
}

static enum gem_pe_status parse_headers(struct parser_state *state,
                                        size_t *out_load_config_dir_offset) {
    uint32_t e_lfanew = 0;
    size_t pe_offset = 0;
    size_t coff_offset = 0;
    size_t optional_offset = 0;
    size_t section_table_offset = 0;
    size_t section_table_size = 0;
    uint32_t signature = 0;
    uint16_t machine = 0;
    uint16_t section_count = 0;
    uint16_t optional_header_size = 0;
    uint16_t optional_magic = 0;
    uint32_t number_of_rva_and_sizes = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t previous_end = 0;
    size_t i = 0;
    struct gem_pe_arm64x_image *image = state->image;

    if (state->byte_count < PE_DOS_HEADER_MIN_SIZE)
        return GEM_PE_ERROR_TRUNCATED;
    if (state->bytes[0] != 'M' || state->bytes[1] != 'Z')
        return GEM_PE_ERROR_BAD_DOS_HEADER;
    e_lfanew = read_u32le_unchecked(state->bytes, 0x3CU);
    pe_offset = (size_t)e_lfanew;
    if (pe_offset < PE_DOS_HEADER_MIN_SIZE)
        return GEM_PE_ERROR_BAD_DOS_HEADER;
    if (require_file_span(state, pe_offset, 4U + PE_COFF_HEADER_SIZE) != GEM_PE_OK)
        return GEM_PE_ERROR_TRUNCATED;
    signature = read_u32le_unchecked(state->bytes, pe_offset);
    if (signature != PE_SIGNATURE)
        return GEM_PE_ERROR_BAD_PE_SIGNATURE;

    coff_offset = pe_offset + 4U;
    machine = read_u16le_unchecked(state->bytes, coff_offset);
    section_count = read_u16le_unchecked(state->bytes, coff_offset + 2U);
    optional_header_size = read_u16le_unchecked(state->bytes, coff_offset + 16U);
    /* Windows/Wine emit CHPE-bearing ARM64 images as 0xaa64. ARM64X is also
     * accepted; the mandatory CHPE parse below rejects ordinary ARM64. */
    if (machine != PE_MACHINE_ARM64 && machine != PE_MACHINE_ARM64X)
        return GEM_PE_ERROR_UNSUPPORTED_FORMAT;
    if (section_count == 0U || section_count > state->options.max_sections)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;

    optional_offset = coff_offset + PE_COFF_HEADER_SIZE;
    if (!checked_add_size(optional_offset, (size_t)optional_header_size, &section_table_offset))
        return GEM_PE_ERROR_OVERFLOW;
    if (require_file_span(state, optional_offset, (size_t)optional_header_size) != GEM_PE_OK)
        return GEM_PE_ERROR_TRUNCATED;
    if (optional_header_size < PE32_PLUS_DATA_DIRECTORY_OFFSET +
                                   ((PE_DIRECTORY_LOAD_CONFIG + 1U) * PE_DATA_DIRECTORY_SIZE))
        return GEM_PE_ERROR_BAD_OPTIONAL_HEADER;

    optional_magic = read_u16le_unchecked(state->bytes, optional_offset);
    if (optional_magic != PE_OPTIONAL_MAGIC_PE32_PLUS)
        return GEM_PE_ERROR_UNSUPPORTED_FORMAT;
    image->summary.address_of_entry_point =
        read_u32le_unchecked(state->bytes, optional_offset + 16U);
    image->summary.image_base = read_u64le_unchecked(state->bytes, optional_offset + 24U);
    section_alignment = read_u32le_unchecked(state->bytes, optional_offset + 32U);
    file_alignment = read_u32le_unchecked(state->bytes, optional_offset + 36U);
    image->summary.size_of_image = read_u32le_unchecked(state->bytes, optional_offset + 56U);
    image->size_of_headers = read_u32le_unchecked(state->bytes, optional_offset + 60U);
    image->summary.size_of_headers = image->size_of_headers;
    number_of_rva_and_sizes = read_u32le_unchecked(state->bytes, optional_offset + 108U);

    if (section_alignment == 0U || file_alignment == 0U || section_alignment < file_alignment ||
        image->summary.size_of_image == 0U || image->size_of_headers == 0U ||
        number_of_rva_and_sizes <= PE_DIRECTORY_LOAD_CONFIG)
        return GEM_PE_ERROR_BAD_OPTIONAL_HEADER;
    if (image->size_of_headers > state->byte_count)
        return GEM_PE_ERROR_BAD_OPTIONAL_HEADER;

    if (!checked_mul_size((size_t)section_count, PE_SECTION_HEADER_SIZE, &section_table_size) ||
        !file_span_fits(state->byte_count, section_table_offset, section_table_size))
        return GEM_PE_ERROR_BAD_SECTION_TABLE;

    image->summary.machine = machine;
    image->summary.section_count = section_count;
    *out_load_config_dir_offset = optional_offset + PE32_PLUS_DATA_DIRECTORY_OFFSET +
                                  ((size_t)PE_DIRECTORY_LOAD_CONFIG * PE_DATA_DIRECTORY_SIZE);

    image->sections = (struct pe_section *)calloc(section_count, sizeof(*image->sections));
    if (image->sections == NULL)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;

    for (i = 0; i < section_count; ++i) {
        const size_t offset = section_table_offset + (i * PE_SECTION_HEADER_SIZE);
        struct pe_section *section = &image->sections[i];
        uint32_t section_end = 0;
        uint32_t raw_end = 0;
        section->virtual_size = read_u32le_unchecked(state->bytes, offset + 8U);
        section->virtual_address = read_u32le_unchecked(state->bytes, offset + 12U);
        section->raw_size = read_u32le_unchecked(state->bytes, offset + 16U);
        section->raw_pointer = read_u32le_unchecked(state->bytes, offset + 20U);
        section->characteristics = read_u32le_unchecked(state->bytes, offset + 36U);

        if (section_virtual_extent(section) == 0U)
            return GEM_PE_ERROR_BAD_SECTION_TABLE;
        if (!checked_add_u32(section->virtual_address, section_virtual_extent(section),
                             &section_end) ||
            section_end > image->summary.size_of_image)
            return GEM_PE_ERROR_BAD_SECTION_TABLE;
        if (i > 0U) {
            if (section->virtual_address < image->sections[i - 1U].virtual_address)
                return GEM_PE_ERROR_UNSORTED_RANGES;
            if (section->virtual_address < previous_end)
                return GEM_PE_ERROR_OVERLAPPING_RANGES;
        }
        previous_end = section_end;
        if (section->raw_size != 0U) {
            if (!checked_add_u32(section->raw_pointer, section->raw_size, &raw_end) ||
                raw_end > state->byte_count)
                return GEM_PE_ERROR_BAD_SECTION_TABLE;
        }
    }
    return GEM_PE_OK;
}

static enum gem_pe_status parse_load_config_and_chpe(struct parser_state *state,
                                                     size_t load_config_dir_offset,
                                                     struct chpe_metadata_fields *out_fields) {
    struct gem_pe_arm64x_image *image = state->image;
    uint32_t load_config_rva = 0;
    uint32_t load_config_size = 0;
    size_t load_config_offset = 0;
    uint32_t load_config_internal_size = 0;
    uint64_t chpe_va = 0;
    uint64_t chpe_rva64 = 0;
    uint32_t chpe_metadata_rva = 0;
    uint32_t metadata_size = 0;
    size_t chpe_metadata_offset = 0;
    enum gem_pe_status status = GEM_PE_OK;

    load_config_rva = read_u32le_unchecked(state->bytes, load_config_dir_offset);
    load_config_size = read_u32le_unchecked(state->bytes, load_config_dir_offset + 4U);
    image->summary.load_config_rva = load_config_rva;
    image->summary.load_config_size = load_config_size;
    if (load_config_rva == 0U || load_config_size < PE_LOAD_CONFIG_CHPE_POINTER_END)
        return GEM_PE_ERROR_BAD_LOAD_CONFIG;
    status = rva_to_file_offset_internal(image, load_config_rva, PE_LOAD_CONFIG_CHPE_POINTER_END,
                                         &load_config_offset);
    if (status != GEM_PE_OK)
        return GEM_PE_ERROR_BAD_LOAD_CONFIG;
    load_config_internal_size = read_u32le_unchecked(state->bytes, load_config_offset);
    /* A newer loader may advertise a longer load-config structure.  Only the
     * prefix through CHPEMetadataPointer is part of this parser's contract. */
    if (load_config_internal_size < PE_LOAD_CONFIG_CHPE_POINTER_END)
        return GEM_PE_ERROR_BAD_LOAD_CONFIG;
    chpe_va =
        read_u64le_unchecked(state->bytes, load_config_offset + PE_LOAD_CONFIG_CHPE_POINTER_OFFSET);
    if (chpe_va == 0U)
        return GEM_PE_ERROR_NO_CHPE_METADATA;
    if (chpe_va < image->summary.image_base)
        return GEM_PE_ERROR_BAD_LOAD_CONFIG;
    chpe_rva64 = chpe_va - image->summary.image_base;
    if (chpe_rva64 > UINT32_MAX)
        return GEM_PE_ERROR_BAD_LOAD_CONFIG;
    chpe_metadata_rva = (uint32_t)chpe_rva64;
    image->summary.chpe_metadata_rva = chpe_metadata_rva;

    status = rva_to_file_offset_internal(image, chpe_metadata_rva, 4U, &chpe_metadata_offset);
    if (status != GEM_PE_OK)
        return GEM_PE_ERROR_BAD_CHPE_METADATA;
    out_fields->version = read_u32le_unchecked(state->bytes, chpe_metadata_offset);
    if (out_fields->version != 1U && out_fields->version != 2U)
        return GEM_PE_ERROR_UNSUPPORTED_CHPE_VERSION;
    metadata_size = out_fields->version == 1U ? PE_CHPE_METADATA_V1_SIZE : PE_CHPE_METADATA_V2_SIZE;
    status =
        rva_to_file_offset_internal(image, chpe_metadata_rva, metadata_size, &chpe_metadata_offset);
    if (status != GEM_PE_OK)
        return GEM_PE_ERROR_BAD_CHPE_METADATA;

    out_fields->code_map_rva = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 4U);
    out_fields->code_map_count = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 8U);
    out_fields->entry_ranges_rva = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 12U);
    out_fields->redirections_rva = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 16U);
    out_fields->entry_range_count = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 48U);
    out_fields->redirection_count = read_u32le_unchecked(state->bytes, chpe_metadata_offset + 52U);
    image->summary.chpe_metadata_version = out_fields->version;
    return GEM_PE_OK;
}

static enum gem_pe_status allocate_metadata_arrays(struct parser_state *state,
                                                   const struct chpe_metadata_fields *fields) {
    struct gem_pe_arm64x_image *image = state->image;
    size_t code_bytes = 0;
    size_t entry_bytes = 0;
    size_t redirection_bytes = 0;
    size_t total = 0;

    if (fields->code_map_count > state->options.max_code_ranges ||
        fields->entry_range_count > state->options.max_entry_ranges ||
        fields->redirection_count > state->options.max_redirections)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;
    if (!checked_mul_size((size_t)fields->code_map_count, sizeof(*image->code_ranges),
                          &code_bytes) ||
        !checked_mul_size((size_t)fields->entry_range_count, sizeof(*image->entry_ranges),
                          &entry_bytes) ||
        !checked_mul_size((size_t)fields->redirection_count, sizeof(*image->redirections),
                          &redirection_bytes) ||
        !checked_add_size(code_bytes, entry_bytes, &total) ||
        !checked_add_size(total, redirection_bytes, &total))
        return GEM_PE_ERROR_OVERFLOW;
    if (total > GEM_PE_ARM64X_DEFAULT_MAX_METADATA_BYTES)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;

    image->summary.code_range_count = fields->code_map_count;
    image->summary.entry_range_count = fields->entry_range_count;
    image->summary.redirection_count = fields->redirection_count;
    if (fields->code_map_count != 0U) {
        image->code_ranges = (struct gem_pe_arm64x_code_range *)calloc(fields->code_map_count,
                                                                       sizeof(*image->code_ranges));
        if (image->code_ranges == NULL)
            return GEM_PE_ERROR_LIMIT_EXCEEDED;
    }
    if (fields->entry_range_count != 0U) {
        image->entry_ranges = (struct gem_pe_arm64x_entry_range *)calloc(
            fields->entry_range_count, sizeof(*image->entry_ranges));
        if (image->entry_ranges == NULL)
            return GEM_PE_ERROR_LIMIT_EXCEEDED;
    }
    if (fields->redirection_count != 0U) {
        image->redirections = (struct gem_pe_arm64x_redirection *)calloc(
            fields->redirection_count, sizeof(*image->redirections));
        if (image->redirections == NULL)
            return GEM_PE_ERROR_LIMIT_EXCEEDED;
    }
    return GEM_PE_OK;
}

static enum gem_pe_status table_file_span(const struct gem_pe_arm64x_image *image, uint32_t rva,
                                          uint32_t count, uint32_t record_size,
                                          size_t *out_offset) {
    size_t table_size_size = 0;
    if (count == 0U) {
        *out_offset = 0U;
        return GEM_PE_OK;
    }
    if (rva == 0U)
        return GEM_PE_ERROR_BAD_CHPE_METADATA;
    if (!checked_mul_size((size_t)count, (size_t)record_size, &table_size_size) ||
        table_size_size > UINT32_MAX)
        return GEM_PE_ERROR_OVERFLOW;
    return rva_to_file_offset_internal(image, rva, (uint32_t)table_size_size, out_offset);
}

static enum gem_pe_status parse_code_map(struct parser_state *state,
                                         const struct chpe_metadata_fields *fields) {
    struct gem_pe_arm64x_image *image = state->image;
    size_t table_offset = 0;
    size_t i = 0;
    enum gem_pe_status status = table_file_span(image, fields->code_map_rva, fields->code_map_count,
                                                PE_CHPE_CODE_MAP_RECORD_SIZE, &table_offset);
    if (status != GEM_PE_OK)
        return status == GEM_PE_ERROR_OVERFLOW ? status : GEM_PE_ERROR_BAD_CHPE_METADATA;

    for (i = 0; i < fields->code_map_count; ++i) {
        const size_t offset = table_offset + (i * PE_CHPE_CODE_MAP_RECORD_SIZE);
        const uint32_t start_offset = read_u32le_unchecked(state->bytes, offset);
        const uint32_t length = read_u32le_unchecked(state->bytes, offset + 4U);
        const uint32_t type = start_offset & UINT32_C(3);
        const uint32_t start = start_offset & ~UINT32_C(3);
        uint32_t end = 0;
        struct gem_pe_arm64x_code_range *range = &image->code_ranges[i];
#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
        fprintf(stderr, "code-map[%zu]: encoded=%#x start=%#x length=%#x type=%u\n", i,
                start_offset, start, length, type);
#endif

        if (length == 0U || type == 3U)
            return GEM_PE_ERROR_BAD_CHPE_METADATA;
        if (!checked_add_u32(start, length, &end) || end > image->summary.size_of_image)
            return GEM_PE_ERROR_BAD_CHPE_METADATA;
        if (i > 0U) {
            const struct gem_pe_arm64x_code_range *previous = &image->code_ranges[i - 1U];
            if (start < previous->start_rva)
                return GEM_PE_ERROR_UNSORTED_RANGES;
            if (start < previous->end_rva)
                return GEM_PE_ERROR_OVERLAPPING_RANGES;
        }
        /* A linker-defined code range may span unmapped section-alignment gaps. The
         * first and final bytes must still land in executable sections; guest-memory
         * checks remain responsible for rejecting accesses in an interior gap. */
        {
            const struct pe_section *first = find_section_for_span(image, start, 1U, NULL);
            const struct pe_section *last = find_section_for_span(image, end - 1U, 1U, NULL);
            if (first == NULL || last == NULL || !section_is_executable(first) ||
                !section_is_executable(last))
                return GEM_PE_ERROR_BAD_CHPE_METADATA;
        }

        range->start_rva = start;
        range->end_rva = end;
        range->isa = code_type_to_class(type);
    }
    return GEM_PE_OK;
}

static enum gem_pe_status parse_entry_ranges(struct parser_state *state,
                                             const struct chpe_metadata_fields *fields) {
    struct gem_pe_arm64x_image *image = state->image;
    size_t table_offset = 0;
    size_t i = 0;
    enum gem_pe_status status =
        table_file_span(image, fields->entry_ranges_rva, fields->entry_range_count,
                        PE_CHPE_ENTRY_RECORD_SIZE, &table_offset);
    if (status != GEM_PE_OK)
        return status == GEM_PE_ERROR_OVERFLOW ? status : GEM_PE_ERROR_BAD_CHPE_METADATA;

    for (i = 0; i < fields->entry_range_count; ++i) {
        const size_t offset = table_offset + (i * PE_CHPE_ENTRY_RECORD_SIZE);
        const uint32_t start = read_u32le_unchecked(state->bytes, offset);
        const uint32_t end = read_u32le_unchecked(state->bytes, offset + 4U);
        const uint32_t entry = read_u32le_unchecked(state->bytes, offset + 8U);
        struct gem_pe_arm64x_entry_range *range = &image->entry_ranges[i];
#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
        fprintf(stderr, "entry-range[%zu]: start=%#x end=%#x entry=%#x\n", i, start, end, entry);
#endif

        if (start >= end || end > image->summary.size_of_image || entry < start || entry >= end)
            return GEM_PE_ERROR_BAD_CHPE_METADATA;
        if (i > 0U) {
            const struct gem_pe_arm64x_entry_range *previous = &image->entry_ranges[i - 1U];
            if (start < previous->start_rva)
                return GEM_PE_ERROR_UNSORTED_RANGES;
            if (start < previous->end_rva)
                return GEM_PE_ERROR_OVERLAPPING_RANGES;
        }
        if (!code_range_contains_class(image, start, end, GEM_PE_RVA_X64))
            return GEM_PE_ERROR_BAD_CHPE_METADATA;
        range->start_rva = start;
        range->end_rva = end;
        range->entry_point_rva = entry;
    }
    return GEM_PE_OK;
}

static enum gem_pe_status parse_redirections(struct parser_state *state,
                                             const struct chpe_metadata_fields *fields) {
    struct gem_pe_arm64x_image *image = state->image;
    size_t table_offset = 0;
    size_t i = 0;
    enum gem_pe_status status =
        table_file_span(image, fields->redirections_rva, fields->redirection_count,
                        PE_CHPE_REDIRECTION_RECORD_SIZE, &table_offset);
    if (status != GEM_PE_OK)
        return status == GEM_PE_ERROR_OVERFLOW ? status : GEM_PE_ERROR_BAD_CHPE_METADATA;

    for (i = 0; i < fields->redirection_count; ++i) {
        const size_t offset = table_offset + (i * PE_CHPE_REDIRECTION_RECORD_SIZE);
        const uint32_t source = read_u32le_unchecked(state->bytes, offset);
        const uint32_t destination = read_u32le_unchecked(state->bytes, offset + 4U);
        struct gem_pe_arm64x_redirection *redirection = &image->redirections[i];

        if (source >= image->summary.size_of_image || destination >= image->summary.size_of_image)
            return GEM_PE_ERROR_BAD_CHPE_METADATA;
        if (i > 0U) {
            const struct gem_pe_arm64x_redirection *previous = &image->redirections[i - 1U];
            if (source < previous->source_rva)
                return GEM_PE_ERROR_UNSORTED_RANGES;
            if (source == previous->source_rva)
                return GEM_PE_ERROR_OVERLAPPING_RANGES;
        }
        redirection->source_rva = source;
        redirection->destination_rva = destination;
    }
    return GEM_PE_OK;
}

const char *gem_pe_status_name(enum gem_pe_status status) {
    static const char *const names[] = {
        "ok",
        "invalid-argument",
        "unsupported-format",
        "truncated",
        "overflow",
        "limit-exceeded",
        "bad-dos-header",
        "bad-pe-signature",
        "bad-coff-header",
        "bad-optional-header",
        "bad-section-table",
        "bad-rva",
        "bad-load-config",
        "no-chpe-metadata",
        "bad-chpe-metadata",
        "unsupported-chpe-version",
        "unsorted-ranges",
        "overlapping-ranges",
    };
    if ((unsigned int)status >= sizeof(names) / sizeof(names[0]))
        return "invalid";
    return names[status];
}

const char *gem_pe_rva_class_name(enum gem_pe_rva_class classification) {
    static const char *const names[] = {
        "invalid", "data", "arm64", "arm64ec", "x64", "thunk", "fast-forward",
    };
    if ((unsigned int)classification >= sizeof(names) / sizeof(names[0]))
        return "invalid";
    return names[classification];
}

void gem_pe_arm64x_default_parse_options(struct gem_pe_arm64x_parse_options *options) {
    if (options == NULL)
        return;
    options->version = GEM_PE_ARM64X_PARSE_OPTIONS_VERSION;
    options->max_sections = GEM_PE_ARM64X_DEFAULT_MAX_SECTIONS;
    options->max_code_ranges = GEM_PE_ARM64X_DEFAULT_MAX_CODE_RANGES;
    options->max_entry_ranges = GEM_PE_ARM64X_DEFAULT_MAX_ENTRY_RANGES;
    options->max_redirections = GEM_PE_ARM64X_DEFAULT_MAX_REDIRECTIONS;
}

enum gem_pe_status gem_pe_arm64x_parse(const uint8_t *bytes, size_t byte_count,
                                       const struct gem_pe_arm64x_parse_options *options,
                                       struct gem_pe_arm64x_image **out_image) {
    struct parser_state state;
    struct chpe_metadata_fields fields;
    size_t load_config_dir_offset = 0;
    enum gem_pe_status status = GEM_PE_OK;
#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
    const char *stage = "options";
#endif

    if (out_image == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_image = NULL;
    if (bytes == NULL || byte_count == 0U)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    memset(&state, 0, sizeof(state));
    memset(&fields, 0, sizeof(fields));
    status = copy_options(options, &state.options);
    if (status != GEM_PE_OK)
        return status;
    state.bytes = bytes;
    state.byte_count = byte_count;
    state.image = (struct gem_pe_arm64x_image *)calloc(1U, sizeof(*state.image));
    if (state.image == NULL)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;
    state.image->byte_count = byte_count;

#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
#define MSWR_PARSE_STAGE(name, expression)                                                         \
    do {                                                                                           \
        if (status == GEM_PE_OK) {                                                                 \
            stage = (name);                                                                        \
            status = (expression);                                                                 \
        }                                                                                          \
    } while (0)
    MSWR_PARSE_STAGE("headers", parse_headers(&state, &load_config_dir_offset));
    MSWR_PARSE_STAGE("load-config/chpe",
                     parse_load_config_and_chpe(&state, load_config_dir_offset, &fields));
    MSWR_PARSE_STAGE("allocation", allocate_metadata_arrays(&state, &fields));
    MSWR_PARSE_STAGE("code-map", parse_code_map(&state, &fields));
    MSWR_PARSE_STAGE("entry-ranges", parse_entry_ranges(&state, &fields));
    MSWR_PARSE_STAGE("redirections", parse_redirections(&state, &fields));
#undef MSWR_PARSE_STAGE
#else
    status = parse_headers(&state, &load_config_dir_offset);
    if (status == GEM_PE_OK)
        status = parse_load_config_and_chpe(&state, load_config_dir_offset, &fields);
    if (status == GEM_PE_OK)
        status = allocate_metadata_arrays(&state, &fields);
    if (status == GEM_PE_OK)
        status = parse_code_map(&state, &fields);
    if (status == GEM_PE_OK)
        status = parse_entry_ranges(&state, &fields);
    if (status == GEM_PE_OK)
        status = parse_redirections(&state, &fields);
#endif

    if (status != GEM_PE_OK) {
#ifdef MSWR_PE_ARM64X_DIAGNOSTICS
        fprintf(stderr, "parse-stage: %s (%s)\n", stage, gem_pe_status_name(status));
#endif
        gem_pe_arm64x_image_destroy(state.image);
        return status;
    }
    *out_image = state.image;
    return GEM_PE_OK;
}

enum gem_pe_status gem_pe_arm64x_image_clone(const struct gem_pe_arm64x_image *image,
                                             struct gem_pe_arm64x_image **out_image) {
    struct gem_pe_arm64x_image *copy = NULL;

    if (image == NULL || out_image == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_image = NULL;
    copy = (struct gem_pe_arm64x_image *)calloc(1U, sizeof(*copy));
    if (copy == NULL)
        return GEM_PE_ERROR_LIMIT_EXCEEDED;
    copy->summary = image->summary;
    copy->byte_count = image->byte_count;
    copy->size_of_headers = image->size_of_headers;

#define GEM_CLONE_ARRAY(field, count)                                                              \
    do {                                                                                           \
        size_t bytes = 0;                                                                          \
        if ((count) != 0U) {                                                                       \
            if (!checked_mul_size((count), sizeof(*copy->field), &bytes)) {                        \
                gem_pe_arm64x_image_destroy(copy);                                                 \
                return GEM_PE_ERROR_OVERFLOW;                                                      \
            }                                                                                      \
            copy->field = malloc(bytes);                                                           \
            if (copy->field == NULL) {                                                             \
                gem_pe_arm64x_image_destroy(copy);                                                 \
                return GEM_PE_ERROR_LIMIT_EXCEEDED;                                                \
            }                                                                                      \
            memcpy(copy->field, image->field, bytes);                                              \
        }                                                                                          \
    } while (0)
    GEM_CLONE_ARRAY(sections, (size_t)image->summary.section_count);
    GEM_CLONE_ARRAY(code_ranges, image->summary.code_range_count);
    GEM_CLONE_ARRAY(entry_ranges, image->summary.entry_range_count);
    GEM_CLONE_ARRAY(redirections, image->summary.redirection_count);
#undef GEM_CLONE_ARRAY
    *out_image = copy;
    return GEM_PE_OK;
}

void gem_pe_arm64x_image_destroy(struct gem_pe_arm64x_image *image) {
    if (image == NULL)
        return;
    free(image->sections);
    free(image->code_ranges);
    free(image->entry_ranges);
    free(image->redirections);
    free(image);
}

enum gem_pe_status gem_pe_arm64x_get_summary(const struct gem_pe_arm64x_image *image,
                                             struct gem_pe_arm64x_summary *out_summary) {
    if (image == NULL || out_summary == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_summary = image->summary;
    return GEM_PE_OK;
}

size_t gem_pe_arm64x_section_count(const struct gem_pe_arm64x_image *image) {
    return image == NULL ? 0U : (size_t)image->summary.section_count;
}

size_t gem_pe_arm64x_code_range_count(const struct gem_pe_arm64x_image *image) {
    return image == NULL ? 0U : image->summary.code_range_count;
}

size_t gem_pe_arm64x_entry_range_count(const struct gem_pe_arm64x_image *image) {
    return image == NULL ? 0U : image->summary.entry_range_count;
}

size_t gem_pe_arm64x_redirection_count(const struct gem_pe_arm64x_image *image) {
    return image == NULL ? 0U : image->summary.redirection_count;
}

enum gem_pe_status gem_pe_arm64x_get_section(const struct gem_pe_arm64x_image *image, size_t index,
                                             struct gem_pe_arm64x_section *out_section) {
    const struct pe_section *section;
    if (image == NULL || out_section == NULL || index >= image->summary.section_count)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    section = &image->sections[index];
    out_section->virtual_address = section->virtual_address;
    out_section->virtual_size = section->virtual_size;
    out_section->raw_size = section->raw_size;
    out_section->characteristics = section->characteristics;
    return GEM_PE_OK;
}

enum gem_pe_status gem_pe_arm64x_get_code_range(const struct gem_pe_arm64x_image *image,
                                                size_t index,
                                                struct gem_pe_arm64x_code_range *out_range) {
    if (image == NULL || out_range == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    if (index >= image->summary.code_range_count)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_range = image->code_ranges[index];
    return GEM_PE_OK;
}

enum gem_pe_status gem_pe_arm64x_get_entry_range(const struct gem_pe_arm64x_image *image,
                                                 size_t index,
                                                 struct gem_pe_arm64x_entry_range *out_range) {
    if (image == NULL || out_range == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    if (index >= image->summary.entry_range_count)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_range = image->entry_ranges[index];
    return GEM_PE_OK;
}

enum gem_pe_status
gem_pe_arm64x_get_redirection(const struct gem_pe_arm64x_image *image, size_t index,
                              struct gem_pe_arm64x_redirection *out_redirection) {
    if (image == NULL || out_redirection == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    if (index >= image->summary.redirection_count)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    *out_redirection = image->redirections[index];
    return GEM_PE_OK;
}

enum gem_pe_status gem_pe_arm64x_classify_rva(const struct gem_pe_arm64x_image *image, uint32_t rva,
                                              struct gem_pe_arm64x_rva_info *out_info) {
    const struct pe_section *section = NULL;
    const struct gem_pe_arm64x_code_range *code_range = NULL;
    const struct gem_pe_arm64x_entry_range *entry_range = NULL;
    const struct gem_pe_arm64x_redirection *redirection = NULL;
    size_t section_index = 0;

    if (image == NULL || out_info == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    memset(out_info, 0, sizeof(*out_info));
    out_info->classification = GEM_PE_RVA_INVALID;
    out_info->code_map_isa = GEM_PE_RVA_INVALID;
    out_info->rva = rva;
    if (rva >= image->summary.size_of_image)
        return GEM_PE_OK;

    section = find_section_for_span(image, rva, 1U, &section_index);
    if (section != NULL) {
        out_info->section_index = (uint32_t)(section_index + 1U);
        out_info->executable_section = section_is_executable(section);
    }

    code_range = find_code_range(image, rva);
    if (code_range != NULL) {
        out_info->code_map_isa = code_range->isa;
        out_info->containing_range_start_rva = code_range->start_rva;
        out_info->containing_range_end_rva = code_range->end_rva;
    }
    entry_range = find_entry_range(image, rva);
    if (entry_range != NULL) {
        out_info->has_entry_point = true;
        out_info->entry_point_rva = entry_range->entry_point_rva;
        if (code_range == NULL) {
            out_info->containing_range_start_rva = entry_range->start_rva;
            out_info->containing_range_end_rva = entry_range->end_rva;
        }
    }
    redirection = find_redirection(image, rva);
    if (redirection != NULL) {
        out_info->has_redirection = true;
        out_info->redirection_destination_rva = redirection->destination_rva;
        out_info->classification = GEM_PE_RVA_FAST_FORWARD;
        return GEM_PE_OK;
    }
    if (entry_range != NULL) {
        out_info->classification = GEM_PE_RVA_THUNK;
        return GEM_PE_OK;
    }
    if (code_range != NULL) {
        out_info->classification = code_range->isa;
        return GEM_PE_OK;
    }
    if (section != NULL && !section_is_executable(section))
        out_info->classification = GEM_PE_RVA_DATA;
    return GEM_PE_OK;
}

enum gem_pe_status gem_pe_arm64x_rva_to_file_offset(const struct gem_pe_arm64x_image *image,
                                                    uint32_t rva, uint32_t size,
                                                    size_t *out_offset) {
    if (image == NULL || out_offset == NULL)
        return GEM_PE_ERROR_INVALID_ARGUMENT;
    return rva_to_file_offset_internal(image, rva, size, out_offset);
}
