// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/pe_arm64x_loader.h"

#include <stdlib.h>
#include <string.h>

#define PE_SECTION_MEM_EXECUTE UINT32_C(0x20000000)
#define PE_SECTION_MEM_READ UINT32_C(0x40000000)
#define PE_SECTION_MEM_WRITE UINT32_C(0x80000000)

struct gem_pe_arm64x_materialized_image {
    struct gem_pe_arm64x_image *metadata;
    uint64_t base;
    uint64_t size;
};

static bool add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (a > UINT64_MAX - b)
        return false;
    *out = a + b;
    return true;
}

static uint32_t section_protection(uint32_t characteristics) {
    const bool read = (characteristics & PE_SECTION_MEM_READ) != 0U;
    const bool write = (characteristics & PE_SECTION_MEM_WRITE) != 0U;
    const bool execute = (characteristics & PE_SECTION_MEM_EXECUTE) != 0U;
    if (execute)
        return write ? GEM_PAGE_EXECUTE_READWRITE : read ? GEM_PAGE_EXECUTE_READ : GEM_PAGE_EXECUTE;
    return write ? GEM_PAGE_READWRITE : read ? GEM_PAGE_READONLY : GEM_PAGE_NOACCESS;
}

static bool section_contains(const struct gem_pe_arm64x_section *section, uint32_t rva,
                             uint32_t size) {
    const uint32_t extent =
        section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
    uint64_t end = (uint64_t)rva + size;
    return rva >= section->virtual_address && end <= (uint64_t)section->virtual_address + extent;
}

const char *gem_pe_materialize_status_name(enum gem_pe_materialize_status status) {
    static const char *const names[] = {
        "ok",          "invalid-argument", "parse-error", "relocation-required",
        "overflow",    "conflict",         "bad-section", "permission-conflict",
        "bad-binding", "memory-error",
    };
    return (unsigned int)status < sizeof(names) / sizeof(names[0]) ? names[status] : "invalid";
}

enum gem_pe_materialize_status
gem_pe_arm64x_materialize_preferred(struct gem_memory *memory, const uint8_t *bytes,
                                    size_t byte_count,
                                    const struct gem_pe_arm64x_materialize_options *options,
                                    struct gem_pe_arm64x_materialized_image **out_image) {
    struct gem_pe_arm64x_materialized_image *result = NULL;
    struct gem_pe_arm64x_summary summary;
    uint32_t *page_protections = NULL;
    size_t page_count = 0U;
    size_t index;
    uint64_t reserved_base;
    uint64_t image_end = 0U;
    bool reserved = false;
    enum gem_pe_materialize_status status = GEM_PE_MATERIALIZE_INVALID_ARGUMENT;

    if (out_image == NULL)
        return status;
    *out_image = NULL;
    if (memory == NULL || bytes == NULL || byte_count == 0U || options == NULL ||
        options->version != GEM_PE_ARM64X_MATERIALIZE_OPTIONS_VERSION || options->reserved != 0U ||
        options->binding_count > GEM_PE_ARM64X_MAX_BINDINGS ||
        (options->binding_count != 0U && options->bindings == NULL))
        return status;
    result = (struct gem_pe_arm64x_materialized_image *)calloc(1U, sizeof(*result));
    if (result == NULL)
        return GEM_PE_MATERIALIZE_MEMORY_ERROR;
    if (gem_pe_arm64x_parse(bytes, byte_count, NULL, &result->metadata) != GEM_PE_OK) {
        status = GEM_PE_MATERIALIZE_PARSE_ERROR;
        goto Fail;
    }
    if (gem_pe_arm64x_get_summary(result->metadata, &summary) != GEM_PE_OK) {
        status = GEM_PE_MATERIALIZE_PARSE_ERROR;
        goto Fail;
    }
    if (options->image_base != summary.image_base) {
        status = GEM_PE_MATERIALIZE_RELOCATION_REQUIRED;
        goto Fail;
    }
    if ((summary.image_base & (GEM_GUEST_PAGE_SIZE - 1U)) != 0U ||
        (summary.size_of_image & (GEM_GUEST_PAGE_SIZE - 1U)) != 0U ||
        summary.size_of_headers == 0U || summary.size_of_headers > summary.size_of_image ||
        !add_u64(summary.image_base, summary.size_of_image, &image_end)) {
        status = GEM_PE_MATERIALIZE_OVERFLOW;
        goto Fail;
    }
    result->base = summary.image_base;
    result->size = summary.size_of_image;
    page_count = summary.size_of_image / (size_t)GEM_GUEST_PAGE_SIZE;
    page_protections = (uint32_t *)calloc(page_count, sizeof(*page_protections));
    if (page_protections == NULL) {
        status = GEM_PE_MATERIALIZE_MEMORY_ERROR;
        goto Fail;
    }
    for (index = 0U; index < ((size_t)summary.size_of_headers + (size_t)GEM_GUEST_PAGE_SIZE - 1U) /
                                 (size_t)GEM_GUEST_PAGE_SIZE;
         ++index)
        page_protections[index] = GEM_PAGE_READONLY;
    reserved_base = result->base;
    if (gem_memory_reserve(memory, &reserved_base, result->size) != GEM_MEMORY_OK) {
        status = GEM_PE_MATERIALIZE_CONFLICT;
        goto Fail;
    }
    reserved = true;
    if (reserved_base != result->base || gem_memory_commit(memory, result->base, result->size,
                                                           GEM_PAGE_READWRITE) != GEM_MEMORY_OK) {
        status = GEM_PE_MATERIALIZE_MEMORY_ERROR;
        goto Fail;
    }
    if (gem_memory_write(memory, result->base, bytes, summary.size_of_headers) != GEM_MEMORY_OK) {
        status = GEM_PE_MATERIALIZE_MEMORY_ERROR;
        goto Fail;
    }

    for (index = 0; index < gem_pe_arm64x_section_count(result->metadata); ++index) {
        struct gem_pe_arm64x_section section;
        uint64_t virtual_end;
        uint32_t first_page;
        uint32_t final_page;
        uint32_t protection;
        size_t file_offset = 0U;
        uint32_t page;
        if (gem_pe_arm64x_get_section(result->metadata, index, &section) != GEM_PE_OK) {
            status = GEM_PE_MATERIALIZE_BAD_SECTION;
            goto Fail;
        }
        if (!add_u64(section.virtual_address,
                     section.virtual_size > section.raw_size ? section.virtual_size
                                                             : section.raw_size,
                     &virtual_end) ||
            virtual_end > summary.size_of_image) {
            status = GEM_PE_MATERIALIZE_BAD_SECTION;
            goto Fail;
        }
        first_page = section.virtual_address / (uint32_t)GEM_GUEST_PAGE_SIZE;
        final_page = (uint32_t)((virtual_end + GEM_GUEST_PAGE_SIZE - 1U) / GEM_GUEST_PAGE_SIZE);
        protection = section_protection(section.characteristics);
        for (page = first_page; page < final_page; ++page) {
            if (page >= page_count ||
                (page_protections[page] != 0U && page_protections[page] != protection)) {
                status = GEM_PE_MATERIALIZE_PERMISSION_CONFLICT;
                goto Fail;
            }
            page_protections[page] = protection;
        }
        if (section.raw_size != 0U) {
            if (gem_pe_arm64x_rva_to_file_offset(result->metadata, section.virtual_address,
                                                 section.raw_size, &file_offset) != GEM_PE_OK ||
                file_offset > byte_count || section.raw_size > byte_count - file_offset ||
                gem_memory_write(memory, result->base + section.virtual_address,
                                 bytes + file_offset, section.raw_size) != GEM_MEMORY_OK) {
                status = GEM_PE_MATERIALIZE_BAD_SECTION;
                goto Fail;
            }
        }
    }

    for (index = 0; index < options->binding_count; ++index) {
        const struct gem_pe_arm64x_binding *binding = &options->bindings[index];
        struct gem_pe_arm64x_section section = {0};
        size_t section_index;
        bool found = false;
        for (section_index = 0; section_index < gem_pe_arm64x_section_count(result->metadata);
             ++section_index) {
            if (gem_pe_arm64x_get_section(result->metadata, section_index, &section) == GEM_PE_OK &&
                section_contains(&section, binding->slot_rva, (uint32_t)sizeof(binding->value))) {
                found = true;
                break;
            }
        }
        if (!found || (section.characteristics & PE_SECTION_MEM_EXECUTE) != 0U ||
            binding->value == 0U ||
            (binding->value >= result->base && binding->value < image_end)) {
            status = GEM_PE_MATERIALIZE_BAD_BINDING;
            goto Fail;
        }
        for (section_index = 0; section_index < index; ++section_index)
            if (options->bindings[section_index].slot_rva == binding->slot_rva) {
                status = GEM_PE_MATERIALIZE_BAD_BINDING;
                goto Fail;
            }
        if (gem_memory_write(memory, result->base + binding->slot_rva, &binding->value,
                             sizeof(binding->value)) != GEM_MEMORY_OK) {
            status = GEM_PE_MATERIALIZE_MEMORY_ERROR;
            goto Fail;
        }
    }

    for (index = 0; index < page_count; ++index) {
        const uint32_t protection =
            page_protections[index] == 0U ? GEM_PAGE_NOACCESS : page_protections[index];
        if (gem_memory_protect(memory, result->base + index * GEM_GUEST_PAGE_SIZE,
                               GEM_GUEST_PAGE_SIZE, protection, NULL) != GEM_MEMORY_OK) {
            status = GEM_PE_MATERIALIZE_MEMORY_ERROR;
            goto Fail;
        }
    }
    free(page_protections);
    *out_image = result;
    return GEM_PE_MATERIALIZE_OK;

Fail:
    free(page_protections);
    if (reserved)
        (void)gem_memory_release(memory, result->base, result->size);
    gem_pe_arm64x_materialized_image_destroy(result);
    return status;
}

void gem_pe_arm64x_materialized_image_destroy(struct gem_pe_arm64x_materialized_image *image) {
    if (image != NULL) {
        gem_pe_arm64x_image_destroy(image->metadata);
        free(image);
    }
}

const struct gem_pe_arm64x_image *
gem_pe_arm64x_materialized_metadata(const struct gem_pe_arm64x_materialized_image *image) {
    return image == NULL ? NULL : image->metadata;
}

uint64_t gem_pe_arm64x_materialized_base(const struct gem_pe_arm64x_materialized_image *image) {
    return image == NULL ? 0U : image->base;
}

uint64_t gem_pe_arm64x_materialized_size(const struct gem_pe_arm64x_materialized_image *image) {
    return image == NULL ? 0U : image->size;
}
