// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/pe_arm64x.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_IMAGE_BYTES (64L * 1024L * 1024L)

static int mapping(const struct gem_pe_arm64x_image *image, uint32_t rva, uint32_t size,
                   size_t *offset) {
    enum gem_pe_status status = gem_pe_arm64x_rva_to_file_offset(image, rva, size, offset);
    if (status != GEM_PE_OK)
        fprintf(stderr, "RVA mapping 0x%08" PRIx32 ": %s\n", rva, gem_pe_status_name(status));
    return status == GEM_PE_OK;
}

static int validate_records(const struct gem_pe_arm64x_image *image,
                            const struct gem_pe_arm64x_summary *summary) {
    size_t i;
    size_t offset;
    struct gem_pe_arm64x_code_range code;
    struct gem_pe_arm64x_entry_range entry;
    struct gem_pe_arm64x_redirection redirection;
    uint32_t metadata_size = summary->chpe_metadata_version == 1U ? 80U : 92U;

    if (!mapping(image, summary->load_config_rva, summary->load_config_size, &offset) ||
        !mapping(image, summary->chpe_metadata_rva, metadata_size, &offset))
        return 0;
    for (i = 0; i < summary->code_range_count; ++i) {
        if (gem_pe_arm64x_get_code_range(image, i, &code) != GEM_PE_OK ||
            !mapping(image, code.start_rva, 1U, &offset) ||
            !mapping(image, code.end_rva - 1U, 1U, &offset))
            return 0;
    }
    for (i = 0; i < summary->entry_range_count; ++i) {
        if (gem_pe_arm64x_get_entry_range(image, i, &entry) != GEM_PE_OK ||
            !mapping(image, entry.start_rva, 1U, &offset) ||
            !mapping(image, entry.end_rva - 1U, 1U, &offset) ||
            (entry.entry_point_rva != 0U && !mapping(image, entry.entry_point_rva, 1U, &offset)))
            return 0;
    }
    for (i = 0; i < summary->redirection_count; ++i) {
        if (gem_pe_arm64x_get_redirection(image, i, &redirection) != GEM_PE_OK ||
            !mapping(image, redirection.source_rva, 1U, &offset) ||
            !mapping(image, redirection.destination_rva, 1U, &offset))
            return 0;
    }
    return 1;
}

static void print_mapping(const struct gem_pe_arm64x_image *image, uint32_t rva, uint32_t size) {
    size_t offset = 0;
    (void)gem_pe_arm64x_rva_to_file_offset(image, rva, size, &offset);
    printf("%" PRIu64, (uint64_t)offset);
}

static void print_json(const struct gem_pe_arm64x_image *image,
                       const struct gem_pe_arm64x_summary *summary) {
    size_t i;
    struct gem_pe_arm64x_code_range code;
    struct gem_pe_arm64x_entry_range entry;
    struct gem_pe_arm64x_redirection redirection;
    uint32_t metadata_size = summary->chpe_metadata_version == 1U ? 80U : 92U;

    printf("{\"schemaVersion\":1,\"machine\":%u,\"sectionCount\":%u,"
           "\"imageBase\":%" PRIu64 ",\"imageSize\":%u,\"entryPointRva\":%u,",
           summary->machine, summary->section_count, summary->image_base, summary->size_of_image,
           summary->address_of_entry_point);
    printf("\"loadConfig\":{\"rva\":%u,\"size\":%u,\"fileOffset\":", summary->load_config_rva,
           summary->load_config_size);
    print_mapping(image, summary->load_config_rva, summary->load_config_size);
    printf("},\"chpeMetadata\":{\"rva\":%u,\"version\":%u,\"minimumSize\":%u,"
           "\"fileOffset\":",
           summary->chpe_metadata_rva, summary->chpe_metadata_version, metadata_size);
    print_mapping(image, summary->chpe_metadata_rva, metadata_size);
    printf("},\"counts\":{\"codeRanges\":%" PRIu64 ",\"entryRanges\":%" PRIu64
           ",\"redirections\":%" PRIu64 "},\"codeRanges\":[",
           (uint64_t)summary->code_range_count, (uint64_t)summary->entry_range_count,
           (uint64_t)summary->redirection_count);
    for (i = 0; i < summary->code_range_count; ++i) {
        (void)gem_pe_arm64x_get_code_range(image, i, &code);
        if (i != 0U)
            putchar(',');
        printf("{\"startRva\":%u,\"endRva\":%u,\"isa\":\"%s\",\"startOffset\":", code.start_rva,
               code.end_rva, gem_pe_rva_class_name(code.isa));
        print_mapping(image, code.start_rva, 1U);
        printf(",\"endByteOffset\":");
        print_mapping(image, code.end_rva - 1U, 1U);
        putchar('}');
    }
    printf("],\"entryRanges\":[");
    for (i = 0; i < summary->entry_range_count; ++i) {
        (void)gem_pe_arm64x_get_entry_range(image, i, &entry);
        if (i != 0U)
            putchar(',');
        printf("{\"startRva\":%u,\"endRva\":%u,\"entryPointRva\":%u,"
               "\"startOffset\":",
               entry.start_rva, entry.end_rva, entry.entry_point_rva);
        print_mapping(image, entry.start_rva, 1U);
        printf(",\"endByteOffset\":");
        print_mapping(image, entry.end_rva - 1U, 1U);
        printf(",\"entryPointOffset\":");
        if (entry.entry_point_rva == 0U)
            printf("null");
        else
            print_mapping(image, entry.entry_point_rva, 1U);
        putchar('}');
    }
    printf("],\"redirections\":[");
    for (i = 0; i < summary->redirection_count; ++i) {
        (void)gem_pe_arm64x_get_redirection(image, i, &redirection);
        if (i != 0U)
            putchar(',');
        printf("{\"sourceRva\":%u,\"destinationRva\":%u,\"sourceOffset\":", redirection.source_rva,
               redirection.destination_rva);
        print_mapping(image, redirection.source_rva, 1U);
        printf(",\"destinationOffset\":");
        print_mapping(image, redirection.destination_rva, 1U);
        putchar('}');
    }
    printf("]}\n");
}

int main(int argc, char **argv) {
    FILE *file;
    long size;
    uint8_t *bytes;
    struct gem_pe_arm64x_image *image = NULL;
    struct gem_pe_arm64x_summary summary;
    enum gem_pe_status status;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PE-file\n", argv[0]);
        return 2;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open input\n");
        return 2;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) <= 0 || size > MAX_IMAGE_BYTES ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "invalid input size\n");
        fclose(file);
        return 2;
    }
    bytes = (uint8_t *)malloc((size_t)size);
    if (bytes == NULL || fread(bytes, 1U, (size_t)size, file) != (size_t)size) {
        fprintf(stderr, "cannot read input\n");
        free(bytes);
        fclose(file);
        return 2;
    }
    fclose(file);
    status = gem_pe_arm64x_parse(bytes, (size_t)size, NULL, &image);
    free(bytes);
    if (status != GEM_PE_OK) {
        fprintf(stderr, "parse: %s\n", gem_pe_status_name(status));
        return 1;
    }
    status = gem_pe_arm64x_get_summary(image, &summary);
    if (status != GEM_PE_OK || !validate_records(image, &summary)) {
        if (status != GEM_PE_OK)
            fprintf(stderr, "summary: %s\n", gem_pe_status_name(status));
        gem_pe_arm64x_image_destroy(image);
        return 1;
    }
    print_json(image, &summary);
    gem_pe_arm64x_image_destroy(image);
    return 0;
}
