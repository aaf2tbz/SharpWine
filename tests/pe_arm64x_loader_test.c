// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/pe_arm64x_loader.h"
#include "pe_arm64x_fixture_builder.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "loader check failed at line %d: %s\n", __LINE__, #condition);         \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct gem_pe_arm64x_materialize_options preferred_options(void) {
    struct gem_pe_arm64x_materialize_options options;
    memset(&options, 0, sizeof(options));
    options.version = GEM_PE_ARM64X_MATERIALIZE_OPTIONS_VERSION;
    options.image_base = PE_ARM64X_FIXTURE_IMAGE_BASE;
    return options;
}

int main(void) {
    struct pe_arm64x_fixture fixture;
    struct gem_memory *memory;
    struct gem_pe_arm64x_materialized_image *image = NULL;
    struct gem_pe_arm64x_materialize_options options = preferred_options();
    uint8_t bytes[4] = {0};
    uint8_t replacement = 0xffU;
    uint64_t address;

    CHECK(pe_arm64x_fixture_build(2U, &fixture));
    memory = gem_memory_create();
    CHECK(memory != NULL);
    CHECK(gem_pe_arm64x_materialize_preferred(memory, fixture.bytes, fixture.size, &options,
                                              &image) == GEM_PE_MATERIALIZE_OK);
    CHECK(image != NULL);
    CHECK(gem_pe_arm64x_materialized_base(image) == PE_ARM64X_FIXTURE_IMAGE_BASE);
    CHECK(gem_pe_arm64x_materialized_size(image) == PE_ARM64X_FIXTURE_SIZE_OF_IMAGE);
    CHECK(gem_memory_read(memory, PE_ARM64X_FIXTURE_IMAGE_BASE, bytes, 2U) == GEM_MEMORY_OK);
    CHECK(bytes[0] == 'M' && bytes[1] == 'Z');
    CHECK(gem_memory_fetch(memory, PE_ARM64X_FIXTURE_IMAGE_BASE + PE_ARM64X_FIXTURE_TEXT_RVA, bytes,
                           sizeof(bytes)) == GEM_MEMORY_OK);
    CHECK(gem_memory_write(memory, PE_ARM64X_FIXTURE_IMAGE_BASE + PE_ARM64X_FIXTURE_TEXT_RVA,
                           &replacement, 1U) == GEM_MEMORY_ACCESS_DENIED);
    CHECK(gem_memory_read(memory, PE_ARM64X_FIXTURE_IMAGE_BASE + PE_ARM64X_FIXTURE_RDATA_RVA, bytes,
                          sizeof(bytes)) == GEM_MEMORY_OK);
    CHECK(gem_memory_fetch(memory, PE_ARM64X_FIXTURE_IMAGE_BASE + PE_ARM64X_FIXTURE_RDATA_RVA,
                           bytes, sizeof(bytes)) == GEM_MEMORY_ACCESS_DENIED);
    gem_pe_arm64x_materialized_image_destroy(image);
    image = NULL;
    CHECK(gem_memory_release(memory, PE_ARM64X_FIXTURE_IMAGE_BASE,
                             PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) == GEM_MEMORY_OK);

    options.image_base += GEM_GUEST_PAGE_SIZE;
    CHECK(gem_pe_arm64x_materialize_preferred(memory, fixture.bytes, fixture.size, &options,
                                              &image) == GEM_PE_MATERIALIZE_RELOCATION_REQUIRED);
    CHECK(image == NULL);
    address = PE_ARM64X_FIXTURE_IMAGE_BASE;
    CHECK(gem_memory_reserve(memory, &address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) == GEM_MEMORY_OK);
    CHECK(gem_memory_release(memory, address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) == GEM_MEMORY_OK);

    options = preferred_options();
    CHECK(gem_pe_arm64x_materialize_preferred(memory, fixture.bytes, 63U, &options, &image) ==
          GEM_PE_MATERIALIZE_PARSE_ERROR);
    CHECK(image == NULL);

    {
        const struct gem_pe_arm64x_binding binding = {PE_ARM64X_FIXTURE_TEXT_RVA,
                                                      UINT64_C(0xffffffffffffffe0)};
        options.bindings = &binding;
        options.binding_count = 1U;
        CHECK(gem_pe_arm64x_materialize_preferred(memory, fixture.bytes, fixture.size, &options,
                                                  &image) == GEM_PE_MATERIALIZE_BAD_BINDING);
        CHECK(image == NULL);
        address = PE_ARM64X_FIXTURE_IMAGE_BASE;
        CHECK(gem_memory_reserve(memory, &address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) ==
              GEM_MEMORY_OK);
        CHECK(gem_memory_release(memory, address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) ==
              GEM_MEMORY_OK);
    }

    options = preferred_options();
    address = PE_ARM64X_FIXTURE_IMAGE_BASE;
    CHECK(gem_memory_reserve(memory, &address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) == GEM_MEMORY_OK);
    CHECK(gem_pe_arm64x_materialize_preferred(memory, fixture.bytes, fixture.size, &options,
                                              &image) == GEM_PE_MATERIALIZE_CONFLICT);
    CHECK(image == NULL);
    CHECK(gem_memory_release(memory, address, PE_ARM64X_FIXTURE_SIZE_OF_IMAGE) == GEM_MEMORY_OK);

    gem_memory_destroy(memory);
    pe_arm64x_fixture_destroy(&fixture);
    puts("preferred-base ARM64X materializer tests passed");
    return 0;
}
