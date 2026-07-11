// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/pe_arm64x.h"
#include "pe_arm64x_fixture_builder.h"

#include <assert.h>
#include <string.h>

#define PE_OFFSET 0x80U
#define OPTIONAL_OFFSET (PE_OFFSET + 24U)
#define SECTION_OFFSET (OPTIONAL_OFFSET + 0xf0U)

static enum gem_pe_status parse(const struct pe_arm64x_fixture *fixture,
                                const struct gem_pe_arm64x_parse_options *options) {
    struct gem_pe_arm64x_image *image = NULL;
    enum gem_pe_status status = gem_pe_arm64x_parse(fixture->bytes, fixture->size, options, &image);
    gem_pe_arm64x_image_destroy(image);
    return status;
}

static void reset(struct pe_arm64x_fixture *fixture) {
    pe_arm64x_fixture_destroy(fixture);
    assert(pe_arm64x_fixture_build(2U, fixture));
}

int main(void) {
    struct pe_arm64x_fixture f;
    struct gem_pe_arm64x_parse_options options;
    size_t md;
    size_t cm;
    size_t er;
    size_t rd;
    struct gem_pe_arm64x_image *truncated_image = NULL;

    assert(pe_arm64x_fixture_build(2U, &f));
    assert(gem_pe_arm64x_parse(f.bytes, 63U, NULL, &truncated_image) == GEM_PE_ERROR_TRUNCATED);
    assert(parse(&f, NULL) == GEM_PE_OK);

    /* ARM64 is accepted only after the same complete CHPE validation. */
    pe_arm64x_fixture_put_u16(f.bytes, PE_OFFSET + 4U, 0xaa64U);
    assert(parse(&f, NULL) == GEM_PE_OK);
    pe_arm64x_fixture_put_u64(f.bytes, pe_arm64x_fixture_rva_to_offset(0x3000U) + 0xc8U, 0U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_NO_CHPE_METADATA);
    reset(&f);
    pe_arm64x_fixture_put_u16(f.bytes, PE_OFFSET + 4U, 0xa641U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_UNSUPPORTED_FORMAT);
    reset(&f);

    md = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CHPE_RVA);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    er = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_ENTRY_RANGES_RVA);
    rd = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_REDIRECTIONS_RVA);

    /* Version sizes are 80 (v1) and 92 (v2), not the consumed 56-byte prefix. */
    pe_arm64x_fixture_put_u32(f.bytes, md, 3U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_UNSUPPORTED_CHPE_VERSION);
    reset(&f);
    md = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CHPE_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, md + 12U, 0x3ff0U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);

    /* At the final 80 raw bytes, v1 fits and v2's last 12 bytes are truncated. */
    reset(&f);
    md = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CHPE_RVA);
    memcpy(f.bytes + pe_arm64x_fixture_rva_to_offset(0x3facU), f.bytes + md, 80U);
    pe_arm64x_fixture_put_u64(f.bytes, pe_arm64x_fixture_rva_to_offset(0x3000U) + 0xc8U,
                              PE_ARM64X_FIXTURE_IMAGE_BASE + 0x3facU);
    pe_arm64x_fixture_put_u32(f.bytes, pe_arm64x_fixture_rva_to_offset(0x3facU), 1U);
    assert(parse(&f, NULL) == GEM_PE_OK);
    pe_arm64x_fixture_put_u32(f.bytes, pe_arm64x_fixture_rva_to_offset(0x3facU), 2U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);

    reset(&f);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, cm + 8U, 0x0fe1U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_UNSORTED_RANGES);
    reset(&f);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, cm + 8U, 0x1301U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_OVERLAPPING_RANGES);
    reset(&f);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, cm, 0xfffffff0U);
    pe_arm64x_fixture_put_u32(f.bytes, cm + 4U, 0x100U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);
    reset(&f);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, cm, 0x1003U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);
    reset(&f);
    cm = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CODE_MAP_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, cm + 4U, 0U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);

    reset(&f);
    er = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_ENTRY_RANGES_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, er, 0x1900U);
    pe_arm64x_fixture_put_u32(f.bytes, er + 4U, 0x1800U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);
    reset(&f);
    er = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_ENTRY_RANGES_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, er + 8U, 0x1900U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);
    reset(&f);
    rd = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_REDIRECTIONS_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, rd + 4U, 0x4000U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);

    /* Table RVAs cannot point outside the image or into virtual zero-fill. */
    reset(&f);
    md = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_CHPE_RVA);
    pe_arm64x_fixture_put_u32(f.bytes, md + 4U, 0x4000U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);
    reset(&f);
    pe_arm64x_fixture_put_u32(f.bytes, SECTION_OFFSET + 40U + 16U, 0x100U);
    assert(parse(&f, NULL) == GEM_PE_ERROR_BAD_CHPE_METADATA);

    reset(&f);
    gem_pe_arm64x_default_parse_options(&options);
    options.version = 0U;
    assert(parse(&f, &options) == GEM_PE_ERROR_INVALID_ARGUMENT);
    gem_pe_arm64x_default_parse_options(&options);
    options.max_code_ranges = 2U;
    assert(parse(&f, &options) == GEM_PE_ERROR_LIMIT_EXCEEDED);
    gem_pe_arm64x_default_parse_options(&options);
    options.max_sections = 1U;
    assert(parse(&f, &options) == GEM_PE_ERROR_LIMIT_EXCEEDED);

    pe_arm64x_fixture_destroy(&f);
    return 0;
}
