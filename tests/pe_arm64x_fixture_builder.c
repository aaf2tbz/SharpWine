// SPDX-License-Identifier: Apache-2.0
#include "pe_arm64x_fixture_builder.h"

#include <stdlib.h>
#include <string.h>

#define PE_OFFSET 0x80U
#define OPTIONAL_OFFSET (PE_OFFSET + 24U)
#define SECTION_OFFSET (OPTIONAL_OFFSET + 0xF0U)
#define TEXT_RAW 0x400U
#define RDATA_RAW 0x2400U

void pe_arm64x_fixture_put_u16(uint8_t *p, size_t o, uint16_t v) {
    p[o] = (uint8_t)v;
    p[o + 1U] = (uint8_t)(v >> 8U);
}
void pe_arm64x_fixture_put_u32(uint8_t *p, size_t o, uint32_t v) {
    p[o] = (uint8_t)v;
    p[o + 1U] = (uint8_t)(v >> 8U);
    p[o + 2U] = (uint8_t)(v >> 16U);
    p[o + 3U] = (uint8_t)(v >> 24U);
}
void pe_arm64x_fixture_put_u64(uint8_t *p, size_t o, uint64_t v) {
    pe_arm64x_fixture_put_u32(p, o, (uint32_t)v);
    pe_arm64x_fixture_put_u32(p, o + 4U, (uint32_t)(v >> 32U));
}
size_t pe_arm64x_fixture_rva_to_offset(uint32_t rva) {
    return rva < 0x400U ? rva
                        : (rva < PE_ARM64X_FIXTURE_RDATA_RVA
                               ? TEXT_RAW + rva - PE_ARM64X_FIXTURE_TEXT_RVA
                               : RDATA_RAW + rva - PE_ARM64X_FIXTURE_RDATA_RVA);
}
static void section(uint8_t *p, size_t o, const char *name, uint32_t va, uint32_t size,
                    uint32_t raw, uint32_t characteristics) {
    memcpy(p + o, name, strlen(name));
    pe_arm64x_fixture_put_u32(p, o + 8U, size);
    pe_arm64x_fixture_put_u32(p, o + 12U, va);
    pe_arm64x_fixture_put_u32(p, o + 16U, size);
    pe_arm64x_fixture_put_u32(p, o + 20U, raw);
    pe_arm64x_fixture_put_u32(p, o + 36U, characteristics);
}
int pe_arm64x_fixture_build(uint32_t version, struct pe_arm64x_fixture *f) {
    uint8_t *p;
    size_t lc, md, cm, er, rd;
    if (f == NULL || (version != 1U && version != 2U))
        return 0;
    memset(f, 0, sizeof(*f));
    f->size = 0x3400U;
    p = calloc(1U, f->size);
    if (!p)
        return 0;
    p[0] = 'M';
    p[1] = 'Z';
    pe_arm64x_fixture_put_u32(p, 0x3cU, PE_OFFSET);
    memcpy(p + PE_OFFSET, "PE\0\0", 4U);
    pe_arm64x_fixture_put_u16(p, PE_OFFSET + 4U, 0xa64eU);
    pe_arm64x_fixture_put_u16(p, PE_OFFSET + 6U, 2U);
    pe_arm64x_fixture_put_u16(p, PE_OFFSET + 20U, 0xf0U);
    pe_arm64x_fixture_put_u16(p, OPTIONAL_OFFSET, 0x20bU);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 16U, 0x1000U);
    pe_arm64x_fixture_put_u64(p, OPTIONAL_OFFSET + 24U, PE_ARM64X_FIXTURE_IMAGE_BASE);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 32U, 0x1000U);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 36U, 0x200U);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 56U, 0x4000U);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 60U, 0x400U);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 108U, 16U);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 112U + 80U, PE_ARM64X_FIXTURE_LOAD_CONFIG_RVA);
    pe_arm64x_fixture_put_u32(p, OPTIONAL_OFFSET + 116U + 80U, PE_ARM64X_FIXTURE_LOAD_CONFIG_SIZE);
    section(p, SECTION_OFFSET, ".text", 0x1000U, 0x2000U, TEXT_RAW, 0x60000020U);
    section(p, SECTION_OFFSET + 40U, ".rdata", 0x3000U, 0x1000U, RDATA_RAW, 0x40000040U);
    lc = pe_arm64x_fixture_rva_to_offset(0x3000U);
    pe_arm64x_fixture_put_u32(p, lc, 0x140U);
    pe_arm64x_fixture_put_u64(p, lc + 0xc8U,
                              PE_ARM64X_FIXTURE_IMAGE_BASE + PE_ARM64X_FIXTURE_CHPE_RVA);
    md = pe_arm64x_fixture_rva_to_offset(0x3100U);
    pe_arm64x_fixture_put_u32(p, md, version);
    pe_arm64x_fixture_put_u32(p, md + 4U, 0x3200U);
    pe_arm64x_fixture_put_u32(p, md + 8U, 3U);
    pe_arm64x_fixture_put_u32(p, md + 12U, 0x3300U);
    pe_arm64x_fixture_put_u32(p, md + 16U, 0x3400U);
    pe_arm64x_fixture_put_u32(p, md + 48U, 1U);
    pe_arm64x_fixture_put_u32(p, md + 52U, 1U);
    cm = pe_arm64x_fixture_rva_to_offset(0x3200U);
    pe_arm64x_fixture_put_u32(p, cm, 0x1000U);
    pe_arm64x_fixture_put_u32(p, cm + 4U, 0x400U);
    pe_arm64x_fixture_put_u32(p, cm + 8U, 0x1401U);
    pe_arm64x_fixture_put_u32(p, cm + 12U, 0x400U);
    pe_arm64x_fixture_put_u32(p, cm + 16U, 0x1802U);
    pe_arm64x_fixture_put_u32(p, cm + 20U, 0x800U);
    er = pe_arm64x_fixture_rva_to_offset(0x3300U);
    pe_arm64x_fixture_put_u32(p, er, 0x1800U);
    pe_arm64x_fixture_put_u32(p, er + 4U, 0x1900U);
    pe_arm64x_fixture_put_u32(p, er + 8U, 0x1800U);
    rd = pe_arm64x_fixture_rva_to_offset(0x3400U);
    pe_arm64x_fixture_put_u32(p, rd, 0x1800U);
    pe_arm64x_fixture_put_u32(p, rd + 4U, 0x1000U);
    f->bytes = p;
    f->version = version;
    return 1;
}
int pe_arm64x_fixture_clone(const struct pe_arm64x_fixture *f, struct pe_arm64x_fixture *out) {
    if (!f || !f->bytes || !out)
        return 0;
    memset(out, 0, sizeof(*out));
    out->bytes = malloc(f->size);
    if (!out->bytes)
        return 0;
    memcpy(out->bytes, f->bytes, f->size);
    out->size = f->size;
    out->version = f->version;
    return 1;
}
void pe_arm64x_fixture_destroy(struct pe_arm64x_fixture *f) {
    if (f) {
        free(f->bytes);
        memset(f, 0, sizeof(*f));
    }
}
