// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/arm64ec_target.h"
#include "pe_arm64x_fixture_builder.h"

#include <assert.h>
#include <string.h>

static bool cfg_allow(void *opaque, uint64_t target) {
    return target == *(const uint64_t *)opaque;
}

static void test_classification_and_policy(void) {
    struct pe_arm64x_fixture fixture;
    struct gem_pe_arm64x_image *image = NULL;
    struct gem_arm64ec_target_map *map = NULL;
    struct gem_arm64ec_target_result result;
    struct gem_arm64ec_target_result unchanged;
    const uint64_t base = PE_ARM64X_FIXTURE_IMAGE_BASE;
    uint64_t allowed = base + UINT64_C(0x1900);
    struct gem_arm64ec_cfg_policy policy = {cfg_allow, &allowed};

    assert(pe_arm64x_fixture_build(2U, &fixture));
    assert(gem_pe_arm64x_parse(fixture.bytes, fixture.size, NULL, &image) == GEM_PE_OK);
    assert(gem_arm64ec_target_map_create(image, base, &map) == GEM_ARM64EC_TARGET_OK);
    gem_pe_arm64x_image_destroy(image);
    pe_arm64x_fixture_destroy(&fixture);

    memset(&result, 0xa5, sizeof(result));
    assert(gem_arm64ec_target_resolve(map, base + 0x1000U, &result) == GEM_ARM64EC_TARGET_OK);
    assert(result.kind == GEM_ARM64EC_TARGET_ARM64 && result.resolved_va == base + 0x1000U);
    assert(gem_arm64ec_target_resolve(map, base + 0x1400U, &result) == GEM_ARM64EC_TARGET_OK);
    assert(result.kind == GEM_ARM64EC_TARGET_ARM64EC);
    assert(gem_arm64ec_target_resolve(map, base + 0x1800U, &result) == GEM_ARM64EC_TARGET_OK);
    assert(result.kind == GEM_ARM64EC_TARGET_ARM64 && result.resolved_va == base + 0x1000U &&
           result.redirection_hops == 1U);
    assert(gem_arm64ec_target_resolve(map, base + 0x1901U, &result) == GEM_ARM64EC_TARGET_OK);
    assert(result.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY && result.resolved_va == base + 0x1901U);

    memset(&result, 0x5a, sizeof(result));
    unchanged = result;
    assert(gem_arm64ec_target_resolve(map, base + 0x2000U, &result) ==
           GEM_ARM64EC_TARGET_NOT_EXECUTABLE);
    assert(memcmp(&result, &unchanged, sizeof(result)) == 0);
    assert(gem_arm64ec_target_resolve(map, base + 0x3000U, &result) ==
           GEM_ARM64EC_TARGET_NOT_EXECUTABLE);
    assert(gem_arm64ec_target_resolve(map, base - 1U, &result) == GEM_ARM64EC_TARGET_OUTSIDE_IMAGE);
    assert(gem_arm64ec_target_resolve(map, base + 0x1401U, &result) ==
           GEM_ARM64EC_TARGET_MISALIGNED);

    assert(gem_arm64ec_cfg_authorize(NULL, allowed) == GEM_ARM64EC_TARGET_CFG_DENIED);
    assert(gem_arm64ec_cfg_authorize(&policy, allowed) == GEM_ARM64EC_TARGET_OK);
    assert(gem_arm64ec_cfg_authorize(&policy, allowed + 1U) == GEM_ARM64EC_TARGET_CFG_DENIED);
    /* Architecture dispatch remains unchanged by CFG policy. */
    assert(gem_arm64ec_target_resolve(map, allowed, &result) == GEM_ARM64EC_TARGET_OK);
    assert(result.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY);

    {
        struct gem_thread_context context;
        struct gem_thread_context before;
        gem_context_initialize(&context, UINT64_C(0x70000000), GEM_ISA_ARM64EC);
        context.x[9] = UINT64_C(0x9999);
        context.x[10] = base + UINT64_C(0x1400);
        context.x[11] = allowed;
        before = context;
        assert(gem_arm64ec_checker_dispatch(map, &policy, true, &context, &result) ==
               GEM_ARM64EC_TARGET_OK);
        assert(result.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY);
        assert(context.x[9] == allowed && context.x[11] == base + UINT64_C(0x1400));
        before.x[9] = context.x[9];
        before.x[11] = context.x[11];
        assert(memcmp(&context, &before, sizeof(context)) == 0);

        context.x[9] = UINT64_C(0x9999);
        context.x[11] = base + UINT64_C(0x1400);
        before = context;
        assert(gem_arm64ec_checker_dispatch(map, NULL, false, &context, &result) ==
               GEM_ARM64EC_TARGET_OK);
        assert(result.kind == GEM_ARM64EC_TARGET_ARM64EC);
        assert(memcmp(&context, &before, sizeof(context)) == 0);

        context.x[11] = allowed + 1U;
        before = context;
        unchanged = result;
        assert(gem_arm64ec_checker_dispatch(map, &policy, true, &context, &result) ==
               GEM_ARM64EC_TARGET_CFG_DENIED);
        assert(memcmp(&context, &before, sizeof(context)) == 0);
        assert(memcmp(&result, &unchanged, sizeof(result)) == 0);
    }

    gem_arm64ec_target_map_destroy(map);
}

static void test_overflow_and_redirection_cycle(void) {
    struct pe_arm64x_fixture fixture;
    struct gem_pe_arm64x_image *image = NULL;
    struct gem_arm64ec_target_map *map = NULL;
    struct gem_arm64ec_target_result result;
    size_t redirection;

    assert(pe_arm64x_fixture_build(1U, &fixture));
    assert(gem_pe_arm64x_parse(fixture.bytes, fixture.size, NULL, &image) == GEM_PE_OK);
    assert(gem_arm64ec_target_map_create(image, UINT64_MAX - 0x1000U, &map) ==
           GEM_ARM64EC_TARGET_OVERFLOW);
    assert(gem_arm64ec_target_map_create(image, PE_ARM64X_FIXTURE_IMAGE_BASE + 0x1000U, &map) ==
           GEM_ARM64EC_TARGET_OK);
    assert(gem_arm64ec_target_resolve(map, PE_ARM64X_FIXTURE_IMAGE_BASE + 0x2000U, &result) ==
           GEM_ARM64EC_TARGET_OK);
    assert(result.requested_rva == 0x1000U &&
           result.resolved_va == PE_ARM64X_FIXTURE_IMAGE_BASE + 0x2000U);
    gem_arm64ec_target_map_destroy(map);
    map = NULL;
    gem_pe_arm64x_image_destroy(image);

    redirection = pe_arm64x_fixture_rva_to_offset(PE_ARM64X_FIXTURE_REDIRECTIONS_RVA);
    pe_arm64x_fixture_put_u32(fixture.bytes, redirection + 4U, 0x1800U);
    assert(gem_pe_arm64x_parse(fixture.bytes, fixture.size, NULL, &image) == GEM_PE_OK);
    assert(gem_arm64ec_target_map_create(image, PE_ARM64X_FIXTURE_IMAGE_BASE, &map) ==
           GEM_ARM64EC_TARGET_OK);
    assert(gem_arm64ec_target_resolve(map, PE_ARM64X_FIXTURE_IMAGE_BASE + 0x1800U, &result) ==
           GEM_ARM64EC_TARGET_MALFORMED_METADATA);
    gem_arm64ec_target_map_destroy(map);
    gem_pe_arm64x_image_destroy(image);
    pe_arm64x_fixture_destroy(&fixture);
}

static void test_descriptor_transaction(void) {
    struct pe_arm64x_fixture fixture;
    struct gem_pe_arm64x_image *image = NULL;
    struct gem_arm64ec_target_map *map = NULL;
    struct gem_memory *memory = gem_memory_create();
    struct gem_arm64ec_target_result result;
    struct gem_arm64ec_target_result unchanged;
    uint64_t pages = UINT64_C(0x90000000);
    uint64_t image_page = PE_ARM64X_FIXTURE_IMAGE_BASE + UINT64_C(0x1000);
    const uint64_t descriptor = UINT64_C(0x90000ffd);
    const uint64_t valid_descriptor = PE_ARM64X_FIXTURE_IMAGE_BASE + UINT64_C(0x13fc);
    const uint8_t bytes[4] = {1U, 2U, 3U, 4U};
    const uint8_t valid_bytes[4] = {1U, 2U, 0U, 0U};

    assert(memory != NULL && pe_arm64x_fixture_build(2U, &fixture));
    assert(gem_pe_arm64x_parse(fixture.bytes, fixture.size, NULL, &image) == GEM_PE_OK);
    assert(gem_arm64ec_target_map_create(image, PE_ARM64X_FIXTURE_IMAGE_BASE, &map) ==
           GEM_ARM64EC_TARGET_OK);
    assert(gem_memory_reserve(memory, &pages, GEM_GUEST_PAGE_SIZE * 2U) == GEM_MEMORY_OK);
    assert(gem_memory_commit(memory, pages, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_memory_write(memory, descriptor, bytes, 3U) == GEM_MEMORY_OK);
    memset(&result, 0x3c, sizeof(result));
    unchanged = result;
    assert(gem_arm64ec_descriptor_resolve(map, memory, descriptor, NULL, &result) ==
           GEM_ARM64EC_TARGET_MEMORY_FAULT);
    assert(memcmp(&result, &unchanged, sizeof(result)) == 0);
    assert(gem_memory_commit(memory, pages + GEM_GUEST_PAGE_SIZE, GEM_GUEST_PAGE_SIZE,
                             GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    assert(gem_memory_write(memory, descriptor + 3U, bytes + 3U, 1U) == GEM_MEMORY_OK);
    assert(gem_arm64ec_descriptor_resolve(map, memory, descriptor, NULL, &result) ==
           GEM_ARM64EC_TARGET_OUTSIDE_IMAGE);
    assert(memcmp(&result, &unchanged, sizeof(result)) == 0);
    assert(gem_memory_reserve(memory, &image_page, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_memory_commit(memory, image_page, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_memory_write(memory, valid_descriptor, valid_bytes, sizeof(valid_bytes)) ==
           GEM_MEMORY_OK);
    assert(gem_arm64ec_descriptor_resolve(map, memory, valid_descriptor, NULL, &result) ==
           GEM_ARM64EC_TARGET_OK);
    assert(result.requested_va == PE_ARM64X_FIXTURE_IMAGE_BASE + 0x1600U &&
           result.resolved_va == PE_ARM64X_FIXTURE_IMAGE_BASE + 0x1600U &&
           result.kind == GEM_ARM64EC_TARGET_ARM64EC);
    memset(&result, 0x3c, sizeof(result));
    unchanged = result;
    assert(gem_arm64ec_descriptor_resolve(map, memory, UINT64_MAX - 2U, NULL, &result) ==
           GEM_ARM64EC_TARGET_OVERFLOW);
    assert(memcmp(&result, &unchanged, sizeof(result)) == 0);

    gem_memory_destroy(memory);
    gem_arm64ec_target_map_destroy(map);
    gem_pe_arm64x_image_destroy(image);
    pe_arm64x_fixture_destroy(&fixture);
}

int main(void) {
    test_classification_and_policy();
    test_overflow_and_redirection_cycle();
    test_descriptor_transaction();
    return 0;
}
