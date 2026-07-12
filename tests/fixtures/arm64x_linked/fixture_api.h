// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_ARM64X_FIXTURE_API_H
#define METALSHARP_ARM64X_FIXTURE_API_H

#include <stdint.h>

#ifdef ARM64X_FIXTURE_EXPORTS
#define ARM64X_FIXTURE_API __declspec(dllexport)
#else
#define ARM64X_FIXTURE_API __declspec(dllimport)
#endif

typedef struct arm64x_fixture_pair {
    int32_t first;
    int32_t second;
} arm64x_fixture_pair;

#ifdef __cplusplus
extern "C" {
#endif

ARM64X_FIXTURE_API int32_t fixture_integer(int32_t value);
ARM64X_FIXTURE_API double fixture_floating(double value);
ARM64X_FIXTURE_API arm64x_fixture_pair fixture_aggregate(arm64x_fixture_pair value);
ARM64X_FIXTURE_API int64_t fixture_variadic(uint32_t count, ...);
ARM64X_FIXTURE_API int32_t fixture_indirect_x64(int32_t value);
ARM64X_FIXTURE_API uint64_t fixture_authentic_roundtrip(uint64_t value);
ARM64X_FIXTURE_API uint64_t fixture_roundtrip_arm_finish(uint64_t value);
ARM64X_FIXTURE_API double fixture_indirect_x64_floating(double value);
ARM64X_FIXTURE_API arm64x_fixture_pair fixture_indirect_x64_aggregate(arm64x_fixture_pair value);
ARM64X_FIXTURE_API int64_t fixture_indirect_x64_variadic(uint32_t count, ...);
ARM64X_FIXTURE_API uintptr_t fixture_checker_slot(void);
ARM64X_FIXTURE_API uintptr_t fixture_dispatch_call_slot(void);
ARM64X_FIXTURE_API uintptr_t fixture_dispatch_ret_slot(void);
ARM64X_FIXTURE_API uint32_t fixture_import_probe(void);

#ifdef __cplusplus
}
#endif

#endif
