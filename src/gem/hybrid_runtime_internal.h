// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_HYBRID_RUNTIME_INTERNAL_H
#define METALSHARP_GEM_HYBRID_RUNTIME_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gem_hybrid_frame_contract {
    uint64_t expected_cookie;
    uint64_t observed_cookie;
    uint64_t expected_return_pc;
    uint64_t observed_return_pc;
    uint64_t expected_sp;
    uint64_t observed_sp;
    uint64_t expected_original_x64_sp;
    uint64_t observed_original_x64_sp;
    uint64_t expected_record;
    uint64_t observed_record;
    uint32_t depth;
    uint32_t maximum_depth;
    bool active;
    bool require_record;
    bool record_readable;
};

bool gem_hybrid_frame_contract_validate(const struct gem_hybrid_frame_contract *contract);

#ifdef __cplusplus
}
#endif

#endif
