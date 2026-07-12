// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_X64_ENGINE_INTERNAL_H
#define METALSHARP_GEM_X64_ENGINE_INTERNAL_H
#include "memory_internal.h"
#include "metalsharp/gem/context_conversion.h"
#include "metalsharp/gem/x64_engine.h"
struct gem_x64_runtime {
    struct gem_memory *memory;
    struct gem_x64_runtime_config config;
    struct gem_x64_stop_info last_stop;
    void *backend;
    struct gem_memory_transaction *transaction;
    bool running;
};
bool gem_x64_blink_create(struct gem_x64_runtime *);
void gem_x64_blink_destroy(struct gem_x64_runtime *);
enum gem_stop_reason gem_x64_blink_step(struct gem_x64_runtime *, const struct gem_x64_context *,
                                        struct gem_x64_context *, uint32_t *);
const char *gem_x64_blink_version(void);
#endif
