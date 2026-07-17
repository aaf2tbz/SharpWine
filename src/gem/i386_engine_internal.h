// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_ENGINE_INTERNAL_H
#define METALSHARP_GEM_I386_ENGINE_INTERNAL_H

#include "i386_engine_ops.h"
#include "memory_internal.h"
#include "metalsharp/gem/i386_engine.h"

#include <stdatomic.h>

#define GEM_I386_ENGINE_STATUS_RESTARTABLE_REP UINT32_C(0x100)

struct gem_i386_runtime {
    struct gem_memory *memory;
    struct gem_i386_runtime_config config;
    struct gem_i386_stop_info last_stop;
    const struct gem_i386_engine_ops *ops;
    void *backend;
    struct gem_memory_transaction *transaction;
    struct gem_i386_performance_info performance;
    uint32_t quantum_budget;
    uint32_t consecutive_conflicts;
    bool running;
    bool backend_failed;
    atomic_bool async_stop_requested;
};

bool gem_i386_blink_create(struct gem_i386_runtime *runtime);
void gem_i386_blink_destroy(struct gem_i386_runtime *runtime);
void gem_i386_blink_sync(struct gem_i386_runtime *runtime);
enum gem_stop_reason gem_i386_blink_step(struct gem_i386_runtime *runtime,
                                         const struct gem_i386_context *in,
                                         struct gem_i386_context *out, uint32_t *retired);
enum gem_stop_reason gem_i386_blink_run(struct gem_i386_runtime *runtime,
                                        const struct gem_i386_context *in,
                                        struct gem_i386_context *out, uint32_t budget,
                                        uint32_t *retired);
bool gem_i386_blink_engine_info(const struct gem_i386_runtime *runtime,
                                struct gem_i386_engine_info *out);
bool gem_i386_blink_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                    uint64_t size);

#endif
