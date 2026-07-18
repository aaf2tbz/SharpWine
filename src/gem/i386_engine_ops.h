// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_ENGINE_OPS_H
#define METALSHARP_GEM_I386_ENGINE_OPS_H

#include "metalsharp/gem/i386_engine.h"

#define GEM_I386_ENGINE_OPS_ABI_VERSION UINT32_C(3)

struct gem_i386_runtime;

/* Private versioned execution-backend seam.  A runtime binds exactly one ops
 * table at creation; the table owns the engine mode and identity, and no
 * backend substitution or silent fallback is permitted inside a process. */
struct gem_i386_engine_ops {
    uint32_t abi_version;
    enum gem_i386_engine_mode engine_mode;
    const char *engine_name;
    const char *engine_version;
    const char *engine_provenance;
    bool (*create)(struct gem_i386_runtime *runtime);
    void (*destroy)(struct gem_i386_runtime *runtime);
    void (*sync)(struct gem_i386_runtime *runtime);
    enum gem_stop_reason (*step)(struct gem_i386_runtime *runtime,
                                 const struct gem_i386_context *in, struct gem_i386_context *out,
                                 uint32_t *retired);
    enum gem_stop_reason (*run)(struct gem_i386_runtime *runtime, const struct gem_i386_context *in,
                                struct gem_i386_context *out, uint32_t budget, uint32_t *retired);
    bool (*engine_info)(const struct gem_i386_runtime *runtime, struct gem_i386_engine_info *out);
    bool (*block_info)(const struct gem_i386_runtime *runtime, struct gem_i386_block_info *out);
    bool (*invalidate_code)(struct gem_i386_runtime *runtime, uint32_t address, uint64_t size);
    bool (*invalidate_memory)(struct gem_i386_runtime *runtime, uint32_t address, uint64_t size);
};

extern const struct gem_i386_engine_ops gem_i386_blink_jit_ops;
extern const struct gem_i386_engine_ops gem_i386_blink_interpreter_ops;

struct gem_i386_runtime *
gem_i386_runtime_create_with_ops(struct gem_memory *memory,
                                 const struct gem_i386_runtime_config *config,
                                 const struct gem_i386_engine_ops *ops);

#endif
