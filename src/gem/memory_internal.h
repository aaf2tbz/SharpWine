// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_MEMORY_INTERNAL_H
#define METALSHARP_GEM_MEMORY_INTERNAL_H

#include "metalsharp/gem/memory.h"

#ifdef __cplusplus
extern "C" {
#endif

enum gem_memory_error gem_memory_peek(struct gem_memory *memory, uint64_t address, void *buffer,
                                      size_t size);

#ifdef __cplusplus
}
#endif

#endif
