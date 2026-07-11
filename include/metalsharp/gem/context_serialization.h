// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_CONTEXT_SERIALIZATION_H
#define METALSHARP_GEM_CONTEXT_SERIALIZATION_H

#include "metalsharp/gem/context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_CONTEXT_WIRE_MAGIC UINT32_C(0x314d4547) /* GEM1, little endian */
#define GEM_CONTEXT_WIRE_HEADER_SIZE_V1 UINT32_C(20)
#define GEM_CONTEXT_WIRE_SIZE_V1 UINT32_C(740)

size_t gem_context_serialized_size(uint32_t version);
bool gem_context_serialize(const struct gem_thread_context *context, uint8_t *buffer,
                           size_t buffer_size, size_t *bytes_written);
bool gem_context_deserialize(struct gem_thread_context *context, const uint8_t *buffer,
                             size_t buffer_size, size_t *bytes_read);

#ifdef __cplusplus
}
#endif
#endif
