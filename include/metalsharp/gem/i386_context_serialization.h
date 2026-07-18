// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_CONTEXT_SERIALIZATION_H
#define METALSHARP_GEM_I386_CONTEXT_SERIALIZATION_H

#include "metalsharp/gem/i386_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* i386 context wire format (ADR 0013 section d).  The header is
 * { magic, serialization_version, layout_version, payload_size }.  Version 1
 * is defined retroactively as layout_version 1 or 2 with the 448-byte v1/v2
 * body; version 2 is layout_version 3 with the 592-byte body (the 448-byte
 * v1/v2 body, then ymm_upper[8], then xcr0, then 8 bytes of zero padding).
 * The default deserializer accepts only version 2; version-1 blobs convert
 * only through the explicitly named migration entry point. */
#define GEM_I386_CONTEXT_WIRE_MAGIC UINT32_C(0x694d4547) /* GEMi, little endian */
#define GEM_I386_CONTEXT_WIRE_HEADER_SIZE UINT32_C(16)
#define GEM_I386_CONTEXT_WIRE_SIZE_V1 UINT32_C(464)
#define GEM_I386_CONTEXT_WIRE_SIZE_V2 UINT32_C(608)

size_t gem_i386_context_serialized_size(uint32_t version);
bool gem_i386_context_serialize(const struct gem_i386_context *context, uint8_t *buffer,
                                size_t buffer_size, size_t *bytes_written);
bool gem_i386_context_deserialize(struct gem_i386_context *context, const uint8_t *buffer,
                                  size_t buffer_size, size_t *bytes_read);
bool gem_i386_context_deserialize_migrate(struct gem_i386_context *context, const uint8_t *buffer,
                                          size_t buffer_size, size_t *bytes_read);

#ifdef __cplusplus
}
#endif
#endif
