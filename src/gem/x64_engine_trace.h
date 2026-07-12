// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_X64_ENGINE_TRACE_H
#define METALSHARP_GEM_X64_ENGINE_TRACE_H
#include "metalsharp/gem/x64_engine.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#include "blink/gem_embed.h"
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Evidence-only accessors for the decoder-owned Blink handler trace. This is a
 * private (non-installed) adapter surface: it exposes the exact handler Blink's
 * own decode dispatch selected for each retired instruction. It never alters
 * guest semantics, the allowlist, or the public x64_engine ABI. Reset/read are
 * only valid while no run is active (existing thread confinement applies). */
void gem_x64_runtime_handler_trace_reset(struct gem_x64_runtime *);
bool gem_x64_runtime_handler_trace_info(const struct gem_x64_runtime *, uint32_t *count,
                                        uint32_t *overflowed);
bool gem_x64_runtime_handler_trace_read(const struct gem_x64_runtime *, size_t index, uint64_t *rip,
                                        uint32_t *handler_id);
const char *gem_x64_runtime_handler_name(uint32_t handler_id);

/* Decoder-owned "last decode attempt" diagnostic wrapper.  The wrapper copies
 * Blink's machine-owned decode record into caller-provided storage; it never
 * aliases Blink-owned storage and never alters execution, allowlisting, or
 * committed architectural state.  abi_version (== BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION)
 * and size (== sizeof(struct blink_gem_decode_attempt)) are validated on entry.
 * On a successful LoadInstruction the record carries valid=1 with Blink's own
 * Mopcode()/DescribeMopcode() identity, the allowlisted handler id (0 when the
 * selected handler is outside the reviewed set), and the bounded Blink-provided
 * name. Pre-decode faults leave valid=0 with an empty name. The complete record,
 * including its bounded name array, is copied into caller-owned storage. This
 * surface is private (non-installed) and is exposed only to tests and to the
 * same evidence-only scope as the handler trace. */
bool gem_x64_runtime_decode_attempt_info(const struct gem_x64_runtime *,
                                         struct blink_gem_decode_attempt *);
#ifdef __cplusplus
}
#endif
#endif
