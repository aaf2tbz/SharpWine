// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_I386_ENGINE_TRACE_H
#define METALSHARP_GEM_I386_ENGINE_TRACE_H

#include "metalsharp/gem/i386_engine.h"

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

/* Evidence-only accessors for the decoder-owned Blink handler trace, mirroring
 * the x64 adapter surface.  These expose the exact handler Blink's own decode
 * dispatch selected for each retired i386 instruction.  They never alter guest
 * semantics, the allowlist, or the public i386_engine ABI.  Reset/read are
 * only valid while no run is active (existing thread confinement applies). */
void gem_i386_runtime_handler_trace_reset(struct gem_i386_runtime *runtime);
bool gem_i386_runtime_handler_trace_info(const struct gem_i386_runtime *runtime, uint32_t *count,
                                         uint32_t *overflowed);
bool gem_i386_runtime_handler_trace_read(const struct gem_i386_runtime *runtime, size_t index,
                                         uint64_t *rip, uint32_t *handler_id);
const char *gem_i386_runtime_handler_name(uint32_t handler_id);

/* Decoder-owned "last decode attempt" diagnostic wrapper, mirroring the x64
 * adapter: abi_version (== BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION) and size
 * (== sizeof(struct blink_gem_decode_attempt)) are validated on entry and the
 * complete record is copied into caller-owned storage. */
bool gem_i386_runtime_decode_attempt_info(const struct gem_i386_runtime *runtime,
                                          struct blink_gem_decode_attempt *out);

/* Env-gated handler-trace drain for application coverage histograms.  When
 * MSWR_I386_HANDLER_TRACE_PATH names a file at runtime creation time, the i386
 * adapter drains the Blink trace buffer after every step/run call (the buffer
 * is appended exactly once per retired instruction on both paths), accumulating
 * a process-wide, thread-safe frequency histogram keyed by handler id.  The
 * check is performed once per runtime creation and cached on the runtime, so
 * unset environments pay no per-instruction cost.  Each drain resets the Blink
 * buffer so its sticky overflow flag can never silently drop counts; every
 * observed overflow is recorded as an overflow event instead.  Every
 * MSWR_I386_HANDLER_TRACE_FLUSH_ENTRIES newly drained entries (default 16384)
 * the cumulative histogram is rewritten immediately, so a process killed
 * before runtime destroy still leaves bounded evidence behind.  Destroying a
 * drain-enabled runtime rewrites the file with the cumulative process-wide
 * histogram, so repeated runtime lifetimes in one process deterministically
 * produce the aggregate of all drained entries up to that point.  The drain is
 * diagnostic-only: it never changes execution, budgets, or committed state. */
#define GEM_I386_HANDLER_TRACE_ENV_VAR "MSWR_I386_HANDLER_TRACE_PATH"
#define GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR "MSWR_I386_HANDLER_TRACE_FLUSH_ENTRIES"

#ifdef __cplusplus
}
#endif

#endif
