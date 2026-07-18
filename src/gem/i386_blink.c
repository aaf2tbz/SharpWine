// SPDX-License-Identifier: Apache-2.0
#include "blink/gem_embed.h"
#include "i386_engine_internal.h"
#include "i386_engine_trace.h"
#include "metalsharp/gem/i386_memory.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GEM_I386_TRACE_ID_SLOTS UINT32_C(0x1400)
#define GEM_I386_TRACE_PATH_BYTES 4096
#define GEM_I386_TRACE_FLUSH_ENTRIES_DEFAULT UINT64_C(16384)
#define GEM_I386_MAX_COMMIT_PAGES 64U

static atomic_uint_fast64_t trace_counts[GEM_I386_TRACE_ID_SLOTS];
static atomic_uint_fast64_t trace_out_of_range;
static atomic_uint_fast64_t trace_drained_total;
static atomic_uint_fast64_t trace_overflow_events;
static atomic_uint_fast64_t trace_since_flush;
static pthread_mutex_t trace_write_mutex = PTHREAD_MUTEX_INITIALIZER;
static char trace_path[GEM_I386_TRACE_PATH_BYTES];
static atomic_bool trace_path_valid;

static uint64_t gem_i386_blink_trace_flush_entries(void) {
    const char *value = getenv(GEM_I386_HANDLER_TRACE_FLUSH_ENV_VAR);
    char *end = NULL;
    unsigned long parsed;
    if (value == NULL || value[0] == '\0')
        return GEM_I386_TRACE_FLUSH_ENTRIES_DEFAULT;
    parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || parsed == 0UL)
        return GEM_I386_TRACE_FLUSH_ENTRIES_DEFAULT;
    return (uint64_t)parsed;
}

static void gem_i386_blink_trace_init(struct gem_i386_runtime *runtime) {
    const char *path = getenv(GEM_I386_HANDLER_TRACE_ENV_VAR);
    runtime->trace_drain = false;
    runtime->trace_flush_entries = GEM_I386_TRACE_FLUSH_ENTRIES_DEFAULT;
    if (path == NULL || path[0] == '\0' || strlen(path) >= sizeof(trace_path))
        return;
    pthread_mutex_lock(&trace_write_mutex);
    if (!atomic_load_explicit(&trace_path_valid, memory_order_acquire)) {
        memcpy(trace_path, path, strlen(path) + 1U);
        atomic_store_explicit(&trace_path_valid, true, memory_order_release);
    }
    pthread_mutex_unlock(&trace_write_mutex);
    runtime->trace_flush_entries = gem_i386_blink_trace_flush_entries();
    runtime->trace_drain = true;
}

/* Caller must hold trace_write_mutex. */
static void gem_i386_blink_trace_write_locked(void) {
    FILE *file = fopen(trace_path, "w");
    uint32_t id;
    if (file == NULL)
        return;
    fprintf(file, "gem_i386_handler_trace 1\n");
    fprintf(file, "total_drained %llu\n",
            (unsigned long long)atomic_load_explicit(&trace_drained_total, memory_order_relaxed));
    fprintf(file, "overflow_events %llu\n",
            (unsigned long long)atomic_load_explicit(&trace_overflow_events, memory_order_relaxed));
    fprintf(file, "out_of_range %llu\n",
            (unsigned long long)atomic_load_explicit(&trace_out_of_range, memory_order_relaxed));
    for (id = 0U; id < GEM_I386_TRACE_ID_SLOTS; ++id) {
        uint64_t count = atomic_load_explicit(&trace_counts[id], memory_order_relaxed);
        if (count != 0U)
            fprintf(file, "handler %u %s %llu\n", id, blink_gem_handler_name(id),
                    (unsigned long long)count);
    }
    fclose(file);
}

static void gem_i386_blink_trace_write(void) {
    if (!atomic_load_explicit(&trace_path_valid, memory_order_acquire))
        return;
    pthread_mutex_lock(&trace_write_mutex);
    gem_i386_blink_trace_write_locked();
    pthread_mutex_unlock(&trace_write_mutex);
}

static void gem_i386_blink_trace_drain(struct gem_i386_runtime *runtime) {
    struct blink_gem_trace_info info;
    uint32_t i;
    memset(&info, 0, sizeof(info));
    info.abi_version = BLINK_GEM_TRACE_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_trace_info(runtime->backend, &info))
        return;
    for (i = 0U; i < info.count; ++i) {
        struct blink_gem_trace_entry entry;
        if (!blink_gem_machine_trace_read(runtime->backend, i, &entry))
            break;
        if (entry.handler_id < GEM_I386_TRACE_ID_SLOTS)
            atomic_fetch_add_explicit(&trace_counts[entry.handler_id], 1U, memory_order_relaxed);
        else
            atomic_fetch_add_explicit(&trace_out_of_range, 1U, memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&trace_drained_total, i, memory_order_relaxed);
    if (info.overflowed != 0U)
        atomic_fetch_add_explicit(&trace_overflow_events, 1U, memory_order_relaxed);
    blink_gem_machine_trace_reset(runtime->backend);
    if (i != 0U && atomic_fetch_add_explicit(&trace_since_flush, i, memory_order_relaxed) + i >=
                       runtime->trace_flush_entries) {
        /* Kill-proof periodic flush: rewrite the cumulative histogram so a
         * process that never reaches runtime destroy still leaves bounded
         * evidence behind. */
        pthread_mutex_lock(&trace_write_mutex);
        atomic_store_explicit(&trace_since_flush, 0, memory_order_relaxed);
        gem_i386_blink_trace_write_locked();
        pthread_mutex_unlock(&trace_write_mutex);
    }
}

static bool i386_range(uint64_t address, uint64_t size) {
    return size != 0U && size <= GEM_I386_ADDRESS_SPACE_SIZE &&
           address <= GEM_I386_ADDRESS_SPACE_SIZE - size;
}

static uint32_t snapshot(void *opaque, uint64_t address, uint8_t data[4096], uint32_t *protection) {
    struct gem_i386_runtime *runtime = (struct gem_i386_runtime *)opaque;
    uint32_t guest_protection = 0U;
    enum gem_memory_error error;
    if (!i386_range(address, GEM_GUEST_PAGE_SIZE))
        return GEM_MEMORY_OVERFLOW;
    error = gem_memory_transaction_snapshot_page(runtime->transaction, address, data,
                                                 &guest_protection);
    if (error == GEM_MEMORY_OK) {
        ++runtime->performance.page_snapshots;
        runtime->performance.bytes_copied += GEM_GUEST_PAGE_SIZE;
    }
    *protection = 0U;
    if ((guest_protection & GEM_PAGE_GUARD) != 0U)
        *protection |= 8U;
    if (error == GEM_MEMORY_OK &&
        gem_memory_transaction_page_is_external(runtime->transaction, address))
        *protection |= 16U;
    if ((guest_protection & ~(uint32_t)GEM_PAGE_GUARD) != GEM_PAGE_NOACCESS) {
        if ((guest_protection & ~(uint32_t)GEM_PAGE_GUARD) != GEM_PAGE_EXECUTE)
            *protection |= 1U;
        if ((guest_protection & (GEM_PAGE_READWRITE | GEM_PAGE_WRITECOPY |
                                 GEM_PAGE_EXECUTE_READWRITE | GEM_PAGE_EXECUTE_WRITECOPY)) != 0U)
            *protection |= 2U;
        if ((guest_protection & (GEM_PAGE_EXECUTE | GEM_PAGE_EXECUTE_READ |
                                 GEM_PAGE_EXECUTE_READWRITE | GEM_PAGE_EXECUTE_WRITECOPY)) != 0U)
            *protection |= 4U;
    }
    return (uint32_t)error;
}

static uint32_t validate(void *opaque, uint64_t address, size_t size,
                         enum blink_gem_access access) {
    struct gem_i386_runtime *runtime = (struct gem_i386_runtime *)opaque;
    if (!i386_range(address, size))
        return GEM_MEMORY_OVERFLOW;
    return (uint32_t)gem_memory_transaction_validate(runtime->transaction, address, size,
                                                     access == BLINK_GEM_ACCESS_WRITE,
                                                     access == BLINK_GEM_ACCESS_FETCH);
}

static uint32_t commit(void *opaque, const struct blink_gem_write *writes, size_t count,
                       uint64_t *fault_address) {
    struct gem_i386_runtime *runtime = (struct gem_i386_runtime *)opaque;
    struct gem_memory_page_write pages[GEM_I386_MAX_COMMIT_PAGES];
    enum gem_memory_error error;
    size_t bytes_committed = 0U;
    size_t i;
    if (count == 0U)
        return GEM_MEMORY_OK;
    if (count > GEM_I386_MAX_COMMIT_PAGES)
        return GEM_MEMORY_INVALID_ARGUMENT;
    for (i = 0; i < count; ++i) {
        if (writes[i].size != GEM_GUEST_PAGE_SIZE ||
            !i386_range(writes[i].address, writes[i].size)) {
            return GEM_MEMORY_OVERFLOW;
        }
        pages[i].address = writes[i].address;
        pages[i].data = writes[i].data;
    }
    error = gem_memory_transaction_commit_pages(runtime->transaction, pages, count, fault_address,
                                                &bytes_committed);
    if (error == GEM_MEMORY_OK)
        runtime->performance.bytes_committed += bytes_committed;
    return (uint32_t)error;
}

static void import_state(const struct gem_i386_context *source, struct blink_gem_state *target) {
    size_t i;
    memset(target, 0, sizeof(*target));
    target->abi_version = BLINK_GEM_STATE_ABI_VERSION;
    target->size = sizeof(*target);
    for (i = 0; i < 8U; ++i)
        target->gpr[i] = source->gpr[i];
    target->rip = source->eip;
    target->rflags = (source->eflags & ~UINT32_C(0x00003000)) | UINT32_C(0x00000200);
    memcpy(target->xmm, source->xmm, sizeof(source->xmm));
    memcpy(target->x87, source->x87, sizeof(source->x87));
    target->mxcsr = source->mxcsr;
    target->fcw = source->fcw;
    target->fsw = source->fsw;
    target->ftw = source->ftw;
    target->fop = source->fop;
    if (source->layout_version >= GEM_I386_CONTEXT_LAYOUT_VERSION_V2) {
        target->fip = source->x87_environment.fip;
        target->fdp = source->x87_environment.fdp;
        target->fcs = source->x87_environment.fcs;
        target->fds = source->x87_environment.fds;
    }
    for (i = 0; i < 6U; ++i) {
        target->segments[i].selector = source->segment[i];
        target->segments[i].base = source->segment_base[i];
        target->segments[i].limit = source->segment_limit[i];
        target->segments[i].attributes = source->segment_attributes[i];
    }
    target->fs_base =
        source->segment_base[GEM_I386_FS] != 0U ? source->segment_base[GEM_I386_FS] : source->teb;
    target->gs_base = source->segment_base[GEM_I386_GS];
    if (source->layout_version >= GEM_I386_CONTEXT_LAYOUT_VERSION_V3) {
        memcpy(target->ymm_upper, source->ymm_upper, sizeof(target->ymm_upper));
        target->xcr0 = source->xcr0;
    }
}

static void export_state(const struct blink_gem_state *source, const struct gem_i386_context *input,
                         struct gem_i386_context *target) {
    size_t i;
    *target = *input;
    for (i = 0; i < 8U; ++i)
        target->gpr[i] = (uint32_t)source->gpr[i];
    target->eip = (uint32_t)source->rip;
    target->eflags = ((uint32_t)source->rflags & ~UINT32_C(0x00003000)) | UINT32_C(0x00000200) |
                     GEM_I386_EFLAGS_REQUIRED;
    memcpy(target->xmm, source->xmm, sizeof(target->xmm));
    memcpy(target->x87, source->x87, sizeof(target->x87));
    target->mxcsr = source->mxcsr;
    target->fcw = source->fcw;
    target->fsw = source->fsw;
    target->ftw = source->ftw;
    target->fop = source->fop;
    if (target->layout_version >= GEM_I386_CONTEXT_LAYOUT_VERSION_V2) {
        target->x87_environment.fip = source->fip;
        target->x87_environment.fdp = source->fdp;
        target->x87_environment.fcs = source->fcs;
        target->x87_environment.fds = source->fds;
    }
    for (i = 0; i < 6U; ++i) {
        target->segment[i] = source->segments[i].selector;
        target->segment_base[i] = source->segments[i].base;
        target->segment_limit[i] = source->segments[i].limit;
        target->segment_attributes[i] = source->segments[i].attributes;
    }
    if (target->layout_version >= GEM_I386_CONTEXT_LAYOUT_VERSION_V3) {
        memcpy(target->ymm_upper, source->ymm_upper, sizeof(target->ymm_upper));
        target->xcr0 = source->xcr0;
    } else {
        /* ADR 0013 section g: a v1/v2 layout carries no extension; the bytes
         * past the pinned 448-byte body are always exported zeroed. */
        memset(target->ymm_upper, 0, sizeof(target->ymm_upper));
        target->xcr0 = 0U;
    }
}

static bool is_virtual_rdtsc(const struct blink_gem_decode_attempt *attempt) {
    return attempt->valid != 0U && attempt->mopcode == UINT32_C(0x131) &&
           attempt->instruction_length >= 2U && attempt->instruction_length <= 15U &&
           strcmp(attempt->name, "OpRdtsc") == 0;
}

static bool is_virtual_rdtscp(const struct blink_gem_decode_attempt *attempt) {
    return attempt->valid != 0U && attempt->mopcode == UINT32_C(0x101) &&
           attempt->instruction_length >= 3U && attempt->instruction_length <= 15U &&
           strcmp(attempt->name, "Op101") == 0;
}

static void record_unsupported(struct gem_i386_runtime *runtime,
                               const struct blink_gem_decode_attempt *attempt) {
    ++runtime->unsupported_instructions;
    runtime->last_unsupported_eip = (uint32_t)attempt->rip;
    runtime->last_unsupported_mopcode = attempt->mopcode;
    runtime->last_unsupported_length = attempt->instruction_length;
    snprintf(runtime->last_unsupported_name, sizeof(runtime->last_unsupported_name), "%s",
             attempt->name);
}

static bool complete_virtual_timestamp(struct gem_i386_runtime *runtime,
                                       struct gem_i386_context *context,
                                       uint32_t instruction_length, uint32_t budget,
                                       uint32_t *retired, bool with_aux) {
    uint64_t timestamp;
    if (*retired >= budget)
        return false;
    timestamp = runtime->virtual_tsc + *retired;
    context->gpr[GEM_I386_EAX] = (uint32_t)timestamp;
    context->gpr[GEM_I386_EDX] = (uint32_t)(timestamp >> 32);
    if (with_aux)
        context->gpr[GEM_I386_ECX] = 0U;
    context->eip += instruction_length;
    ++*retired;
    return true;
}

bool gem_i386_blink_create(struct gem_i386_runtime *runtime) {
    const struct blink_gem_callbacks callbacks = {BLINK_GEM_ABI_VERSION, sizeof(callbacks),
                                                  snapshot, validate, commit};
    const struct blink_gem_config config = {BLINK_GEM_CONFIG_ABI_VERSION, sizeof(config),
                                            runtime->config.engine_mode == GEM_I386_ENGINE_JIT
                                                ? BLINK_GEM_ENGINE_JIT
                                                : BLINK_GEM_ENGINE_INTERPRETER,
                                            BLINK_GEM_GUEST_LEGACY_32};
    runtime->backend = blink_gem_machine_create_with_config(&config, &callbacks, runtime);
    if (runtime->backend == NULL)
        return false;
    gem_i386_blink_trace_init(runtime);
    return true;
}

void gem_i386_blink_destroy(struct gem_i386_runtime *runtime) {
    if (runtime->trace_drain)
        gem_i386_blink_trace_write();
    blink_gem_machine_destroy(runtime->backend);
    runtime->backend = NULL;
}

void gem_i386_blink_sync(struct gem_i386_runtime *runtime) {
    if (!runtime->precise_host_dirty)
        blink_gem_machine_sync(runtime->backend);
}

enum gem_stop_reason gem_i386_blink_step(struct gem_i386_runtime *runtime,
                                         const struct gem_i386_context *in,
                                         struct gem_i386_context *out, uint32_t *retired) {
    struct blink_gem_state blink_in;
    struct blink_gem_state blink_out;
    struct blink_gem_result result;
    import_state(in, &blink_in);
    ++runtime->performance.state_imports;
    result = blink_gem_machine_step(runtime->backend, &blink_in, &blink_out);
    if (runtime->trace_drain)
        gem_i386_blink_trace_drain(runtime);
    *retired = result.retired;
    runtime->last_stop.fault_address = (uint32_t)result.fault_address;
    runtime->last_stop.access = (enum gem_i386_memory_access)result.access;
    runtime->last_stop.memory_error = result.memory_error;
    runtime->last_stop.engine_status = result.engine_status;
    if (result.outcome == BLINK_GEM_RETIRED) {
        export_state(&blink_out, in, out);
        ++runtime->performance.state_exports;
        return result.retired == 1U ? GEM_STOP_NONE : GEM_STOP_INVARIANT_VIOLATION;
    }
    if (result.outcome == BLINK_GEM_MEMORY_FAULT) {
        if (result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_REP ||
            result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_GATHER) {
            export_state(&blink_out, in, out);
            runtime->last_stop.engine_status =
                result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_REP
                    ? GEM_I386_ENGINE_STATUS_RESTARTABLE_REP
                    : GEM_I386_ENGINE_STATUS_RESTARTABLE_GATHER;
        }
        return GEM_STOP_MEMORY_FAULT;
    }
    if (result.outcome == BLINK_GEM_EXCEPTION) {
        switch (result.engine_status) {
        case BLINK_GEM_EXCEPTION_ILLEGAL_INSTRUCTION:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION;
            break;
        case BLINK_GEM_EXCEPTION_DIVIDE:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_DIVIDE_BY_ZERO;
            break;
        case BLINK_GEM_EXCEPTION_OVERFLOW:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_OVERFLOW;
            break;
        case BLINK_GEM_EXCEPTION_PROTECTION:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_GENERAL_PROTECTION;
            break;
        default:
            return GEM_STOP_INVARIANT_VIOLATION;
        }
        return GEM_STOP_WINDOWS_EXCEPTION;
    }
    if (result.outcome == BLINK_GEM_UNSUPPORTED) {
        struct blink_gem_decode_attempt attempt;
        memset(&attempt, 0, sizeof(attempt));
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt);
        if (!blink_gem_machine_decode_attempt_info(runtime->backend, &attempt) || !attempt.valid)
            return GEM_STOP_UNSUPPORTED_INSTRUCTION;
        if (is_virtual_rdtsc(&attempt) || is_virtual_rdtscp(&attempt)) {
            *out = *in;
            ++runtime->performance.state_exports;
            return complete_virtual_timestamp(runtime, out, attempt.instruction_length, 1U, retired,
                                              is_virtual_rdtscp(&attempt))
                       ? GEM_STOP_NONE
                       : GEM_STOP_INVARIANT_VIOLATION;
        }
        if (strcmp(attempt.name, "OpInterrupt3") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_BREAKPOINT;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpInto") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_OVERFLOW;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpUd") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpInterruptImm") == 0 ||
            strcmp(attempt.name, "OpSysenter") == 0) {
            runtime->last_stop.engine_status = GEM_I386_BOUNDARY_WINDOWS_SYSCALL;
            return GEM_STOP_SYSCALL;
        }
        record_unsupported(runtime, &attempt);
        return GEM_STOP_UNSUPPORTED_INSTRUCTION;
    }
    return GEM_STOP_INVARIANT_VIOLATION;
}

static bool async_stop(void *opaque) {
    struct gem_i386_runtime *runtime = (struct gem_i386_runtime *)opaque;
    return atomic_exchange_explicit(&runtime->async_stop_requested, false, memory_order_acq_rel);
}

enum gem_stop_reason gem_i386_blink_run(struct gem_i386_runtime *runtime,
                                        const struct gem_i386_context *in,
                                        struct gem_i386_context *out, uint32_t budget,
                                        uint32_t *retired) {
    struct blink_gem_state blink_in;
    struct blink_gem_state blink_out;
    struct blink_gem_result result;
    uint64_t stop_pcs[3];
    uint32_t stop_count = 0U;
    struct blink_gem_run_request request;
    stop_pcs[stop_count++] = runtime->config.host_return_sentinel;
    if (runtime->config.windows_syscall_boundary != 0U)
        stop_pcs[stop_count++] = runtime->config.windows_syscall_boundary;
    if (runtime->config.unix_call_boundary != 0U)
        stop_pcs[stop_count++] = runtime->config.unix_call_boundary;
    memset(&request, 0, sizeof(request));
    request.abi_version = BLINK_GEM_RUN_REQUEST_ABI_VERSION;
    request.size = sizeof(request);
    request.instruction_budget = budget;
    request.stop_pc_count = stop_count;
    request.stop_pcs = stop_pcs;
    request.async_stop = async_stop;
    request.async_opaque = runtime;
    import_state(in, &blink_in);
    ++runtime->performance.state_imports;
    result = blink_gem_machine_run(runtime->backend, &request, &blink_in, &blink_out);
    if (runtime->trace_drain)
        gem_i386_blink_trace_drain(runtime);
    *retired = result.retired;
    runtime->last_stop.fault_address = (uint32_t)result.fault_address;
    runtime->last_stop.access = (enum gem_i386_memory_access)result.access;
    runtime->last_stop.memory_error = result.memory_error;
    runtime->last_stop.engine_status = result.engine_status;
    if (result.outcome == BLINK_GEM_RETIRED || result.outcome == BLINK_GEM_STOP_PC ||
        result.outcome == BLINK_GEM_ASYNC_STOP || result.outcome == BLINK_GEM_QUANTUM_BOUNDARY ||
        result.retired != 0U || result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_REP ||
        result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_GATHER) {
        export_state(&blink_out, in, out);
        ++runtime->performance.state_exports;
    }
    if (result.outcome == BLINK_GEM_RETIRED)
        return result.retired == budget ? GEM_STOP_NONE : GEM_STOP_INVARIANT_VIOLATION;
    if (result.outcome == BLINK_GEM_QUANTUM_BOUNDARY)
        return result.retired != 0U && result.retired <= budget ? GEM_STOP_NONE
                                                                : GEM_STOP_INVARIANT_VIOLATION;
    if (result.outcome == BLINK_GEM_STOP_PC) {
        uint32_t boundary = 0U;
        if (out->eip == runtime->config.host_return_sentinel)
            return GEM_STOP_HOST_RETURN;
        if (out->eip == runtime->config.windows_syscall_boundary)
            boundary = GEM_I386_BOUNDARY_WINDOWS_SYSCALL;
        else if (out->eip == runtime->config.unix_call_boundary)
            boundary = GEM_I386_BOUNDARY_UNIX_CALL;
        runtime->last_stop.engine_status = boundary;
        return boundary != 0U ? GEM_STOP_SYSCALL : GEM_STOP_INVARIANT_VIOLATION;
    }
    if (result.outcome == BLINK_GEM_ASYNC_STOP)
        return GEM_STOP_ASYNC_REQUEST;
    if (result.outcome == BLINK_GEM_MEMORY_FAULT) {
        if (result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_REP)
            runtime->last_stop.engine_status = GEM_I386_ENGINE_STATUS_RESTARTABLE_REP;
        else if (result.engine_status == BLINK_GEM_ENGINE_STATUS_RESTARTABLE_GATHER)
            runtime->last_stop.engine_status = GEM_I386_ENGINE_STATUS_RESTARTABLE_GATHER;
        return GEM_STOP_MEMORY_FAULT;
    }
    if (result.outcome == BLINK_GEM_EXCEPTION) {
        switch (result.engine_status) {
        case BLINK_GEM_EXCEPTION_ILLEGAL_INSTRUCTION:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION;
            break;
        case BLINK_GEM_EXCEPTION_DIVIDE:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_DIVIDE_BY_ZERO;
            break;
        case BLINK_GEM_EXCEPTION_OVERFLOW:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_OVERFLOW;
            break;
        case BLINK_GEM_EXCEPTION_PROTECTION:
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_GENERAL_PROTECTION;
            break;
        default:
            return GEM_STOP_INVARIANT_VIOLATION;
        }
        return GEM_STOP_WINDOWS_EXCEPTION;
    }
    if (result.outcome == BLINK_GEM_UNSUPPORTED) {
        struct blink_gem_decode_attempt attempt;
        memset(&attempt, 0, sizeof(attempt));
        attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
        attempt.size = sizeof(attempt);
        if (!blink_gem_machine_decode_attempt_info(runtime->backend, &attempt) || !attempt.valid)
            return GEM_STOP_UNSUPPORTED_INSTRUCTION;
        if (is_virtual_rdtsc(&attempt) || is_virtual_rdtscp(&attempt)) {
            if (result.retired == 0U) {
                *out = *in;
                ++runtime->performance.state_exports;
            }
            if (!complete_virtual_timestamp(runtime, out, attempt.instruction_length, budget,
                                            retired, is_virtual_rdtscp(&attempt)))
                return GEM_STOP_INVARIANT_VIOLATION;
            if (out->eip == runtime->config.host_return_sentinel)
                return GEM_STOP_HOST_RETURN;
            if (out->eip == runtime->config.windows_syscall_boundary ||
                out->eip == runtime->config.unix_call_boundary) {
                runtime->last_stop.engine_status =
                    out->eip == runtime->config.windows_syscall_boundary
                        ? GEM_I386_BOUNDARY_WINDOWS_SYSCALL
                        : GEM_I386_BOUNDARY_UNIX_CALL;
                return GEM_STOP_SYSCALL;
            }
            return GEM_STOP_NONE;
        }
        if (strcmp(attempt.name, "OpInterrupt3") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_BREAKPOINT;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpInto") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_OVERFLOW;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpUd") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (strcmp(attempt.name, "OpInterruptImm") == 0 ||
            strcmp(attempt.name, "OpSysenter") == 0) {
            runtime->last_stop.engine_status = GEM_I386_BOUNDARY_WINDOWS_SYSCALL;
            return GEM_STOP_SYSCALL;
        }
        record_unsupported(runtime, &attempt);
        return GEM_STOP_UNSUPPORTED_INSTRUCTION;
    }
    return GEM_STOP_INVARIANT_VIOLATION;
}

bool gem_i386_blink_engine_info(const struct gem_i386_runtime *runtime,
                                struct gem_i386_engine_info *out) {
    struct blink_gem_engine_info info;
    if (runtime == NULL || out == NULL || out->abi_version != 1U || out->size != sizeof(*out))
        return false;
    memset(&info, 0, sizeof(info));
    info.abi_version = BLINK_GEM_ENGINE_INFO_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_engine_info(runtime->backend, &info))
        return false;
    out->engine_mode =
        info.engine == BLINK_GEM_ENGINE_JIT ? GEM_I386_ENGINE_JIT : GEM_I386_ENGINE_INTERPRETER;
    out->host_arch =
        info.host_arch == BLINK_GEM_HOST_AARCH64 ? GEM_I386_HOST_AARCH64 : GEM_I386_HOST_UNKNOWN;
    out->jit_compilations = info.jit_compilations;
    out->jit_executions = info.jit_executions;
    out->jit_failures = info.jit_failures;
    out->write_xor_execute = info.write_xor_execute;
    out->reserved = 0U;
    return true;
}

bool gem_i386_blink_block_info(const struct gem_i386_runtime *runtime,
                               struct gem_i386_block_info *out) {
    struct blink_gem_block_info info;
    if (runtime == NULL || out == NULL || out->abi_version != GEM_I386_BLOCK_INFO_ABI_VERSION ||
        out->size != sizeof(*out))
        return false;
    memset(&info, 0, sizeof(info));
    info.abi_version = BLINK_GEM_BLOCK_INFO_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_block_info(runtime->backend, &info))
        return false;
    out->blocks_created = info.blocks_created;
    out->block_lookups = info.block_lookups;
    out->block_cache_hits = info.block_cache_hits;
    out->direct_link_hits = info.direct_link_hits;
    out->call_predictions = info.call_predictions;
    out->return_predictions = info.return_predictions;
    out->return_prediction_hits = info.return_prediction_hits;
    out->return_prediction_misses = info.return_prediction_misses;
    out->block_invalidations = info.block_invalidations;
    return true;
}

bool gem_i386_blink_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                    uint64_t size) {
    return runtime != NULL && i386_range(address, size) &&
           blink_gem_machine_invalidate_code(runtime->backend, address, size);
}

bool gem_i386_blink_invalidate_memory(struct gem_i386_runtime *runtime, uint32_t address,
                                      uint64_t size) {
    return runtime != NULL && i386_range(address, size) &&
           blink_gem_machine_invalidate_memory(runtime->backend, address, size);
}

void gem_i386_runtime_handler_trace_reset(struct gem_i386_runtime *runtime) {
    if (runtime != NULL)
        blink_gem_machine_trace_reset(runtime->backend);
}

bool gem_i386_runtime_handler_trace_info(const struct gem_i386_runtime *runtime, uint32_t *count,
                                         uint32_t *overflowed) {
    struct blink_gem_trace_info info;
    if (runtime == NULL)
        return false;
    memset(&info, 0, sizeof(info));
    info.abi_version = BLINK_GEM_TRACE_ABI_VERSION;
    info.size = sizeof(info);
    if (!blink_gem_machine_trace_info(runtime->backend, &info))
        return false;
    if (count != NULL)
        *count = info.count;
    if (overflowed != NULL)
        *overflowed = info.overflowed;
    return true;
}

bool gem_i386_runtime_handler_trace_read(const struct gem_i386_runtime *runtime, size_t index,
                                         uint64_t *rip, uint32_t *handler_id) {
    struct blink_gem_trace_entry entry;
    if (runtime == NULL || !blink_gem_machine_trace_read(runtime->backend, index, &entry))
        return false;
    if (rip != NULL)
        *rip = entry.rip;
    if (handler_id != NULL)
        *handler_id = entry.handler_id;
    return true;
}

const char *gem_i386_runtime_handler_name(uint32_t handler_id) {
    return blink_gem_handler_name(handler_id);
}

bool gem_i386_runtime_decode_attempt_info(const struct gem_i386_runtime *runtime,
                                          struct blink_gem_decode_attempt *out) {
    struct blink_gem_decode_attempt probe;
    if (runtime == NULL || out == NULL)
        return false;
    /* Validate the caller's struct ABI up front so a future caller ABI drift
     * fails closed at the wrapper boundary instead of silently reading or
     * writing past the destination buffer. */
    if (out->abi_version != BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION || out->size != sizeof(probe))
        return false;
    memset(&probe, 0, sizeof(probe));
    probe.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
    probe.size = sizeof(probe);
    if (!blink_gem_machine_decode_attempt_info(runtime->backend, &probe))
        return false;
    *out = probe;
    return true;
}

const struct gem_i386_engine_ops gem_i386_blink_jit_ops = {
    GEM_I386_ENGINE_OPS_ABI_VERSION,
    GEM_I386_ENGINE_JIT,
    "GEM_i386 Blink AArch64 JIT",
    "blink-f006a4fc-gem-i386-v4",
    "jart/blink@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580;legacy32;"
    "context-v3;cpuid-sse42-aes-pclmul-bmi1;"
    "bounded-multi-instruction;checked-block-links;bounded-return-prediction;"
    "interpreter-or-aarch64-jit",
    gem_i386_blink_create,
    gem_i386_blink_destroy,
    gem_i386_blink_sync,
    gem_i386_blink_step,
    gem_i386_blink_run,
    gem_i386_blink_engine_info,
    gem_i386_blink_block_info,
    gem_i386_blink_invalidate_code,
    gem_i386_blink_invalidate_memory,
};

const struct gem_i386_engine_ops gem_i386_blink_interpreter_ops = {
    GEM_I386_ENGINE_OPS_ABI_VERSION,
    GEM_I386_ENGINE_INTERPRETER,
    "GEM_i386 Blink interpreter",
    "blink-f006a4fc-gem-i386-v4",
    "jart/blink@f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580;legacy32;"
    "context-v3;cpuid-sse42-aes-pclmul-bmi1;"
    "bounded-multi-instruction;checked-block-links;bounded-return-prediction;"
    "interpreter-or-aarch64-jit",
    gem_i386_blink_create,
    gem_i386_blink_destroy,
    gem_i386_blink_sync,
    gem_i386_blink_step,
    gem_i386_blink_run,
    gem_i386_blink_engine_info,
    gem_i386_blink_block_info,
    gem_i386_blink_invalidate_code,
    gem_i386_blink_invalidate_memory,
};
