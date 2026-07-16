// SPDX-License-Identifier: Apache-2.0
#include "blink/gem_embed.h"
#include "i386_engine_internal.h"
#include "metalsharp/gem/i386_memory.h"

#include <stdlib.h>
#include <string.h>

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
    *protection = 0U;
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
    struct gem_memory_page_write *pages;
    enum gem_memory_error error;
    size_t i;
    if (count == 0U)
        return GEM_MEMORY_OK;
    pages = (struct gem_memory_page_write *)calloc(count, sizeof(*pages));
    if (pages == NULL)
        return GEM_MEMORY_NO_MEMORY;
    for (i = 0; i < count; ++i) {
        if (writes[i].size != GEM_GUEST_PAGE_SIZE ||
            !i386_range(writes[i].address, writes[i].size)) {
            free(pages);
            return GEM_MEMORY_OVERFLOW;
        }
        pages[i].address = writes[i].address;
        pages[i].data = writes[i].data;
    }
    error = gem_memory_transaction_commit_pages(runtime->transaction, pages, count, fault_address);
    free(pages);
    return (uint32_t)error;
}

static void import_state(const struct gem_i386_context *source, struct blink_gem_state *target) {
    size_t i;
    memset(target, 0, sizeof(*target));
    target->abi_version = 1U;
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
    target->fs_base = source->teb;
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
    target->teb = (uint32_t)source->fs_base;
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
    return runtime->backend != NULL;
}

void gem_i386_blink_destroy(struct gem_i386_runtime *runtime) {
    blink_gem_machine_destroy(runtime->backend);
    runtime->backend = NULL;
}

void gem_i386_blink_sync(struct gem_i386_runtime *runtime) {
    blink_gem_machine_sync(runtime->backend);
}

enum gem_stop_reason gem_i386_blink_step(struct gem_i386_runtime *runtime,
                                         const struct gem_i386_context *in,
                                         struct gem_i386_context *out, uint32_t *retired) {
    struct blink_gem_state blink_in;
    struct blink_gem_state blink_out;
    struct blink_gem_result result;
    import_state(in, &blink_in);
    result = blink_gem_machine_step(runtime->backend, &blink_in, &blink_out);
    *retired = result.retired;
    runtime->last_stop.fault_address = (uint32_t)result.fault_address;
    runtime->last_stop.access = (enum gem_i386_memory_access)result.access;
    runtime->last_stop.memory_error = result.memory_error;
    runtime->last_stop.engine_status = result.engine_status;
    if (result.outcome == BLINK_GEM_RETIRED) {
        export_state(&blink_out, in, out);
        return result.retired == 1U ? GEM_STOP_NONE : GEM_STOP_INVARIANT_VIOLATION;
    }
    if (result.outcome == BLINK_GEM_MEMORY_FAULT)
        return GEM_STOP_MEMORY_FAULT;
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
        if (blink_gem_machine_decode_attempt_info(runtime->backend, &attempt) && attempt.valid &&
            strcmp(attempt.name, "OpInterrupt3") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_BREAKPOINT;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (attempt.valid && strcmp(attempt.name, "OpInto") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_INTEGER_OVERFLOW;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (attempt.valid && strcmp(attempt.name, "OpUd") == 0) {
            runtime->last_stop.engine_status = GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION;
            return GEM_STOP_WINDOWS_EXCEPTION;
        }
        if (attempt.valid && (strcmp(attempt.name, "OpInterruptImm") == 0 ||
                              strcmp(attempt.name, "OpSysenter") == 0)) {
            runtime->last_stop.engine_status = GEM_I386_BOUNDARY_WINDOWS_SYSCALL;
            return GEM_STOP_SYSCALL;
        }
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

bool gem_i386_blink_invalidate_code(struct gem_i386_runtime *runtime, uint32_t address,
                                    uint64_t size) {
    return runtime != NULL && i386_range(address, size) &&
           blink_gem_machine_invalidate_code(runtime->backend, address, size);
}
