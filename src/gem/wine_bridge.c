// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/wine_bridge.h"

#include "metalsharp/gem/arm64ec_engine.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(GEM_WINE_GUEST_PAGE_SIZE == GEM_GUEST_PAGE_SIZE,
               "Wine bridge guest-page ABI diverged from GEM");
_Static_assert(GEM_WINE_KUSER_SHARED_DATA_ADDRESS == GEM_KUSER_SHARED_DATA_ADDRESS,
               "Wine bridge KUSER alias diverged from GEM");
_Static_assert(GEM_WINE_KUSER_CANONICAL_ADDRESS == GEM_KUSER_CANONICAL_ADDRESS,
               "Wine bridge KUSER canonical address diverged from GEM");
_Static_assert((uint32_t)GEM_WINE_PAGE_NOACCESS == (uint32_t)GEM_PAGE_NOACCESS &&
                   (uint32_t)GEM_WINE_PAGE_READONLY == (uint32_t)GEM_PAGE_READONLY &&
                   (uint32_t)GEM_WINE_PAGE_READWRITE == (uint32_t)GEM_PAGE_READWRITE &&
                   (uint32_t)GEM_WINE_PAGE_WRITECOPY == (uint32_t)GEM_PAGE_WRITECOPY &&
                   (uint32_t)GEM_WINE_PAGE_EXECUTE == (uint32_t)GEM_PAGE_EXECUTE &&
                   (uint32_t)GEM_WINE_PAGE_EXECUTE_READ == (uint32_t)GEM_PAGE_EXECUTE_READ &&
                   (uint32_t)GEM_WINE_PAGE_EXECUTE_READWRITE ==
                       (uint32_t)GEM_PAGE_EXECUTE_READWRITE &&
                   (uint32_t)GEM_WINE_PAGE_EXECUTE_WRITECOPY ==
                       (uint32_t)GEM_PAGE_EXECUTE_WRITECOPY &&
                   (uint32_t)GEM_WINE_PAGE_GUARD == (uint32_t)GEM_PAGE_GUARD,
               "Wine bridge protection ABI diverged from GEM");

struct gem_wine_thread {
    struct gem_wine_process *process;
    struct gem_wine_thread *next;
    struct gem_arm64ec_runtime *runtime;
    struct gem_wine_thread_config config;
    pthread_mutex_t run_lock;
    pthread_mutex_t runtime_lock;
};

struct gem_wine_process {
    struct gem_memory *memory;
    struct gem_wine_process_config config;
    struct gem_wine_thread *threads;
    pthread_mutex_t threads_lock;
};

static bool zero_words(const uint64_t *words, size_t count) {
    size_t index;
    for (index = 0; index < count; ++index)
        if (words[index] != 0U)
            return false;
    return true;
}

static enum gem_wine_status memory_status(enum gem_memory_error error) {
    switch (error) {
    case GEM_MEMORY_OK:
        return GEM_WINE_OK;
    case GEM_MEMORY_INVALID_ARGUMENT:
    case GEM_MEMORY_OVERFLOW:
        return GEM_WINE_INVALID_ARGUMENT;
    case GEM_MEMORY_NO_MEMORY:
        return GEM_WINE_NO_MEMORY;
    case GEM_MEMORY_CONFLICT:
        return GEM_WINE_CONFLICT;
    default:
        return GEM_WINE_MEMORY_ERROR;
    }
}

static bool context_valid_for_thread(const struct gem_wine_thread *thread,
                                     const struct gem_thread_context *context) {
    return context != NULL && gem_context_is_valid(context) && context->reserved0 == 0U &&
           context->stop_reason <= GEM_STOP_INVARIANT_VIOLATION &&
           context->isa == (uint32_t)GEM_ISA_ARM64EC && context->teb == thread->config.teb &&
           context->x[18] == thread->config.teb;
}

static void initialize_result(struct gem_wine_run_result *result) {
    memset(result, 0, sizeof(*result));
    result->version = GEM_WINE_RUN_RESULT_VERSION;
    result->struct_size = (uint32_t)sizeof(*result);
    result->outcome = GEM_WINE_RUN_FAILED;
}

static void copy_stop_info(struct gem_wine_stop_info *destination,
                           const struct gem_arm64ec_stop_info *source) {
    memset(destination, 0, sizeof(*destination));
    destination->reason = (uint32_t)source->reason;
    destination->access = (uint32_t)source->access;
    destination->memory_error = source->memory_error;
    destination->engine_status = source->engine_status;
    destination->instructions_retired = source->instructions_retired;
    destination->fault_address = source->fault_address;
}

uint32_t gem_wine_bridge_abi_version(void) {
    return GEM_WINE_BRIDGE_ABI_VERSION;
}

const char *gem_wine_status_name(enum gem_wine_status status) {
    static const char *const names[] = {
        "ok",           "invalid-argument", "no-memory",      "conflict", "memory-error",
        "engine-error", "callback-error",   "budget-expired", "stopped",  "terminated",
    };
    if ((unsigned int)status >= sizeof(names) / sizeof(names[0]))
        return "invalid";
    return names[status];
}

enum gem_wine_status gem_wine_process_create(const struct gem_wine_process_config *config,
                                             struct gem_wine_process **out_process) {
    struct gem_wine_process *process;

    if (config == NULL || out_process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    *out_process = NULL;
    if (config->version != GEM_WINE_PROCESS_CONFIG_VERSION ||
        config->struct_size != sizeof(*config) || config->segment_instruction_budget == 0U ||
        config->total_instruction_budget < config->segment_instruction_budget ||
        config->max_boundary_callbacks == 0U || config->host_return_sentinel == 0U ||
        config->host_return_sentinel == config->unix_call_dispatcher ||
        !zero_words(config->reserved, sizeof(config->reserved) / sizeof(config->reserved[0])))
        return GEM_WINE_INVALID_ARGUMENT;

    process = (struct gem_wine_process *)calloc(1U, sizeof(*process));
    if (process == NULL)
        return GEM_WINE_NO_MEMORY;
    process->config = *config;
    if (pthread_mutex_init(&process->threads_lock, NULL) != 0) {
        free(process);
        return GEM_WINE_ENGINE_ERROR;
    }
    process->memory = gem_memory_create();
    if (process->memory == NULL) {
        (void)pthread_mutex_destroy(&process->threads_lock);
        free(process);
        return GEM_WINE_NO_MEMORY;
    }
    *out_process = process;
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_process_destroy(struct gem_wine_process *process) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&process->threads_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    if (process->threads != NULL) {
        (void)pthread_mutex_unlock(&process->threads_lock);
        return GEM_WINE_CONFLICT;
    }
    (void)pthread_mutex_unlock(&process->threads_lock);
    gem_memory_destroy(process->memory);
    (void)pthread_mutex_destroy(&process->threads_lock);
    free(process);
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_process_map_identity(struct gem_wine_process *process,
                                                   uint64_t address, void *host, uint64_t size,
                                                   uint32_t protection) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(gem_memory_map_identity(process->memory, address, host, size, protection));
}

enum gem_wine_status gem_wine_process_unmap(struct gem_wine_process *process, uint64_t address,
                                            uint64_t size) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(gem_memory_unmap(process->memory, address, size));
}

enum gem_wine_status gem_wine_process_protect(struct gem_wine_process *process, uint64_t address,
                                              uint64_t size, uint32_t protection,
                                              uint32_t *old_protection) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(
        gem_memory_protect(process->memory, address, size, protection, old_protection));
}

enum gem_wine_status gem_wine_process_bind_kuser(struct gem_wine_process *process,
                                                 void *host_page) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(gem_memory_bind_kuser(process->memory, host_page));
}

enum gem_wine_status gem_wine_process_invalidate_code(struct gem_wine_process *process,
                                                      uint64_t address, uint64_t size) {
    struct gem_wine_thread *thread;
    if (process == NULL || size == 0U || address > UINT64_MAX - size)
        return GEM_WINE_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&process->threads_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    for (thread = process->threads; thread != NULL; thread = thread->next) {
        if (pthread_mutex_lock(&thread->runtime_lock) != 0) {
            (void)pthread_mutex_unlock(&process->threads_lock);
            return GEM_WINE_ENGINE_ERROR;
        }
        gem_arm64ec_runtime_invalidate_code(thread->runtime, address, size);
        (void)pthread_mutex_unlock(&thread->runtime_lock);
    }
    (void)pthread_mutex_unlock(&process->threads_lock);
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_thread_create(struct gem_wine_process *process,
                                            const struct gem_wine_thread_config *config,
                                            struct gem_wine_thread **out_thread) {
    struct gem_wine_thread *thread;
    struct gem_arm64ec_runtime_config runtime_config;

    if (process == NULL || config == NULL || out_thread == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    *out_thread = NULL;
    if (config->version != GEM_WINE_THREAD_CONFIG_VERSION ||
        config->struct_size != sizeof(*config) || config->teb == 0U ||
        !zero_words(config->reserved, sizeof(config->reserved) / sizeof(config->reserved[0])))
        return GEM_WINE_INVALID_ARGUMENT;

    thread = (struct gem_wine_thread *)calloc(1U, sizeof(*thread));
    if (thread == NULL)
        return GEM_WINE_NO_MEMORY;
    thread->process = process;
    thread->config = *config;
    if (pthread_mutex_init(&thread->run_lock, NULL) != 0) {
        free(thread);
        return GEM_WINE_ENGINE_ERROR;
    }
    if (pthread_mutex_init(&thread->runtime_lock, NULL) != 0) {
        (void)pthread_mutex_destroy(&thread->run_lock);
        free(thread);
        return GEM_WINE_ENGINE_ERROR;
    }
    memset(&runtime_config, 0, sizeof(runtime_config));
    runtime_config.host_return_sentinel = process->config.host_return_sentinel;
    runtime_config.max_budget = process->config.segment_instruction_budget;
    runtime_config.execution_profile = GEM_ARM64EC_PROFILE_NATIVE_ARM64;
    thread->runtime = gem_arm64ec_runtime_create(process->memory, &runtime_config);
    if (thread->runtime == NULL) {
        (void)pthread_mutex_destroy(&thread->runtime_lock);
        (void)pthread_mutex_destroy(&thread->run_lock);
        free(thread);
        return GEM_WINE_ENGINE_ERROR;
    }
    if (pthread_mutex_lock(&process->threads_lock) != 0) {
        gem_arm64ec_runtime_destroy(thread->runtime);
        (void)pthread_mutex_destroy(&thread->runtime_lock);
        (void)pthread_mutex_destroy(&thread->run_lock);
        free(thread);
        return GEM_WINE_ENGINE_ERROR;
    }
    thread->next = process->threads;
    process->threads = thread;
    (void)pthread_mutex_unlock(&process->threads_lock);
    *out_thread = thread;
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_thread_destroy(struct gem_wine_thread *thread) {
    struct gem_wine_thread **link;
    struct gem_wine_process *process;
    if (thread == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    process = thread->process;
    if (pthread_mutex_lock(&process->threads_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    for (link = &process->threads; *link != NULL && *link != thread; link = &(*link)->next)
        ;
    if (*link == NULL) {
        (void)pthread_mutex_unlock(&process->threads_lock);
        return GEM_WINE_CONFLICT;
    }
    if (pthread_mutex_trylock(&thread->run_lock) != 0) {
        (void)pthread_mutex_unlock(&process->threads_lock);
        return GEM_WINE_CONFLICT;
    }
    *link = thread->next;
    (void)pthread_mutex_unlock(&process->threads_lock);
    gem_arm64ec_runtime_destroy(thread->runtime);
    (void)pthread_mutex_unlock(&thread->run_lock);
    (void)pthread_mutex_destroy(&thread->runtime_lock);
    (void)pthread_mutex_destroy(&thread->run_lock);
    free(thread);
    return GEM_WINE_OK;
}

static enum gem_wine_boundary_event classify_event(const struct gem_wine_process *process,
                                                   enum gem_stop_reason reason,
                                                   const struct gem_thread_context *context,
                                                   const struct gem_arm64ec_stop_info *stop) {
    switch (reason) {
    case GEM_STOP_SYSCALL:
        return GEM_WINE_EVENT_SYSCALL;
    case GEM_STOP_MEMORY_FAULT:
        if (process->config.unix_call_dispatcher != 0U &&
            context->pc == process->config.unix_call_dispatcher &&
            stop->fault_address == process->config.unix_call_dispatcher &&
            stop->access == GEM_ARM64EC_ACCESS_FETCH)
            return GEM_WINE_EVENT_UNIX_CALL;
        return GEM_WINE_EVENT_MEMORY_FAULT;
    case GEM_STOP_WINDOWS_EXCEPTION:
        return GEM_WINE_EVENT_WINDOWS_EXCEPTION;
    case GEM_STOP_ARCH_TRANSITION:
        return GEM_WINE_EVENT_ARCH_TRANSITION;
    case GEM_STOP_ASYNC_REQUEST:
        return GEM_WINE_EVENT_ASYNC_REQUEST;
    case GEM_STOP_UNSUPPORTED_INSTRUCTION:
        return GEM_WINE_EVENT_UNSUPPORTED_INSTRUCTION;
    case GEM_STOP_INVARIANT_VIOLATION:
    default:
        return GEM_WINE_EVENT_INVARIANT_VIOLATION;
    }
}

enum gem_wine_status gem_wine_thread_run(struct gem_wine_thread *thread,
                                         const struct gem_thread_context *input,
                                         struct gem_thread_context *out_context,
                                         struct gem_wine_run_result *result) {
    struct gem_thread_context context;
    struct gem_wine_run_result run_result;
    struct gem_wine_process *process;
    enum gem_wine_status status = GEM_WINE_ENGINE_ERROR;

    if (thread == NULL || input == NULL || out_context == NULL || result == NULL ||
        !context_valid_for_thread(thread, input) || input->stop_reason != GEM_STOP_NONE)
        return GEM_WINE_INVALID_ARGUMENT;
    process = thread->process;
    if (pthread_mutex_trylock(&thread->run_lock) != 0)
        return GEM_WINE_CONFLICT;
    context = *input;
    initialize_result(&run_result);

    for (;;) {
        struct gem_arm64ec_stop_info stop;
        enum gem_stop_reason reason;
        uint64_t remaining;
        uint64_t budget;

        if (run_result.instructions_retired >= process->config.total_instruction_budget) {
            run_result.outcome = GEM_WINE_RUN_BUDGET_EXPIRED;
            run_result.stop_reason = GEM_STOP_BUDGET_EXPIRED;
            status = GEM_WINE_BUDGET_EXPIRED;
            break;
        }
        remaining = process->config.total_instruction_budget - run_result.instructions_retired;
        budget = remaining < process->config.segment_instruction_budget
                     ? remaining
                     : process->config.segment_instruction_budget;
        if (pthread_mutex_lock(&thread->runtime_lock) != 0) {
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        reason = gem_arm64ec_runtime_run(thread->runtime, &context, budget);
        if (!gem_arm64ec_runtime_last_stop_info(thread->runtime, &stop)) {
            (void)pthread_mutex_unlock(&thread->runtime_lock);
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        (void)pthread_mutex_unlock(&thread->runtime_lock);
        copy_stop_info(&run_result.stop, &stop);
        run_result.stop_reason = (uint32_t)reason;
        if (stop.instructions_retired > UINT64_MAX - run_result.instructions_retired) {
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        run_result.instructions_retired += stop.instructions_retired;

        if (!context_valid_for_thread(thread, &context)) {
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        if (reason == GEM_STOP_HOST_RETURN) {
            run_result.outcome = GEM_WINE_RUN_COMPLETE;
            status = GEM_WINE_OK;
            break;
        }
        if (reason == GEM_STOP_BUDGET_EXPIRED) {
            run_result.outcome = GEM_WINE_RUN_BUDGET_EXPIRED;
            status = GEM_WINE_BUDGET_EXPIRED;
            break;
        }
        run_result.last_event = (uint32_t)classify_event(process, reason, &context, &stop);
        if (run_result.last_event == GEM_WINE_EVENT_INVARIANT_VIOLATION) {
            run_result.outcome = GEM_WINE_RUN_FAILED;
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        if (thread->config.boundary == NULL) {
            run_result.outcome = GEM_WINE_RUN_UNHANDLED_STOP;
            status = GEM_WINE_STOPPED;
            break;
        }
        if (run_result.boundary_callbacks >= process->config.max_boundary_callbacks) {
            run_result.outcome = GEM_WINE_RUN_BUDGET_EXPIRED;
            status = GEM_WINE_BUDGET_EXPIRED;
            break;
        }

        {
            struct gem_wine_boundary_request request;
            struct gem_wine_boundary_response response;
            enum gem_wine_status callback_status;

            memset(&request, 0, sizeof(request));
            request.version = GEM_WINE_BOUNDARY_ABI_VERSION;
            request.struct_size = (uint32_t)sizeof(request);
            request.event = run_result.last_event;
            request.context = context;
            copy_stop_info(&request.stop, &stop);
            memset(&response, 0, sizeof(response));
            response.version = GEM_WINE_BOUNDARY_ABI_VERSION;
            response.struct_size = (uint32_t)sizeof(response);
            response.context = context;
            ++run_result.boundary_callbacks;
            callback_status = thread->config.boundary(thread->config.opaque, &request, &response);
            if (callback_status != GEM_WINE_OK ||
                response.version != GEM_WINE_BOUNDARY_ABI_VERSION ||
                response.struct_size != sizeof(response)) {
                run_result.outcome = GEM_WINE_RUN_FAILED;
                status = GEM_WINE_CALLBACK_ERROR;
                break;
            }
            if (response.action == GEM_WINE_BOUNDARY_TERMINATE) {
                run_result.outcome = GEM_WINE_RUN_TERMINATED;
                run_result.exit_status = response.exit_status;
                status = GEM_WINE_TERMINATED;
                break;
            }
            if (response.action != GEM_WINE_BOUNDARY_RESUME ||
                !context_valid_for_thread(thread, &response.context) ||
                response.context.stop_reason != GEM_STOP_NONE ||
                ((request.event == GEM_WINE_EVENT_SYSCALL ||
                  request.event == GEM_WINE_EVENT_UNIX_CALL) &&
                 response.context.pc == request.context.pc)) {
                run_result.outcome = GEM_WINE_RUN_FAILED;
                status = GEM_WINE_CALLBACK_ERROR;
                break;
            }
            context = response.context;
        }
    }

    *out_context = context;
    *result = run_result;
    (void)pthread_mutex_unlock(&thread->run_lock);
    return status;
}
