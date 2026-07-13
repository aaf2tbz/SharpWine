// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/wine_bridge.h"

#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/arm64ec_target.h"
#include "metalsharp/gem/hybrid_runtime.h"
#include "metalsharp/gem/pe_arm64x.h"

#include <pthread.h>
#include <stdatomic.h>
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

struct gem_wine_arm64x_image {
    struct gem_wine_arm64x_image *next;
    struct gem_pe_arm64x_image *metadata;
    struct gem_arm64ec_target_map *map;
    struct gem_pe_arm64x_summary summary;
    struct gem_wine_arm64x_config config;
    uint64_t loaded_end;
};

struct gem_wine_hybrid_binding {
    struct gem_wine_hybrid_binding *next;
    const struct gem_wine_arm64x_image *image;
    struct gem_hybrid_runtime *runtime;
};

struct gem_wine_thread {
    struct gem_wine_process *process;
    struct gem_wine_thread *next;
    struct gem_arm64ec_runtime *runtime;
    struct gem_wine_hybrid_binding *hybrids;
    _Atomic(struct gem_hybrid_runtime *) active_hybrid;
    struct gem_wine_thread_config config;
    pthread_mutex_t run_lock;
    pthread_mutex_t runtime_lock;
};

struct gem_wine_process {
    struct gem_memory *memory;
    struct gem_wine_process_config config;
    struct gem_wine_thread *threads;
    struct gem_wine_arm64x_image *images;
    _Atomic bool arm64x_routing_enabled;
    pthread_mutex_t threads_lock;
    pthread_mutex_t images_lock;
};

static bool zero_words(const uint64_t *words, size_t count) {
    size_t index;
    for (index = 0; index < count; ++index)
        if (words[index] != 0U)
            return false;
    return true;
}

static void destroy_arm64x_image(struct gem_wine_arm64x_image *image) {
    if (image != NULL) {
        gem_arm64ec_target_map_destroy(image->map);
        gem_pe_arm64x_image_destroy(image->metadata);
        free(image);
    }
}

static void destroy_hybrid_bindings(struct gem_wine_hybrid_binding *binding) {
    while (binding != NULL) {
        struct gem_wine_hybrid_binding *next = binding->next;
        gem_hybrid_runtime_destroy(binding->runtime);
        free(binding);
        binding = next;
    }
}

static struct gem_wine_arm64x_image *find_image_for_pc(struct gem_wine_process *process,
                                                       uint64_t pc) {
    struct gem_wine_arm64x_image *image = NULL;
    if (pthread_mutex_lock(&process->images_lock) != 0)
        return NULL;
    for (image = process->images; image != NULL; image = image->next)
        if (pc >= image->config.loaded_base && pc < image->loaded_end)
            break;
    (void)pthread_mutex_unlock(&process->images_lock);
    return image;
}

static enum gem_arm64ec_target_status
process_target_resolve(void *opaque, uint64_t requested_va,
                       struct gem_arm64ec_target_result *out_result) {
    struct gem_wine_process *process = (struct gem_wine_process *)opaque;
    struct gem_wine_arm64x_image *image;
    enum gem_arm64ec_target_status status = GEM_ARM64EC_TARGET_OUTSIDE_IMAGE;

    if (process == NULL || out_result == NULL)
        return GEM_ARM64EC_TARGET_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&process->images_lock) != 0)
        return GEM_ARM64EC_TARGET_MALFORMED_METADATA;
    for (image = process->images; image != NULL; image = image->next) {
        if (requested_va >= image->config.loaded_base && requested_va < image->loaded_end) {
            status = gem_arm64ec_target_resolve(image->map, requested_va, out_result);
            break;
        }
    }
    (void)pthread_mutex_unlock(&process->images_lock);
    return status;
}

static enum gem_arm64ec_boundary_action
native_image_boundary(void *opaque, uint64_t pc, struct gem_thread_context *context,
                      enum gem_arm64ec_boundary_kind *out_kind) {
    struct gem_wine_thread *thread = (struct gem_wine_thread *)opaque;
    struct gem_wine_arm64x_image *image = find_image_for_pc(thread->process, pc);
    struct gem_arm64ec_target_result target;
    (void)context;
    if (image == NULL)
        return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
    *out_kind = GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
    if (gem_arm64ec_target_resolve(image->map, pc, &target) != GEM_ARM64EC_TARGET_OK)
        return GEM_ARM64EC_BOUNDARY_FAIL;
    return GEM_ARM64EC_BOUNDARY_STOP;
}

static struct gem_wine_hybrid_binding *
find_or_create_hybrid(struct gem_wine_thread *thread, const struct gem_wine_arm64x_image *image) {
    struct gem_wine_hybrid_binding *binding;
    struct gem_hybrid_runtime_config config;

    for (binding = thread->hybrids; binding != NULL; binding = binding->next)
        if (binding->image == image)
            return binding;
    binding = (struct gem_wine_hybrid_binding *)calloc(1U, sizeof(*binding));
    if (binding == NULL)
        return NULL;
    memset(&config, 0, sizeof(config));
    config.version = GEM_HYBRID_RUNTIME_CONFIG_VERSION;
    config.boundary_delivery = (image->config.flags & GEM_WINE_ARM64X_FLAG_SVC_BOUNDARIES) != 0U
                                   ? GEM_ARM64EC_BOUNDARY_SVC_TRAP
                                   : GEM_ARM64EC_BOUNDARY_PRECISE;
    config.loaded_base = image->config.loaded_base;
    config.checker_helper = image->config.checker_helper;
    config.dispatch_call_helper = image->config.dispatch_call_helper;
    config.dispatch_jump_helper = image->config.dispatch_jump_helper;
    config.dispatch_ret_helper = image->config.dispatch_ret_helper;
    config.x64_return_sentinel = UINT64_MAX - UINT64_C(31);
    config.host_return_sentinel = thread->process->config.host_return_sentinel;
    config.max_budget = thread->process->config.segment_instruction_budget;
    config.target_resolver = process_target_resolve;
    config.target_resolver_opaque = thread->process;
    binding->runtime = gem_hybrid_runtime_create(thread->process->memory, image->metadata, &config);
    if (binding->runtime == NULL) {
        free(binding);
        return NULL;
    }
    binding->image = image;
    binding->next = thread->hybrids;
    thread->hybrids = binding;
    return binding;
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
           (context->isa == (uint32_t)GEM_ISA_ARM64EC || context->isa == (uint32_t)GEM_ISA_X64) &&
           context->teb == thread->config.teb && context->x[18] == thread->config.teb;
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

static bool copy_hybrid_stop_info(struct gem_wine_stop_info *destination,
                                  const struct gem_hybrid_stop_info *source,
                                  uint64_t instructions_retired) {
    memset(destination, 0, sizeof(*destination));
    destination->reason = (uint32_t)source->reason;
    destination->instructions_retired = instructions_retired;
    if (source->source == GEM_HYBRID_STOP_SOURCE_ARM64EC) {
        destination->access = (uint32_t)source->arm64ec.access;
        destination->memory_error = source->arm64ec.memory_error;
        destination->engine_status = source->arm64ec.engine_status;
        destination->fault_address = source->arm64ec.fault_address;
        return true;
    }
    if (source->source == GEM_HYBRID_STOP_SOURCE_X64) {
        destination->access = (uint32_t)source->x64.access;
        destination->memory_error = source->x64.memory_error;
        destination->engine_status = source->x64.engine_status;
        destination->fault_address = source->x64.fault_address;
        return true;
    }
    if (source->source == GEM_HYBRID_STOP_SOURCE_BROKER) {
        destination->engine_status = source->arm64ec.engine_status;
        destination->fault_address = source->arm64ec.fault_address;
        return true;
    }
    return false;
}

static void unlock_run_lock(void *opaque) {
    struct gem_wine_thread *thread = (struct gem_wine_thread *)opaque;
    (void)pthread_mutex_unlock(&thread->run_lock);
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
    atomic_init(&process->arm64x_routing_enabled, false);
    if (pthread_mutex_init(&process->threads_lock, NULL) != 0) {
        free(process);
        return GEM_WINE_ENGINE_ERROR;
    }
    if (pthread_mutex_init(&process->images_lock, NULL) != 0) {
        (void)pthread_mutex_destroy(&process->threads_lock);
        free(process);
        return GEM_WINE_ENGINE_ERROR;
    }
    process->memory = gem_memory_create();
    if (process->memory == NULL) {
        (void)pthread_mutex_destroy(&process->images_lock);
        (void)pthread_mutex_destroy(&process->threads_lock);
        free(process);
        return GEM_WINE_NO_MEMORY;
    }
    *out_process = process;
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_process_destroy(struct gem_wine_process *process) {
    struct gem_wine_arm64x_image *image;
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&process->threads_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    if (process->threads != NULL) {
        (void)pthread_mutex_unlock(&process->threads_lock);
        return GEM_WINE_CONFLICT;
    }
    (void)pthread_mutex_unlock(&process->threads_lock);
    image = process->images;
    while (image != NULL) {
        struct gem_wine_arm64x_image *next = image->next;
        destroy_arm64x_image(image);
        image = next;
    }
    gem_memory_destroy(process->memory);
    (void)pthread_mutex_destroy(&process->images_lock);
    (void)pthread_mutex_destroy(&process->threads_lock);
    free(process);
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_process_prepare_arm64ec(struct gem_wine_process *process) {
    struct gem_wine_thread *thread;

    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    atomic_store_explicit(&process->arm64x_routing_enabled, true, memory_order_release);
    if (pthread_mutex_lock(&process->threads_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    for (thread = process->threads; thread != NULL; thread = thread->next) {
        bool accepted;
        if (pthread_mutex_lock(&thread->runtime_lock) != 0) {
            (void)pthread_mutex_unlock(&process->threads_lock);
            return GEM_WINE_ENGINE_ERROR;
        }
        accepted =
            gem_arm64ec_runtime_set_boundary_broker(thread->runtime, native_image_boundary, thread);
        (void)pthread_mutex_unlock(&thread->runtime_lock);
        if (!accepted) {
            (void)pthread_mutex_unlock(&process->threads_lock);
            return GEM_WINE_ENGINE_ERROR;
        }
    }
    (void)pthread_mutex_unlock(&process->threads_lock);
    return GEM_WINE_OK;
}

enum gem_wine_status
gem_wine_process_register_arm64x_mapped(struct gem_wine_process *process,
                                        const struct gem_wine_arm64x_config *config) {
    struct gem_wine_arm64x_image *image;
    struct gem_wine_arm64x_image *current;
    enum gem_pe_status pe_status;

    if (process == NULL || config == NULL || config->version != GEM_WINE_ARM64X_CONFIG_VERSION ||
        config->struct_size != sizeof(*config) || config->loaded_base == 0U ||
        config->image_size == 0U || config->image_size > SIZE_MAX ||
        config->loaded_base > UINT64_MAX - config->image_size || config->checker_helper == 0U ||
        config->dispatch_call_helper == 0U || config->dispatch_ret_helper == 0U ||
        config->checker_helper == config->dispatch_call_helper ||
        config->checker_helper == config->dispatch_ret_helper ||
        config->dispatch_call_helper == config->dispatch_ret_helper ||
        (config->dispatch_jump_helper != 0U &&
         (config->dispatch_jump_helper == config->checker_helper ||
          config->dispatch_jump_helper == config->dispatch_call_helper ||
          config->dispatch_jump_helper == config->dispatch_ret_helper)) ||
        (config->flags &
         ~(GEM_WINE_ARM64X_FLAG_SVC_BOUNDARIES | GEM_WINE_ARM64X_FLAG_DEFER_ROUTING)) != 0U ||
        !zero_words(config->reserved, sizeof(config->reserved) / sizeof(config->reserved[0])))
        return GEM_WINE_INVALID_ARGUMENT;
    image = (struct gem_wine_arm64x_image *)calloc(1U, sizeof(*image));
    if (image == NULL)
        return GEM_WINE_NO_MEMORY;
    image->config = *config;
    image->config.flags &= ~GEM_WINE_ARM64X_FLAG_DEFER_ROUTING;
    image->loaded_end = config->loaded_base + config->image_size;
    pe_status = gem_pe_arm64x_parse_mapped((const uint8_t *)(uintptr_t)config->loaded_base,
                                           (size_t)config->image_size, config->loaded_base, NULL,
                                           &image->metadata);
    if (pe_status != GEM_PE_OK ||
        gem_pe_arm64x_get_summary(image->metadata, &image->summary) != GEM_PE_OK ||
        image->summary.size_of_image != config->image_size ||
        gem_arm64ec_target_map_create(image->metadata, config->loaded_base, &image->map) !=
            GEM_ARM64EC_TARGET_OK) {
        destroy_arm64x_image(image);
        return pe_status == GEM_PE_ERROR_LIMIT_EXCEEDED ? GEM_WINE_NO_MEMORY
                                                        : GEM_WINE_INVALID_ARGUMENT;
    }
    if (pthread_mutex_lock(&process->images_lock) != 0) {
        destroy_arm64x_image(image);
        return GEM_WINE_ENGINE_ERROR;
    }
    for (current = process->images; current != NULL; current = current->next) {
        if (config->loaded_base < current->loaded_end &&
            current->config.loaded_base < image->loaded_end) {
            const bool identical =
                current->config.loaded_base == config->loaded_base &&
                current->loaded_end == image->loaded_end &&
                memcmp(&current->config, &image->config, sizeof(image->config)) == 0;
            (void)pthread_mutex_unlock(&process->images_lock);
            destroy_arm64x_image(image);
            if (!identical)
                return GEM_WINE_CONFLICT;
            if ((config->flags & GEM_WINE_ARM64X_FLAG_DEFER_ROUTING) != 0U)
                return GEM_WINE_OK;
            return gem_wine_process_prepare_arm64ec(process);
        }
    }
    image->next = process->images;
    process->images = image;
    (void)pthread_mutex_unlock(&process->images_lock);
    if ((config->flags & GEM_WINE_ARM64X_FLAG_DEFER_ROUTING) != 0U)
        return GEM_WINE_OK;
    return gem_wine_process_prepare_arm64ec(process);
}

enum gem_wine_status gem_wine_process_reserve(struct gem_wine_process *process, uint64_t address,
                                              uint64_t size) {
    uint64_t reserved = address;
    enum gem_memory_error error;
    if (process == NULL || address == 0U)
        return GEM_WINE_INVALID_ARGUMENT;
    error = gem_memory_reserve(process->memory, &reserved, size);
    if (error == GEM_MEMORY_OK && reserved != address) {
        (void)gem_memory_release(process->memory, reserved, size);
        return GEM_WINE_MEMORY_ERROR;
    }
    return memory_status(error);
}

enum gem_wine_status gem_wine_process_commit_identity(struct gem_wine_process *process,
                                                      uint64_t address, void *host, uint64_t size,
                                                      uint32_t protection) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(
        gem_memory_commit_identity(process->memory, address, host, size, protection));
}

enum gem_wine_status gem_wine_process_decommit(struct gem_wine_process *process, uint64_t address,
                                               uint64_t size) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(gem_memory_decommit(process->memory, address, size));
}

enum gem_wine_status gem_wine_process_release(struct gem_wine_process *process, uint64_t address,
                                              uint64_t size) {
    if (process == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    return memory_status(gem_memory_release(process->memory, address, size));
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
        struct gem_wine_hybrid_binding *binding;
        if (pthread_mutex_lock(&thread->runtime_lock) != 0) {
            (void)pthread_mutex_unlock(&process->threads_lock);
            return GEM_WINE_ENGINE_ERROR;
        }
        gem_arm64ec_runtime_invalidate_code(thread->runtime, address, size);
        for (binding = thread->hybrids; binding != NULL; binding = binding->next)
            gem_hybrid_runtime_invalidate_code(binding->runtime, address, size);
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
    atomic_init(&thread->active_hybrid, NULL);
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
        gem_arm64ec_runtime_destroy(thread->runtime);
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
    if (atomic_load_explicit(&process->arm64x_routing_enabled, memory_order_acquire) &&
        !gem_arm64ec_runtime_set_boundary_broker(thread->runtime, native_image_boundary, thread)) {
        (void)pthread_mutex_unlock(&process->threads_lock);
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
    atomic_store_explicit(&thread->active_hybrid, NULL, memory_order_release);
    destroy_hybrid_bindings(thread->hybrids);
    gem_arm64ec_runtime_destroy(thread->runtime);
    (void)pthread_mutex_unlock(&thread->run_lock);
    (void)pthread_mutex_destroy(&thread->runtime_lock);
    (void)pthread_mutex_destroy(&thread->run_lock);
    free(thread);
    return GEM_WINE_OK;
}

enum gem_wine_status gem_wine_thread_set_native_upper_simd(struct gem_wine_thread *thread,
                                                           const struct gem_u128 vectors[16]) {
    bool accepted;
    if (thread == NULL || vectors == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&thread->runtime_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    accepted = gem_arm64ec_runtime_set_native_upper_simd(thread->runtime, vectors);
    (void)pthread_mutex_unlock(&thread->runtime_lock);
    return accepted ? GEM_WINE_OK : GEM_WINE_CONFLICT;
}

enum gem_wine_status gem_wine_thread_get_native_upper_simd(struct gem_wine_thread *thread,
                                                           struct gem_u128 vectors[16]) {
    bool accepted;
    if (thread == NULL || vectors == NULL)
        return GEM_WINE_INVALID_ARGUMENT;
    if (pthread_mutex_lock(&thread->runtime_lock) != 0)
        return GEM_WINE_ENGINE_ERROR;
    accepted = gem_arm64ec_runtime_get_native_upper_simd(thread->runtime, vectors);
    (void)pthread_mutex_unlock(&thread->runtime_lock);
    return accepted ? GEM_WINE_OK : GEM_WINE_CONFLICT;
}

void gem_wine_thread_request_async_stop(struct gem_wine_thread *thread) {
    if (thread != NULL) {
        struct gem_hybrid_runtime *hybrid =
            atomic_load_explicit(&thread->active_hybrid, memory_order_acquire);
        if (hybrid != NULL)
            gem_hybrid_runtime_request_async_stop(hybrid);
        gem_arm64ec_runtime_request_async_stop(thread->runtime);
    }
}

static enum gem_wine_boundary_event classify_event(const struct gem_wine_process *process,
                                                   enum gem_stop_reason reason,
                                                   const struct gem_thread_context *context,
                                                   const struct gem_wine_stop_info *stop) {
    switch (reason) {
    case GEM_STOP_SYSCALL:
        if (stop->engine_status == GEM_WINE_NATIVE_UNIX_CALL_SVC)
            return GEM_WINE_EVENT_UNIX_CALL;
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
    pthread_cleanup_push(unlock_run_lock, thread);
    context = *input;
    initialize_result(&run_result);

    for (;;) {
        struct gem_wine_stop_info stop;
        struct gem_wine_arm64x_image *image;
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
        image = atomic_load_explicit(&process->arm64x_routing_enabled, memory_order_acquire)
                    ? find_image_for_pc(process, context.pc)
                    : NULL;
        if (image != NULL) {
            struct gem_wine_hybrid_binding *binding = find_or_create_hybrid(thread, image);
            struct gem_hybrid_roundtrip_stats stats;
            struct gem_hybrid_stop_info hybrid_stop;
            uint64_t retired;
            if (binding == NULL) {
                (void)pthread_mutex_unlock(&thread->runtime_lock);
                status = GEM_WINE_ENGINE_ERROR;
                break;
            }
            atomic_store_explicit(&thread->active_hybrid, binding->runtime, memory_order_release);
            reason = gem_hybrid_runtime_run(binding->runtime, &context, budget, &stats);
            atomic_store_explicit(&thread->active_hybrid, NULL, memory_order_release);
            retired = stats.arm64ec_instructions_retired + stats.x64_instructions_retired;
            if (!gem_hybrid_runtime_last_stop_info(binding->runtime, &hybrid_stop) ||
                !copy_hybrid_stop_info(&stop, &hybrid_stop, retired)) {
                (void)pthread_mutex_unlock(&thread->runtime_lock);
                status = GEM_WINE_ENGINE_ERROR;
                break;
            }
        } else {
            struct gem_arm64ec_stop_info arm_stop;
            if (context.isa != GEM_ISA_ARM64EC) {
                (void)pthread_mutex_unlock(&thread->runtime_lock);
                status = GEM_WINE_ENGINE_ERROR;
                break;
            }
            reason = gem_arm64ec_runtime_run(thread->runtime, &context, budget);
            if (!gem_arm64ec_runtime_last_stop_info(thread->runtime, &arm_stop)) {
                (void)pthread_mutex_unlock(&thread->runtime_lock);
                status = GEM_WINE_ENGINE_ERROR;
                break;
            }
            copy_stop_info(&stop, &arm_stop);
        }
        (void)pthread_mutex_unlock(&thread->runtime_lock);
        run_result.stop = stop;
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
        if (reason == GEM_STOP_ARCH_TRANSITION &&
            (image != NULL ||
             (atomic_load_explicit(&process->arm64x_routing_enabled, memory_order_acquire) &&
              find_image_for_pc(process, context.pc) != NULL))) {
            context.stop_reason = GEM_STOP_NONE;
            continue;
        }
        if (reason == GEM_STOP_HOST_RETURN) {
            run_result.outcome = GEM_WINE_RUN_COMPLETE;
            status = GEM_WINE_OK;
            break;
        }
        if (reason == GEM_STOP_BUDGET_EXPIRED) {
            /*
             * The engine budget is a scheduling slice, not the public Wine
             * run budget.  Keep executing inside the bridge until the total
             * budget is exhausted so routine JIT slices do not bounce through
             * ntdll and rebuild the Wine/GEM thread context each time.
             */
            context.stop_reason = GEM_STOP_NONE;
            continue;
        }
        run_result.last_event = (uint32_t)classify_event(process, reason, &context, &stop);
        if (run_result.last_event == GEM_WINE_EVENT_INVARIANT_VIOLATION) {
            run_result.outcome = GEM_WINE_RUN_FAILED;
            status = GEM_WINE_ENGINE_ERROR;
            break;
        }
        if (thread->config.boundary == NULL || context.isa != GEM_ISA_ARM64EC) {
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
            struct gem_u128 upper_simd_before[16];
            enum gem_wine_status callback_status;

            memset(&request, 0, sizeof(request));
            request.version = GEM_WINE_BOUNDARY_ABI_VERSION;
            request.struct_size = (uint32_t)sizeof(request);
            request.event = run_result.last_event;
            request.context = context;
            request.stop = stop;
            memset(&response, 0, sizeof(response));
            response.version = GEM_WINE_BOUNDARY_ABI_VERSION;
            response.struct_size = (uint32_t)sizeof(response);
            response.context = context;
            if (!gem_arm64ec_runtime_get_native_upper_simd(thread->runtime, upper_simd_before)) {
                run_result.outcome = GEM_WINE_RUN_FAILED;
                status = GEM_WINE_ENGINE_ERROR;
                break;
            }
            ++run_result.boundary_callbacks;
            callback_status = thread->config.boundary(thread->config.opaque, &request, &response);
            if (callback_status != GEM_WINE_OK ||
                response.version != GEM_WINE_BOUNDARY_ABI_VERSION ||
                response.struct_size != sizeof(response)) {
                (void)gem_arm64ec_runtime_set_native_upper_simd(thread->runtime, upper_simd_before);
                run_result.outcome = GEM_WINE_RUN_FAILED;
                status = GEM_WINE_CALLBACK_ERROR;
                break;
            }
            /* transition_cookie and original_x64_sp are GEM coordinator
             * sidecars, not guest-visible Wine CONTEXT fields. Wine rebuilds
             * response.context from its syscall frame, which intentionally
             * has no storage for either value. Preserve them across the
             * boundary so a syscall inside an ARM64EC callback can resume the
             * exact depth/call frame that produced it. */
            response.context.transition_cookie = request.context.transition_cookie;
            response.context.original_x64_sp = request.context.original_x64_sp;
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
                (void)gem_arm64ec_runtime_set_native_upper_simd(thread->runtime, upper_simd_before);
                run_result.outcome = GEM_WINE_RUN_FAILED;
                status = GEM_WINE_CALLBACK_ERROR;
                break;
            }
            context = response.context;
        }
    }

    *out_context = context;
    *result = run_result;
    pthread_cleanup_pop(1);
    return status;
}
