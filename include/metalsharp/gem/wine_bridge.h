// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_WINE_BRIDGE_H
#define METALSHARP_GEM_WINE_BRIDGE_H

#include "metalsharp/gem/context.h"

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(GEM_WINE_BUILD)
#define GEM_WINE_API __declspec(dllexport)
#elif defined(_WIN32)
#define GEM_WINE_API __declspec(dllimport)
#elif defined(__GNUC__)
#define GEM_WINE_API __attribute__((visibility("default")))
#else
#define GEM_WINE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define GEM_WINE_BRIDGE_ABI_VERSION UINT32_C(1)
#define GEM_WINE_PROCESS_CONFIG_VERSION UINT32_C(1)
#define GEM_WINE_THREAD_CONFIG_VERSION UINT32_C(1)
#define GEM_WINE_BOUNDARY_ABI_VERSION UINT32_C(1)
#define GEM_WINE_RUN_RESULT_VERSION UINT32_C(1)
#define GEM_WINE_NATIVE_UNIX_CALL_SVC UINT32_C(0x5749)
#define GEM_WINE_GUEST_PAGE_SIZE UINT64_C(4096)
#define GEM_WINE_KUSER_SHARED_DATA_ADDRESS UINT64_C(0x7ffe0000)
#define GEM_WINE_KUSER_CANONICAL_ADDRESS UINT64_C(0x1007ffe0000)

struct gem_wine_process;
struct gem_wine_thread;

enum gem_wine_status {
    GEM_WINE_OK = 0,
    GEM_WINE_INVALID_ARGUMENT = 1,
    GEM_WINE_NO_MEMORY = 2,
    GEM_WINE_CONFLICT = 3,
    GEM_WINE_MEMORY_ERROR = 4,
    GEM_WINE_ENGINE_ERROR = 5,
    GEM_WINE_CALLBACK_ERROR = 6,
    GEM_WINE_BUDGET_EXPIRED = 7,
    GEM_WINE_STOPPED = 8,
    GEM_WINE_TERMINATED = 9,
};

enum gem_wine_boundary_event {
    GEM_WINE_EVENT_SYSCALL = 1,
    GEM_WINE_EVENT_UNIX_CALL = 2,
    GEM_WINE_EVENT_MEMORY_FAULT = 3,
    GEM_WINE_EVENT_WINDOWS_EXCEPTION = 4,
    GEM_WINE_EVENT_ARCH_TRANSITION = 5,
    GEM_WINE_EVENT_ASYNC_REQUEST = 6,
    GEM_WINE_EVENT_UNSUPPORTED_INSTRUCTION = 7,
    GEM_WINE_EVENT_INVARIANT_VIOLATION = 8,
};

enum gem_wine_boundary_action {
    GEM_WINE_BOUNDARY_RESUME = 1,
    GEM_WINE_BOUNDARY_TERMINATE = 2,
    GEM_WINE_BOUNDARY_FAIL = 3,
};

enum gem_wine_memory_access {
    GEM_WINE_ACCESS_NONE = 0,
    GEM_WINE_ACCESS_FETCH = 1,
    GEM_WINE_ACCESS_READ = 2,
    GEM_WINE_ACCESS_WRITE = 3,
};

enum gem_wine_page_protection {
    GEM_WINE_PAGE_NOACCESS = 0x01,
    GEM_WINE_PAGE_READONLY = 0x02,
    GEM_WINE_PAGE_READWRITE = 0x04,
    GEM_WINE_PAGE_WRITECOPY = 0x08,
    GEM_WINE_PAGE_EXECUTE = 0x10,
    GEM_WINE_PAGE_EXECUTE_READ = 0x20,
    GEM_WINE_PAGE_EXECUTE_READWRITE = 0x40,
    GEM_WINE_PAGE_EXECUTE_WRITECOPY = 0x80,
    GEM_WINE_PAGE_GUARD = 0x100,
};

enum gem_wine_run_outcome {
    GEM_WINE_RUN_COMPLETE = 1,
    GEM_WINE_RUN_TERMINATED = 2,
    GEM_WINE_RUN_BUDGET_EXPIRED = 3,
    GEM_WINE_RUN_UNHANDLED_STOP = 4,
    GEM_WINE_RUN_FAILED = 5,
};

struct gem_wine_process_config {
    uint32_t version;
    uint32_t struct_size;
    uint64_t segment_instruction_budget;
    uint64_t total_instruction_budget;
    uint64_t max_boundary_callbacks;
    uint64_t host_return_sentinel;
    /* Exact registered Mach-O dispatcher address. A fetch fault at any other
     * host address remains a guest memory fault; instruction bytes are never
     * used to infer a Unix-call boundary. */
    uint64_t unix_call_dispatcher;
    uint64_t reserved[4];
};

/* Bridge-owned copy of engine stop information. Fixed-width fields keep the
 * public dylib ABI independent from the internal engine's enum layout. */
struct gem_wine_stop_info {
    uint32_t reason;
    uint32_t access;
    uint32_t memory_error;
    uint32_t engine_status;
    uint64_t instructions_retired;
    uint64_t fault_address;
    uint64_t reserved;
};

struct gem_wine_boundary_request {
    uint32_t version;
    uint32_t struct_size;
    uint32_t event;
    uint32_t reserved;
    struct gem_thread_context context;
    struct gem_wine_stop_info stop;
};

struct gem_wine_boundary_response {
    uint32_t version;
    uint32_t struct_size;
    enum gem_wine_boundary_action action;
    uint32_t exit_status;
    struct gem_thread_context context;
};

typedef enum gem_wine_status (*gem_wine_boundary_callback)(
    void *opaque, const struct gem_wine_boundary_request *request,
    struct gem_wine_boundary_response *response);

struct gem_wine_thread_config {
    uint32_t version;
    uint32_t struct_size;
    uint64_t teb;
    gem_wine_boundary_callback boundary;
    void *opaque;
    uint64_t reserved[4];
};

struct gem_wine_run_result {
    uint32_t version;
    uint32_t struct_size;
    uint32_t outcome;
    uint32_t last_event;
    uint32_t stop_reason;
    uint32_t exit_status;
    uint64_t instructions_retired;
    uint64_t boundary_callbacks;
    uint64_t reserved;
    struct gem_wine_stop_info stop;
};

#if defined(__cplusplus)
#define GEM_WINE_STATIC_ASSERT(condition, message) static_assert((condition), message)
#else
#define GEM_WINE_STATIC_ASSERT(condition, message) _Static_assert((condition), message)
#endif

GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_status) == 4U, "gem_wine_status ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_boundary_event) == 4U,
                       "gem_wine_boundary_event ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_boundary_action) == 4U,
                       "gem_wine_boundary_action ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_memory_access) == 4U,
                       "gem_wine_memory_access ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_page_protection) == 4U,
                       "gem_wine_page_protection ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(enum gem_wine_run_outcome) == 4U, "gem_wine_run_outcome ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_process_config) == 80U,
                       "gem_wine_process_config ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_stop_info) == 40U, "gem_wine_stop_info ABI changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_stop_info, instructions_retired) == 16U,
                       "gem_wine_stop_info instructions offset changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_stop_info, fault_address) == 24U,
                       "gem_wine_stop_info fault offset changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_boundary_request) == 776U,
                       "gem_wine_boundary_request ABI changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_boundary_request, context) == 16U,
                       "gem_wine_boundary_request context offset changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_boundary_request, stop) == 736U,
                       "gem_wine_boundary_request stop offset changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_boundary_response) == 736U,
                       "gem_wine_boundary_response ABI changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_boundary_response, context) == 16U,
                       "gem_wine_boundary_response context offset changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_thread_config) == 64U,
                       "gem_wine_thread_config ABI changed");
GEM_WINE_STATIC_ASSERT(sizeof(struct gem_wine_run_result) == 88U,
                       "gem_wine_run_result ABI changed");
GEM_WINE_STATIC_ASSERT(offsetof(struct gem_wine_run_result, stop) == 48U,
                       "gem_wine_run_result stop offset changed");

#undef GEM_WINE_STATIC_ASSERT

GEM_WINE_API uint32_t gem_wine_bridge_abi_version(void);
GEM_WINE_API const char *gem_wine_status_name(enum gem_wine_status status);
GEM_WINE_API enum gem_wine_status
gem_wine_process_create(const struct gem_wine_process_config *config,
                        struct gem_wine_process **out_process);
GEM_WINE_API enum gem_wine_status gem_wine_process_destroy(struct gem_wine_process *process);
GEM_WINE_API enum gem_wine_status gem_wine_process_reserve(struct gem_wine_process *process,
                                                           uint64_t address, uint64_t size);
GEM_WINE_API enum gem_wine_status gem_wine_process_commit_identity(struct gem_wine_process *process,
                                                                   uint64_t address, void *host,
                                                                   uint64_t size,
                                                                   uint32_t protection);
GEM_WINE_API enum gem_wine_status gem_wine_process_decommit(struct gem_wine_process *process,
                                                            uint64_t address, uint64_t size);
GEM_WINE_API enum gem_wine_status gem_wine_process_release(struct gem_wine_process *process,
                                                           uint64_t address, uint64_t size);
GEM_WINE_API enum gem_wine_status gem_wine_process_map_identity(struct gem_wine_process *process,
                                                                uint64_t address, void *host,
                                                                uint64_t size, uint32_t protection);
GEM_WINE_API enum gem_wine_status gem_wine_process_unmap(struct gem_wine_process *process,
                                                         uint64_t address, uint64_t size);
GEM_WINE_API enum gem_wine_status gem_wine_process_protect(struct gem_wine_process *process,
                                                           uint64_t address, uint64_t size,
                                                           uint32_t protection,
                                                           uint32_t *old_protection);
GEM_WINE_API enum gem_wine_status gem_wine_process_bind_kuser(struct gem_wine_process *process,
                                                              void *host_page);
GEM_WINE_API enum gem_wine_status gem_wine_process_invalidate_code(struct gem_wine_process *process,
                                                                   uint64_t address, uint64_t size);
GEM_WINE_API enum gem_wine_status
gem_wine_thread_create(struct gem_wine_process *process,
                       const struct gem_wine_thread_config *config,
                       struct gem_wine_thread **out_thread);
GEM_WINE_API enum gem_wine_status gem_wine_thread_destroy(struct gem_wine_thread *thread);
GEM_WINE_API enum gem_wine_status
gem_wine_thread_set_native_upper_simd(struct gem_wine_thread *thread,
                                      const struct gem_u128 vectors[16]);
GEM_WINE_API enum gem_wine_status
gem_wine_thread_get_native_upper_simd(struct gem_wine_thread *thread, struct gem_u128 vectors[16]);
/* The input is copied before execution. Callback responses are proposals that
 * are validated in full before replacing GEM's canonical context. `out_context`
 * and `result` are published only after the run reaches a bounded stop. */
GEM_WINE_API enum gem_wine_status gem_wine_thread_run(struct gem_wine_thread *thread,
                                                      const struct gem_thread_context *input,
                                                      struct gem_thread_context *out_context,
                                                      struct gem_wine_run_result *result);

#ifdef __cplusplus
}
#endif

#undef GEM_WINE_API
#endif
