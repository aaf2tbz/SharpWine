// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/i386_engine.h"
#include "metalsharp/gem/i386_memory.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>

struct start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned waiting;
    bool open;
};

struct worker {
    struct gem_i386_runtime *runtime;
    struct gem_i386_context context;
    struct start_gate *gate;
};

static void gate_wait(struct start_gate *gate) {
    assert(pthread_mutex_lock(&gate->mutex) == 0);
    if (++gate->waiting == 2U) {
        gate->open = true;
        assert(pthread_cond_broadcast(&gate->condition) == 0);
    }
    while (!gate->open)
        assert(pthread_cond_wait(&gate->condition, &gate->mutex) == 0);
    assert(pthread_mutex_unlock(&gate->mutex) == 0);
}

static void *run_worker(void *opaque) {
    struct worker *worker = (struct worker *)opaque;
    gate_wait(worker->gate);
    assert(gem_i386_runtime_run(worker->runtime, &worker->context, UINT32_C(65536)) ==
           GEM_STOP_BUDGET_EXPIRED);
    return NULL;
}

int main(void) {
    static const uint8_t loop[] = {
        0x0fU, 0x1fU, 0x84U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x0fU, 0x1fU, 0x84U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xe9U, 0xebU, 0xffU, 0xffU, 0xffU,
    };
    struct gem_memory *memory = gem_memory_create();
    struct gem_i386_runtime_config config;
    struct start_gate gate;
    struct worker workers[2];
    pthread_t threads[2];
    uint32_t code = UINT32_C(0x00400000);
    uint32_t stacks[2] = {UINT32_C(0x00100000), UINT32_C(0x00200000)};
    size_t i;
    assert(memory != NULL);
    assert(gem_i386_memory_reserve(memory, &code, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(memory, code, GEM_GUEST_PAGE_SIZE, GEM_PAGE_EXECUTE_READWRITE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_write(memory, code, loop, sizeof(loop)) == GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = GEM_I386_ENGINE_INTERPRETER;
    config.max_budget = UINT32_C(65536);
    memset(&gate, 0, sizeof(gate));
    assert(pthread_mutex_init(&gate.mutex, NULL) == 0);
    assert(pthread_cond_init(&gate.condition, NULL) == 0);
    for (i = 0U; i < 2U; ++i) {
        assert(gem_i386_memory_reserve(memory, &stacks[i], GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK);
        assert(gem_i386_memory_commit(memory, stacks[i], GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
               GEM_MEMORY_OK);
        workers[i].runtime = gem_i386_runtime_create(memory, &config);
        assert(workers[i].runtime != NULL);
        gem_i386_context_initialize(&workers[i].context, UINT32_C(0x7ffde000));
        workers[i].context.eip = code;
        workers[i].context.gpr[GEM_I386_ESP] = stacks[i] + GEM_GUEST_PAGE_SIZE - 16U;
        workers[i].gate = &gate;
        assert(pthread_create(&threads[i], NULL, run_worker, &workers[i]) == 0);
    }
    for (i = 0U; i < 2U; ++i) {
        struct gem_i386_performance_info performance;
        assert(pthread_join(threads[i], NULL) == 0);
        memset(&performance, 0, sizeof(performance));
        performance.abi_version = GEM_I386_PERFORMANCE_INFO_ABI_VERSION;
        performance.size = sizeof(performance);
        assert(gem_i386_runtime_performance_info(workers[i].runtime, &performance));
        assert(performance.retired_instructions == UINT32_C(65536));
        assert(performance.quanta < performance.retired_instructions);
        gem_i386_runtime_destroy(workers[i].runtime);
    }
    assert(pthread_cond_destroy(&gate.condition) == 0);
    assert(pthread_mutex_destroy(&gate.mutex) == 0);
    gem_memory_destroy(memory);
    return 0;
}
