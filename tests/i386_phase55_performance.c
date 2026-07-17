// SPDX-License-Identifier: Apache-2.0
#include "i386_engine_internal.h"
#include "memory_internal.h"
#include "metalsharp/gem/i386_memory.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef GEM_PHASE55_REQUIRED_SPEEDUP
#define GEM_PHASE55_REQUIRED_SPEEDUP 1.5
#endif
#define GEM_PHASE55_PERFORMANCE_SAMPLES 5U

_Static_assert(sizeof(struct gem_i386_performance_info) == 88U,
               "performance query ABI size changed");

struct fixture {
    struct gem_memory *memory;
    struct gem_i386_runtime *step_runtime;
    struct gem_i386_runtime *run_runtime;
    uint32_t code;
    uint32_t stack;
};

static uint64_t monotonic_ns(void) {
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static struct fixture fixture_create(void) {
    uint8_t loop[32U * 8U + 5U];
    size_t offset;
    int32_t displacement = -(int32_t)sizeof(loop);
    struct fixture fixture;
    struct gem_i386_runtime_config config;
    memset(&fixture, 0, sizeof(fixture));
    fixture.code = UINT32_C(0x00400000);
    fixture.stack = UINT32_C(0x00100000);
    fixture.memory = gem_memory_create();
    assert(fixture.memory != NULL);
    assert(gem_i386_memory_reserve(fixture.memory, &fixture.code, GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(fixture.memory, fixture.code, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK);
    for (offset = 0U; offset < 32U * 8U; offset += 8U) {
        static const uint8_t nop[8] = {0x0fU, 0x1fU, 0x84U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
        memcpy(loop + offset, nop, sizeof(nop));
    }
    loop[offset++] = 0xe9U;
    memcpy(loop + offset, &displacement, sizeof(displacement));
    assert(gem_i386_memory_write(fixture.memory, fixture.code, loop, sizeof(loop)) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_reserve(fixture.memory, &fixture.stack, GEM_GUEST_PAGE_SIZE) ==
           GEM_MEMORY_OK);
    assert(gem_i386_memory_commit(fixture.memory, fixture.stack, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    memset(&config, 0, sizeof(config));
    config.engine_mode = GEM_I386_ENGINE_INTERPRETER;
    config.max_budget = UINT64_C(1000000);
    fixture.step_runtime = gem_i386_runtime_create(fixture.memory, &config);
    fixture.run_runtime = gem_i386_runtime_create(fixture.memory, &config);
    assert(fixture.step_runtime != NULL && fixture.run_runtime != NULL);
    return fixture;
}

static void fixture_destroy(struct fixture *fixture) {
    gem_i386_runtime_destroy(fixture->step_runtime);
    gem_i386_runtime_destroy(fixture->run_runtime);
    gem_memory_destroy(fixture->memory);
}

static struct gem_i386_context initial_context(const struct fixture *fixture) {
    struct gem_i386_context context;
    gem_i386_context_initialize(&context, UINT32_C(0x7ffde000));
    context.eip = fixture->code;
    context.gpr[GEM_I386_ESP] = fixture->stack + (uint32_t)GEM_GUEST_PAGE_SIZE - 16U;
    return context;
}

static void execute_steps(struct fixture *fixture, struct gem_i386_context *context,
                          uint32_t budget) {
    uint32_t i;
    fixture->step_runtime->transaction = gem_memory_transaction_begin(fixture->memory);
    assert(fixture->step_runtime->transaction != NULL);
    gem_i386_blink_sync(fixture->step_runtime);
    for (i = 0U; i < budget; ++i) {
        struct gem_i386_context output;
        uint32_t retired = 0U;
        assert(gem_i386_blink_step(fixture->step_runtime, context, &output, &retired) ==
               GEM_STOP_NONE);
        assert(retired == 1U);
        *context = output;
    }
    gem_memory_transaction_end(fixture->step_runtime->transaction);
    fixture->step_runtime->transaction = NULL;
    context->stop_reason = GEM_STOP_BUDGET_EXPIRED;
}

static void verify_boundaries(struct fixture *fixture) {
    uint32_t budget;
    for (budget = 1U; budget <= 256U; ++budget) {
        struct gem_i386_context stepped = initial_context(fixture);
        struct gem_i386_context batched = stepped;
        execute_steps(fixture, &stepped, budget);
        assert(gem_i386_runtime_run(fixture->run_runtime, &batched, budget) ==
               GEM_STOP_BUDGET_EXPIRED);
        if (memcmp(&stepped, &batched, sizeof(stepped)) != 0) {
            fprintf(stderr,
                    "boundary %u mismatch: step eip=%08x eax=%08x flags=%08x; "
                    "run eip=%08x eax=%08x flags=%08x\n",
                    budget, stepped.eip, stepped.gpr[GEM_I386_EAX], stepped.eflags, batched.eip,
                    batched.gpr[GEM_I386_EAX], batched.eflags);
            assert(0);
        }
    }
}

static void sort_samples(uint64_t samples[GEM_PHASE55_PERFORMANCE_SAMPLES]) {
    size_t i;
    for (i = 1U; i < GEM_PHASE55_PERFORMANCE_SAMPLES; ++i) {
        const uint64_t value = samples[i];
        size_t position = i;
        while (position != 0U && samples[position - 1U] > value) {
            samples[position] = samples[position - 1U];
            --position;
        }
        samples[position] = value;
    }
}

int main(void) {
    const uint32_t budget = UINT32_C(65536);
    struct fixture fixture = fixture_create();
    struct gem_i386_context stepped;
    struct gem_i386_context batched;
    struct gem_i386_performance_info performance;
    uint64_t step_samples[GEM_PHASE55_PERFORMANCE_SAMPLES];
    uint64_t run_samples[GEM_PHASE55_PERFORMANCE_SAMPLES];
    uint64_t step_ns, run_ns;
    size_t sample;
    double speedup;
    verify_boundaries(&fixture);
    for (sample = 0U; sample < GEM_PHASE55_PERFORMANCE_SAMPLES; ++sample) {
        uint64_t begin;
        stepped = initial_context(&fixture);
        batched = stepped;
        if ((sample & 1U) == 0U) {
            begin = monotonic_ns();
            execute_steps(&fixture, &stepped, budget);
            step_samples[sample] = monotonic_ns() - begin;
            begin = monotonic_ns();
            assert(gem_i386_runtime_run(fixture.run_runtime, &batched, budget) ==
                   GEM_STOP_BUDGET_EXPIRED);
            run_samples[sample] = monotonic_ns() - begin;
        } else {
            begin = monotonic_ns();
            assert(gem_i386_runtime_run(fixture.run_runtime, &batched, budget) ==
                   GEM_STOP_BUDGET_EXPIRED);
            run_samples[sample] = monotonic_ns() - begin;
            begin = monotonic_ns();
            execute_steps(&fixture, &stepped, budget);
            step_samples[sample] = monotonic_ns() - begin;
        }
        assert(memcmp(&stepped, &batched, sizeof(stepped)) == 0);
    }
    sort_samples(step_samples);
    sort_samples(run_samples);
    step_ns = step_samples[GEM_PHASE55_PERFORMANCE_SAMPLES / 2U];
    run_ns = run_samples[GEM_PHASE55_PERFORMANCE_SAMPLES / 2U];
    memset(&performance, 0, sizeof(performance));
    assert(!gem_i386_runtime_performance_info(fixture.run_runtime, &performance));
    performance.abi_version = GEM_I386_PERFORMANCE_INFO_ABI_VERSION;
    performance.size = sizeof(performance);
    assert(gem_i386_runtime_performance_info(fixture.run_runtime, &performance));
    assert(performance.retired_instructions >= budget);
    assert(performance.quanta < performance.retired_instructions);
    assert(performance.state_imports == performance.quanta);
    speedup = (double)step_ns / (double)run_ns;
    printf("phase55 median_step_ns=%llu median_run_ns=%llu speedup=%.3fx required=%.3fx "
           "quanta=%llu\n",
           (unsigned long long)step_ns, (unsigned long long)run_ns, speedup,
           (double)GEM_PHASE55_REQUIRED_SPEEDUP, (unsigned long long)performance.quanta);
    assert(speedup >= GEM_PHASE55_REQUIRED_SPEEDUP);
    fixture_destroy(&fixture);
    return 0;
}
