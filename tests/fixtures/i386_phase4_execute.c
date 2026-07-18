// SPDX-License-Identifier: Apache-2.0
#include "i386_phase4_execute.h"

#include "metalsharp/gem/i386_memory.h"

#include <stddef.h>
#include <string.h>

#define CODE UINT32_C(0x00400000)
#define DATA UINT32_C(0x00500000)
#define STACK UINT32_C(0x00600000)

uint64_t i386_phase4_hash_bytes(const uint8_t *data, uint32_t size) {
    uint64_t hash = UINT64_C(1469598103934665603);
    uint32_t i;
    for (i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void hash_value(uint64_t *hash, const void *value, size_t size) {
    const uint8_t *bytes = value;
    size_t i;
    for (i = 0; i < size; ++i) {
        *hash ^= bytes[i];
        *hash *= UINT64_C(1099511628211);
    }
}

uint64_t i386_phase4_semantic_hash(const struct i386_phase4_record *record) {
    uint64_t hash = UINT64_C(1469598103934665603);
    uint32_t flags;
    uint32_t i;
    if (!record)
        return 0U;
    for (i = 0; i < 8U; ++i) {
        if ((record->defined.gpr_mask & (1U << i)) != 0U)
            hash_value(&hash, &record->final.gpr[i], sizeof(record->final.gpr[i]));
    }
    hash_value(&hash, &record->final.eip, sizeof(record->final.eip));
    flags = record->final.eflags & record->defined.eflags_mask;
    hash_value(&hash, &flags, sizeof(flags));
    hash_value(&hash, record->final.segment, sizeof(record->final.segment));
    hash_value(&hash, record->final.segment_base, sizeof(record->final.segment_base));
    hash_value(&hash, record->final.segment_limit, sizeof(record->final.segment_limit));
    hash_value(&hash, record->final.segment_attributes, sizeof(record->final.segment_attributes));
    hash_value(&hash, record->final.xmm, sizeof(record->final.xmm));
    hash_value(&hash, record->final.x87, sizeof(record->final.x87));
    hash_value(&hash, &record->final.mxcsr, sizeof(record->final.mxcsr));
    hash_value(&hash, &record->final.fcw, sizeof(record->final.fcw));
    hash_value(&hash, &record->final.fsw, sizeof(record->final.fsw));
    hash_value(&hash, &record->final.ftw, sizeof(record->final.ftw));
    hash_value(&hash, &record->final.fop, sizeof(record->final.fop));
    hash_value(&hash, &record->final.x87_environment, sizeof(record->final.x87_environment));
    hash_value(&hash, &record->memory_hash_after, sizeof(record->memory_hash_after));
    hash_value(&hash, &record->stop_reason, sizeof(record->stop_reason));
    hash_value(&hash, &record->exception_status, sizeof(record->exception_status));
    hash_value(&hash, &record->fault_address, sizeof(record->fault_address));
    hash_value(&hash, &record->access, sizeof(record->access));
    hash_value(&hash, &record->memory_error, sizeof(record->memory_error));
    hash_value(&hash, &record->retired_count, sizeof(record->retired_count));
    return hash;
}

uint64_t i386_phase4_compatibility_hash(const struct i386_phase4_record *record) {
    uint64_t hash = UINT64_C(1469598103934665603);
    uint32_t delta;
    uint32_t flags;
    uint32_t exception;
    uint32_t i;
    if (!record)
        return 0U;
    for (i = GEM_I386_EAX; i <= GEM_I386_EBX; ++i)
        hash_value(&hash, &record->final.gpr[i], sizeof(record->final.gpr[i]));
    delta = record->final.gpr[GEM_I386_ESI] - record->initial.gpr[GEM_I386_ESI];
    hash_value(&hash, &delta, sizeof(delta));
    delta = record->final.gpr[GEM_I386_EDI] - record->initial.gpr[GEM_I386_EDI];
    hash_value(&hash, &delta, sizeof(delta));
    flags = record->final.eflags & record->defined.eflags_mask;
    hash_value(&hash, &flags, sizeof(flags));
    hash_value(&hash, record->final.xmm, sizeof(record->final.xmm));
    hash_value(&hash, record->final.x87, sizeof(record->final.x87));
    hash_value(&hash, &record->final.mxcsr, sizeof(record->final.mxcsr));
    hash_value(&hash, &record->final.fcw, sizeof(record->final.fcw));
    hash_value(&hash, &record->final.fsw, sizeof(record->final.fsw));
    hash_value(&hash, &record->final.ftw, sizeof(record->final.ftw));
    hash_value(&hash, &record->memory_hash_after, sizeof(record->memory_hash_after));
    exception = record->category == I386_PHASE4_NEGATIVE ? GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION
                                                         : record->exception_status;
    hash_value(&hash, &exception, sizeof(exception));
    return hash;
}

int i386_phase4_execute(const struct i386_phase4_case *test, enum gem_i386_engine_mode mode,
                        struct i386_phase4_record *record) {
    struct gem_i386_runtime_config config = {0};
    struct gem_i386_engine_info info = {0};
    struct gem_i386_stop_info stop = {0};
    struct gem_i386_runtime *runtime = NULL;
    struct gem_memory *memory = NULL;
    uint8_t observed[I386_PHASE4_MEMORY_SIZE];
    uint32_t address;
    int pass = i386_phase4_validate(test) && record != NULL;
    if (!pass)
        return 0;
    memset(record, 0, sizeof(*record));
    record->schema_version = test->schema_version;
    record->template_id = test->template_id;
    record->shard = test->shard;
    record->ordinal = test->ordinal;
    record->seed = test->seed;
    record->category = test->category;
    memcpy(record->instruction, test->instruction, sizeof(record->instruction));
    record->instruction_size = test->instruction_size;
    record->initial = test->initial;
    record->final = test->initial;
    record->defined = test->defined;
    record->memory_hash_before = i386_phase4_hash_bytes(test->memory, I386_PHASE4_MEMORY_SIZE);
    memory = gem_memory_create();
    pass = memory != NULL;
    address = CODE;
    if (pass)
        pass = gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK;
    if (pass)
        pass = gem_i386_memory_commit(memory, CODE, GEM_GUEST_PAGE_SIZE,
                                      GEM_PAGE_EXECUTE_READWRITE) == GEM_MEMORY_OK;
    if (pass)
        pass = gem_i386_memory_write(memory, CODE, test->instruction, test->instruction_size) ==
               GEM_MEMORY_OK;
    address = DATA;
    if (pass)
        pass = gem_i386_memory_reserve(memory, &address, 2U * GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK;
    if (pass)
        pass = gem_i386_memory_commit(memory, DATA, 2U * GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
               GEM_MEMORY_OK;
    if (pass)
        pass = gem_i386_memory_write(memory, DATA, test->memory, I386_PHASE4_MEMORY_SIZE) ==
               GEM_MEMORY_OK;
    address = STACK;
    if (pass)
        pass = gem_i386_memory_reserve(memory, &address, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK;
    if (pass)
        pass = gem_i386_memory_commit(memory, STACK, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
               GEM_MEMORY_OK;
    config.engine_mode = mode;
    config.host_return_sentinel = CODE + test->instruction_size;
    config.max_budget = 1U;
    runtime = pass ? gem_i386_runtime_create(memory, &config) : NULL;
    pass = pass && runtime != NULL;
    if (pass) {
        record->stop_reason =
            (uint32_t)gem_i386_runtime_run(runtime, &record->final, config.max_budget);
        pass = gem_i386_runtime_last_stop_info(runtime, &stop);
    }
    if (pass) {
        record->exception_status = stop.engine_status;
        record->fault_address = stop.fault_address;
        record->access = (uint32_t)stop.access;
        record->memory_error = stop.memory_error;
        record->retired_count = stop.instructions_retired;
        pass = gem_i386_memory_read(memory, DATA, observed, sizeof(observed)) == GEM_MEMORY_OK;
    }
    if (pass) {
        record->memory_hash_after = i386_phase4_hash_bytes(observed, sizeof(observed));
        info.abi_version = 1U;
        info.size = sizeof(info);
        pass = gem_i386_runtime_engine_info(runtime, &info);
    }
    if (pass) {
        record->jit_compilations = info.jit_compilations;
        record->jit_executions = info.jit_executions;
        record->jit_failures = info.jit_failures;
        if (test->expected_negative) {
            pass = record->stop_reason == GEM_STOP_UNSUPPORTED_INSTRUCTION ||
                   (record->stop_reason == GEM_STOP_WINDOWS_EXCEPTION &&
                    record->exception_status == GEM_I386_EXCEPTION_ILLEGAL_INSTRUCTION);
        } else {
            pass = record->stop_reason == GEM_STOP_HOST_RETURN;
        }
    }
    record->classification = pass ? I386_PHASE4_PASS : I386_PHASE4_INFRASTRUCTURE_FAILURE;
    if (runtime)
        gem_i386_runtime_destroy(runtime);
    if (memory)
        gem_memory_destroy(memory);
    return pass;
}

static int contexts_match(const struct i386_phase4_record *left,
                          const struct i386_phase4_record *right) {
    uint32_t i;
    for (i = 0; i < 8U; ++i) {
        if ((left->defined.gpr_mask & (1U << i)) != 0U && left->final.gpr[i] != right->final.gpr[i])
            return 0;
    }
    if (left->final.eip != right->final.eip ||
        ((left->final.eflags ^ right->final.eflags) & left->defined.eflags_mask) != 0U)
        return 0;
    if (memcmp(left->final.xmm, right->final.xmm, sizeof(left->final.xmm)) != 0 ||
        memcmp(left->final.x87, right->final.x87, sizeof(left->final.x87)) != 0)
        return 0;
    if (((left->final.mxcsr ^ right->final.mxcsr) & left->defined.mxcsr_mask) != 0U)
        return 0;
    return memcmp(left->final.segment, right->final.segment,
                  sizeof(left->final.segment) + sizeof(left->final.segment_base) +
                      sizeof(left->final.segment_limit) + sizeof(left->final.segment_attributes)) ==
           0;
}

int i386_phase4_records_match(const struct i386_phase4_record *left,
                              const struct i386_phase4_record *right) {
    if (!left || !right || left->schema_version != right->schema_version ||
        left->template_id != right->template_id || left->shard != right->shard ||
        left->ordinal != right->ordinal || left->seed != right->seed ||
        left->stop_reason != right->stop_reason ||
        left->exception_status != right->exception_status ||
        left->fault_address != right->fault_address || left->access != right->access ||
        left->memory_error != right->memory_error || left->retired_count != right->retired_count ||
        left->memory_hash_after != right->memory_hash_after)
        return 0;
    return contexts_match(left, right);
}

int i386_phase4_sdm_expectation_met(const struct i386_phase4_case *test,
                                    const struct i386_phase4_record *record) {
    uint16_t expected_fop;
    if (!test || !record || test->template_id != record->template_id)
        return 0;
    if (test->template_id != 300U && test->template_id != 301U)
        return 1;
    expected_fop = test->template_id == 300U ? UINT16_C(0x01e8) : UINT16_C(0x01ee);
    return record->classification == I386_PHASE4_PASS &&
           record->stop_reason == GEM_STOP_HOST_RETURN && record->retired_count == 1U &&
           (record->final.fsw & UINT16_C(0x0241)) == UINT16_C(0x0241) &&
           (record->final.fsw & UINT16_C(0x3800)) == UINT16_C(0x3800) &&
           ((record->final.ftw >> 14U) & 3U) == 2U && record->final.fop == expected_fop &&
           record->final.x87[7].lo == UINT64_C(0xc000000000000000) &&
           (record->final.x87[7].hi & UINT64_C(0xffff)) == UINT64_C(0xffff);
}
