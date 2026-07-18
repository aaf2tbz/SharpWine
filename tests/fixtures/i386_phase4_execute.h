// SPDX-License-Identifier: Apache-2.0
#ifndef SHARPWINE_I386_PHASE4_EXECUTE_H
#define SHARPWINE_I386_PHASE4_EXECUTE_H

#include "i386_phase4_records.h"
#include "metalsharp/gem/i386_engine.h"

int i386_phase4_execute(const struct i386_phase4_case *test, enum gem_i386_engine_mode mode,
                        struct i386_phase4_record *record);
int i386_phase4_records_match(const struct i386_phase4_record *left,
                              const struct i386_phase4_record *right);
int i386_phase4_sdm_expectation_met(const struct i386_phase4_case *test,
                                    const struct i386_phase4_record *record);
uint64_t i386_phase4_hash_bytes(const uint8_t *data, uint32_t size);
uint64_t i386_phase4_semantic_hash(const struct i386_phase4_record *record);
uint64_t i386_phase4_compatibility_hash(const struct i386_phase4_record *record);

#endif
