// SPDX-License-Identifier: Apache-2.0
#include "fixtures/i386_phase4_execute.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_u32(const char *text, uint32_t *value) {
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno || !end || *end != '\0' || parsed > UINT32_MAX)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int write_case(const char *path, const struct i386_phase4_case *test) {
    FILE *file = fopen(path, "wb");
    int pass = file && fwrite(test, sizeof(*test), 1U, file) == 1U;
    if (file)
        pass = fclose(file) == 0 && pass;
    return pass;
}

static int read_case(const char *path, struct i386_phase4_case *test) {
    FILE *file = fopen(path, "rb");
    int pass = file && fread(test, sizeof(*test), 1U, file) == 1U && fgetc(file) == EOF;
    if (file)
        pass = fclose(file) == 0 && pass;
    return pass && i386_phase4_validate(test);
}

int main(int argc, char **argv) {
    struct i386_phase4_case test;
    struct i386_phase4_record record;
    enum gem_i386_engine_mode mode = GEM_I386_ENGINE_INTERPRETER;
    const char *case_path = NULL;
    const char *save_path = NULL;
    uint32_t shard = UINT32_MAX;
    uint32_t ordinal = UINT32_MAX;
    int binary = 0;
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--shard") && i + 1 < argc) {
            if (!parse_u32(argv[++i], &shard))
                return 2;
        } else if (!strcmp(argv[i], "--case") && i + 1 < argc) {
            if (!parse_u32(argv[++i], &ordinal))
                return 2;
        } else if (!strcmp(argv[i], "--case-file") && i + 1 < argc) {
            case_path = argv[++i];
        } else if (!strcmp(argv[i], "--save-case") && i + 1 < argc) {
            save_path = argv[++i];
        } else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *name = argv[++i];
            if (!strcmp(name, "interpreter"))
                mode = GEM_I386_ENGINE_INTERPRETER;
            else if (!strcmp(name, "jit"))
                mode = GEM_I386_ENGINE_JIT;
            else
                return 2;
        } else if (!strcmp(argv[i], "--binary")) {
            binary = 1;
        } else if (!strcmp(argv[i], "--json")) {
            binary = 0;
        } else {
            return 2;
        }
    }
    if (case_path) {
        if (!read_case(case_path, &test))
            return 3;
    } else if (!i386_phase4_generate(shard, ordinal, &test)) {
        return 3;
    }
    if (save_path && !write_case(save_path, &test))
        return 4;
    if (!i386_phase4_execute(&test, mode, &record))
        return 5;
    if (binary) {
        if (fwrite(&record, sizeof(record), 1U, stdout) != 1U)
            return 6;
    } else {
        printf("{\"schemaVersion\":%u,\"generatorVersion\":%u,\"templateRevision\":%u,"
               "\"templateId\":%u,\"shard\":%u,\"case\":%u,\"seed\":\"0x%016llx\","
               "\"category\":\"%s\",\"mode\":\"%s\",\"classification\":%u,"
               "\"stopReason\":%u,\"exceptionStatus\":%u,\"faultAddress\":%u,"
               "\"retiredCount\":%u,\"jitExecutions\":%llu,"
               "\"semanticHash\":\"0x%016llx\","
               "\"compatibilityHash\":\"0x%016llx\",\"eax\":%u,\"ecx\":%u,"
               "\"esiDelta\":%u,\"ediDelta\":%u,\"eflags\":%u,\"fsw\":%u,\"ftw\":%u,"
               "\"fop\":%u,\"sdmExpectation\":%s,\"x87_0_lo\":\"0x%016llx\","
               "\"x87_7_lo\":\"0x%016llx\"}\n",
               I386_PHASE4_SCHEMA, I386_PHASE4_GENERATOR_VERSION, I386_PHASE4_TEMPLATE_REVISION,
               test.template_id, test.shard, test.ordinal, (unsigned long long)test.seed,
               i386_phase4_category_name(test.category),
               mode == GEM_I386_ENGINE_JIT ? "jit" : "interpreter", (unsigned)record.classification,
               record.stop_reason, record.exception_status, record.fault_address,
               record.retired_count, (unsigned long long)record.jit_executions,
               (unsigned long long)i386_phase4_semantic_hash(&record),
               (unsigned long long)i386_phase4_compatibility_hash(&record),
               record.final.gpr[GEM_I386_EAX], record.final.gpr[GEM_I386_ECX],
               record.final.gpr[GEM_I386_ESI] - record.initial.gpr[GEM_I386_ESI],
               record.final.gpr[GEM_I386_EDI] - record.initial.gpr[GEM_I386_EDI],
               record.final.eflags & record.defined.eflags_mask, record.final.fsw, record.final.ftw,
               record.final.fop, i386_phase4_sdm_expectation_met(&test, &record) ? "true" : "false",
               (unsigned long long)record.final.x87[0].lo,
               (unsigned long long)record.final.x87[7].lo);
    }
    return record.classification == I386_PHASE4_PASS ? 0 : 1;
}
