// SPDX-License-Identifier: Apache-2.0
#include "rosetta_x64_oracle.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

typedef void (*oracle_case)(struct rosetta_x64_record *);

struct code_range {
    const unsigned char *start;
    const unsigned char *end;
};

static void emit_u64(const char *name, uint64_t value, int last) {
    printf("\"%s\":\"0x%016llx\"%c", name, (unsigned long long)value, last ? '}' : ',');
}

static void emit_u32(const char *name, uint32_t value, int last) {
    printf("\"%s\":\"0x%08x\"%c", name, value, last ? '}' : ',');
}

static void emit(const struct rosetta_x64_record *record) {
    unsigned int index;
    printf("{\"schemaVersion\":1,");
    emit_u32("case", record->case_id, 0);
    emit_u64("rax", record->rax, 0);
    emit_u64("rcx", record->rcx, 0);
    emit_u64("rdx", record->rdx, 0);
    emit_u64("rflags", record->rflags, 0);
    emit_u32("memory0", record->memory[0], 0);
    emit_u32("memory1", record->memory[1], 0);
    for (index = 0; index < 4; ++index) {
        char name[16];
        snprintf(name, sizeof(name), "xmm0_%u", index);
        emit_u32(name, record->xmm0[index], 0);
    }
    for (index = 0; index < 8; ++index) {
        char name[16];
        snprintf(name, sizeof(name), "ymm0_%u", index);
        emit_u32(name, record->ymm0[index], index == 7);
    }
    putchar('\n');
}

static int is_translated(void) {
    int translated = 0;
    size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) != 0)
        return 0;
    return translated == 1;
}

static int run_dynamic(const struct code_range *range, struct rosetta_x64_record *record) {
    size_t code_size = (size_t)(range->end - range->start);
    size_t page_size = (size_t)getpagesize();
    void *mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED || code_size > page_size)
        return 0;
    memcpy(mapping, range->start, code_size);
    if (mprotect(mapping, page_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(mapping, page_size);
        return 0;
    }
    ((oracle_case)mapping)(record);
    return munmap(mapping, page_size) == 0;
}

int main(void) {
    static const struct code_range cases[] = {
        {rosetta_x64_add_start, rosetta_x64_add_end},
        {rosetta_x64_shift_start, rosetta_x64_shift_end},
        {rosetta_x64_memory_start, rosetta_x64_memory_end},
        {rosetta_x64_sse2_start, rosetta_x64_sse2_end},
        {rosetta_x64_avx2_start, rosetta_x64_avx2_end},
    };
    struct rosetta_x64_record records[sizeof(cases) / sizeof(cases[0])] = {{0}};
    size_t index;
    if (!is_translated()) {
        fputs("translated-process proof failed\n", stderr);
        return 2;
    }
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (!run_dynamic(&cases[index], &records[index])) {
            fprintf(stderr, "dynamic case %zu failed: %s\n", index, strerror(errno));
            return 3;
        }
        emit(&records[index]);
    }
    return 0;
}
