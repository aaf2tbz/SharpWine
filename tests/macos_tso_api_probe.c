// SPDX-License-Identifier: Apache-2.0
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    static const char *const names[] = {
        "pthread_set_tso_np",
        "thread_set_tso",
        "sys_set_tso",
    };
    size_t i;
    int discovered = 0;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        const int present = dlsym(RTLD_DEFAULT, names[i]) != NULL;
        printf("%s=%s\n", names[i], present ? "present" : "absent");
        discovered |= present;
    }
    if (discovered) {
        fputs("TSO-like symbol discovered; support and per-thread semantics require review\n",
              stderr);
        return 1;
    }
    puts("hardware_tso=unavailable_known_public_symbols_absent");
    return 0;
}
