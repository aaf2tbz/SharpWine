// SPDX-License-Identifier: Apache-2.0
/* Minimal ordinary PE32+ startup/exception/teardown fixture. It imports only
 * ntdll so the Apple Silicon acceptance path measures the Wine/GEM x86_64
 * boundary, not a C runtime or application-framework dependency graph. */
typedef long ntstatus;
typedef long(__stdcall *exception_handler)(void *exception_pointers);

struct exception_pointers {
    void *record;
    unsigned char *context;
};

__declspec(dllimport) ntstatus __stdcall NtTerminateProcess(void *process, ntstatus status);
__declspec(dllimport) void *__stdcall RtlAddVectoredExceptionHandler(unsigned long first,
                                                                     exception_handler handler);

static long __stdcall handle_breakpoint(void *opaque) {
    struct exception_pointers *pointers = opaque;
    /* RIP is at offset 0xf8 in the public AMD64 CONTEXT layout. */
    unsigned long long *rip = (unsigned long long *)(pointers->context + 0xf8);
    if (*(const unsigned char *)(__UINTPTR_TYPE__)*rip != 0xcc)
        return 0;
    ++*rip;
    return -1; /* EXCEPTION_CONTINUE_EXECUTION */
}

__declspec(noreturn) void mainCRTStartup(void) {
    if (!RtlAddVectoredExceptionHandler(1, handle_breakpoint))
        (void)NtTerminateProcess((void *)(__UINTPTR_TYPE__)-1, 2);
    __asm__ volatile("int3");
    (void)NtTerminateProcess((void *)(__UINTPTR_TYPE__)-1, 0);
    __builtin_unreachable();
}
