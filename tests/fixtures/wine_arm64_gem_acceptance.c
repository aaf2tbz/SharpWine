/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>

static volatile LONG access_seen;
static volatile LONG guard_seen;
static volatile LONG worker_ready;
static volatile LONG worker_release;
static volatile BYTE *fault_page;
static volatile BYTE *guard_page;

static void emit(const char *text, DWORD length) {
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, length, &written, NULL);
}

#define EMIT(text) emit((text), (DWORD)(sizeof(text) - 1))

static LONG CALLBACK exception_handler(EXCEPTION_POINTERS *exception) {
    const DWORD code = exception->ExceptionRecord->ExceptionCode;
    const ULONG_PTR address = exception->ExceptionRecord->ExceptionInformation[1];

    if (code == EXCEPTION_ACCESS_VIOLATION && address == (ULONG_PTR)fault_page &&
        InterlockedCompareExchange(&access_seen, 1, 0) == 0) {
        /* The faulting instruction is one fixed-width ARM64 load. */
        exception->ContextRecord->Pc += 4;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == STATUS_GUARD_PAGE_VIOLATION && address == (ULONG_PTR)guard_page &&
        InterlockedCompareExchange(&guard_seen, 1, 0) == 0) {
        /* Windows consumes PAGE_GUARD before dispatch; retry the write. */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static void trigger_access_violation(void) {
    volatile BYTE ignored = *fault_page;
    (void)ignored;
}

static DWORD WINAPI worker(void *unused) {
    (void)unused;
    InterlockedExchange(&worker_ready, 1);
    while (!InterlockedCompareExchange(&worker_release, 0, 0))
        YieldProcessor();
    return 42;
}

int main(void) {
    PVOID handler;
    DWORD old_protection;
    DWORD started;
    DWORD exit_code;
    HANDLE thread;

    handler = AddVectoredExceptionHandler(1, exception_handler);
    if (!handler) {
        EMIT("metalsharp-gem-acceptance: failed=exception-handler\r\n");
        return 1;
    }

    fault_page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!fault_page || !VirtualProtect((void *)fault_page, 4096, PAGE_NOACCESS, &old_protection)) {
        EMIT("metalsharp-gem-acceptance: failed=access-setup\r\n");
        return 2;
    }
    trigger_access_violation();
    if (InterlockedCompareExchange(&access_seen, 0, 0) != 1) {
        EMIT("metalsharp-gem-acceptance: failed=access-continuation\r\n");
        return 3;
    }
    EMIT("metalsharp-gem-acceptance: access-violation=continued\r\n");

    guard_page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!guard_page ||
        !VirtualProtect((void *)guard_page, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protection)) {
        EMIT("metalsharp-gem-acceptance: failed=guard-setup\r\n");
        return 4;
    }
    *guard_page = 0x5a;
    if (InterlockedCompareExchange(&guard_seen, 0, 0) != 1 || *guard_page != 0x5a) {
        EMIT("metalsharp-gem-acceptance: failed=guard-consumption\r\n");
        return 5;
    }
    EMIT("metalsharp-gem-acceptance: guard=consumed\r\n");

    thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!thread) {
        EMIT("metalsharp-gem-acceptance: failed=thread-create\r\n");
        return 6;
    }
    started = GetTickCount();
    while (!InterlockedCompareExchange(&worker_ready, 0, 0)) {
        if (GetTickCount() - started > 5000) {
            EMIT("metalsharp-gem-acceptance: failed=thread-start\r\n");
            return 7;
        }
        Sleep(1);
    }
    if (SuspendThread(thread) == (DWORD)-1) {
        EMIT("metalsharp-gem-acceptance: failed=thread-suspend\r\n");
        return 8;
    }
    Sleep(20);
    if (ResumeThread(thread) == (DWORD)-1) {
        EMIT("metalsharp-gem-acceptance: failed=thread-resume\r\n");
        return 9;
    }
    InterlockedExchange(&worker_release, 1);
    if (WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(thread, &exit_code) || exit_code != 42) {
        EMIT("metalsharp-gem-acceptance: failed=thread-exit\r\n");
        return 10;
    }
    CloseHandle(thread);
    EMIT("metalsharp-gem-acceptance: thread=create,suspend,resume,exit\r\n");

    RemoveVectoredExceptionHandler(handler);
    VirtualFree((void *)guard_page, 0, MEM_RELEASE);
    VirtualFree((void *)fault_page, 0, MEM_RELEASE);
    EMIT("metalsharp-gem-acceptance: passed\r\n");
    return 0;
}
