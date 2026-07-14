// SPDX-License-Identifier: Apache-2.0
/* Source-built PE32+ acceptance fixture; generated binaries are never tracked. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG shared_counter;
static DWORD tls_index = TLS_OUT_OF_INDEXES;

static void progress(const char *stage) {
    printf("MSWR_X64_PROGRESS %s\n", stage);
    fflush(stdout);
}

static BOOL CALLBACK init_once_callback(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void)once;
    (void)parameter;
    *context = (PVOID)(uintptr_t)0x5aU;
    return TRUE;
}

static DWORD WINAPI worker(void *opaque) {
    HANDLE event = (HANDLE)opaque;
    unsigned int i;

    if (!TlsSetValue(tls_index, (PVOID)(uintptr_t)0x44U))
        return 10U;
    for (i = 0; i < 1000U; ++i)
        InterlockedIncrement(&shared_counter);
    if ((uintptr_t)TlsGetValue(tls_index) != 0x44U)
        return 11U;
    return SetEvent(event) ? 0U : 12U;
}

static int run_child(void) {
    const char *value = getenv("MSWR_X64_CHILD");
    return value && !strcmp(value, "1") ? 37 : 38;
}

/* Clang cannot catch an asynchronous SEH exception generated in the same
 * function as the __try scope. Keep the raise in a distinct non-inlined frame
 * so the fixture exercises a valid Windows x64 unwind across a call boundary. */
__declspec(noinline) static void raise_test_exception(void) {
    RaiseException(0xe0454d47U, 0, 0, NULL);
}

static int check_exception(void) {
    int caught = 0;

    __try {
        raise_test_exception();
    } __except (GetExceptionCode() == 0xe0454d47U ? EXCEPTION_EXECUTE_HANDLER
                                                  : EXCEPTION_CONTINUE_SEARCH) {
        caught = 1;
    }
    return caught;
}

int main(int argc, char **argv) {
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    PVOID callback_context = NULL;
    HANDLE event = NULL, mutex = NULL, thread = NULL;
    HMODULE kernel32 = NULL;
    FARPROC tick = NULL;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOA startup = {0};
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    HKEY key = NULL;
    DWORD disposition = 0, child_code = 0, thread_code = 0;
    DWORD registry_value = 0x1234abcdU, registry_size = sizeof(registry_value), type = 0;
    char child_command[32768], module[MAX_PATH], temporary[MAX_PATH], file_name[MAX_PATH];
    char environment[64];
    void *memory = NULL;
    FILE *file = NULL;
    __m128d left = _mm_set_pd(2.0, 1.0), right = _mm_set1_pd(3.0), sum;
    double lanes[2];
    unsigned char checks[13] = {0};
    int passed = 1;

    if (argc == 2 && !strcmp(argv[1], "--child"))
        return run_child();
    startup.cb = sizeof(startup);

    progress("entry");
    checks[0] = argc == 2 && !strcmp(argv[1], "mswr-argument");
    checks[1] = GetEnvironmentVariableA("MSWR_X64_ENV", environment, sizeof(environment)) == 13 &&
                !strcmp(environment, "oracle-value");
    checks[2] = GetModuleFileNameA(NULL, module, sizeof(module)) > 0;

    kernel32 = LoadLibraryA("kernel32.dll");
    tick = kernel32 ? GetProcAddress(kernel32, "GetTickCount") : NULL;
    checks[3] = tick != NULL;

    sum = _mm_add_pd(left, right);
    _mm_storeu_pd(lanes, sum);
    checks[4] = lanes[0] == 4.0 && lanes[1] == 5.0 && ((INT64)-7 >> 1) == -4;

    progress("threads");
    tls_index = TlsAlloc();
    event = CreateEventA(NULL, TRUE, FALSE, NULL);
    mutex = CreateMutexA(NULL, FALSE, NULL);
    thread = event ? CreateThread(NULL, 0, worker, event, 0, NULL) : NULL;
    checks[5] = tls_index != TLS_OUT_OF_INDEXES && event && mutex && thread &&
                WaitForSingleObject(event, 10000) == WAIT_OBJECT_0 &&
                WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0 &&
                GetExitCodeThread(thread, &thread_code) && thread_code == 0 &&
                shared_counter == 1000 && WaitForSingleObject(mutex, 1000) == WAIT_OBJECT_0 &&
                ReleaseMutex(mutex);

    progress("virtual-memory");
    memory = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (memory) {
        DWORD old_protection = 0;
        memset(memory, 0xa5, 8192);
        checks[6] = VirtualProtect(memory, 8192, PAGE_READONLY, &old_protection) &&
                    old_protection == PAGE_READWRITE && VirtualFree(memory, 0, MEM_RELEASE);
    }

    progress("file");
    checks[7] = GetTempPathA(sizeof(temporary), temporary) > 0 &&
                GetTempFileNameA(temporary, "msx", 0, file_name) != 0;
    if (checks[7]) {
        file = fopen(file_name, "wb");
        checks[7] = file && fwrite("metalsharp", 1, 10, file) == 10 && !fclose(file) &&
                    GetFileAttributesExA(file_name, GetFileExInfoStandard, &attributes) &&
                    attributes.nFileSizeLow == 10 && DeleteFileA(file_name);
        file = NULL;
    }

    progress("registry");
    checks[8] = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\MetalSharp\\x64Acceptance", 0, NULL,
                                0, KEY_ALL_ACCESS, NULL, &key, &disposition) == ERROR_SUCCESS &&
                RegSetValueExA(key, "value", 0, REG_DWORD, (BYTE *)&registry_value,
                               sizeof(registry_value)) == ERROR_SUCCESS;
    registry_value = 0;
    checks[8] = checks[8] &&
                RegQueryValueExA(key, "value", NULL, &type, (BYTE *)&registry_value,
                                 &registry_size) == ERROR_SUCCESS &&
                type == REG_DWORD && registry_value == 0x1234abcdU;
    if (key)
        RegCloseKey(key);
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\MetalSharp\\x64Acceptance");

    progress("callback-exception");
    checks[9] = InitOnceExecuteOnce(&once, init_once_callback, NULL, &callback_context) &&
                (uintptr_t)callback_context == 0x5aU;
    checks[10] = check_exception() != 0;

    progress("child-process");
    _snprintf(child_command, sizeof(child_command), "\"%s\" --child", module);
    SetEnvironmentVariableA("MSWR_X64_CHILD", "1");
    checks[11] =
        CreateProcessA(NULL, child_command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process) &&
        WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, &child_code) && child_code == 37;
    checks[12] = GetCurrentProcessId() != 0 && GetCurrentThreadId() != 0;

    progress("result");
    for (unsigned int i = 0; i < sizeof(checks); ++i)
        passed &= checks[i] != 0;
    printf("MSWR_X64_V1 {\"passed\":%s,\"checks\":{"
           "\"entryArgsEnv\":%s,\"pebModule\":%s,\"dynamicImport\":%s,"
           "\"integerSimd\":%s,\"tlsThreadsAtomics\":%s,\"virtualMemory\":%s,"
           "\"fileDirectory\":%s,\"registry\":%s,\"callback\":%s,"
           "\"exceptionUnwind\":%s,\"childProcess\":%s,\"identity\":%s}}\n",
           passed ? "true" : "false", checks[0] && checks[1] ? "true" : "false",
           checks[2] ? "true" : "false", checks[3] ? "true" : "false", checks[4] ? "true" : "false",
           checks[5] ? "true" : "false", checks[6] ? "true" : "false", checks[7] ? "true" : "false",
           checks[8] ? "true" : "false", checks[9] ? "true" : "false",
           checks[10] ? "true" : "false", checks[11] ? "true" : "false",
           checks[12] ? "true" : "false");

    if (process.hThread)
        CloseHandle(process.hThread);
    if (process.hProcess)
        CloseHandle(process.hProcess);
    if (thread)
        CloseHandle(thread);
    if (mutex)
        CloseHandle(mutex);
    if (event)
        CloseHandle(event);
    if (tls_index != TLS_OUT_OF_INDEXES)
        TlsFree(tls_index);
    if (kernel32)
        FreeLibrary(kernel32);
    return passed ? 0 : 1;
}
