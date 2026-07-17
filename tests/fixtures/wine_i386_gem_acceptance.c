// SPDX-License-Identifier: Apache-2.0
#include <windows.h>
#include <winternl.h>

#include <stdint.h>
#include <string.h>

static volatile LONG exception_count;
static volatile LONG exception_failure;

static LONG CALLBACK phase3_exception_handler(EXCEPTION_POINTERS *pointers) {
    CONTEXT *context = pointers->ContextRecord;
    XSAVE_FORMAT *xsave = (XSAVE_FORMAT *)context->ExtendedRegisters;
    LONG index;

    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    index = InterlockedIncrement(&exception_count);
    if (index == 1) {
        if (!(context->EFlags & UINT32_C(0x400)))
            exception_failure = 1;
        else if (xsave->MxCsr != UINT32_C(0x1f80))
            exception_failure = 2;
        else if (xsave->XmmRegisters[0].Low != UINT64_C(0x0123456789abcdef))
            exception_failure = 3;
        else if (xsave->FloatRegisters[7].Low != UINT64_C(0x8000000000000000))
            exception_failure = 4;
        context->EFlags &= ~UINT32_C(0x400);
        context->Eax = UINT32_C(0x13579bdf);
        xsave->MxCsr = UINT32_C(0x3f80);
        xsave->XmmRegisters[0].Low = UINT64_C(0xfedcba9876543210);
    } else if (index == 2) {
        if (xsave->FloatRegisters[0].Low != UINT64_C(0x1122334455667788))
            exception_failure = 5;
    } else {
        exception_failure = 3;
    }
    context->Eip += 1U;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static int verify_phase3_context(void) {
    static const unsigned char source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint64_t xmm_input[2] = {UINT64_C(0x0123456789abcdef), UINT64_C(0xf0e1d2c3b4a59687)};
    uint64_t xmm_output[2] = {0, 0};
    uint64_t mmx_input = UINT64_C(0x1122334455667788);
    unsigned char forward[8] = {0};
    unsigned char backward[8] = {0};
    DWORD eax_output = 0;
    DWORD mxcsr_input = UINT32_C(0x1f80);
    DWORD mxcsr_output = 0;
    CONTEXT captured;
    PVOID handler = AddVectoredExceptionHandler(1, phase3_exception_handler);

    if (!handler)
        return 20;
    __asm__ volatile("fninit\n\t"
                     "fld1\n\t"
                     "ldmxcsr %3\n\t"
                     "movdqu %4, %%xmm0\n\t"
                     "std\n\t"
                     "int3\n\t"
                     "movl %%eax, %0\n\t"
                     "stmxcsr %1\n\t"
                     "movdqu %%xmm0, %2\n\t"
                     : "=m"(eax_output), "=m"(mxcsr_output), "=m"(xmm_output)
                     : "m"(mxcsr_input), "m"(xmm_input)
                     : "eax", "xmm0", "memory", "cc");
    if (exception_failure)
        return 20 + exception_failure;
    if (eax_output != UINT32_C(0x13579bdf))
        return 26;
    if (mxcsr_output != UINT32_C(0x3f80))
        return 27;
    if (xmm_output[0] != UINT64_C(0xfedcba9876543210))
        return 28;
    __asm__ volatile("movq %0, %%mm0\n\tint3\n\temms" : : "m"(mmx_input) : "memory", "cc");
    if (exception_failure)
        return 30 + exception_failure;
    if (exception_count != 2)
        return 36;
    {
        const unsigned char *src = source;
        unsigned char *dst = forward;
        size_t count = sizeof(source);
        __asm__ volatile("cld\n\trep movsb" : "+S"(src), "+D"(dst), "+c"(count) : : "memory", "cc");
    }
    {
        const unsigned char *src = source + sizeof(source) - 1;
        unsigned char *dst = backward + sizeof(backward) - 1;
        size_t count = sizeof(source);
        __asm__ volatile("std\n\trep movsb\n\tcld"
                         : "+S"(src), "+D"(dst), "+c"(count)
                         :
                         : "memory", "cc");
    }
    if (memcmp(source, forward, sizeof(source)) || memcmp(source, backward, sizeof(source)))
        return 23;
    memset(&captured, 0, sizeof(captured));
    RtlCaptureContext(&captured);
    if (!(captured.ContextFlags & CONTEXT_CONTROL) ||
        !(captured.ContextFlags & CONTEXT_FLOATING_POINT))
        return 24;
    if (!RemoveVectoredExceptionHandler(handler))
        return 25;
    __asm__ volatile("fninit\n\tldmxcsr %0" : : "m"(mxcsr_input) : "memory");
    return 0;
}

int main(void) {
    static const char marker[] = "METALSHARP_GEM_I386_OK\r\n";
    DWORD written = 0;
    HANDLE file = CreateFileA("C:\\metalsharp-gem-i386-ok.txt", GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int phase3_status = verify_phase3_context();

    if (phase3_status)
        return phase3_status;
    if (file == INVALID_HANDLE_VALUE)
        return 10;
    if (!WriteFile(file, marker, sizeof(marker) - 1, &written, NULL) ||
        written != sizeof(marker) - 1) {
        CloseHandle(file);
        return 11;
    }
    if (!CloseHandle(file))
        return 12;
    return 0;
}
