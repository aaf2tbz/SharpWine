// SPDX-License-Identifier: Apache-2.0
#include "fixture_api.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef uint64_t (*fixture_u64_fn)(uint64_t);

static int fail(const char *message) {
    fprintf(stderr, "ARM64X fixture failure: %s\n", message);
    return 1;
}

static fixture_u64_fn find_u64(HMODULE module, const char *name) {
    FARPROC address = GetProcAddress(module, name);
    fixture_u64_fn function = NULL;
    if (sizeof(address) != sizeof(function))
        return NULL;
    memcpy(&function, &address, sizeof(function));
    return function;
}

static int write_native_evidence(const char *path) {
    FILE *output = NULL;
    if (fopen_s(&output, path, "wb") != 0 || output == NULL)
        return fail("native evidence output");
    fprintf(output, "{\"schemaVersion\":2,\"nativeMachine\":\"arm64\","
                    "\"roundtripInput\":12,\"roundtripResult\":30,"
                    "\"directResult\":47,\"callbackResumeResult\":82,"
                    "\"tailTransferResult\":23120,\"nestedResult\":85,\"passed\":true}\n");
    if (fclose(output) != 0)
        return fail("native evidence close");
    return 0;
}

static int write_entry_map(const char *path) {
    const HMODULE module = GetModuleHandleW(L"arm64x_fixture.dll");
    const uintptr_t base = (uintptr_t)module;
    const uintptr_t entries[] = {
        (uintptr_t)(void *)fixture_indirect_x64,
        (uintptr_t)(void *)fixture_indirect_x64_floating,
        (uintptr_t)(void *)fixture_indirect_x64_aggregate,
        (uintptr_t)(void *)fixture_indirect_x64_variadic,
    };
    const uintptr_t roundtrip = (uintptr_t)(void *)fixture_authentic_roundtrip;
    const uintptr_t finish = (uintptr_t)(void *)fixture_roundtrip_arm_finish;
    const uintptr_t direct = (uintptr_t)(void *)find_u64(module, "fixture_direct_x64_call");
    const uintptr_t callback_resume =
        (uintptr_t)(void *)find_u64(module, "fixture_callback_and_resume");
    const uintptr_t tail_transfer = (uintptr_t)(void *)find_u64(module, "fixture_tail_transfer");
    const uintptr_t bounded_nested = (uintptr_t)(void *)find_u64(module, "fixture_bounded_nested");
    const uintptr_t arm_callback = (uintptr_t)(void *)find_u64(module, "fixture_arm_callback");
    const uintptr_t arm_nested_callback =
        (uintptr_t)(void *)find_u64(module, "fixture_arm_nested_callback");
    const uintptr_t checker_slot = fixture_checker_slot();
    const uintptr_t dispatch_call_slot = fixture_dispatch_call_slot();
    const uintptr_t dispatch_ret_slot = fixture_dispatch_ret_slot();
    FILE *output = NULL;
    size_t index;
    if (module == NULL)
        return fail("fixture module handle");
    for (index = 0; index < sizeof(entries) / sizeof(entries[0]); ++index) {
        if (entries[index] < base || entries[index] - base > UINT32_MAX)
            return fail("ARM64EC entry RVA");
    }
    if (roundtrip < base || roundtrip - base > UINT32_MAX)
        return fail("round-trip entry RVA");
    if (finish < base || finish - base > UINT32_MAX)
        return fail("round-trip finish RVA");
    if (direct < base || direct - base > UINT32_MAX || callback_resume < base ||
        callback_resume - base > UINT32_MAX || tail_transfer < base ||
        tail_transfer - base > UINT32_MAX || bounded_nested < base ||
        bounded_nested - base > UINT32_MAX || arm_callback < base ||
        arm_callback - base > UINT32_MAX || arm_nested_callback < base ||
        arm_nested_callback - base > UINT32_MAX)
        return fail("Issue 14.5 entry RVA");
    if (checker_slot < base || checker_slot - base > UINT32_MAX)
        return fail("ARM64EC checker slot RVA");
    if (dispatch_call_slot < base || dispatch_call_slot - base > UINT32_MAX)
        return fail("dispatch-call slot RVA");
    if (dispatch_ret_slot < base || dispatch_ret_slot - base > UINT32_MAX)
        return fail("dispatch-ret slot RVA");
    if (fopen_s(&output, path, "wb") != 0 || output == NULL)
        return fail("entry map output");
    fprintf(
        output,
        "MSWR_ARM64EC_ENTRY_MAP_V3\n"
        "integer %08llx\n"
        "floating %08llx\n"
        "aggregate %08llx\n"
        "variadic %08llx\n"
        "roundtrip %08llx\n"
        "finish %08llx\n"
        "direct %08llx\n"
        "callbackResume %08llx\n"
        "tailTransfer %08llx\n"
        "boundedNested %08llx\n"
        "armCallback %08llx\n"
        "armNestedCallback %08llx\n"
        "checkerSlot %08llx\n"
        "dispatchCallSlot %08llx\n"
        "dispatchRetSlot %08llx\n",
        (unsigned long long)(entries[0] - base), (unsigned long long)(entries[1] - base),
        (unsigned long long)(entries[2] - base), (unsigned long long)(entries[3] - base),
        (unsigned long long)(roundtrip - base), (unsigned long long)(finish - base),
        (unsigned long long)(direct - base), (unsigned long long)(callback_resume - base),
        (unsigned long long)(tail_transfer - base), (unsigned long long)(bounded_nested - base),
        (unsigned long long)(arm_callback - base), (unsigned long long)(arm_nested_callback - base),
        (unsigned long long)(checker_slot - base), (unsigned long long)(dispatch_call_slot - base),
        (unsigned long long)(dispatch_ret_slot - base));
    if (fclose(output) != 0)
        return fail("entry map close");
    return 0;
}

int main(int argc, char **argv) {
    USHORT process_machine = 0;
    USHORT native_machine = 0;
    arm64x_fixture_pair input = {31, 47};
    arm64x_fixture_pair output;
    HMODULE module = GetModuleHandleW(L"arm64x_fixture.dll");
    fixture_u64_fn direct;
    fixture_u64_fn callback_resume;
    fixture_u64_fn tail_transfer;
    fixture_u64_fn bounded_nested;

    if (module == NULL)
        return fail("fixture module handle");
    direct = find_u64(module, "fixture_direct_x64_call");
    callback_resume = find_u64(module, "fixture_callback_and_resume");
    tail_transfer = find_u64(module, "fixture_tail_transfer");
    bounded_nested = find_u64(module, "fixture_bounded_nested");
    if (direct == NULL || callback_resume == NULL || tail_transfer == NULL ||
        bounded_nested == NULL)
        return fail("Issue 14.5 export lookup");
    if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
        return fail("IsWow64Process2 failed");
    if (native_machine != IMAGE_FILE_MACHINE_ARM64)
        return fail("host OS is not native ARM64");
    if (fixture_integer(0x100) != 0x1334)
        return fail("integer result");
    if (fabs(fixture_floating(2.5) - 4.0) > 0.000001)
        return fail("floating result");
    output = fixture_aggregate(input);
    if (output.first != 58 || output.second != 22)
        return fail("aggregate result");
    if (fixture_variadic(4, 3, -5, 17, 9) != 24)
        return fail("variadic result");
    if (fixture_indirect_x64(12) != 43)
        return fail("indirect x64 integer result");
    if (fixture_authentic_roundtrip(UINT64_C(12)) != UINT64_C(30))
        return fail("authentic integer round-trip result");
    if (direct(UINT64_C(10)) != UINT64_C(47))
        return fail("direct ARM64EC-to-x64 normal return result");
    if (callback_resume(UINT64_C(10)) != UINT64_C(82))
        return fail("x64-to-ARM64EC callback and x64 resumption result");
    if (tail_transfer(UINT64_C(10)) != UINT64_C(23120))
        return fail("explicit tail transfer result");
    if (bounded_nested(UINT64_C(10)) != UINT64_C(85))
        return fail("bounded nested transition result");
    if (fabs(fixture_indirect_x64_floating(2.5) - 4.5) > 0.000001)
        return fail("indirect x64 floating result");
    output = fixture_indirect_x64_aggregate(input);
    if (output.first != 44 || output.second != 36)
        return fail("indirect x64 aggregate result");
    if (fixture_indirect_x64_variadic(4, 3, -5, 17, 9) != 24)
        return fail("indirect x64 variadic result");
    if (fixture_import_probe() != 1u)
        return fail("import probe");
    if (argc > 3)
        return fail("usage: host [entry-map-output] [native-evidence-output]");
    if (argc >= 2 && write_entry_map(argv[1]) != 0)
        return 1;
    if (argc == 3 && write_native_evidence(argv[2]) != 0)
        return 1;
    printf("ARM64X linked fixture native execution passed\n");
    return 0;
}
