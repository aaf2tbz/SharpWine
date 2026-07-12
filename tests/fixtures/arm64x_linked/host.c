// SPDX-License-Identifier: Apache-2.0
#include "fixture_api.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef int32_t (*fixture_i32_fn)(int32_t);
typedef double (*fixture_double_fn)(double);
typedef arm64x_fixture_pair (*fixture_pair_fn)(arm64x_fixture_pair);
typedef int64_t (*fixture_variadic_fn)(uint32_t, ...);
typedef uint64_t (*fixture_u64_fn)(uint64_t);
typedef uintptr_t (*fixture_slot_fn)(void);
typedef uint32_t (*fixture_u32_fn)(void);

static int fail(const char *message) {
    fprintf(stderr, "ARM64X fixture failure: %s\n", message);
    return 1;
}

static int find_function(HMODULE module, const char *name, void *output, size_t output_size) {
    FARPROC address = GetProcAddress(module, name);
    if (address == NULL || output == NULL || output_size > sizeof(address))
        return 0;
    memset(output, 0, output_size);
    memcpy(output, &address, output_size);
    return 1;
}

static uintptr_t find_address(HMODULE module, const char *name) {
    FARPROC address = GetProcAddress(module, name);
    uintptr_t value = 0U;
    if (address != NULL && sizeof(value) <= sizeof(address))
        memcpy(&value, &address, sizeof(value));
    return value;
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

static int write_entry_map(HMODULE module, const char *path) {
    const uintptr_t base = (uintptr_t)module;
    const uintptr_t entries[] = {
        find_address(module, "fixture_indirect_x64"),
        find_address(module, "fixture_indirect_x64_floating"),
        find_address(module, "fixture_indirect_x64_aggregate"),
        find_address(module, "fixture_indirect_x64_variadic"),
    };
    const uintptr_t roundtrip = find_address(module, "fixture_authentic_roundtrip");
    const uintptr_t finish = find_address(module, "fixture_roundtrip_arm_finish");
    const uintptr_t direct = find_address(module, "fixture_direct_x64_call");
    const uintptr_t callback_resume = find_address(module, "fixture_callback_and_resume");
    const uintptr_t tail_transfer = find_address(module, "fixture_tail_transfer");
    const uintptr_t bounded_nested = find_address(module, "fixture_bounded_nested");
    const uintptr_t arm_callback = find_address(module, "fixture_arm_callback");
    const uintptr_t arm_nested_callback = find_address(module, "fixture_arm_nested_callback");
    fixture_slot_fn checker_function = NULL;
    fixture_slot_fn dispatch_call_function = NULL;
    fixture_slot_fn dispatch_ret_function = NULL;
    uintptr_t checker_slot;
    uintptr_t dispatch_call_slot;
    uintptr_t dispatch_ret_slot;
    FILE *output = NULL;
    size_t index;
    if (!find_function(module, "fixture_checker_slot", &checker_function,
                       sizeof(checker_function)) ||
        !find_function(module, "fixture_dispatch_call_slot", &dispatch_call_function,
                       sizeof(dispatch_call_function)) ||
        !find_function(module, "fixture_dispatch_ret_slot", &dispatch_ret_function,
                       sizeof(dispatch_ret_function)))
        return fail("helper slot export lookup");
    checker_slot = checker_function();
    dispatch_call_slot = dispatch_call_function();
    dispatch_ret_slot = dispatch_ret_function();
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
    HMODULE module = LoadLibraryW(L"arm64x_fixture.dll");
    fixture_i32_fn integer = NULL;
    fixture_double_fn floating = NULL;
    fixture_pair_fn aggregate = NULL;
    fixture_variadic_fn variadic = NULL;
    fixture_i32_fn indirect_x64 = NULL;
    fixture_u64_fn roundtrip = NULL;
    fixture_u64_fn direct = NULL;
    fixture_u64_fn callback_resume = NULL;
    fixture_u64_fn tail_transfer = NULL;
    fixture_u64_fn bounded_nested = NULL;
    fixture_double_fn indirect_floating = NULL;
    fixture_pair_fn indirect_aggregate = NULL;
    fixture_variadic_fn indirect_variadic = NULL;
    fixture_u32_fn import_probe = NULL;

    if (module == NULL)
        return fail("fixture load");
#define LOAD(name, symbol)                                                                         \
    if (!find_function(module, symbol, &name, sizeof(name)))                                       \
    return fail("fixture export lookup: " symbol)
    LOAD(integer, "fixture_integer");
    LOAD(floating, "fixture_floating");
    LOAD(aggregate, "fixture_aggregate");
    LOAD(variadic, "fixture_variadic");
    LOAD(indirect_x64, "fixture_indirect_x64");
    LOAD(roundtrip, "fixture_authentic_roundtrip");
    LOAD(direct, "fixture_direct_x64_call");
    LOAD(callback_resume, "fixture_callback_and_resume");
    LOAD(tail_transfer, "fixture_tail_transfer");
    LOAD(bounded_nested, "fixture_bounded_nested");
    LOAD(indirect_floating, "fixture_indirect_x64_floating");
    LOAD(indirect_aggregate, "fixture_indirect_x64_aggregate");
    LOAD(indirect_variadic, "fixture_indirect_x64_variadic");
    LOAD(import_probe, "fixture_import_probe");
#undef LOAD
    if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
        return fail("IsWow64Process2 failed");
    if (native_machine != IMAGE_FILE_MACHINE_ARM64)
        return fail("host OS is not native ARM64");
    if (integer(0x100) != 0x1334)
        return fail("integer result");
    if (fabs(floating(2.5) - 4.0) > 0.000001)
        return fail("floating result");
    output = aggregate(input);
    if (output.first != 58 || output.second != 22)
        return fail("aggregate result");
    if (variadic(4, 3, -5, 17, 9) != 24)
        return fail("variadic result");
    if (indirect_x64(12) != 43)
        return fail("indirect x64 integer result");
    if (roundtrip(UINT64_C(12)) != UINT64_C(30))
        return fail("authentic integer round-trip result");
    if (direct(UINT64_C(10)) != UINT64_C(47))
        return fail("direct ARM64EC-to-x64 normal return result");
    if (callback_resume(UINT64_C(10)) != UINT64_C(82))
        return fail("x64-to-ARM64EC callback and x64 resumption result");
    if (tail_transfer(UINT64_C(10)) != UINT64_C(23120))
        return fail("explicit tail transfer result");
    if (bounded_nested(UINT64_C(10)) != UINT64_C(85))
        return fail("bounded nested transition result");
    if (fabs(indirect_floating(2.5) - 4.5) > 0.000001)
        return fail("indirect x64 floating result");
    output = indirect_aggregate(input);
    if (output.first != 44 || output.second != 36)
        return fail("indirect x64 aggregate result");
    if (indirect_variadic(4, 3, -5, 17, 9) != 24)
        return fail("indirect x64 variadic result");
    if (import_probe() != 1u)
        return fail("import probe");
    if (argc > 3)
        return fail("usage: host [entry-map-output] [native-evidence-output]");
    if (argc >= 2 && write_entry_map(module, argv[1]) != 0)
        return 1;
    if (argc == 3 && write_native_evidence(argv[2]) != 0)
        return 1;
    if (!FreeLibrary(module))
        return fail("fixture unload");
    printf("ARM64X linked fixture native execution passed\n");
    return 0;
}
