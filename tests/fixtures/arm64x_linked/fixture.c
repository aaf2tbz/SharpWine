// SPDX-License-Identifier: Apache-2.0
#include "fixture_api.h"

#include <stdarg.h>
#include <windows.h>

#if defined(_M_ARM64EC)
extern int32_t fixture_x64_target(int32_t value);
extern double fixture_x64_floating_target(double value);
extern arm64x_fixture_pair fixture_x64_aggregate_target(arm64x_fixture_pair value);
extern int64_t fixture_x64_variadic_target(uint32_t count, ...);
extern void (*__os_arm64x_check_icall)(void);
#endif

int32_t fixture_integer(int32_t value) {
    return value + 0x1234;
}

double fixture_floating(double value) {
    return value * 1.5 + 0.25;
}

arm64x_fixture_pair fixture_aggregate(arm64x_fixture_pair value) {
    arm64x_fixture_pair result = {value.second + 11, value.first - 9};
    return result;
}

int64_t fixture_variadic(uint32_t count, ...) {
    int64_t total = 0;
    uint32_t index;
    va_list values;
    va_start(values, count);
    for (index = 0; index < count; ++index)
        total += va_arg(values, int32_t);
    va_end(values);
    return total;
}

#if defined(_M_ARM64EC)
int32_t fixture_indirect_x64(int32_t value) {
    int32_t (*volatile target)(int32_t) = fixture_x64_target;
    return target(value);
}

double fixture_indirect_x64_floating(double value) {
    double (*volatile target)(double) = fixture_x64_floating_target;
    return target(value);
}

arm64x_fixture_pair fixture_indirect_x64_aggregate(arm64x_fixture_pair value) {
    arm64x_fixture_pair (*volatile target)(arm64x_fixture_pair) = fixture_x64_aggregate_target;
    return target(value);
}

int64_t fixture_indirect_x64_variadic(uint32_t count, ...) {
    int64_t (*volatile target)(uint32_t, ...) = fixture_x64_variadic_target;
    va_list values;
    int32_t first;
    int32_t second;
    int32_t third;
    int32_t fourth;
    if (count != 4U)
        return INT64_MIN;
    va_start(values, count);
    first = va_arg(values, int32_t);
    second = va_arg(values, int32_t);
    third = va_arg(values, int32_t);
    fourth = va_arg(values, int32_t);
    va_end(values);
    return target(count, first, second, third, fourth);
}
uintptr_t fixture_checker_slot(void) {
    return (uintptr_t)&__os_arm64x_check_icall;
}
#endif

uint32_t fixture_import_probe(void) {
    return GetCurrentProcessId() != 0 ? 1u : 0u;
}
