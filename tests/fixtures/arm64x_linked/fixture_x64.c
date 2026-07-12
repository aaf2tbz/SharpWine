// SPDX-License-Identifier: Apache-2.0
#include "fixture_api.h"

#include <stdarg.h>

int32_t fixture_x64_target(int32_t value) {
    return value * 3 + 7;
}

uint64_t fixture_x64_normal_return(uint64_t value) {
    return value * UINT64_C(3) + UINT64_C(17);
}

uint64_t fixture_x64_callback_path(uint64_t value) {
    const uint64_t callback = fixture_arm_callback(value + UINT64_C(2));
    return callback + UINT64_C(19);
}

uint64_t fixture_x64_tail_target(uint64_t value) {
    return value ^ UINT64_C(0x5a5a);
}

uint64_t fixture_x64_nested_inner(uint64_t value) {
    return value * UINT64_C(2) + UINT64_C(13);
}

uint64_t fixture_x64_nested_outer(uint64_t value) {
    return fixture_arm_nested_callback(value + UINT64_C(5)) + UINT64_C(17);
}

double fixture_x64_floating_target(double value) {
    return value * 2.0 - 0.5;
}

arm64x_fixture_pair fixture_x64_aggregate_target(arm64x_fixture_pair value) {
    arm64x_fixture_pair result = {value.second - 3, value.first + 5};
    return result;
}

int64_t fixture_x64_variadic_target(uint32_t count, ...) {
    int64_t total = 0;
    uint32_t index;
    va_list values;
    va_start(values, count);
    for (index = 0; index < count; ++index)
        total += va_arg(values, int32_t);
    va_end(values);
    return total;
}
