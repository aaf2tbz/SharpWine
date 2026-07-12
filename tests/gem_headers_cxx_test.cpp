// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/arm64ec_target.h"
#include "metalsharp/gem/context.h"
#include "metalsharp/gem/context_conversion.h"
#include "metalsharp/gem/context_serialization.h"
#include "metalsharp/gem/hybrid_runtime.h"
#include "metalsharp/gem/memory.h"
#include "metalsharp/gem/pe_arm64x.h"
#include "metalsharp/gem/pe_arm64x_loader.h"
#include "metalsharp/gem/x64_engine.h"

#include <type_traits>

static_assert(std::is_standard_layout<gem_thread_context>::value,
              "context must remain C++ ABI-safe");
static_assert(GEM_GUEST_PAGE_SIZE == 4096U, "guest page contract changed");

int main() {
    gem_x64_context state{};
    return state.teb == 0U ? 0 : 1;
}
