# SPDX-License-Identifier: Apache-2.0
# Apply the two local compatibility changes required by the pinned Dynarmic
# source.  Keep each replacement fail-closed so a dependency update cannot
# silently carry stale integration assumptions.
#
# Dynarmic 6.7.0's native ARM64 callback trampolines assume that a 16-byte
# aggregate returned by a C++ member function is returned in x0/x1. MSVC's
# Windows ARM64 ABI instead passes a result-buffer pointer in x1 and shifts the
# first explicit member-function argument to x2. Adapt only the three Vector
# read trampolines; scalar and Vector write callbacks already match MSVC's ABI.

if(NOT DEFINED DYNARMIC_SOURCE_DIR)
    message(FATAL_ERROR "DYNARMIC_SOURCE_DIR is required")
endif()

set(source "${DYNARMIC_SOURCE_DIR}/src/dynarmic/backend/arm64/a64_address_space.cpp")
file(READ "${source}" contents)

set(normal_old [=[    code.LDR(X0, l_this);
    code.LDR(Xscratch0, l_addr);
    code.BLR(Xscratch0);
    code.FMOV(D0, X0);
    code.FMOV(V0.D()[1], X1);
    ABI_PopRegisters(code, (1ull << 29) | (1ull << 30), 0);
]=])
set(normal_new [=[    code.LDR(X0, l_this);
#if defined(_WIN32) && defined(_MSC_VER)
    code.MOV(X2, X1);
    code.SUB(SP, SP, 16);
    code.MOV(X1, SP);
#endif
    code.LDR(Xscratch0, l_addr);
    code.BLR(Xscratch0);
#if defined(_WIN32) && defined(_MSC_VER)
    code.LDP(X0, X1, SP, 0);
    code.ADD(SP, SP, 16);
#else
    code.FMOV(D0, X0);
    code.FMOV(V0.D()[1], X1);
#endif
    ABI_PopRegisters(code, (1ull << 29) | (1ull << 30), 0);
]=])
set(wrapped_old [=[    code.LDR(X0, l_this);
    code.MOV(X1, Xscratch0);
    code.LDR(Xscratch0, l_addr);
    code.BLR(Xscratch0);
    code.FMOV(D0, X0);
    code.FMOV(V0.D()[1], X1);
    ABI_PopRegisters(code, save_regs, 0);
]=])
set(wrapped_new [=[    code.LDR(X0, l_this);
#if defined(_WIN32) && defined(_MSC_VER)
    code.MOV(X2, Xscratch0);
    code.SUB(SP, SP, 16);
    code.MOV(X1, SP);
#else
    code.MOV(X1, Xscratch0);
#endif
    code.LDR(Xscratch0, l_addr);
    code.BLR(Xscratch0);
#if defined(_WIN32) && defined(_MSC_VER)
    code.LDP(X0, X1, SP, 0);
    code.ADD(SP, SP, 16);
#else
    code.FMOV(D0, X0);
    code.FMOV(V0.D()[1], X1);
#endif
    ABI_PopRegisters(code, save_regs, 0);
]=])

string(FIND "${contents}" "${normal_old}" normal_offset)
string(FIND "${contents}" "${wrapped_old}" wrapped_offset)
string(FIND "${contents}" "${normal_new}" normal_new_offset)
string(FIND "${contents}" "${wrapped_new}" wrapped_new_offset)
if(normal_offset EQUAL -1 AND wrapped_offset EQUAL -1 AND
   NOT normal_new_offset EQUAL -1 AND NOT wrapped_new_offset EQUAL -1)
    set(callbacks_already_patched TRUE)
elseif(normal_offset EQUAL -1 OR wrapped_offset EQUAL -1 OR
       NOT normal_new_offset EQUAL -1 OR NOT wrapped_new_offset EQUAL -1)
    message(FATAL_ERROR "pinned Dynarmic ARM64 callback trampoline text changed or is partially patched")
endif()

if(NOT callbacks_already_patched)
    string(REPLACE "${normal_old}" "${normal_new}" contents "${contents}")
    string(REPLACE "${wrapped_old}" "${wrapped_new}" contents "${contents}")
    string(FIND "${contents}" "${normal_old}" remaining_normal_offset)
    string(FIND "${contents}" "${wrapped_old}" remaining_wrapped_offset)
    if(NOT remaining_normal_offset EQUAL -1 OR NOT remaining_wrapped_offset EQUAL -1)
        message(FATAL_ERROR "failed to patch all Dynarmic ARM64 Vector read trampolines")
    endif()
    file(WRITE "${source}" "${contents}")
endif()

# The macOS fastmem backend installs a task-wide Mach EXC_BAD_ACCESS port as
# soon as an A64 JIT is created. MetalSharp's checked-memory profile does not
# use fastmem, and issue #23 requires Wine to retain its ordinary per-thread
# Unix signal path. Select Dynarmic's inert generic handler on Apple hosts;
# checked guest faults continue through the explicit memory callbacks.
set(cmake_source "${DYNARMIC_SOURCE_DIR}/src/dynarmic/CMakeLists.txt")
file(READ "${cmake_source}" cmake_contents)
set(macos_old [=[elseif (APPLE)
    find_path(MACH_EXC_DEFS_DIR "mach/mach_exc.defs")
]=])
set(macos_new [=[elseif (APPLE)
    message(STATUS "macOS fastmem disabled for MetalSharp checked-memory integration")
    target_sources(dynarmic PRIVATE backend/exception_handler_generic.cpp)
elseif (FALSE) # Upstream macOS fastmem path intentionally disabled by MetalSharp.
    find_path(MACH_EXC_DEFS_DIR "mach/mach_exc.defs")
]=])
string(FIND "${cmake_contents}" "${macos_old}" macos_offset)
string(FIND "${cmake_contents}" "${macos_new}" macos_new_offset)
if(macos_offset EQUAL -1 AND NOT macos_new_offset EQUAL -1)
    set(macos_already_patched TRUE)
elseif(macos_offset EQUAL -1 OR NOT macos_new_offset EQUAL -1)
    message(FATAL_ERROR "pinned Dynarmic macOS exception-handler selection changed or is partially patched")
endif()
if(NOT macos_already_patched)
    string(REPLACE "${macos_old}" "${macos_new}" cmake_contents "${cmake_contents}")
    file(WRITE "${cmake_source}" "${cmake_contents}")
endif()

# Do not enter a translated block that exceeds the exact GEM budget.  The
# engine resumes with Jit::Step() for the remaining bounded tail.
set(emit_source "${DYNARMIC_SOURCE_DIR}/src/dynarmic/backend/arm64/emit_arm64.cpp")
file(READ "${emit_source}" emit_contents)
set(budget_old [=[    ebi.entry_point = code.xptr<CodePtr>();

    if (ctx.block.GetCondition() == IR::Cond::AL) {]=])
set(budget_new [=[    ebi.entry_point = code.xptr<CodePtr>();

    if (conf.enable_cycle_counting) {
        oaknut::Label enough_ticks, halt_loop;
        const size_t max_cycles = block.CycleCount();
        code.CMP(Xticks, max_cycles);
        code.B(HS, enough_ticks);
        code.l(halt_loop);
        code.LDAXR(Wscratch0, Xhalt);
        code.ORR(Wscratch0, Wscratch0, static_cast<u32>(HaltReason::UserDefined2));
        code.STLXR(Wscratch1, Wscratch0, Xhalt);
        code.CBNZ(Wscratch1, halt_loop);
        EmitRelocation(code, ctx, LinkTarget::ReturnToDispatcher);
        code.l(enough_ticks);
    }

    if (ctx.block.GetCondition() == IR::Cond::AL) {]=])
string(FIND "${emit_contents}" "#include \"dynarmic/interface/halt_reason.h\"" halt_include_offset)
if(halt_include_offset EQUAL -1)
    string(REPLACE [=[#include "dynarmic/ir/basic_block.h"
]=] [=[#include "dynarmic/interface/halt_reason.h"
#include "dynarmic/ir/basic_block.h"
]=] emit_contents "${emit_contents}")
endif()
string(FIND "${emit_contents}" "${budget_old}" budget_offset)
string(FIND "${emit_contents}" "${budget_new}" budget_new_offset)
if(budget_offset EQUAL -1 AND NOT budget_new_offset EQUAL -1)
    set(budget_already_patched TRUE)
elseif(budget_offset EQUAL -1 OR NOT budget_new_offset EQUAL -1)
    message(FATAL_ERROR "pinned Dynarmic ARM64 budget-guard text changed or is partially patched")
endif()
if(NOT budget_already_patched)
    string(REPLACE "${budget_old}" "${budget_new}" emit_contents "${emit_contents}")
    file(WRITE "${emit_source}" "${emit_contents}")
endif()

# A directly linked block has not passed through the dispatcher, so its guest
# PC is not yet present in JIT state. Record the destination before following
# the link; if the destination's exact-budget guard returns to the dispatcher,
# GEM can then execute the correct bounded tail instead of resuming a stale PC.
set(a64_terminal_source "${DYNARMIC_SOURCE_DIR}/src/dynarmic/backend/arm64/emit_arm64_a64.cpp")
file(READ "${a64_terminal_source}" a64_terminal_contents)
set(link_old [=[            code.CMP(Xticks, 0);
            code.B(LE, fail);
            EmitBlockLinkRelocation(code, ctx, terminal.next, BlockRelocationType::Branch);]=])
set(link_new [=[            code.CMP(Xticks, 0);
            code.B(LE, fail);
            code.MOV(Xscratch0, A64::LocationDescriptor{terminal.next}.PC());
            code.STR(Xscratch0, Xstate, offsetof(A64JitState, pc));
            EmitBlockLinkRelocation(code, ctx, terminal.next, BlockRelocationType::Branch);]=])
string(FIND "${a64_terminal_contents}" "${link_old}" link_offset)
string(FIND "${a64_terminal_contents}" "${link_new}" link_new_offset)
if(link_offset EQUAL -1 AND NOT link_new_offset EQUAL -1)
    set(link_already_patched TRUE)
elseif(link_offset EQUAL -1 OR NOT link_new_offset EQUAL -1)
    message(FATAL_ERROR "pinned Dynarmic ARM64 linked-block text changed or is partially patched")
endif()
if(NOT link_already_patched)
    string(REPLACE "${link_old}" "${link_new}" a64_terminal_contents "${a64_terminal_contents}")
    file(WRITE "${a64_terminal_source}" "${a64_terminal_contents}")
endif()
