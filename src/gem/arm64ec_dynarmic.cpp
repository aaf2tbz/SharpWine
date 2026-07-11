// SPDX-License-Identifier: Apache-2.0
#include "arm64ec_engine_internal.h"
#include "memory_internal.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#if !defined(MSWR_DYNARMIC_SYSTEM)
#include "arm64ec_forbidden_register_decoder.h"
#include "dynarmic/frontend/A64/decoder/a64.h"
#endif
#include "dynarmic/interface/exclusive_monitor.h"
#include "dynarmic/interface/halt_reason.h"
#include "dynarmic/interface/optimization_flags.h"

namespace {

constexpr std::uint32_t kNzcvMask = 0xf0000000U;
constexpr std::size_t kVectorBytes = 16U;
constexpr std::size_t kDczvaBytes = 64U;

struct CpuSnapshot {
    std::array<std::uint64_t, 31> regs{};
    std::array<Dynarmic::A64::Vector, 32> vectors{};
    std::uint64_t sp = 0;
    std::uint64_t pc = 0;
    std::uint32_t pstate = 0;
    std::uint32_t fpcr = 0;
    std::uint32_t fpsr = 0;
};

class Environment final : public Dynarmic::A64::UserCallbacks {
  public:
    explicit Environment(gem_arm64ec_runtime *runtime_) : runtime(runtime_) {
    }

    void Attach(Dynarmic::A64::Jit *jit_) {
        jit = jit_;
    }

    void ResetRun() {
        pending_reason = GEM_STOP_NONE;
        pending_access = GEM_ARM64EC_ACCESS_NONE;
        pending_memory_error = GEM_MEMORY_OK;
        pending_fault_address = 0;
        pending_engine_status = 0;
        cache_dirty = false;
        ticks_left = 1;
        cntpct = 0;
    }

    void ResetInstruction() {
        pending_reason = GEM_STOP_NONE;
        pending_access = GEM_ARM64EC_ACCESS_NONE;
        pending_memory_error = GEM_MEMORY_OK;
        pending_fault_address = 0;
        pending_engine_status = 0;
        cache_dirty = false;
        ticks_left = 1;
    }

    std::optional<std::uint32_t> MemoryReadCode(Dynarmic::A64::VAddr vaddr) override {
        std::array<std::uint8_t, sizeof(std::uint32_t)> bytes{};
        if (runtime->target_map != nullptr) {
            gem_arm64ec_target_result target{};
            const gem_arm64ec_target_status status =
                gem_arm64ec_target_resolve(runtime->target_map, vaddr, &target);
            if (status != GEM_ARM64EC_TARGET_OK || target.resolved_va != vaddr ||
                target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
                const gem_stop_reason reason =
                    status == GEM_ARM64EC_TARGET_OK &&
                            target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY
                        ? GEM_STOP_ARCH_TRANSITION
                        : GEM_STOP_INVARIANT_VIOLATION;
                SetStop(reason, status == GEM_ARM64EC_TARGET_OK ? target.resolved_va : vaddr,
                        static_cast<std::uint32_t>(status));
                return std::nullopt;
            }
        }
        const gem_memory_error error =
            gem_memory_fetch(runtime->memory, vaddr, bytes.data(), bytes.size());
        if (error != GEM_MEMORY_OK) {
            SetFault(vaddr, GEM_ARM64EC_ACCESS_FETCH, error);
            return std::nullopt;
        }
        return LoadUnsigned<std::uint32_t>(bytes.data(), bytes.size());
    }

    std::uint8_t MemoryRead8(Dynarmic::A64::VAddr vaddr) override {
        return ReadScalar<std::uint8_t>(vaddr);
    }

    std::uint16_t MemoryRead16(Dynarmic::A64::VAddr vaddr) override {
        return ReadScalar<std::uint16_t>(vaddr);
    }

    std::uint32_t MemoryRead32(Dynarmic::A64::VAddr vaddr) override {
        return ReadScalar<std::uint32_t>(vaddr);
    }

    std::uint64_t MemoryRead64(Dynarmic::A64::VAddr vaddr) override {
        return ReadScalar<std::uint64_t>(vaddr);
    }

    Dynarmic::A64::Vector MemoryRead128(Dynarmic::A64::VAddr vaddr) override {
        return ReadVector(vaddr, true);
    }

    void MemoryWrite8(Dynarmic::A64::VAddr vaddr, std::uint8_t value) override {
        WriteScalar(vaddr, value);
    }

    void MemoryWrite16(Dynarmic::A64::VAddr vaddr, std::uint16_t value) override {
        WriteScalar(vaddr, value);
    }

    void MemoryWrite32(Dynarmic::A64::VAddr vaddr, std::uint32_t value) override {
        WriteScalar(vaddr, value);
    }

    void MemoryWrite64(Dynarmic::A64::VAddr vaddr, std::uint64_t value) override {
        WriteScalar(vaddr, value);
    }

    void MemoryWrite128(Dynarmic::A64::VAddr vaddr, Dynarmic::A64::Vector value) override {
        std::array<std::uint8_t, kVectorBytes> bytes{};
        StoreUnsigned(bytes.data(), value[0], sizeof(value[0]));
        StoreUnsigned(bytes.data() + sizeof(value[0]), value[1], sizeof(value[1]));
        const gem_memory_error error =
            gem_memory_write(runtime->memory, vaddr, bytes.data(), bytes.size());
        if (error != GEM_MEMORY_OK) {
            SetFault(vaddr, GEM_ARM64EC_ACCESS_WRITE, error);
            return;
        }
        /* Clearing Dynarmic's code cache from inside a generated-code memory
         * callback can invalidate the block that is still executing. Defer the
         * invalidation until Step() has returned to the adapter. */
        cache_dirty = true;
    }

    bool MemoryWriteExclusive8(Dynarmic::A64::VAddr vaddr, std::uint8_t value,
                               std::uint8_t expected) override {
        return ExclusiveWriteScalar(vaddr, value, expected);
    }

    bool MemoryWriteExclusive16(Dynarmic::A64::VAddr vaddr, std::uint16_t value,
                                std::uint16_t expected) override {
        return ExclusiveWriteScalar(vaddr, value, expected);
    }

    bool MemoryWriteExclusive32(Dynarmic::A64::VAddr vaddr, std::uint32_t value,
                                std::uint32_t expected) override {
        return ExclusiveWriteScalar(vaddr, value, expected);
    }

    bool MemoryWriteExclusive64(Dynarmic::A64::VAddr vaddr, std::uint64_t value,
                                std::uint64_t expected) override {
        return ExclusiveWriteScalar(vaddr, value, expected);
    }

    bool MemoryWriteExclusive128(Dynarmic::A64::VAddr vaddr, Dynarmic::A64::Vector value,
                                 Dynarmic::A64::Vector expected) override {
        const Dynarmic::A64::Vector current = ReadVector(vaddr, false);
        if (pending_reason != GEM_STOP_NONE)
            return false;
        if (current != expected)
            return false;
        MemoryWrite128(vaddr, value);
        return pending_reason == GEM_STOP_NONE;
    }

    void InterpreterFallback(Dynarmic::A64::VAddr pc, std::size_t num_instructions) override {
        (void)num_instructions;
        SetStop(GEM_STOP_UNSUPPORTED_INSTRUCTION, pc, 0U);
    }

    void CallSVC(std::uint32_t swi) override {
        SetStop(GEM_STOP_SYSCALL, 0U, swi);
    }

    void ExceptionRaised(Dynarmic::A64::VAddr pc, Dynarmic::A64::Exception exception) override {
        const std::uint32_t status = static_cast<std::uint32_t>(exception);
        switch (exception) {
        case Dynarmic::A64::Exception::NoExecuteFault:
            SetFault(pc, GEM_ARM64EC_ACCESS_FETCH, GEM_MEMORY_ACCESS_DENIED);
            break;
        case Dynarmic::A64::Exception::Breakpoint:
            SetStop(GEM_STOP_WINDOWS_EXCEPTION, pc, status);
            break;
        case Dynarmic::A64::Exception::UnallocatedEncoding:
        case Dynarmic::A64::Exception::ReservedValue:
        case Dynarmic::A64::Exception::UnpredictableInstruction:
        case Dynarmic::A64::Exception::WaitForInterrupt:
        case Dynarmic::A64::Exception::WaitForEvent:
        case Dynarmic::A64::Exception::SendEvent:
        case Dynarmic::A64::Exception::SendEventLocal:
        case Dynarmic::A64::Exception::Yield:
            SetStop(GEM_STOP_UNSUPPORTED_INSTRUCTION, pc, status);
            break;
        default:
            SetStop(GEM_STOP_UNSUPPORTED_INSTRUCTION, pc, status);
            break;
        }
    }

    void DataCacheOperationRaised(Dynarmic::A64::DataCacheOperation operation,
                                  Dynarmic::A64::VAddr value) override {
        if (operation == Dynarmic::A64::DataCacheOperation::ZeroByVA) {
            std::array<std::uint8_t, kDczvaBytes> zeroes{};
            const gem_memory_error error =
                gem_memory_write(runtime->memory, value, zeroes.data(), zeroes.size());
            if (error != GEM_MEMORY_OK) {
                SetFault(value, GEM_ARM64EC_ACCESS_WRITE, error);
                return;
            }
        }
        cache_dirty = true;
    }

    void InstructionCacheOperationRaised(Dynarmic::A64::InstructionCacheOperation operation,
                                         Dynarmic::A64::VAddr value) override {
        (void)operation;
        (void)value;
        cache_dirty = true;
    }

    void InstructionSynchronizationBarrierRaised() override {
    }

    void AddTicks(std::uint64_t ticks) override {
        if (ticks > ticks_left)
            ticks_left = 0;
        else
            ticks_left -= ticks;
    }

    std::uint64_t GetTicksRemaining() override {
        return ticks_left;
    }

    std::uint64_t GetCNTPCT() override {
        return cntpct;
    }

    enum gem_stop_reason pending_reason = GEM_STOP_NONE;
    enum gem_arm64ec_memory_access pending_access = GEM_ARM64EC_ACCESS_NONE;
    enum gem_memory_error pending_memory_error = GEM_MEMORY_OK;
    std::uint64_t pending_fault_address = 0;
    std::uint32_t pending_engine_status = 0;
    bool cache_dirty = false;
    std::uint64_t cntpct = 0;

  private:
    template <typename T> static T LoadUnsigned(const std::uint8_t *bytes, std::size_t size) {
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < size; ++index)
            value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
        return static_cast<T>(value);
    }

    static Dynarmic::A64::Vector VectorFromBytes(const std::uint8_t *bytes) {
        return Dynarmic::A64::Vector{
            LoadUnsigned<std::uint64_t>(bytes, sizeof(std::uint64_t)),
            LoadUnsigned<std::uint64_t>(bytes + sizeof(std::uint64_t), sizeof(std::uint64_t))};
    }

    static void StoreUnsigned(std::uint8_t *bytes, std::uint64_t value, std::size_t size) {
        for (std::size_t index = 0; index < size; ++index)
            bytes[index] = static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU);
    }

    Dynarmic::A64::Vector ReadVector(Dynarmic::A64::VAddr vaddr, bool record_read) {
        std::array<std::uint8_t, kVectorBytes> bytes{};
        const gem_memory_error error =
            gem_memory_read(runtime->memory, vaddr, bytes.data(), bytes.size());
        if (error != GEM_MEMORY_OK) {
            SetFault(vaddr, GEM_ARM64EC_ACCESS_READ, error);
            return Dynarmic::A64::Vector{};
        }
        (void)record_read;
        return VectorFromBytes(bytes.data());
    }

    template <typename T> T ReadScalar(Dynarmic::A64::VAddr vaddr, bool record_read = true) {
        std::array<std::uint8_t, sizeof(T)> bytes{};
        const gem_memory_error error =
            gem_memory_read(runtime->memory, vaddr, bytes.data(), bytes.size());
        if (error != GEM_MEMORY_OK) {
            SetFault(vaddr, GEM_ARM64EC_ACCESS_READ, error);
            return 0;
        }
        (void)record_read;
        return LoadUnsigned<T>(bytes.data(), bytes.size());
    }

    template <typename T> void WriteScalar(Dynarmic::A64::VAddr vaddr, T value) {
        std::array<std::uint8_t, sizeof(T)> bytes{};
        StoreUnsigned(bytes.data(), static_cast<std::uint64_t>(value), bytes.size());
        const gem_memory_error error =
            gem_memory_write(runtime->memory, vaddr, bytes.data(), bytes.size());
        if (error != GEM_MEMORY_OK) {
            SetFault(vaddr, GEM_ARM64EC_ACCESS_WRITE, error);
            return;
        }
        cache_dirty = true;
        if (jit != nullptr)
            jit->ClearCache();
    }

    template <typename T>
    bool ExclusiveWriteScalar(Dynarmic::A64::VAddr vaddr, T value, T expected) {
        const T current = ReadScalar<T>(vaddr, false);
        if (pending_reason != GEM_STOP_NONE)
            return false;
        if (current != expected)
            return false;
        WriteScalar(vaddr, value);
        return pending_reason == GEM_STOP_NONE;
    }

    void SetFault(Dynarmic::A64::VAddr vaddr, enum gem_arm64ec_memory_access access,
                  enum gem_memory_error error) {
        if (pending_reason == GEM_STOP_NONE) {
            pending_reason = GEM_STOP_MEMORY_FAULT;
            pending_access = access;
            pending_memory_error = error;
            pending_fault_address = vaddr;
            pending_engine_status = static_cast<std::uint32_t>(error);
        }
        if (jit != nullptr)
            jit->HaltExecution(Dynarmic::HaltReason::MemoryAbort);
    }

    void SetStop(enum gem_stop_reason reason, std::uint64_t address, std::uint32_t status) {
        if (pending_reason == GEM_STOP_NONE) {
            pending_reason = reason;
            pending_fault_address = address;
            pending_engine_status = status;
        }
        if (jit != nullptr)
            jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
    }

    gem_arm64ec_runtime *runtime;
    Dynarmic::A64::Jit *jit = nullptr;
    std::uint64_t ticks_left = 1;
};

struct Backend {
    explicit Backend(gem_arm64ec_runtime *runtime_)
        : env(runtime_), monitor(1), config(MakeConfig()),
          jit(std::make_unique<Dynarmic::A64::Jit>(config)) {
        env.Attach(jit.get());
    }

    void RecreateJit() {
        jit = std::make_unique<Dynarmic::A64::Jit>(config);
        env.Attach(jit.get());
    }

    Dynarmic::A64::UserConfig MakeConfig() {
        Dynarmic::A64::UserConfig user_config{};
        user_config.callbacks = &env;
        user_config.processor_id = 0;
        user_config.global_monitor = &monitor;
        user_config.optimizations = Dynarmic::no_optimizations;
        user_config.unsafe_optimizations = false;
        user_config.hook_data_cache_operations = true;
        user_config.hook_isb = true;
        user_config.hook_hint_instructions = false;
        user_config.page_table = nullptr;
        user_config.fastmem_pointer = std::nullopt;
        user_config.fastmem_exclusive_access = false;
        user_config.define_unpredictable_behaviour = false;
        user_config.wall_clock_cntpct = false;
        user_config.check_halt_on_memory_access = true;
        user_config.enable_cycle_counting = true;
        user_config.code_cache_size = 16U * 1024U * 1024U;
        return user_config;
    }

    Environment env;
    Dynarmic::ExclusiveMonitor monitor;
    Dynarmic::A64::UserConfig config;
    std::unique_ptr<Dynarmic::A64::Jit> jit;
};

CpuSnapshot TakeSnapshot(const Dynarmic::A64::Jit &jit) {
    CpuSnapshot snapshot{};
    snapshot.regs = jit.GetRegisters();
    snapshot.vectors = jit.GetVectors();
    snapshot.sp = jit.GetSP();
    snapshot.pc = jit.GetPC();
    snapshot.pstate = jit.GetPstate();
    snapshot.fpcr = jit.GetFpcr();
    snapshot.fpsr = jit.GetFpsr();
    return snapshot;
}

void RestoreSnapshot(Dynarmic::A64::Jit &jit, const CpuSnapshot &snapshot) {
    jit.SetRegisters(snapshot.regs);
    jit.SetVectors(snapshot.vectors);
    jit.SetSP(snapshot.sp);
    jit.SetPC(snapshot.pc);
    jit.SetPstate(snapshot.pstate);
    jit.SetFpcr(snapshot.fpcr);
    jit.SetFpsr(snapshot.fpsr);
}

void ImportContext(Dynarmic::A64::Jit &jit, const gem_thread_context &context) {
    std::array<std::uint64_t, 31> regs{};
    std::array<Dynarmic::A64::Vector, 32> vectors{};
    for (std::size_t index = 0; index < regs.size(); ++index)
        regs[index] = context.x[index];
    for (std::size_t index = 0; index < 16U; ++index) {
        vectors[index][0] = context.v[index].lo;
        vectors[index][1] = context.v[index].hi;
    }
    jit.SetRegisters(regs);
    jit.SetVectors(vectors);
    jit.SetSP(context.sp);
    jit.SetPC(context.pc);
    jit.SetPstate(context.nzcv & kNzcvMask);
    jit.SetFpcr(context.fpcr);
    jit.SetFpsr(context.fpsr);
    jit.ClearExclusiveState();
}

void ExportContext(const Dynarmic::A64::Jit &jit, gem_thread_context &context) {
    const std::array<std::uint64_t, 31> regs = jit.GetRegisters();
    const std::array<Dynarmic::A64::Vector, 32> vectors = jit.GetVectors();
    for (std::size_t index = 0; index < regs.size(); ++index)
        context.x[index] = regs[index];
    for (std::size_t index = 0; index < 16U; ++index) {
        context.v[index].lo = vectors[index][0];
        context.v[index].hi = vectors[index][1];
    }
    context.sp = jit.GetSP();
    context.pc = jit.GetPC();
    context.nzcv = jit.GetPstate() & kNzcvMask;
    context.fpcr = jit.GetFpcr();
    context.fpsr = jit.GetFpsr();
}

void SetStopInfo(gem_arm64ec_runtime &runtime, enum gem_stop_reason reason, std::uint64_t retired,
                 std::uint64_t fault_address, enum gem_arm64ec_memory_access access,
                 enum gem_memory_error memory_error, std::uint32_t engine_status) {
    runtime.last_stop.reason = reason;
    runtime.last_stop.instructions_retired = retired;
    runtime.last_stop.fault_address = fault_address;
    runtime.last_stop.access = access;
    runtime.last_stop.memory_error = static_cast<std::uint32_t>(memory_error);
    runtime.last_stop.engine_status = engine_status;
}

bool HasHalt(Dynarmic::HaltReason value, Dynarmic::HaltReason flag) {
    return Dynarmic::Has(value, flag);
}

bool FetchInstruction(gem_arm64ec_runtime &runtime, std::uint64_t pc, std::uint32_t &word,
                      gem_memory_error &error) {
    std::array<std::uint8_t, sizeof(word)> bytes{};
    error = gem_memory_fetch(runtime.memory, pc, bytes.data(), bytes.size());
    if (error != GEM_MEMORY_OK)
        return false;
    word = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index)
        word |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
    return true;
}

bool IsBrk(std::uint32_t word) {
    return (word & 0xffe0001fU) == 0xd4200000U;
}

bool IsUdf(std::uint32_t word) {
    return (word & 0xffff0000U) == 0x00000000U;
}

/* Decode against the exact pinned Dynarmic operand schema.  The generated
 * visitor records every Reg and Vec argument supplied by that schema, including
 * GPR/SIMD transfer, indexed, pair, list, and addressing operands.  An encoding
 * absent from the decoder is deliberately unsupported: allowing an ambiguous
 * word could let a disallowed architectural operand reach Step(). */
bool HasForbiddenArm64ecRegister(std::uint32_t word) {
#if defined(MSWR_DYNARMIC_SYSTEM)
    (void)word;
    /* A system library does not expose the pinned operand schema. Do not run
     * unchecked guest instructions in this explicitly non-conformance mode. */
    return true;
#else
    const auto decoded = Dynarmic::A64::Decode<mswr::ForbiddenRegisterVisitor>(word);
    if (!decoded.has_value())
        return true;
    mswr::ForbiddenRegisterVisitor visitor{};
    (void)decoded->get().call(visitor, word);
    return visitor.forbidden;
#endif
}

void ClearTransientHalts(Dynarmic::A64::Jit &jit) {
    jit.ClearHalt(Dynarmic::HaltReason::Step);
    jit.ClearHalt(Dynarmic::HaltReason::CacheInvalidation);
    jit.ClearHalt(Dynarmic::HaltReason::MemoryAbort);
    jit.ClearHalt(Dynarmic::HaltReason::UserDefined1);
}

} // namespace

extern "C" bool gem_arm64ec_dynarmic_create(struct gem_arm64ec_runtime *runtime) {
    if (runtime == nullptr)
        return false;
    try {
        runtime->backend = new Backend(runtime);
        return true;
    } catch (...) {
        runtime->backend = nullptr;
        return false;
    }
}

extern "C" void gem_arm64ec_dynarmic_destroy(struct gem_arm64ec_runtime *runtime) {
    if (runtime != nullptr) {
        delete static_cast<Backend *>(runtime->backend);
        runtime->backend = nullptr;
    }
}

extern "C" enum gem_stop_reason gem_arm64ec_dynarmic_run(struct gem_arm64ec_runtime *runtime,
                                                         struct gem_thread_context *context,
                                                         std::uint64_t budget) {
    if (runtime == nullptr || context == nullptr || runtime->backend == nullptr)
        return GEM_STOP_INVARIANT_VIOLATION;

    Backend &backend = *static_cast<Backend *>(runtime->backend);
    Dynarmic::A64::Jit &jit = *backend.jit;
    std::uint64_t retired = 0;

    backend.env.ResetRun();
    backend.monitor.Clear();
    jit.Reset();
    jit.ClearExclusiveState();
    jit.ClearCache();
    ImportContext(jit, *context);
    ClearTransientHalts(jit);

    while (retired < budget) {
        std::uint64_t pc_before = jit.GetPC();
        gem_arm64ec_target_kind target_kind = GEM_ARM64EC_TARGET_ARM64EC;
        bool broker_resumed = false;
        if (runtime->boundary_broker != nullptr) {
            gem_thread_context broker_context = *context;
            gem_arm64ec_boundary_kind boundary_kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
            ExportContext(jit, broker_context);
            const gem_arm64ec_boundary_action action = runtime->boundary_broker(
                runtime->boundary_opaque, pc_before, &broker_context, &boundary_kind);
            if (action != GEM_ARM64EC_BOUNDARY_NOT_HANDLED) {
                if (boundary_kind < GEM_ARM64EC_BOUNDARY_CHECK_ICALL ||
                    boundary_kind > GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN ||
                    action == GEM_ARM64EC_BOUNDARY_FAIL || !gem_context_is_valid(&broker_context) ||
                    broker_context.x[18] != context->teb ||
                    (action == GEM_ARM64EC_BOUNDARY_STOP && broker_context.pc != pc_before) ||
                    (action == GEM_ARM64EC_BOUNDARY_RESUME && broker_context.pc == pc_before) ||
                    (runtime->config.max_transitions != 0U &&
                     runtime->transition_count >= runtime->config.max_transitions)) {
                    ExportContext(jit, *context);
                    SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired, pc_before,
                                GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK,
                                static_cast<std::uint32_t>(action));
                    return GEM_STOP_INVARIANT_VIOLATION;
                }
                ++runtime->transition_count;
                if (action == GEM_ARM64EC_BOUNDARY_STOP) {
                    *context = broker_context;
                    SetStopInfo(*runtime, GEM_STOP_ARCH_TRANSITION, retired, pc_before,
                                GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK,
                                static_cast<std::uint32_t>(boundary_kind));
                    return GEM_STOP_ARCH_TRANSITION;
                }
                if (action != GEM_ARM64EC_BOUNDARY_RESUME) {
                    ExportContext(jit, *context);
                    SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired, pc_before,
                                GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK,
                                static_cast<std::uint32_t>(action));
                    return GEM_STOP_INVARIANT_VIOLATION;
                }
                ImportContext(jit, broker_context);
                *context = broker_context;
                pc_before = broker_context.pc;
                broker_resumed = true;
            }
        }
        if (pc_before == runtime->config.host_return_sentinel &&
            (runtime->target_map == nullptr || broker_resumed)) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_HOST_RETURN, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK, 0);
            return GEM_STOP_HOST_RETURN;
        }
        if (pc_before == runtime->config.arch_transition_sentinel &&
            (runtime->target_map == nullptr || broker_resumed)) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_ARCH_TRANSITION, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK, 0);
            return GEM_STOP_ARCH_TRANSITION;
        }
        if (runtime->target_map != nullptr) {
            gem_arm64ec_target_result target{};
            const gem_arm64ec_target_status target_status =
                gem_arm64ec_target_resolve(runtime->target_map, pc_before, &target);
            if (target_status != GEM_ARM64EC_TARGET_OK) {
                ExportContext(jit, *context);
                SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired, pc_before,
                            GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK,
                            static_cast<std::uint32_t>(target_status));
                return GEM_STOP_INVARIANT_VIOLATION;
            }
            if (target.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY) {
                jit.SetPC(target.resolved_va);
                ExportContext(jit, *context);
                SetStopInfo(*runtime, GEM_STOP_ARCH_TRANSITION, retired, target.resolved_va,
                            GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK, 0);
                return GEM_STOP_ARCH_TRANSITION;
            }
            target_kind = target.kind;
            if (target.resolved_va != pc_before) {
                jit.SetPC(target.resolved_va);
                pc_before = target.resolved_va;
            }
        }
        std::uint32_t instruction = 0;
        gem_memory_error fetch_error = GEM_MEMORY_OK;
        if (!FetchInstruction(*runtime, pc_before, instruction, fetch_error)) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_MEMORY_FAULT, retired, pc_before,
                        GEM_ARM64EC_ACCESS_FETCH, fetch_error,
                        static_cast<std::uint32_t>(fetch_error));
            return GEM_STOP_MEMORY_FAULT;
        }
        /* Dynarmic's A64 native backend deliberately has no Interpret emitter
         * for these architecturally trapping encodings.  They are classified
         * only after the checked GEM fetch above; no state or guest memory is
         * changed on this fallback path. */
        if (IsBrk(instruction) || IsUdf(instruction)) {
            const enum gem_stop_reason reason =
                IsBrk(instruction) ? GEM_STOP_WINDOWS_EXCEPTION : GEM_STOP_UNSUPPORTED_INSTRUCTION;
            ExportContext(jit, *context);
            SetStopInfo(*runtime, reason, retired, pc_before, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK, instruction);
            return reason;
        }
        if (target_kind == GEM_ARM64EC_TARGET_ARM64EC && HasForbiddenArm64ecRegister(instruction)) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_UNSUPPORTED_INSTRUCTION, retired, pc_before,
                        GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK, instruction);
            return GEM_STOP_UNSUPPORTED_INSTRUCTION;
        }

        backend.env.ResetInstruction();
        const CpuSnapshot before = TakeSnapshot(jit);
        const Dynarmic::HaltReason halt = jit.Step();

        if (backend.env.cache_dirty || HasHalt(halt, Dynarmic::HaltReason::CacheInvalidation))
            jit.ClearCache();

        if (backend.env.pending_reason == GEM_STOP_ARCH_TRANSITION) {
            if (jit.GetPC() == backend.env.pending_fault_address &&
                jit.GetRegister(18) == context->teb) {
                ++retired;
                ExportContext(jit, *context);
                SetStopInfo(*runtime, GEM_STOP_ARCH_TRANSITION, retired,
                            backend.env.pending_fault_address, GEM_ARM64EC_ACCESS_NONE,
                            GEM_MEMORY_OK, 0);
                ClearTransientHalts(jit);
                return GEM_STOP_ARCH_TRANSITION;
            }
            RestoreSnapshot(jit, before);
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired,
                        backend.env.pending_fault_address, GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK,
                        backend.env.pending_engine_status);
            ClearTransientHalts(jit);
            return GEM_STOP_INVARIANT_VIOLATION;
        }

        if (backend.env.pending_reason != GEM_STOP_NONE) {
            RestoreSnapshot(jit, before);
            ExportContext(jit, *context);
            SetStopInfo(*runtime, backend.env.pending_reason, retired,
                        backend.env.pending_fault_address, backend.env.pending_access,
                        backend.env.pending_memory_error, backend.env.pending_engine_status);
            ClearTransientHalts(jit);
            return backend.env.pending_reason;
        }

        if (HasHalt(halt, Dynarmic::HaltReason::MemoryAbort)) {
            RestoreSnapshot(jit, before);
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK,
                        static_cast<std::uint32_t>(Dynarmic::HaltReason::MemoryAbort));
            ClearTransientHalts(jit);
            return GEM_STOP_INVARIANT_VIOLATION;
        }

        ++retired;
        backend.env.cntpct = retired;
        if (jit.GetRegister(18) != context->teb) {
            RestoreSnapshot(jit, before);
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_INVARIANT_VIOLATION, retired - 1U, 0,
                        GEM_ARM64EC_ACCESS_NONE, GEM_MEMORY_OK, 0);
            ClearTransientHalts(jit);
            return GEM_STOP_INVARIANT_VIOLATION;
        }

        const std::uint64_t pc_after = jit.GetPC();
        if (runtime->target_map == nullptr && pc_after == runtime->config.host_return_sentinel) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_HOST_RETURN, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK, 0);
            ClearTransientHalts(jit);
            return GEM_STOP_HOST_RETURN;
        }
        if (runtime->target_map == nullptr &&
            pc_after == runtime->config.arch_transition_sentinel) {
            ExportContext(jit, *context);
            SetStopInfo(*runtime, GEM_STOP_ARCH_TRANSITION, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                        GEM_MEMORY_OK, 0);
            ClearTransientHalts(jit);
            return GEM_STOP_ARCH_TRANSITION;
        }
        ClearTransientHalts(jit);
    }

    ExportContext(jit, *context);
    SetStopInfo(*runtime, GEM_STOP_BUDGET_EXPIRED, retired, 0, GEM_ARM64EC_ACCESS_NONE,
                GEM_MEMORY_OK, 0);
    return GEM_STOP_BUDGET_EXPIRED;
}

extern "C" void gem_arm64ec_dynarmic_invalidate_code(struct gem_arm64ec_runtime *runtime,
                                                     std::uint64_t address, std::uint64_t size) {
    if (runtime == nullptr || runtime->backend == nullptr || size == 0U)
        return;
    Backend &backend = *static_cast<Backend *>(runtime->backend);
    backend.RecreateJit();
    (void)address;
    (void)size;
}

extern "C" const char *gem_arm64ec_dynarmic_engine_name(void) {
    return "Dynarmic";
}

extern "C" const char *gem_arm64ec_dynarmic_engine_version(void) {
    return "6.7.0";
}

extern "C" const char *gem_arm64ec_dynarmic_engine_license(void) {
    return "ISC";
}

extern "C" const char *gem_arm64ec_dynarmic_engine_provenance(void) {
#if defined(MSWR_DYNARMIC_SYSTEM)
    return "system (non-conformance developer mode)";
#else
    return "https://github.com/lioncash/dynarmic.git@a41c380246d3d9f9874f0f792d234dc0cc17c180";
#endif
}
