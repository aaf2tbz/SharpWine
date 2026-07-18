// SPDX-License-Identifier: Apache-2.0
#include "hybrid_runtime_internal.h"
#include "metalsharp/gem/arm64ec_target.h"
#include "metalsharp/gem/context.h"
#include "metalsharp/gem/context_conversion.h"
#include "metalsharp/gem/hybrid_runtime.h"
#include "metalsharp/gem/pe_arm64x_loader.h"
#include "metalsharp/gem/x64_engine.h"
#include "x64_engine_trace.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t kStackBase = UINT64_C(0x0000000400000000);
constexpr std::uint64_t kStackSize = UINT64_C(0x10000);
constexpr std::uint64_t kWriteCopyStackAlias = UINT64_C(0x0000000500000000);
constexpr std::uint64_t kChecker = UINT64_C(0xfffffffffffffd00);
constexpr std::uint64_t kDispatchCall = UINT64_C(0xfffffffffffffc00);
constexpr std::uint64_t kDispatchRet = UINT64_C(0xfffffffffffffb00);
constexpr std::uint64_t kX64Return = UINT64_C(0xfffffffffffffa00);
constexpr std::uint64_t kHostReturn = UINT64_C(0xfffffffffffff900);

std::vector<std::uint8_t> read_binary(const char *path) {
    std::ifstream input(path, std::ios::binary);
    assert(input);
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    assert(size > 0 && size <= 64 * 1024 * 1024);
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    assert(input.read(reinterpret_cast<char *>(bytes.data()), size));
    return bytes;
}

struct NativeOracle {
    std::uint64_t roundtrip_input;
    std::uint64_t roundtrip_result;
    std::uint64_t direct_result;
    std::uint64_t callback_resume_result;
    std::uint64_t tail_transfer_result;
    std::uint64_t nested_result;
};

NativeOracle read_native_oracle(const char *path) {
    std::ifstream input(path, std::ios::binary);
    assert(input);
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    const std::string expected =
        "{\"schemaVersion\":2,\"nativeMachine\":\"arm64\",\"roundtripInput\":12,"
        "\"roundtripResult\":30,\"directResult\":47,\"callbackResumeResult\":82,"
        "\"tailTransferResult\":23120,\"nestedResult\":85,\"passed\":true}\n";
    assert(text == expected);
    return {12U, 30U, 47U, 82U, 23120U, 85U};
}

std::map<std::string, std::uint32_t> read_map(const char *path) {
    std::ifstream input(path);
    std::string header;
    std::map<std::string, std::uint32_t> result;
    assert(input && std::getline(input, header) && header == "MSWR_ARM64EC_ENTRY_MAP_V3");
    std::string name;
    std::string value;
    while (input >> name >> value) {
        assert(value.size() == 8U && result.find(name) == result.end());
        std::size_t consumed = 0U;
        const auto parsed = std::stoul(value, &consumed, 16);
        assert(consumed == value.size() && parsed <= UINT32_MAX);
        result.emplace(name, static_cast<std::uint32_t>(parsed));
    }
    assert(input.eof());
    const std::array<const char *, 15> required = {
        "integer",      "floating",         "aggregate",      "variadic",
        "roundtrip",    "finish",           "direct",         "callbackResume",
        "tailTransfer", "boundedNested",    "armCallback",    "armNestedCallback",
        "checkerSlot",  "dispatchCallSlot", "dispatchRetSlot"};
    assert(result.size() == required.size());
    for (const auto *key : required)
        assert(result.find(key) != result.end());
    return result;
}

struct Harness {
    Harness() = default;
    Harness(const Harness &) = delete;
    Harness &operator=(const Harness &) = delete;
    Harness(Harness &&other) noexcept
        : memory(other.memory), materialized(other.materialized), map(other.map),
          caller(other.caller), finish(other.finish) {
        other.memory = nullptr;
        other.materialized = nullptr;
        other.map = nullptr;
    }

    gem_memory *memory{};
    gem_pe_arm64x_materialized_image *materialized{};
    gem_arm64ec_target_map *map{};
    std::uint64_t caller{};
    std::uint64_t finish{};

    ~Harness() {
        gem_arm64ec_target_map_destroy(map);
        gem_pe_arm64x_materialized_image_destroy(materialized);
        gem_memory_destroy(memory);
    }
};

Harness make_harness(const std::vector<std::uint8_t> &bytes,
                     const std::map<std::string, std::uint32_t> &entries) {
    Harness harness;
    harness.memory = gem_memory_create();
    assert(harness.memory);
    /* The linked direct/tail exit thunks load the non-CFG checker from RVA
     * 0x7010. Keep it bound separately from the exported CFG checker slot. */
    const std::array<gem_pe_arm64x_binding, 4> bindings{{
        {entries.at("checkerSlot"), kChecker},
        {UINT32_C(0x7010), kChecker},
        {entries.at("dispatchCallSlot"), kDispatchCall},
        {entries.at("dispatchRetSlot"), kDispatchRet},
    }};
    gem_pe_arm64x_materialize_options options{};
    options.version = GEM_PE_ARM64X_MATERIALIZE_OPTIONS_VERSION;
    options.image_base = UINT64_C(0x180000000);
    options.bindings = bindings.data();
    options.binding_count = bindings.size();
    const auto materialize_status = gem_pe_arm64x_materialize_preferred(
        harness.memory, bytes.data(), bytes.size(), &options, &harness.materialized);
    if (materialize_status != GEM_PE_MATERIALIZE_OK)
        std::fprintf(stderr, "materialize failed: %s\n",
                     gem_pe_materialize_status_name(materialize_status));
    assert(materialize_status == GEM_PE_MATERIALIZE_OK);
    const auto *metadata = gem_pe_arm64x_materialized_metadata(harness.materialized);
    assert(metadata);
    assert(gem_arm64ec_target_map_create(metadata, options.image_base, &harness.map) ==
           GEM_ARM64EC_TARGET_OK);
    gem_arm64ec_target_result target{};
    assert(gem_arm64ec_target_resolve(harness.map, options.image_base + entries.at("roundtrip"),
                                      &target) == GEM_ARM64EC_TARGET_OK);
    assert(target.kind == GEM_ARM64EC_TARGET_ARM64EC && target.redirection_hops == 1U);
    harness.caller = target.resolved_va;
    assert(gem_arm64ec_target_resolve(harness.map, options.image_base + entries.at("finish"),
                                      &target) == GEM_ARM64EC_TARGET_OK);
    assert(target.kind == GEM_ARM64EC_TARGET_ARM64EC && target.redirection_hops == 1U);
    harness.finish = target.resolved_va;
    std::uint64_t stack = kStackBase;
    assert(gem_memory_reserve(harness.memory, &stack, kStackSize) == GEM_MEMORY_OK);
    assert(gem_memory_commit(harness.memory, stack, kStackSize, GEM_PAGE_READWRITE) ==
           GEM_MEMORY_OK);
    return harness;
}

gem_hybrid_runtime_config runtime_config() {
    gem_hybrid_runtime_config config{};
    config.version = GEM_HYBRID_RUNTIME_CONFIG_VERSION;
    config.loaded_base = UINT64_C(0x180000000);
    config.checker_helper = kChecker;
    config.dispatch_call_helper = kDispatchCall;
    config.dispatch_ret_helper = kDispatchRet;
    config.x64_return_sentinel = kX64Return;
    config.host_return_sentinel = kHostReturn;
    config.max_budget = 10000U;
    return config;
}

gem_thread_context initial_context(std::uint64_t caller) {
    gem_thread_context context{};
    gem_context_initialize(&context, UINT64_C(0x70000000), GEM_ISA_ARM64EC);
    context.pc = caller;
    context.sp = kStackBase + kStackSize - UINT64_C(0x100);
    context.x[30] = kHostReturn;
    context.x[0] = 12U;
    for (unsigned index = 0; index < 16U; ++index) {
        context.v[index].lo = UINT64_C(0x1000000000000000) + index;
        context.v[index].hi = UINT64_C(0x2000000000000000) + index;
    }
    for (unsigned index = 0; index < 8U; ++index) {
        context.x87[index].lo = UINT64_C(0x3000000000000000) + index;
        context.x87[index].hi = UINT64_C(0x4000000000000000) + index;
    }
    return context;
}

std::uint64_t fnv1a(const std::uint8_t *data, std::size_t size);

void fill_stack_oracle(gem_memory *memory, std::uint8_t seed) {
    std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>(seed + i * 17U);
    assert(gem_memory_write(memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE, bytes.data(),
                            bytes.size()) == GEM_MEMORY_OK);
}

void assert_stack_oracle(const std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> &before,
                         const std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> &after,
                         std::uint64_t expected_hash, std::size_t first_touched,
                         std::size_t last_touched) {
    assert(first_touched <= last_touched && last_touched < after.size());
    assert(fnv1a(after.data(), after.size()) == expected_hash);
    assert(std::equal(before.begin(), before.begin() + first_touched, after.begin()));
    assert(std::equal(before.begin() + last_touched + 1U, before.end(),
                      after.begin() + last_touched + 1U));
}

void assert_context_oracle(const gem_thread_context &actual, const gem_thread_context &expected) {
    if (std::memcmp(&actual, &expected, sizeof(actual)) != 0) {
        std::array<std::uint64_t, sizeof(actual) / sizeof(std::uint64_t)> actual_words{};
        std::array<std::uint64_t, sizeof(expected) / sizeof(std::uint64_t)> expected_words{};
        std::memcpy(actual_words.data(), &actual, sizeof(actual));
        std::memcpy(expected_words.data(), &expected, sizeof(expected));
        for (std::size_t offset = 0; offset < sizeof(actual); offset += sizeof(std::uint64_t)) {
            const auto index = offset / sizeof(std::uint64_t);
            if (actual_words[index] != expected_words[index])
                std::fprintf(stderr,
                             "context mismatch offset=%zu actual=%016llx expected=%016llx\n",
                             offset, static_cast<unsigned long long>(actual_words[index]),
                             static_cast<unsigned long long>(expected_words[index]));
        }
        assert(false && "context oracle mismatch");
    }
}
/* Authentic ARM64X first-boundary transitions captured against the validated
 * issue14-5 evidence build. The expected stop RVA per entry prevents the
 * evidence from drifting across rebuilds; any future deviation fails the probe
 * closed. */
struct PhaseBPath {
    const char *entry_name;
    std::uint32_t expected_stop_rva;
    enum gem_stop_reason x64_reason;
    std::uint64_t x64_retired;
    std::uint32_t x64_handler_count;
    std::uint32_t x64_handler_ids[4];
    std::uint32_t x64_handler_rvas[4];
    bool x64_stop_in_image;
    std::uint32_t x64_stop_rva;
    bool x64_decode_valid;
    std::uint32_t x64_decode_handler_id;
    const char *x64_decode_name;
};
/* Authentic decoder-owned x64 evidence pinned against Blink's own dispatch.
 * LEA, CALL, and ALU-flip are reviewed handlers 10, 11, and 12. The direct
 * segment now reaches its controlled RET. Callback and nested CALLs retire
 * normally, and checked ARM64X metadata stops the probe before any ARM64EC byte
 * can be fetched as x64. */
constexpr std::array<PhaseBPath, 4> kPhaseBPaths = {{
    {"direct",
     UINT32_C(0x4080),
     GEM_STOP_HOST_RETURN,
     3U,
     3U,
     {10, 12, 9, 0},
     {0x4080, 0x4088, 0x408B, 0},
     false,
     0U,
     true,
     9U,
     "OpRet"},
    {"callbackResume",
     UINT32_C(0x4020),
     GEM_STOP_ARCH_TRANSITION,
     3U,
     3U,
     {6, 6, 11, 0},
     {0x4020, 0x4024, 0x4028, 0},
     true,
     UINT32_C(0x2790),
     true,
     11U,
     "OpCallJvds"},
    {"tailTransfer",
     UINT32_C(0x4090),
     GEM_STOP_HOST_RETURN,
     3U,
     3U,
     {6, 4, 9, 0},
     {0x4090, 0x4097, 0x409A, 0},
     false,
     0U,
     true,
     9U,
     "OpRet"},
    {"boundedNested",
     UINT32_C(0x4060),
     GEM_STOP_ARCH_TRANSITION,
     3U,
     3U,
     {6, 6, 11, 0},
     {0x4060, 0x4064, 0x4068, 0},
     true,
     UINT32_C(0x27A0),
     true,
     11U,
     "OpCallJvds"},
}};
constexpr std::uint64_t kPhaseBLoadedBase = UINT64_C(0x180000000);
constexpr std::uint64_t kPhaseBExpectedRetired = UINT64_C(17);

const char *arm64ec_target_kind_label(enum gem_arm64ec_target_kind kind) {
    switch (kind) {
    case GEM_ARM64EC_TARGET_ARM64:
        return "arm64";
    case GEM_ARM64EC_TARGET_ARM64EC:
        return "arm64ec";
    case GEM_ARM64EC_TARGET_X64_BOUNDARY:
        return "x64-boundary";
    }
    return "invalid";
}

std::string hex_u64(std::uint64_t value, std::size_t width = 16) {
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << std::setw(static_cast<int>(width))
       << std::setfill('0') << value;
    return os.str();
}

std::string hex_u64_quoted(std::uint64_t value, std::size_t width = 16) {
    std::ostringstream os;
    os << '"' << "0x" << std::uppercase << std::hex << std::setw(static_cast<int>(width))
       << std::setfill('0') << value << '"';
    return os.str();
}

std::string dec_u64(std::uint64_t value) {
    std::ostringstream os;
    os << std::dec << value;
    return os.str();
}

enum gem_arm64ec_boundary_action trace_boundary(void *, std::uint64_t pc, gem_thread_context *,
                                                gem_arm64ec_boundary_kind *kind) {
    if (pc == kChecker)
        *kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
    else if (pc == kDispatchCall)
        *kind = GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
    else if (pc == kDispatchRet)
        *kind = GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN;
    else
        return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;
    return GEM_ARM64EC_BOUNDARY_STOP;
}

std::uint64_t fnv1a(const std::uint8_t *data, std::size_t size) {
    std::uint64_t hash = UINT64_C(14695981039346656037);
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

/* Decoder-owned x64 segment evidence.  Each authentic first-boundary x64 target
 * is stepped one deterministic instruction at a time through the pinned Blink
 * adapter.  The handler sequence is Blink's own decode-dispatch identity (never
 * a second decoder or opcode scanner).  We stop at the exact unsupported or
 * return/host boundary Blink reports and never emulate callback/nesting. */
constexpr std::uint64_t kX64EvidenceStack = UINT64_C(0x0000000600000000);
constexpr std::uint64_t kX64EvidenceStackSize = UINT64_C(0x1000);
constexpr std::uint64_t kX64SegmentSentinel = UINT64_C(0xFFFFFFFFFFFFFA00);
constexpr unsigned kX64SegmentStepLimit = 16U;

struct X64SegmentEvidence {
    enum gem_stop_reason reason {};
    std::uint64_t stop_pc{};
    std::uint32_t stop_rva{};
    bool stop_in_image{};
    std::uint64_t retired{};
    std::vector<std::pair<std::uint64_t, std::uint32_t>> handlers;
    std::uint32_t overflow{};
    std::uint64_t fault_address{};
    unsigned access{};
    std::uint32_t memory_error{};
    std::uint32_t engine_status{};
    std::uint64_t cpu_hash{};
    std::uint64_t stack_hash{};
    std::uint64_t code_hash{};
    std::uint64_t final_rax{};
    bool decode_valid{};
    std::uint64_t decode_rip{};
    std::uint32_t decode_handler_id{};
    std::string decode_name{};
};

X64SegmentEvidence probe_x64_segment(gem_memory *memory, const gem_pe_arm64x_image *metadata,
                                     std::uint64_t entry_va, std::uint64_t base) {
    X64SegmentEvidence evidence;
    /* Deterministic scratch stack: zero-filled, with the segment return sentinel
     * at the initial rsp so a genuine x64 RET lands on a controlled host-return
     * boundary rather than an undefined address. */
    std::array<std::uint8_t, kX64EvidenceStackSize> zero{};
    assert(gem_memory_write(memory, kX64EvidenceStack, zero.data(), zero.size()) == GEM_MEMORY_OK);
    const auto initial_sp = kX64EvidenceStack + kX64EvidenceStackSize - UINT64_C(0x100);
    std::uint64_t sentinel = kX64SegmentSentinel;
    assert(gem_memory_write(memory, initial_sp, &sentinel, sizeof(sentinel)) == GEM_MEMORY_OK);

    gem_x64_runtime_config config{};
    config.host_return_sentinel = kX64SegmentSentinel;
    config.max_budget = kX64SegmentStepLimit;
    auto *runtime = gem_x64_runtime_create(memory, &config);
    assert(runtime);
    gem_x64_runtime_handler_trace_reset(runtime);

    gem_thread_context context{};
    gem_context_initialize(&context, UINT64_C(0x70000000), GEM_ISA_X64);
    context.pc = entry_va;
    context.sp = initial_sp;
    context.x64_rflags = 2U;
    context.x64_mxcsr = 0x1f80U;
    context.x64_fcw = 0x37fU;

    enum gem_stop_reason reason = GEM_STOP_BUDGET_EXPIRED;
    std::uint64_t retired = 0;
    for (unsigned step = 0; step < kX64SegmentStepLimit; ++step) {
        reason = gem_x64_runtime_run(runtime, &context, 1U);
        gem_x64_stop_info info{};
        assert(gem_x64_runtime_last_stop_info(runtime, &info) && info.reason == reason &&
               info.instructions_retired <= 1U);
        retired += info.instructions_retired;
        evidence.fault_address = info.fault_address;
        evidence.access = static_cast<unsigned>(info.access);
        evidence.memory_error = info.memory_error;
        evidence.engine_status = info.engine_status;
        if (reason != GEM_STOP_BUDGET_EXPIRED)
            break;
        if (context.pc < base || context.pc - base > UINT32_MAX)
            break;
        gem_pe_arm64x_rva_info next_info{};
        assert(gem_pe_arm64x_classify_rva(metadata, static_cast<std::uint32_t>(context.pc - base),
                                          &next_info) == GEM_PE_OK);
        if (next_info.classification != GEM_PE_RVA_X64) {
            reason = GEM_STOP_ARCH_TRANSITION;
            break;
        }
        context.stop_reason = GEM_STOP_NONE;
    }
    evidence.reason = reason;
    evidence.retired = retired;
    evidence.stop_pc = context.pc;
    evidence.final_rax = context.x[8];

    std::uint32_t count = 0U;
    std::uint32_t overflow = 0U;
    assert(gem_x64_runtime_handler_trace_info(runtime, &count, &overflow));
    evidence.overflow = overflow;
    for (std::uint32_t index = 0U; index < count; ++index) {
        std::uint64_t rip = 0U;
        std::uint32_t handler_id = 0U;
        assert(gem_x64_runtime_handler_trace_read(runtime, index, &rip, &handler_id));
        assert(handler_id != 0U);
        evidence.handlers.emplace_back(rip, handler_id);
    }
    /* One decoder-owned handler entry per retired instruction, and no more. */
    assert(count == retired);
    assert(!gem_x64_runtime_handler_trace_read(runtime, count, nullptr, nullptr));

    gem_pe_arm64x_rva_info stop_info{};
    if (evidence.stop_pc >= base && evidence.stop_pc - base <= UINT32_MAX &&
        gem_pe_arm64x_classify_rva(metadata, static_cast<std::uint32_t>(evidence.stop_pc - base),
                                   &stop_info) == GEM_PE_OK) {
        evidence.stop_in_image = true;
        evidence.stop_rva = static_cast<std::uint32_t>(evidence.stop_pc - base);
    }

    std::array<std::uint8_t, 8U + 8U + 31U * 8U + 8U> cpu{};
    std::size_t cursor = 0U;
    auto put = [&cpu, &cursor](std::uint64_t value) {
        for (unsigned byte = 0U; byte < 8U; ++byte)
            cpu[cursor++] = static_cast<std::uint8_t>(value >> (byte * 8U));
    };
    put(context.pc);
    put(context.sp);
    for (unsigned index = 0U; index < 31U; ++index)
        put(context.x[index]);
    put(context.x64_rflags);
    evidence.cpu_hash = fnv1a(cpu.data(), cpu.size());

    std::array<std::uint8_t, kX64EvidenceStackSize> stack{};
    assert(gem_memory_read(memory, kX64EvidenceStack, stack.data(), stack.size()) == GEM_MEMORY_OK);
    evidence.stack_hash = fnv1a(stack.data(), stack.size());
    std::array<std::uint8_t, 64U> code{};
    assert(gem_memory_read(memory, entry_va, code.data(), code.size()) == GEM_MEMORY_OK);
    evidence.code_hash = fnv1a(code.data(), code.size());

    /* Decoder-owned last-decode-attempt: Blink's own Mopcode()/DescribeMopcode()
     * identity for the exact instruction that produced the stop.  Reading is
     * a side-effect-free diagnostic; the wrapper never alters execution or
     * allowlisting. */
    blink_gem_decode_attempt attempt{};
    attempt.abi_version = BLINK_GEM_DECODE_ATTEMPT_ABI_VERSION;
    attempt.size = sizeof(attempt);
    if (gem_x64_runtime_decode_attempt_info(runtime, &attempt)) {
        evidence.decode_valid = attempt.valid != 0U;
        evidence.decode_rip = attempt.rip;
        evidence.decode_handler_id = attempt.handler_id;
        std::array<char, BLINK_GEM_DECODE_ATTEMPT_NAME_BYTES> bounded{};
        for (std::size_t index = 0; index < bounded.size(); ++index)
            bounded[index] = attempt.name[index];
        const auto terminator = std::find(bounded.begin(), bounded.end(), '\0');
        evidence.decode_name.assign(bounded.data(),
                                    static_cast<std::size_t>(terminator - bounded.begin()));
    }

    gem_x64_runtime_destroy(runtime);
    return evidence;
}

void write_phase_b_trace(const char *path, Harness &harness,
                         const std::map<std::string, std::uint32_t> &entries,
                         const gem_pe_arm64x_image *metadata) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    assert(out);
    out << "{\n  \"schema\":\"mswr.phase-b.execution-evidence.v2\",\n  \"paths\":[\n";
    /* Deterministic scratch stack for authentic x64 segment stepping, distinct
     * from the ARM64EC round-trip stack so the two probes never interfere. */
    std::uint64_t x64_stack = kX64EvidenceStack;
    assert(gem_memory_reserve(harness.memory, &x64_stack, kX64EvidenceStackSize) == GEM_MEMORY_OK);
    assert(gem_memory_commit(harness.memory, x64_stack, kX64EvidenceStackSize,
                             GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    /* Hash the entire reserved guest stack region (a single fixed checked range)
     * rather than a window relative to context.sp, which may legitimately move
     * across runs and would otherwise sample different pages. */
    std::vector<std::uint8_t> stack_before(kStackSize);
    std::vector<std::uint8_t> stack_after(kStackSize);
    for (std::size_t i = 0; i < kPhaseBPaths.size(); ++i) {
        const auto *entry_name = kPhaseBPaths[i].entry_name;
        const auto expected_stop_rva = kPhaseBPaths[i].expected_stop_rva;
        const auto expected_stop_va = kPhaseBLoadedBase + expected_stop_rva;

        gem_arm64ec_target_result target{};
        const auto requested_va = kPhaseBLoadedBase + entries.at(entry_name);
        assert(gem_arm64ec_target_resolve(harness.map, requested_va, &target) ==
               GEM_ARM64EC_TARGET_OK);
        /* Preserve requested and resolved classifications distinctly so a future
         * misclassification of either side fails loudly rather than silently
         * passing through the other. */
        gem_pe_arm64x_rva_info requested_info{};
        gem_pe_arm64x_rva_info resolved_info{};
        assert(gem_pe_arm64x_classify_rva(metadata, target.requested_rva, &requested_info) ==
               GEM_PE_OK);
        assert(gem_pe_arm64x_classify_rva(metadata, target.resolved_rva, &resolved_info) ==
               GEM_PE_OK);
        assert(target.kind == GEM_ARM64EC_TARGET_ARM64EC);
        assert(arm64ec_target_kind_label(target.kind) ==
               std::string(gem_pe_rva_class_name(resolved_info.classification)));
        const auto resolved_va = target.resolved_va;

        gem_arm64ec_runtime_config config{};
        config.host_return_sentinel = kHostReturn;
        config.max_budget = 10000U;
        auto *runtime = gem_arm64ec_runtime_create(harness.memory, &config);
        assert(runtime && gem_arm64ec_runtime_attach_arm64x(runtime, metadata, kPhaseBLoadedBase));
        assert(gem_arm64ec_runtime_set_boundary_broker(runtime, trace_boundary, nullptr));
        auto context = initial_context(resolved_va);
        const auto initial_sp = context.sp;
        assert(gem_memory_read(harness.memory, kStackBase, stack_before.data(), kStackSize) ==
               GEM_MEMORY_OK);
        const auto reason = gem_arm64ec_runtime_run(runtime, &context, 10000U);
        gem_arm64ec_stop_info stop{};
        assert(gem_arm64ec_runtime_last_stop_info(runtime, &stop));
        assert(stop.reason == reason && context.x[18] == context.teb &&
               gem_context_is_valid(&context));
        const auto final_sp = context.sp;
        assert(gem_memory_read(harness.memory, kStackBase, stack_after.data(), kStackSize) ==
               GEM_MEMORY_OK);

        /* Drift-detecting assertions against the authentic evidence. Each first
         * ARM64X architecture transition must land at the recorded x64 PC,
         * retire exactly 17 instructions, and the broker must stop before the
         * engine commits any x64 fetch. */
        assert(reason == GEM_STOP_ARCH_TRANSITION);
        const auto stop_va = context.pc;
        const auto stop_rva = static_cast<std::uint32_t>(stop_va - kPhaseBLoadedBase);
        gem_pe_arm64x_rva_info stop_info{};
        assert(gem_pe_arm64x_classify_rva(metadata, stop_rva, &stop_info) == GEM_PE_OK);
        assert(stop_info.classification == GEM_PE_RVA_X64);
        assert(stop_va == expected_stop_va);
        assert(stop_rva == expected_stop_rva);
        assert(stop.instructions_retired == kPhaseBExpectedRetired);

        /* Authentic decoder-owned x64 segment evidence: step Blink from the
         * first x64 boundary one deterministic segment at a time. */
        const auto segment =
            probe_x64_segment(harness.memory, metadata, stop_va, kPhaseBLoadedBase);
        const auto &expected = kPhaseBPaths[i];
        assert(segment.reason == expected.x64_reason);
        assert(segment.retired == expected.x64_retired);
        assert(!segment.overflow);
        assert(segment.handlers.size() == expected.x64_handler_count);
        for (std::size_t h = 0; h < segment.handlers.size(); ++h) {
            assert(segment.handlers[h].second == expected.x64_handler_ids[h]);
            assert(segment.handlers[h].first == kPhaseBLoadedBase + expected.x64_handler_rvas[h]);
        }
        assert(segment.stop_in_image == expected.x64_stop_in_image);
        if (expected.x64_stop_in_image)
            assert(segment.stop_rva == expected.x64_stop_rva);
        else
            assert(segment.stop_pc == kX64SegmentSentinel);
        if (std::string(entry_name) == "direct")
            assert(segment.final_rax == UINT64_C(17));

        /* Decoder-owned identity for the final attempted or retired instruction.
         * CALL names come from Blink and metadata classification stops before
         * ARM64EC bytes are passed back to Blink. */
        assert(segment.decode_valid == expected.x64_decode_valid);
        assert(segment.decode_handler_id == expected.x64_decode_handler_id);
        assert(segment.decode_name == std::string(expected.x64_decode_name));

        /* Deterministic, allocation-free-of-fixed-sizes JSON via std::ostringstream.
         * Field order is fixed; numeric bases and widths are fixed. */
        std::ostringstream os;
        os << "    {\"path\":\"" << entry_name << '"';
        os << ",\"requested\":" << hex_u64_quoted(requested_va);
        os << ",\"requestedClassification\":\""
           << gem_pe_rva_class_name(requested_info.classification) << '"';
        os << ",\"resolved\":" << hex_u64_quoted(resolved_va);
        os << ",\"resolvedClassification\":\""
           << gem_pe_rva_class_name(resolved_info.classification) << '"';
        os << ",\"stop\":" << hex_u64_quoted(stop_va);
        os << ",\"stopRva\":\"" << hex_u64(stop_rva, 8) << '"';
        os << ",\"stopClassification\":\"" << gem_pe_rva_class_name(stop_info.classification)
           << '"';
        os << ",\"expectedStop\":" << hex_u64_quoted(expected_stop_va);
        os << ",\"expectedStopRva\":\"" << hex_u64(expected_stop_rva, 8) << '"';
        os << ",\"reason\":\"" << gem_stop_reason_name(reason) << '"';
        os << ",\"pc\":" << hex_u64_quoted(context.pc);
        os << ",\"sp\":" << hex_u64_quoted(context.sp);
        os << ",\"lr\":" << hex_u64_quoted(context.x[30]);
        os << ",\"x0\":" << hex_u64_quoted(context.x[0]);
        os << ",\"x8\":" << hex_u64_quoted(context.x[8]);
        os << ",\"x9\":" << hex_u64_quoted(context.x[9]);
        os << ",\"x10\":" << hex_u64_quoted(context.x[10]);
        os << ",\"x11\":" << hex_u64_quoted(context.x[11]);
        os << ",\"x18\":" << hex_u64_quoted(context.x[18]);
        os << ",\"teb\":" << hex_u64_quoted(context.teb);
        os << ",\"retired\":" << dec_u64(stop.instructions_retired);
        os << ",\"faultAddress\":" << hex_u64_quoted(stop.fault_address);
        os << ",\"access\":" << static_cast<unsigned>(stop.access);
        os << ",\"memoryError\":" << stop.memory_error;
        os << ",\"engineStatus\":" << stop.engine_status;
        os << ",\"stackBase\":" << hex_u64_quoted(kStackBase);
        os << ",\"stackSize\":" << kStackSize;
        os << ",\"stackHashBefore\":\"" << hex_u64(fnv1a(stack_before.data(), kStackSize)) << '"';
        os << ",\"stackHashAfter\":\"" << hex_u64(fnv1a(stack_after.data(), kStackSize)) << '"';
        os << ",\"initialSp\":" << hex_u64_quoted(initial_sp);
        os << ",\"finalSp\":" << hex_u64_quoted(final_sp);
        os << ",\"x64Entry\":" << hex_u64_quoted(stop_va);
        os << ",\"x64StopReason\":\"" << gem_stop_reason_name(segment.reason) << '"';
        os << ",\"x64StopPc\":" << hex_u64_quoted(segment.stop_pc);
        os << ",\"x64StopInImage\":" << (segment.stop_in_image ? "true" : "false");
        if (segment.stop_in_image)
            os << ",\"x64StopRva\":\"" << hex_u64(segment.stop_rva, 8) << '"';
        os << ",\"x64Retired\":" << dec_u64(segment.retired);
        os << ",\"x64DecoderHandlers\":[";
        for (std::size_t h = 0; h < segment.handlers.size(); ++h) {
            if (h != 0)
                os << ',';
            os << "{\"rip\":" << hex_u64_quoted(segment.handlers[h].first);
            os << ",\"id\":" << segment.handlers[h].second;
            os << ",\"name\":\"" << gem_x64_runtime_handler_name(segment.handlers[h].second)
               << "\"}";
        }
        os << ']';
        os << ",\"x64DecoderTraceOverflow\":" << (segment.overflow ? "true" : "false");
        os << ",\"x64FaultAddress\":" << hex_u64_quoted(segment.fault_address);
        os << ",\"x64Access\":" << segment.access;
        os << ",\"x64MemoryError\":" << segment.memory_error;
        os << ",\"x64EngineStatus\":" << segment.engine_status;
        os << ",\"x64CpuHash\":\"" << hex_u64(segment.cpu_hash) << '"';
        os << ",\"x64StackHash\":\"" << hex_u64(segment.stack_hash) << '"';
        os << ",\"x64CodeHash\":\"" << hex_u64(segment.code_hash) << '"';
        os << ",\"x64Rax\":" << hex_u64_quoted(segment.final_rax);
        os << ",\"x64DecodeAttempt\":{";
        os << "\"valid\":" << (segment.decode_valid ? "true" : "false");
        os << ",\"rip\":" << hex_u64_quoted(segment.decode_rip);
        os << ",\"handlerId\":" << segment.decode_handler_id;
        os << ",\"name\":\"" << segment.decode_name << "\"}";
        os << '}';
        if (i + 1 != kPhaseBPaths.size())
            os << ',';
        os << '\n';
        out << os.str();
        assert(out.good());
        gem_arm64ec_runtime_destroy(runtime);
    }
    out << "  ]\n}\n";
    assert(out.good());
}

void test_frame_contract_validation() {
    gem_hybrid_frame_contract valid{};
    valid.expected_cookie = 7U;
    valid.observed_cookie = 7U;
    valid.expected_return_pc = UINT64_C(0x18000406D);
    valid.observed_return_pc = valid.expected_return_pc;
    valid.expected_sp = UINT64_C(0x40000FED0);
    valid.observed_sp = valid.expected_sp;
    valid.expected_original_x64_sp = UINT64_C(0x40000FED8);
    valid.observed_original_x64_sp = valid.expected_original_x64_sp;
    valid.expected_record = valid.expected_return_pc;
    valid.observed_record = valid.expected_record;
    valid.depth = 1U;
    valid.maximum_depth = 2U;
    valid.active = true;
    valid.require_record = true;
    valid.record_readable = true;
    assert(gem_hybrid_frame_contract_validate(&valid));
    valid.depth = 2U;
    assert(gem_hybrid_frame_contract_validate(&valid));
    valid.depth = 1U;
    assert(!gem_hybrid_frame_contract_validate(nullptr));

    const auto expect_rejected = [&](auto mutate) {
        auto malformed = valid;
        mutate(malformed);
        assert(!gem_hybrid_frame_contract_validate(&malformed));
    };
    expect_rejected([](auto &frame) { frame.active = false; });
    expect_rejected([](auto &frame) { frame.depth = 0U; });
    expect_rejected([](auto &frame) { frame.depth = 3U; });
    expect_rejected([](auto &frame) { frame.maximum_depth = 3U; });
    expect_rejected([](auto &frame) { frame.observed_cookie ^= 1U; });
    expect_rejected([](auto &frame) { frame.expected_cookie = 0U; });
    expect_rejected([](auto &frame) { frame.observed_return_pc += 4U; });
    expect_rejected([](auto &frame) { frame.observed_sp += 8U; });
    expect_rejected([](auto &frame) { frame.observed_original_x64_sp += 8U; });
    expect_rejected([](auto &frame) { frame.record_readable = false; });
    expect_rejected([](auto &frame) { frame.observed_record += 1U; });
    valid.require_record = false;
    valid.record_readable = false;
    valid.observed_record = 0U;
    assert(gem_hybrid_frame_contract_validate(&valid));
}

void assert_stop(gem_hybrid_runtime *runtime, gem_stop_reason reason,
                 gem_hybrid_stop_source source) {
    gem_hybrid_stop_info info{};
    assert(gem_hybrid_runtime_last_stop_info(runtime, &info));
    if (info.reason != reason || info.source != source)
        std::fprintf(stderr, "stop mismatch expected reason=%u source=%u got reason=%u source=%u\n",
                     static_cast<unsigned>(reason), static_cast<unsigned>(source),
                     static_cast<unsigned>(info.reason), static_cast<unsigned>(info.source));
    assert(info.reason == reason && info.source == source);
    if (source == GEM_HYBRID_STOP_SOURCE_ARM64EC)
        assert(info.arm64ec.reason == reason);
    if (source == GEM_HYBRID_STOP_SOURCE_X64)
        assert(info.x64.reason == reason);
}
} // namespace

int main(int argc, char **argv) {
    assert(argc == 4 || argc == 5);
    test_frame_contract_validation();
    const auto bytes = read_binary(argv[1]);
    const auto entries = read_map(argv[2]);
    const auto native = read_native_oracle(argv[3]);
    auto harness = make_harness(bytes, entries);
    const auto config = runtime_config();
    const auto *metadata = gem_pe_arm64x_materialized_metadata(harness.materialized);
    const std::array<std::uint64_t, 4> immutable_page_addresses{
        {config.loaded_base + UINT64_C(0x2000), config.loaded_base + UINT64_C(0x3000),
         config.loaded_base + UINT64_C(0x4000), config.loaded_base + UINT64_C(0x7000)}};
    std::array<std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE>, 4> immutable_pages{};
    for (std::size_t i = 0; i < immutable_pages.size(); ++i)
        assert(gem_memory_read(harness.memory, immutable_page_addresses[i],
                               immutable_pages[i].data(),
                               immutable_pages[i].size()) == GEM_MEMORY_OK);
    gem_thread_context roundtrip_oracle_context{};
    std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> expected_stack{};

    /* The native evidence supplies externally observed results. Full 720-byte
     * contexts below combine those results with the linked instruction/thunk
     * contract and ABI-preserved entry fields. Deterministic stack seeds plus
     * full-page hashes cover every byte, while touched bounds prove no write
     * escaped the linked stack footprint. */
    /* Authentic normal-return and explicit-tail paths. These exact linked
     * addresses bind the x0=x8 handback to the retained fixture evidence. */
    {
        struct ReturnCase {
            gem_hybrid_return_mode mode;
            std::uint64_t requested;
            std::uint64_t resolved;
            std::uint64_t target;
            std::uint64_t expected;
        };
        const std::array<ReturnCase, 2> cases{{
            {GEM_HYBRID_RETURN_NORMAL, config.loaded_base + entries.at("direct"),
             config.loaded_base + UINT64_C(0x2840), config.loaded_base + UINT64_C(0x4080),
             native.direct_result},
            {GEM_HYBRID_RETURN_TAIL, config.loaded_base + entries.at("tailTransfer"),
             config.loaded_base + UINT64_C(0x2AB0), config.loaded_base + UINT64_C(0x4090),
             native.tail_transfer_result},
        }};
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        assert(runtime);
        for (const auto &test : cases) {
            fill_stack_oracle(harness.memory, test.mode == GEM_HYBRID_RETURN_NORMAL
                                                  ? UINT8_C(0x21)
                                                  : UINT8_C(0x42));
            gem_thread_context oracle{};
            std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_before_first{};
            assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                   stack_before_first.data(),
                                   stack_before_first.size()) == GEM_MEMORY_OK);
            std::uint64_t successful_budget = 0U;
            for (unsigned iteration = 0; iteration < 100U; ++iteration) {
                auto context = initial_context(test.requested);
                context.x[0] = 10U;
                const auto entry = context;
                const gem_hybrid_return_control control{test.mode, 0U, test.requested,
                                                        test.resolved, test.target};
                gem_hybrid_roundtrip_stats stats{};
                const auto reason = gem_hybrid_runtime_run_integer_return(
                    runtime, &context, &control, config.max_budget, &stats);
                if (reason != GEM_STOP_HOST_RETURN)
                    std::fprintf(
                        stderr, "return mode=%u reason=%u pc=%llx arm=%llu x64=%llu\n",
                        static_cast<unsigned>(test.mode), static_cast<unsigned>(reason),
                        static_cast<unsigned long long>(context.pc),
                        static_cast<unsigned long long>(stats.arm64ec_instructions_retired),
                        static_cast<unsigned long long>(stats.x64_instructions_retired));
                assert(reason == GEM_STOP_HOST_RETURN);
                auto expected_context = entry;
                expected_context.x[0] = test.expected;
                expected_context.x[8] = test.expected;
                expected_context.x[9] = kChecker;
                expected_context.x[10] = config.loaded_base + UINT64_C(0x3C50);
                expected_context.x[11] = test.target;
                expected_context.x[12] = test.target;
                expected_context.pc = kHostReturn;
                expected_context.x64_rflags =
                    test.mode == GEM_HYBRID_RETURN_NORMAL ? UINT64_C(0x100A) : UINT64_C(0x100E);
                expected_context.isa = GEM_ISA_ARM64EC;
                expected_context.stop_reason = GEM_STOP_HOST_RETURN;
                assert_context_oracle(context, expected_context);
                assert(stats.checker_boundaries == 1U && stats.dispatch_call_boundaries == 0U &&
                       stats.x64_to_arm64ec_boundaries == 1U && stats.frame_pushes == 1U &&
                       stats.frame_pops == 1U && stats.maximum_frame_depth == 1U &&
                       stats.final_frame_depth == 0U);
                std::uint64_t record_after = 0U;
                assert(gem_memory_read(harness.memory, entry.sp - sizeof(record_after),
                                       &record_after, sizeof(record_after)) == GEM_MEMORY_OK &&
                       record_after == entry.x[30]);
                if (iteration == 0U) {
                    std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_after_first{};
                    assert(gem_memory_read(harness.memory,
                                           kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                           stack_after_first.data(),
                                           stack_after_first.size()) == GEM_MEMORY_OK);
                    const auto expected_stack_hash = test.mode == GEM_HYBRID_RETURN_NORMAL
                                                         ? UINT64_C(0x6D8559F8E8A96B24)
                                                         : UINT64_C(0xF59B1C37410F35D4);
                    assert_stack_oracle(stack_before_first, stack_after_first, expected_stack_hash,
                                        0xEF0U, 0xEFFU);
                    oracle = context;
                    successful_budget =
                        stats.arm64ec_instructions_retired + stats.x64_instructions_retired;
                    assert(successful_budget > 1U);
                } else {
                    assert_context_oracle(context, oracle);
                }
            }

            auto exhausted = initial_context(test.requested);
            exhausted.x[0] = 10U;
            const auto exhausted_entry = exhausted;
            const gem_hybrid_return_control control{test.mode, 0U, test.requested, test.resolved,
                                                    test.target};
            gem_hybrid_roundtrip_stats exhausted_stats{};
            const auto exhausted_reason = gem_hybrid_runtime_run_integer_return(
                runtime, &exhausted, &control, 19U, &exhausted_stats);
            if (exhausted_reason != GEM_STOP_BUDGET_EXPIRED)
                std::fprintf(
                    stderr, "return budget mode=%u reason=%u arm=%llu x64=%llu\n",
                    static_cast<unsigned>(test.mode), static_cast<unsigned>(exhausted_reason),
                    static_cast<unsigned long long>(exhausted_stats.arm64ec_instructions_retired),
                    static_cast<unsigned long long>(exhausted_stats.x64_instructions_retired));
            assert(exhausted_reason == GEM_STOP_BUDGET_EXPIRED);
            auto expected_exhausted = exhausted_entry;
            expected_exhausted.stop_reason = GEM_STOP_BUDGET_EXPIRED;
            assert(std::memcmp(&exhausted, &expected_exhausted, sizeof(exhausted)) == 0);
            assert(exhausted_stats.arm64ec_instructions_retired == 16U &&
                   exhausted_stats.x64_instructions_retired == 3U &&
                   exhausted_stats.frame_pushes == 1U && exhausted_stats.frame_pops == 1U &&
                   exhausted_stats.final_frame_depth == 0U);
            exhausted = exhausted_entry;
            assert(gem_hybrid_runtime_run_integer_return(runtime, &exhausted, &control,
                                                         config.max_budget,
                                                         nullptr) == GEM_STOP_HOST_RETURN);
            assert(exhausted.x[0] == test.expected);

            for (std::uint64_t budget = 1U; budget < successful_budget; ++budget) {
                auto limited = exhausted_entry;
                gem_hybrid_roundtrip_stats limited_stats{};
                assert(gem_hybrid_runtime_run_integer_return(runtime, &limited, &control, budget,
                                                             &limited_stats) ==
                       GEM_STOP_BUDGET_EXPIRED);
                auto expected_limited = exhausted_entry;
                expected_limited.stop_reason = GEM_STOP_BUDGET_EXPIRED;
                assert(std::memcmp(&limited, &expected_limited, sizeof(limited)) == 0);
                assert(limited_stats.frame_pushes == limited_stats.frame_pops &&
                       limited_stats.final_frame_depth == 0U);
                limited = exhausted_entry;
                assert(gem_hybrid_runtime_run_integer_return(runtime, &limited, &control,
                                                             config.max_budget,
                                                             nullptr) == GEM_STOP_HOST_RETURN);
                assert(limited.x[0] == test.expected);
            }
        }
        gem_hybrid_runtime_destroy(runtime);
    }

    /* Authentic depth-2 path: the outer x64 CALL enters ARM64EC, whose linked
     * exit thunk enters a second x64 segment before returning through both
     * broker-owned frames. */
    {
        const gem_hybrid_nested_control control{
            GEM_HYBRID_NESTED_CONTROL_VERSION,
            0U,
            config.loaded_base + entries.at("boundedNested"),
            config.loaded_base + UINT64_C(0x2810),
            config.loaded_base + UINT64_C(0x4060),
            config.loaded_base + UINT64_C(0x27A0),
            config.loaded_base + UINT64_C(0x406D),
            config.loaded_base + UINT64_C(0x4050),
        };
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        assert(runtime);
        fill_stack_oracle(harness.memory, UINT8_C(0x63));
        gem_thread_context oracle{};
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> oracle_stack{};
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_before_first{};
        assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                               stack_before_first.data(),
                               stack_before_first.size()) == GEM_MEMORY_OK);
        std::uint64_t successful_budget = 0U;
        for (unsigned iteration = 0; iteration < 100U; ++iteration) {
            auto context = initial_context(control.requested_start_va);
            context.x[0] = 10U;
            const auto entry = context;
            gem_hybrid_roundtrip_stats stats{};
            const auto reason = gem_hybrid_runtime_run_integer_nested(runtime, &context, &control,
                                                                      config.max_budget, &stats);
            if (reason != GEM_STOP_HOST_RETURN)
                std::fprintf(
                    stderr,
                    "nested reason=%u pc=%llx arm=%llu x64=%llu checker=%llu "
                    "ret=%llu pushes=%llu pops=%llu depth=%u\n",
                    static_cast<unsigned>(reason), static_cast<unsigned long long>(context.pc),
                    static_cast<unsigned long long>(stats.arm64ec_instructions_retired),
                    static_cast<unsigned long long>(stats.x64_instructions_retired),
                    static_cast<unsigned long long>(stats.checker_boundaries),
                    static_cast<unsigned long long>(stats.dispatch_ret_boundaries),
                    static_cast<unsigned long long>(stats.frame_pushes),
                    static_cast<unsigned long long>(stats.frame_pops), stats.maximum_frame_depth);
            assert(reason == GEM_STOP_HOST_RETURN);
            auto expected_context = entry;
            expected_context.x[0] = native.nested_result;
            expected_context.x[4] = entry.sp - UINT64_C(0x30);
            expected_context.x[8] = native.nested_result;
            expected_context.x[9] = kChecker;
            expected_context.x[10] = config.loaded_base + UINT64_C(0x3C50);
            expected_context.x[11] = control.inner_x64_target_va;
            expected_context.x[12] = control.inner_x64_target_va;
            expected_context.x[16] = kDispatchRet;
            expected_context.pc = kHostReturn;
            expected_context.x64_rflags = UINT64_C(0x100A);
            expected_context.isa = GEM_ISA_ARM64EC;
            expected_context.stop_reason = GEM_STOP_HOST_RETURN;
            assert_context_oracle(context, expected_context);
            assert(stats.x64_instructions_retired == 8U && stats.checker_boundaries == 2U &&
                   stats.dispatch_call_boundaries == 0U && stats.x64_to_arm64ec_boundaries == 3U &&
                   stats.descriptor_resolutions == 1U && stats.dispatch_ret_boundaries == 1U &&
                   stats.frame_pushes == 2U && stats.frame_pops == 2U &&
                   stats.maximum_frame_depth == 2U && stats.final_frame_depth == 0U);
            std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> current_stack{};
            assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                   current_stack.data(), current_stack.size()) == GEM_MEMORY_OK);
            if (iteration == 0U) {
                assert_stack_oracle(stack_before_first, current_stack, UINT64_C(0x834AA83BBDE4856C),
                                    0xE00U, 0xEFFU);
                oracle = context;
                oracle_stack = current_stack;
                successful_budget =
                    stats.arm64ec_instructions_retired + stats.x64_instructions_retired;
                assert(successful_budget > 1U);
            } else {
                assert_context_oracle(context, oracle);
                assert(current_stack == oracle_stack);
            }
        }

        bool exhausted_at_depth_two = false;
        for (std::uint64_t budget = 1U; budget < successful_budget; ++budget) {
            auto context = initial_context(control.requested_start_va);
            context.x[0] = 10U;
            const auto entry = context;
            gem_hybrid_roundtrip_stats stats{};
            assert(gem_hybrid_runtime_run_integer_nested(runtime, &context, &control, budget,
                                                         &stats) == GEM_STOP_BUDGET_EXPIRED);
            auto expected = entry;
            expected.stop_reason = GEM_STOP_BUDGET_EXPIRED;
            assert(std::memcmp(&context, &expected, sizeof(context)) == 0);
            assert(stats.frame_pushes == stats.frame_pops && stats.frame_pushes <= 2U &&
                   stats.final_frame_depth == 0U);
            exhausted_at_depth_two |= stats.maximum_frame_depth == 2U;
            context = entry;
            assert(gem_hybrid_runtime_run_integer_nested(runtime, &context, &control,
                                                         config.max_budget,
                                                         nullptr) == GEM_STOP_HOST_RETURN);
            assert(context.x[0] == native.nested_result);
        }
        assert(exhausted_at_depth_two);
        auto reused = initial_context(control.requested_start_va);
        reused.x[0] = 10U;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &reused, &control, config.max_budget,
                                                     nullptr) == GEM_STOP_HOST_RETURN);
        assert(reused.x[0] == native.nested_result);

        const auto reject_control = [&](const gem_hybrid_nested_control &malformed) {
            auto rejected = initial_context(control.requested_start_va);
            rejected.x[0] = 10U;
            const auto entry = rejected;
            gem_hybrid_roundtrip_stats stats{};
            assert(gem_hybrid_runtime_run_integer_nested(runtime, &rejected, &malformed,
                                                         config.max_budget,
                                                         &stats) == GEM_STOP_INVARIANT_VIOLATION);
            auto expected = entry;
            expected.stop_reason = GEM_STOP_INVARIANT_VIOLATION;
            assert(std::memcmp(&rejected, &expected, sizeof(rejected)) == 0);
            assert(stats.frame_pushes == stats.frame_pops && stats.frame_pushes <= 2U &&
                   stats.final_frame_depth == 0U);
        };
        auto malformed = control;
        malformed.version += 1U;
        reject_control(malformed);
        malformed = control;
        malformed.reserved = 1U;
        reject_control(malformed);
        malformed = control;
        malformed.outer_resume_va += 1U;
        reject_control(malformed);
        malformed = control;
        malformed.inner_x64_target_va = control.callback_va;
        reject_control(malformed);
        auto wrong_cookie = initial_context(control.requested_start_va);
        wrong_cookie.transition_cookie = 1U;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &wrong_cookie, &control,
                                                     config.max_budget,
                                                     nullptr) == GEM_STOP_INVARIANT_VIOLATION);

        /* Supplemental negative mutations retain authentic metadata routing.
         * They replace only the admitted inner x64 instruction bytes to prove
         * unsupported execution and a third transition attempt fail closed at
         * depth two; the authentic bytes are restored before each retry. */
        const auto inner_page = control.inner_x64_target_va & ~UINT64_C(0xFFF);
        std::array<std::uint8_t, 8> authentic_inner{};
        std::uint32_t old_protection = 0U;
        assert(gem_memory_read(harness.memory, control.inner_x64_target_va, authentic_inner.data(),
                               authentic_inner.size()) == GEM_MEMORY_OK);
        assert(gem_memory_protect(harness.memory, inner_page, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE, &old_protection) == GEM_MEMORY_OK);
        const std::uint8_t unsupported = 0xf4; /* HLT remains deliberately denied. */
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va, &unsupported,
                                sizeof(unsupported)) == GEM_MEMORY_OK);
        auto unsupported_context = initial_context(control.requested_start_va);
        unsupported_context.x[0] = 10U;
        const auto unsupported_entry = unsupported_context;
        gem_hybrid_roundtrip_stats unsupported_stats{};
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &unsupported_context, &control,
                                                     config.max_budget, &unsupported_stats) ==
               GEM_STOP_UNSUPPORTED_INSTRUCTION);
        auto unsupported_expected = unsupported_entry;
        unsupported_expected.stop_reason = GEM_STOP_UNSUPPORTED_INSTRUCTION;
        assert(std::memcmp(&unsupported_context, &unsupported_expected,
                           sizeof(unsupported_context)) == 0);
        assert(unsupported_stats.frame_pushes == 2U && unsupported_stats.frame_pops == 2U &&
               unsupported_stats.maximum_frame_depth == 2U &&
               unsupported_stats.final_frame_depth == 0U);
        assert_stop(runtime, GEM_STOP_UNSUPPORTED_INSTRUCTION, GEM_HYBRID_STOP_SOURCE_X64);
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va, authentic_inner.data(),
                                1U) == GEM_MEMORY_OK);
        unsupported_context = unsupported_entry;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &unsupported_context, &control,
                                                     config.max_budget,
                                                     nullptr) == GEM_STOP_HOST_RETURN);

        const std::array<std::uint8_t, 5> third_transition{{0xE8, 0x4B, 0xE7, 0xFF, 0xFF}};
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va,
                                third_transition.data(), third_transition.size()) == GEM_MEMORY_OK);
        auto overflow = initial_context(control.requested_start_va);
        overflow.x[0] = 10U;
        const auto overflow_entry = overflow;
        gem_hybrid_roundtrip_stats overflow_stats{};
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &overflow, &control,
                                                     config.max_budget, &overflow_stats) ==
               GEM_STOP_INVARIANT_VIOLATION);
        auto overflow_expected = overflow_entry;
        overflow_expected.stop_reason = GEM_STOP_INVARIANT_VIOLATION;
        assert(std::memcmp(&overflow, &overflow_expected, sizeof(overflow)) == 0);
        assert(overflow_stats.frame_pushes == 2U && overflow_stats.frame_pops == 2U &&
               overflow_stats.maximum_frame_depth == 2U && overflow_stats.final_frame_depth == 0U);
        assert_stop(runtime, GEM_STOP_INVARIANT_VIOLATION, GEM_HYBRID_STOP_SOURCE_BROKER);
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va, authentic_inner.data(),
                                authentic_inner.size()) == GEM_MEMORY_OK);
        overflow = overflow_entry;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &overflow, &control,
                                                     config.max_budget,
                                                     nullptr) == GEM_STOP_HOST_RETURN);

        const std::array<std::uint8_t, 4> load_and_return{{0x48, 0x8B, 0x03, 0xC3}};
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va, load_and_return.data(),
                                load_and_return.size()) == GEM_MEMORY_OK);
        std::uint32_t data_protection = 0U;
        assert(gem_memory_protect(harness.memory, kStackBase, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE | GEM_PAGE_GUARD,
                                  &data_protection) == GEM_MEMORY_OK);
        auto guarded = initial_context(control.requested_start_va);
        guarded.x[0] = 10U;
        guarded.x[27] = kStackBase; /* RBX in the canonical x64 mapping. */
        const auto guarded_entry = guarded;
        gem_hybrid_roundtrip_stats guarded_stats{};
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &guarded, &control, config.max_budget,
                                                     &guarded_stats) == GEM_STOP_MEMORY_FAULT);
        auto guarded_expected = guarded_entry;
        guarded_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
        assert(std::memcmp(&guarded, &guarded_expected, sizeof(guarded)) == 0);
        assert(guarded_stats.frame_pushes == 2U && guarded_stats.frame_pops == 2U &&
               guarded_stats.maximum_frame_depth == 2U && guarded_stats.final_frame_depth == 0U);
        gem_hybrid_stop_info fault_info{};
        assert(gem_hybrid_runtime_last_stop_info(runtime, &fault_info) &&
               fault_info.source == GEM_HYBRID_STOP_SOURCE_X64 &&
               fault_info.reason == GEM_STOP_MEMORY_FAULT &&
               fault_info.x64.fault_address == kStackBase &&
               fault_info.x64.memory_error == GEM_MEMORY_GUARD_PAGE);
        std::uint32_t consumed_protection = 0U;
        assert(gem_memory_protect(harness.memory, kStackBase, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_READWRITE, &consumed_protection) == GEM_MEMORY_OK &&
               consumed_protection == GEM_PAGE_READWRITE);
        guarded = guarded_entry;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &guarded, &control, config.max_budget,
                                                     nullptr) == GEM_STOP_HOST_RETURN);

        assert(gem_memory_protect(harness.memory, kStackBase, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_NOACCESS, nullptr) == GEM_MEMORY_OK);
        auto denied = guarded_entry;
        gem_hybrid_roundtrip_stats denied_stats{};
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &denied, &control, config.max_budget,
                                                     &denied_stats) == GEM_STOP_MEMORY_FAULT);
        auto denied_expected = guarded_entry;
        denied_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
        assert(std::memcmp(&denied, &denied_expected, sizeof(denied)) == 0);
        assert(denied_stats.frame_pushes == 2U && denied_stats.frame_pops == 2U &&
               denied_stats.maximum_frame_depth == 2U && denied_stats.final_frame_depth == 0U);
        assert(gem_hybrid_runtime_last_stop_info(runtime, &fault_info) &&
               fault_info.source == GEM_HYBRID_STOP_SOURCE_X64 &&
               fault_info.x64.fault_address == kStackBase &&
               fault_info.x64.memory_error == GEM_MEMORY_ACCESS_DENIED);
        assert(gem_memory_protect(harness.memory, kStackBase, GEM_GUEST_PAGE_SIZE, data_protection,
                                  nullptr) == GEM_MEMORY_OK);
        denied = guarded_entry;
        assert(gem_hybrid_runtime_run_integer_nested(runtime, &denied, &control, config.max_budget,
                                                     nullptr) == GEM_STOP_HOST_RETURN);
        assert(gem_memory_write(harness.memory, control.inner_x64_target_va, authentic_inner.data(),
                                authentic_inner.size()) == GEM_MEMORY_OK);
        assert(gem_memory_protect(harness.memory, inner_page, GEM_GUEST_PAGE_SIZE, old_protection,
                                  nullptr) == GEM_MEMORY_OK);
        gem_hybrid_runtime_destroy(runtime);
    }

    /* Authentic Round-1 callback/resumption: metadata selects the x64 entry
     * and ARM callback; the descriptor selects the real entry thunk. */
    {
        gem_arm64ec_target_result callback_entry{}, callback{};
        assert(gem_arm64ec_target_resolve(harness.map, config.loaded_base + UINT64_C(0x4020),
                                          &callback_entry) == GEM_ARM64EC_TARGET_OK);
        assert(callback_entry.kind == GEM_ARM64EC_TARGET_X64_BOUNDARY &&
               callback_entry.resolved_va == config.loaded_base + UINT64_C(0x4020));
        assert(gem_arm64ec_target_resolve(harness.map,
                                          config.loaded_base + entries.at("armCallback"),
                                          &callback) == GEM_ARM64EC_TARGET_OK);
        assert(callback.kind == GEM_ARM64EC_TARGET_ARM64EC &&
               callback.resolved_va == config.loaded_base + UINT64_C(0x2790));
        gem_arm64ec_target_result callback_thunk{};
        assert(gem_arm64ec_descriptor_resolve(harness.map, harness.memory,
                                              callback.resolved_va - UINT64_C(4), nullptr,
                                              &callback_thunk) == GEM_ARM64EC_TARGET_OK);
        assert(callback_thunk.kind == GEM_ARM64EC_TARGET_ARM64EC &&
               callback_thunk.resolved_va == config.loaded_base + UINT64_C(0x3B78));
        const auto resume = config.loaded_base + UINT64_C(0x402D);
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        assert(runtime);
        fill_stack_oracle(harness.memory, UINT8_C(0x84));
        gem_thread_context oracle{};
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> oracle_stack{};
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_before_first{};
        assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                               stack_before_first.data(),
                               stack_before_first.size()) == GEM_MEMORY_OK);
        std::uint64_t successful_budget = 0U;
        for (unsigned iteration = 0; iteration < 100U; ++iteration) {
            auto context = initial_context(harness.caller);
            context.isa = GEM_ISA_X64;
            context.pc = callback_entry.resolved_va;
            context.x[0] = 10U;
            const auto initial = context;
            gem_hybrid_roundtrip_stats stats{};
            assert(gem_hybrid_runtime_run_integer_callback_resume(
                       runtime, &context, callback.resolved_va, resume, config.max_budget,
                       &stats) == GEM_STOP_ARCH_TRANSITION);
            assert_stop(runtime, GEM_STOP_ARCH_TRANSITION, GEM_HYBRID_STOP_SOURCE_BROKER);
            if (context.isa != GEM_ISA_X64 || context.pc != resume ||
                context.sp != initial.sp - UINT64_C(0x28) ||
                context.x[8] != native.callback_resume_result - UINT64_C(19) ||
                context.x[18] != context.teb || context.transition_cookie != 0U)
                std::fprintf(stderr,
                             "callback result x0=%llx x8=%llx pc=%llx sp=%llx initial_sp=%llx "
                             "lr=%llx original=%llx\\n",
                             static_cast<unsigned long long>(context.x[0]),
                             static_cast<unsigned long long>(context.x[8]),
                             static_cast<unsigned long long>(context.pc),
                             static_cast<unsigned long long>(context.sp),
                             static_cast<unsigned long long>(initial.sp),
                             static_cast<unsigned long long>(context.x[30]),
                             static_cast<unsigned long long>(context.original_x64_sp));
            const auto intermediate = native.callback_resume_result - UINT64_C(19);
            auto expected_context = initial;
            expected_context.x[0] = intermediate;
            expected_context.x[4] = initial.sp - UINT64_C(0x28);
            expected_context.x[8] = intermediate;
            expected_context.x[9] = callback.resolved_va;
            expected_context.x[16] = kDispatchRet;
            expected_context.x[30] = resume;
            expected_context.sp = initial.sp - UINT64_C(0x28);
            expected_context.pc = resume;
            expected_context.x64_rflags = UINT64_C(0x100E);
            expected_context.isa = GEM_ISA_X64;
            expected_context.stop_reason = GEM_STOP_ARCH_TRANSITION;
            assert_context_oracle(context, expected_context);
            assert(stats.x64_instructions_retired == 3U && stats.x64_to_arm64ec_boundaries == 1U &&
                   stats.descriptor_resolutions == 1U && stats.dispatch_ret_boundaries == 1U &&
                   stats.frame_pushes == 1U && stats.frame_pops == 1U &&
                   stats.maximum_frame_depth == 1U && stats.final_frame_depth == 0U);
            std::uint64_t record = 0U;
            assert(gem_memory_read(harness.memory, initial.sp - UINT64_C(0x30), &record,
                                   sizeof(record)) == GEM_MEMORY_OK &&
                   record == resume);
            std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack{};
            assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                   stack.data(), stack.size()) == GEM_MEMORY_OK);
            if (iteration == 0U) {
                assert_stack_oracle(stack_before_first, stack, UINT64_C(0xED2D68340821F5CD), 0xE20U,
                                    0xED7U);
                oracle = context;
                oracle_stack = stack;
                successful_budget =
                    stats.arm64ec_instructions_retired + stats.x64_instructions_retired;
                assert(successful_budget > 1U);
            } else {
                assert_context_oracle(context, oracle);
                assert(stack == oracle_stack);
            }
        }

        /* Exhaustion immediately after CALL rolls CPU back but deliberately
         * retains CALL's committed return record; the same runtime retries. */
        auto failed = initial_context(harness.caller);
        failed.isa = GEM_ISA_X64;
        failed.pc = callback_entry.resolved_va;
        failed.x[0] = 10U;
        const auto failed_initial = failed;
        gem_hybrid_roundtrip_stats failed_stats{};
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &failed, callback.resolved_va, resume, 3U, &failed_stats) ==
               GEM_STOP_BUDGET_EXPIRED);
        auto expected_failed = failed_initial;
        expected_failed.stop_reason = GEM_STOP_BUDGET_EXPIRED;
        assert(std::memcmp(&failed, &expected_failed, sizeof(failed)) == 0);
        assert(failed_stats.x64_instructions_retired == 3U && failed_stats.frame_pushes == 1U &&
               failed_stats.frame_pops == 1U && failed_stats.final_frame_depth == 0U);
        std::uint64_t retained = 0U;
        assert(gem_memory_read(harness.memory, failed_initial.sp - UINT64_C(0x30), &retained,
                               sizeof(retained)) == GEM_MEMORY_OK &&
               retained == resume);
        failed = failed_initial;
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &failed, callback.resolved_va, resume, config.max_budget, nullptr) ==
               GEM_STOP_ARCH_TRANSITION);
        for (std::uint64_t budget = 1U; budget < successful_budget; ++budget) {
            auto limited = failed_initial;
            gem_hybrid_roundtrip_stats limited_stats{};
            assert(gem_hybrid_runtime_run_integer_callback_resume(
                       runtime, &limited, callback.resolved_va, resume, budget, &limited_stats) ==
                   GEM_STOP_BUDGET_EXPIRED);
            auto expected_limited = failed_initial;
            expected_limited.stop_reason = GEM_STOP_BUDGET_EXPIRED;
            assert(std::memcmp(&limited, &expected_limited, sizeof(limited)) == 0);
            assert(limited_stats.frame_pushes == limited_stats.frame_pops &&
                   limited_stats.frame_pushes <= 1U && limited_stats.final_frame_depth == 0U);
            limited = failed_initial;
            assert(gem_hybrid_runtime_run_integer_callback_resume(
                       runtime, &limited, callback.resolved_va, resume, config.max_budget,
                       nullptr) == GEM_STOP_ARCH_TRANSITION);
        }

        /* Supplemental linked-callback mutations exercise the same runtime
         * frame validator at the dispatch-return boundary. */
        const auto callback_page = callback.resolved_va & ~UINT64_C(0xFFF);
        std::array<std::uint8_t, 4> callback_first_instruction{};
        std::uint32_t callback_old_protection = 0U;
        assert(gem_memory_read(harness.memory, callback.resolved_va,
                               callback_first_instruction.data(),
                               callback_first_instruction.size()) == GEM_MEMORY_OK);
        assert(gem_memory_protect(harness.memory, callback_page, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READWRITE,
                                  &callback_old_protection) == GEM_MEMORY_OK);
        const auto reject_malformed_callback = [&](const std::array<std::uint8_t, 4> &patch) {
            assert(gem_memory_write(harness.memory, callback.resolved_va, patch.data(),
                                    patch.size()) == GEM_MEMORY_OK);
            auto malformed_context = failed_initial;
            gem_hybrid_roundtrip_stats malformed_stats{};
            assert(gem_hybrid_runtime_run_integer_callback_resume(
                       runtime, &malformed_context, callback.resolved_va, resume, config.max_budget,
                       &malformed_stats) == GEM_STOP_INVARIANT_VIOLATION);
            auto malformed_expected = failed_initial;
            malformed_expected.stop_reason = GEM_STOP_INVARIANT_VIOLATION;
            assert(std::memcmp(&malformed_context, &malformed_expected,
                               sizeof(malformed_context)) == 0);
            assert(malformed_stats.frame_pushes == 1U && malformed_stats.frame_pops == 1U &&
                   malformed_stats.final_frame_depth == 0U);
            assert_stop(runtime, GEM_STOP_INVARIANT_VIOLATION, GEM_HYBRID_STOP_SOURCE_ARM64EC);
            assert(gem_memory_write(harness.memory, callback.resolved_va,
                                    callback_first_instruction.data(),
                                    callback_first_instruction.size()) == GEM_MEMORY_OK);
            malformed_context = failed_initial;
            assert(gem_hybrid_runtime_run_integer_callback_resume(
                       runtime, &malformed_context, callback.resolved_va, resume, config.max_budget,
                       nullptr) == GEM_STOP_ARCH_TRANSITION);
        };
        reject_malformed_callback({{0xFF, 0x43, 0x00, 0xD1}}); /* sub sp, sp, #16 */
        reject_malformed_callback({{0x9F, 0x80, 0x1F, 0xF8}}); /* stur xzr, [x4, #-8] */
        assert(gem_memory_protect(harness.memory, callback_page, GEM_GUEST_PAGE_SIZE,
                                  callback_old_protection, nullptr) == GEM_MEMORY_OK);

        const auto thunk_page = callback_thunk.resolved_va & ~UINT64_C(0xFFF);
        std::uint32_t thunk_protection = 0U;
        assert(gem_memory_protect(harness.memory, thunk_page, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_EXECUTE_READ | GEM_PAGE_GUARD,
                                  &thunk_protection) == GEM_MEMORY_OK);
        auto guarded_thunk = failed_initial;
        gem_hybrid_roundtrip_stats guarded_thunk_stats{};
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &guarded_thunk, callback.resolved_va, resume, config.max_budget,
                   &guarded_thunk_stats) == GEM_STOP_MEMORY_FAULT);
        auto guarded_thunk_expected = failed_initial;
        guarded_thunk_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
        assert(std::memcmp(&guarded_thunk, &guarded_thunk_expected, sizeof(guarded_thunk)) == 0);
        assert(guarded_thunk_stats.frame_pushes == 1U && guarded_thunk_stats.frame_pops == 1U &&
               guarded_thunk_stats.final_frame_depth == 0U);
        gem_hybrid_stop_info arm_fault{};
        assert(gem_hybrid_runtime_last_stop_info(runtime, &arm_fault) &&
               arm_fault.source == GEM_HYBRID_STOP_SOURCE_ARM64EC &&
               arm_fault.reason == GEM_STOP_MEMORY_FAULT &&
               arm_fault.arm64ec.fault_address == callback_thunk.resolved_va &&
               arm_fault.arm64ec.memory_error == GEM_MEMORY_GUARD_PAGE);
        std::uint32_t consumed_thunk_protection = 0U;
        assert(gem_memory_protect(harness.memory, thunk_page, GEM_GUEST_PAGE_SIZE, thunk_protection,
                                  &consumed_thunk_protection) == GEM_MEMORY_OK &&
               consumed_thunk_protection == thunk_protection);
        guarded_thunk = failed_initial;
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &guarded_thunk, callback.resolved_va, resume, config.max_budget,
                   nullptr) == GEM_STOP_ARCH_TRANSITION);

        assert(gem_memory_protect(harness.memory, thunk_page, GEM_GUEST_PAGE_SIZE,
                                  GEM_PAGE_NOACCESS, nullptr) == GEM_MEMORY_OK);
        auto denied_thunk = failed_initial;
        gem_hybrid_roundtrip_stats denied_thunk_stats{};
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &denied_thunk, callback.resolved_va, resume, config.max_budget,
                   &denied_thunk_stats) == GEM_STOP_MEMORY_FAULT);
        auto denied_thunk_expected = failed_initial;
        denied_thunk_expected.stop_reason = GEM_STOP_MEMORY_FAULT;
        assert(std::memcmp(&denied_thunk, &denied_thunk_expected, sizeof(denied_thunk)) == 0);
        assert(denied_thunk_stats.frame_pushes == 1U && denied_thunk_stats.frame_pops == 1U &&
               denied_thunk_stats.final_frame_depth == 0U);
        assert(gem_hybrid_runtime_last_stop_info(runtime, &arm_fault) &&
               arm_fault.source == GEM_HYBRID_STOP_SOURCE_ARM64EC &&
               arm_fault.arm64ec.fault_address == callback_thunk.resolved_va &&
               arm_fault.arm64ec.memory_error == GEM_MEMORY_ACCESS_DENIED);
        assert(gem_memory_protect(harness.memory, thunk_page, GEM_GUEST_PAGE_SIZE, thunk_protection,
                                  nullptr) == GEM_MEMORY_OK);
        denied_thunk = failed_initial;
        assert(gem_hybrid_runtime_run_integer_callback_resume(
                   runtime, &denied_thunk, callback.resolved_va, resume, config.max_budget,
                   nullptr) == GEM_STOP_ARCH_TRANSITION);
        gem_hybrid_runtime_destroy(runtime);
    }

    fill_stack_oracle(harness.memory, UINT8_C(0xA5));
    std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> roundtrip_stack_before{};
    assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                           roundtrip_stack_before.data(),
                           roundtrip_stack_before.size()) == GEM_MEMORY_OK);
    for (unsigned iteration = 0; iteration < 100U; ++iteration) {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        assert(runtime);
        auto context = initial_context(harness.caller);
        const auto initial = context;
        gem_hybrid_roundtrip_stats stats{};
        const auto reason = gem_hybrid_runtime_run_integer_roundtrip(
            runtime, &context, harness.caller, harness.finish, 10000U, &stats);
        if (reason != GEM_STOP_HOST_RETURN)
            std::fprintf(
                stderr,
                "roundtrip failed: %s pc=%llx sp=%llx x0=%llx x8=%llx x9=%llx x18=%llx teb=%llx "
                "arm=%llu x64=%llu checker=%llu call=%llu x2a=%llu desc=%llu ret=%llu "
                "depth=%u\n",
                gem_stop_reason_name(reason), static_cast<unsigned long long>(context.pc),
                static_cast<unsigned long long>(context.sp),
                static_cast<unsigned long long>(context.x[0]),
                static_cast<unsigned long long>(context.x[8]),
                static_cast<unsigned long long>(context.x[9]),
                static_cast<unsigned long long>(context.x[18]),
                static_cast<unsigned long long>(context.teb),
                static_cast<unsigned long long>(stats.arm64ec_instructions_retired),
                static_cast<unsigned long long>(stats.x64_instructions_retired),
                static_cast<unsigned long long>(stats.checker_boundaries),
                static_cast<unsigned long long>(stats.dispatch_call_boundaries),
                static_cast<unsigned long long>(stats.x64_to_arm64ec_boundaries),
                static_cast<unsigned long long>(stats.descriptor_resolutions),
                static_cast<unsigned long long>(stats.dispatch_ret_boundaries),
                stats.final_frame_depth);
        assert(reason == GEM_STOP_HOST_RETURN);
        assert_stop(runtime, reason, GEM_HYBRID_STOP_SOURCE_BROKER);
        assert(initial.x[0] == native.roundtrip_input);
        auto oracle_context = initial;
        oracle_context.x[0] = native.roundtrip_result;
        oracle_context.x[4] = initial.sp - UINT64_C(0x50);
        oracle_context.x[8] = native.roundtrip_result;
        oracle_context.x[9] = harness.finish;
        oracle_context.x[10] = config.loaded_base + UINT64_C(0x3C50);
        oracle_context.x[11] = config.loaded_base + UINT64_C(0x3C50);
        oracle_context.x[16] = kDispatchRet;
        oracle_context.x[17] = initial.sp - UINT64_C(0x10);
        oracle_context.pc = kHostReturn;
        oracle_context.x64_rflags = UINT64_C(0x101A);
        oracle_context.isa = GEM_ISA_ARM64EC;
        oracle_context.stop_reason = GEM_STOP_HOST_RETURN;
        assert_context_oracle(context, oracle_context);
        assert(stats.x64_instructions_retired == 4U && stats.checker_boundaries == 1U &&
               stats.dispatch_call_boundaries == 1U && stats.x64_to_arm64ec_boundaries == 1U &&
               stats.descriptor_resolutions == 1U && stats.dispatch_ret_boundaries == 1U &&
               stats.frame_pushes == 1U && stats.frame_pops == 1U &&
               stats.maximum_frame_depth == 1U && stats.final_frame_depth == 0U);
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> current_stack{};
        assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                               current_stack.data(), current_stack.size()) == GEM_MEMORY_OK);
        if (iteration == 0U) {
            assert_stack_oracle(roundtrip_stack_before, current_stack, UINT64_C(0xED419578AAC667E),
                                0xE00U, 0xEF7U);
            roundtrip_oracle_context = context;
            expected_stack = current_stack;
        } else {
            assert_context_oracle(context, roundtrip_oracle_context);
            assert(current_stack == expected_stack);
        }
        gem_hybrid_runtime_destroy(runtime);
    }

    {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        assert(runtime);
        auto probe = initial_context(harness.caller);
        gem_hybrid_roundtrip_stats probe_stats{};
        assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &probe, harness.caller,
                                                        harness.finish, config.max_budget,
                                                        &probe_stats) == GEM_STOP_HOST_RETURN);
        const auto successful_budget =
            probe_stats.arm64ec_instructions_retired + probe_stats.x64_instructions_retired;
        assert(successful_budget > 1U);
        for (std::uint64_t budget = 1U; budget < successful_budget; ++budget) {
            auto context = initial_context(harness.caller);
            const auto entry = context;
            std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_before{};
            std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> stack_after{};
            assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                   stack_before.data(), stack_before.size()) == GEM_MEMORY_OK);
            gem_hybrid_roundtrip_stats stats{};
            assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &context, harness.caller,
                                                            harness.finish, budget,
                                                            &stats) == GEM_STOP_BUDGET_EXPIRED);
            auto expected = entry;
            expected.stop_reason = GEM_STOP_BUDGET_EXPIRED;
            assert(std::memcmp(&context, &expected, sizeof(context)) == 0);
            assert(stats.frame_pushes == stats.frame_pops && stats.frame_pushes <= 1U &&
                   stats.final_frame_depth == 0U);
            assert(gem_memory_read(harness.memory, kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE,
                                   stack_after.data(), stack_after.size()) == GEM_MEMORY_OK &&
                   stack_after == stack_before);
            context = entry;
            assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &context, harness.caller,
                                                            harness.finish, config.max_budget,
                                                            nullptr) == GEM_STOP_HOST_RETURN);
        }
        gem_hybrid_runtime_destroy(runtime);
    }

    {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        auto context = initial_context(harness.caller);
        context.transition_cookie = 7U;
        assert(runtime && gem_hybrid_runtime_run_integer_roundtrip(
                              runtime, &context, harness.caller, harness.finish, 10000U, nullptr) ==
                              GEM_STOP_INVARIANT_VIOLATION);
        assert_stop(runtime, GEM_STOP_INVARIANT_VIOLATION, GEM_HYBRID_STOP_SOURCE_BROKER);
        gem_hybrid_runtime_destroy(runtime);
    }
    {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        auto context = initial_context(harness.caller);
        assert(runtime && gem_hybrid_runtime_run_integer_roundtrip(
                              runtime, &context, harness.caller, harness.finish, 1U, nullptr) ==
                              GEM_STOP_BUDGET_EXPIRED);
        assert_stop(runtime, GEM_STOP_BUDGET_EXPIRED, GEM_HYBRID_STOP_SOURCE_ARM64EC);
        gem_hybrid_runtime_destroy(runtime);
    }
    {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        bool reached_post_frame_budget = false;
        assert(runtime);
        for (std::uint64_t budget = 2U; budget < 512U && !reached_post_frame_budget; ++budget) {
            auto context = initial_context(harness.caller);
            const auto initial = context;
            gem_hybrid_roundtrip_stats stats{};
            const auto reason = gem_hybrid_runtime_run_integer_roundtrip(
                runtime, &context, harness.caller, harness.finish, budget, &stats);
            if (reason == GEM_STOP_BUDGET_EXPIRED && stats.frame_pushes == 1U) {
                const auto stop = context.stop_reason;
                context.stop_reason = GEM_STOP_NONE;
                assert(std::memcmp(&context, &initial, sizeof(context)) == 0);
                assert(stop == GEM_STOP_BUDGET_EXPIRED && context.transition_cookie == 0U &&
                       stats.final_frame_depth == 0U);
                gem_hybrid_stop_info info{};
                assert(gem_hybrid_runtime_last_stop_info(runtime, &info));
                assert(info.reason == reason);
                reached_post_frame_budget = true;
            }
        }
        assert(reached_post_frame_budget);
        auto retry = initial_context(harness.caller);
        assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &retry, harness.caller,
                                                        harness.finish, 10000U,
                                                        nullptr) == GEM_STOP_HOST_RETURN);
        assert_stop(runtime, GEM_STOP_HOST_RETURN, GEM_HYBRID_STOP_SOURCE_BROKER);
        gem_hybrid_runtime_destroy(runtime);
    }
    {
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        auto context = initial_context(harness.caller);
        const auto initial = context;
        std::uint64_t stack_before = 0U;
        std::uint64_t stack_after = 0U;
        gem_hybrid_roundtrip_stats stats{};
        assert(gem_memory_read(harness.memory, context.sp - sizeof(stack_before), &stack_before,
                               sizeof(stack_before)) == GEM_MEMORY_OK);
        assert(runtime && gem_hybrid_runtime_run_integer_roundtrip(
                              runtime, &context, harness.caller, harness.caller, 10000U, &stats) ==
                              GEM_STOP_INVARIANT_VIOLATION);
        const auto stop = context.stop_reason;
        context.stop_reason = GEM_STOP_NONE;
        assert(std::memcmp(&context, &initial, sizeof(context)) == 0);
        assert(stop == GEM_STOP_INVARIANT_VIOLATION && stats.frame_pushes == 1U &&
               stats.final_frame_depth == 0U && context.transition_cookie == 0U);
        assert(gem_memory_read(harness.memory, context.sp - sizeof(stack_after), &stack_after,
                               sizeof(stack_after)) == GEM_MEMORY_OK &&
               stack_after == stack_before);
        assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &context, harness.caller,
                                                        harness.finish, 10000U,
                                                        nullptr) == GEM_STOP_HOST_RETURN);
        gem_hybrid_runtime_destroy(runtime);
    }
    {
        const auto source_page = kStackBase + kStackSize - GEM_GUEST_PAGE_SIZE;
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &config);
        auto context = initial_context(harness.caller);
        const std::uint64_t marker = UINT64_C(0x6a5b4c3d2e1f9081);
        std::uint64_t previous = 0U;
        std::uint64_t observed = 0U;
        assert(gem_memory_read(harness.memory, source_page, &previous, sizeof(previous)) ==
               GEM_MEMORY_OK);
        assert(runtime &&
               gem_memory_alias(harness.memory, kWriteCopyStackAlias, source_page,
                                GEM_GUEST_PAGE_SIZE, GEM_PAGE_WRITECOPY) == GEM_MEMORY_OK);
        context.sp = kWriteCopyStackAlias + GEM_GUEST_PAGE_SIZE - UINT64_C(0x100);
        assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &context, harness.caller,
                                                        harness.finish, 10000U,
                                                        nullptr) == GEM_STOP_INVARIANT_VIOLATION);
        assert(context.transition_cookie == 0U);
        assert(gem_memory_write(harness.memory, source_page, &marker, sizeof(marker)) ==
               GEM_MEMORY_OK);
        assert(gem_memory_read(harness.memory, kWriteCopyStackAlias, &observed, sizeof(observed)) ==
                   GEM_MEMORY_OK &&
               observed == marker);
        assert(gem_memory_write(harness.memory, source_page, &previous, sizeof(previous)) ==
               GEM_MEMORY_OK);
        context = initial_context(harness.caller);
        assert(gem_hybrid_runtime_run_integer_roundtrip(runtime, &context, harness.caller,
                                                        harness.finish, 10000U,
                                                        nullptr) == GEM_STOP_HOST_RETURN);
        assert(gem_memory_release(harness.memory, kWriteCopyStackAlias, GEM_GUEST_PAGE_SIZE) ==
               GEM_MEMORY_OK);
        gem_hybrid_runtime_destroy(runtime);
    }
    {
        gem_hybrid_runtime_config wrong = config;
        wrong.dispatch_call_helper--;
        gem_hybrid_runtime *runtime = gem_hybrid_runtime_create(harness.memory, metadata, &wrong);
        auto context = initial_context(harness.caller);
        assert(runtime && gem_hybrid_runtime_run_integer_roundtrip(
                              runtime, &context, harness.caller, harness.finish, 10000U, nullptr) ==
                              GEM_STOP_INVARIANT_VIOLATION);
        gem_hybrid_runtime_destroy(runtime);
    }

    /* Wine-facing coordinator: helper dispatch is discovered from the linked
     * metadata slots, transition frames survive one-instruction budget stops,
     * and only the exact captured native caller is exposed to the bridge. */
    {
        struct GenericCase {
            const char *entry;
            std::uint64_t expected;
            std::uint32_t expected_depth;
        };
        const std::array<GenericCase, 2> cases{{
            {"direct", native.direct_result, 1U},
            {"boundedNested", native.nested_result, 2U},
        }};
        for (const auto &test : cases) {
            gem_hybrid_runtime *runtime =
                gem_hybrid_runtime_create(harness.memory, metadata, &config);
            auto context = initial_context(config.loaded_base + entries.at(test.entry));
            std::uint32_t maximum_depth = 0U;
            context.x[0] = 10U;
            assert(runtime);
            for (unsigned segment = 0; segment < 10000U; ++segment) {
                gem_hybrid_roundtrip_stats stats{};
                const auto reason = gem_hybrid_runtime_run(runtime, &context, 1U, &stats);
                maximum_depth = std::max(maximum_depth, stats.maximum_frame_depth);
                if (reason == GEM_STOP_BUDGET_EXPIRED) {
                    context.stop_reason = GEM_STOP_NONE;
                    continue;
                }
                if (reason != GEM_STOP_ARCH_TRANSITION || context.pc != kHostReturn ||
                    context.x[0] != test.expected)
                    std::fprintf(
                        stderr,
                        "generic %s reason=%u pc=%llx x0=%llu isa=%u cookie=%llu "
                        "arm=%llu x64=%llu depth=%u max=%u\n",
                        test.entry, static_cast<unsigned>(reason),
                        static_cast<unsigned long long>(context.pc),
                        static_cast<unsigned long long>(context.x[0]), context.isa,
                        static_cast<unsigned long long>(context.transition_cookie),
                        static_cast<unsigned long long>(stats.arm64ec_instructions_retired),
                        static_cast<unsigned long long>(stats.x64_instructions_retired),
                        stats.final_frame_depth, stats.maximum_frame_depth);
                assert(reason == GEM_STOP_ARCH_TRANSITION && context.pc == kHostReturn &&
                       context.isa == GEM_ISA_ARM64EC && context.transition_cookie == 0U &&
                       context.x[0] == test.expected && stats.final_frame_depth == 0U);
                break;
            }
            assert(context.pc == kHostReturn && maximum_depth == test.expected_depth);
            assert_stop(runtime, GEM_STOP_ARCH_TRANSITION, GEM_HYBRID_STOP_SOURCE_BROKER);
            gem_hybrid_runtime_destroy(runtime);
        }
    }

    for (std::size_t i = 0; i < immutable_pages.size(); ++i) {
        std::array<std::uint8_t, GEM_GUEST_PAGE_SIZE> after{};
        assert(gem_memory_read(harness.memory, immutable_page_addresses[i], after.data(),
                               after.size()) == GEM_MEMORY_OK &&
               after == immutable_pages[i]);
    }

    if (argc == 5)
        write_phase_b_trace(argv[4], harness, entries, metadata);

    std::puts("authentic ARM64EC -> Blink -> ARM64EC integer round trip passed");
    return 0;
}
