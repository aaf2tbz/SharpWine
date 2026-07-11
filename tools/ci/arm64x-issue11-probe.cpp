// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/arm64ec_engine.h"
#include "metalsharp/gem/arm64ec_target.h"
#include "metalsharp/gem/context.h"
#include "metalsharp/gem/memory.h"
#include "metalsharp/gem/pe_arm64x.h"

#include <windows.h>
#include <winternl.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t kStackBase = UINT64_C(0x0000000400000000);
constexpr std::uint64_t kStackSize = UINT64_C(0x10000);
constexpr std::uint64_t kHostReturn = UINT64_C(0xfffffffffffffff0);
constexpr const char *kDynarmicCommit = "a41c380246d3d9f9874f0f792d234dc0cc17c180";

struct StageResult {
    const char *name{};
    bool passed{};
    std::uint64_t start{};
    std::uint64_t boundary{};
    std::uint64_t retired{};
    std::uint64_t transitions{};
    std::uint64_t descriptor{};
    std::uint64_t thunk{};
};

struct Broker {
    gem_arm64ec_target_map *map{};
    std::uint64_t image_base{};
    std::uint64_t image_end{};
    unsigned checker_calls{};
    unsigned dispatch_calls{};
    bool entry_stage{};
};

[[noreturn]] void Fail(const char *message) {
    std::fprintf(stderr, "ARM64X issue #11 probe: %s\n", message);
    std::exit(1);
}

std::vector<std::uint8_t> ReadFile(const wchar_t *path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        Fail("cannot open linked DLL");
    stream.seekg(0, std::ios::end);
    const auto length = stream.tellg();
    if (length <= 0)
        Fail("linked DLL is empty");
    stream.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
    if (!stream.read(reinterpret_cast<char *>(bytes.data()), length))
        Fail("cannot read linked DLL");
    return bytes;
}

std::uint32_t GemProtection(DWORD protection) {
    const DWORD base = protection & 0xffU;
    const bool guard = (protection & PAGE_GUARD) != 0U;
    std::uint32_t result = GEM_PAGE_NOACCESS;
    switch (base) {
    case PAGE_READONLY:
        result = GEM_PAGE_READONLY;
        break;
    case PAGE_READWRITE:
        result = GEM_PAGE_READWRITE;
        break;
    case PAGE_WRITECOPY:
        result = GEM_PAGE_WRITECOPY;
        break;
    case PAGE_EXECUTE:
        result = GEM_PAGE_EXECUTE;
        break;
    case PAGE_EXECUTE_READ:
        result = GEM_PAGE_EXECUTE_READ;
        break;
    case PAGE_EXECUTE_READWRITE:
        result = GEM_PAGE_EXECUTE_READWRITE;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        result = GEM_PAGE_EXECUTE_WRITECOPY;
        break;
    default:
        result = GEM_PAGE_NOACCESS;
        break;
    }
    return guard ? result | GEM_PAGE_GUARD : result;
}

void MapLoadedImage(gem_memory *memory, std::uint64_t base, std::uint64_t size) {
    for (std::uint64_t offset = 0; offset < size; offset += GEM_GUEST_PAGE_SIZE) {
        MEMORY_BASIC_INFORMATION info{};
        auto *host = reinterpret_cast<void *>(base + offset);
        if (VirtualQuery(host, &info, sizeof(info)) != sizeof(info) || info.State != MEM_COMMIT)
            continue;
        const std::uint32_t protection = GemProtection(info.Protect);
        if ((protection & 0xffU) == GEM_PAGE_NOACCESS)
            continue;
        if (gem_memory_map_identity(memory, base + offset, host, GEM_GUEST_PAGE_SIZE, protection) !=
            GEM_MEMORY_OK)
            Fail("cannot map checked loader-view page into GEM");
    }
}

bool InsideImage(const Broker &broker, std::uint64_t address) {
    return address >= broker.image_base && address < broker.image_end;
}

gem_arm64ec_boundary_action Boundary(void *opaque, std::uint64_t pc, gem_thread_context *context,
                                     gem_arm64ec_boundary_kind *kind) {
    auto &broker = *static_cast<Broker *>(opaque);
    if (InsideImage(broker, pc))
        return GEM_ARM64EC_BOUNDARY_NOT_HANDLED;

    if (!broker.entry_stage && broker.checker_calls == 0U) {
        gem_arm64ec_target_result target{};
        *kind = GEM_ARM64EC_BOUNDARY_CHECK_ICALL;
        if (gem_arm64ec_checker_dispatch(broker.map, nullptr, false, context, &target) !=
                GEM_ARM64EC_TARGET_OK ||
            target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
            return GEM_ARM64EC_BOUNDARY_FAIL;
        ++broker.checker_calls;
        context->pc = context->x[30];
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }

    *kind = broker.entry_stage ? GEM_ARM64EC_BOUNDARY_DISPATCH_RETURN
                               : GEM_ARM64EC_BOUNDARY_DISPATCH_CALL;
    if (broker.entry_stage) {
        ++broker.dispatch_calls;
        context->pc = kHostReturn;
        return GEM_ARM64EC_BOUNDARY_RESUME;
    }

    gem_arm64ec_target_result target{};
    if (gem_arm64ec_target_resolve(broker.map, context->x[9], &target) != GEM_ARM64EC_TARGET_OK ||
        target.kind != GEM_ARM64EC_TARGET_X64_BOUNDARY)
        return GEM_ARM64EC_BOUNDARY_FAIL;
    ++broker.dispatch_calls;
    context->pc = target.resolved_va;
    return GEM_ARM64EC_BOUNDARY_RESUME;
}

void InitContext(gem_thread_context &context, std::uint64_t pc, std::uint64_t teb) {
    gem_context_initialize(&context, teb, GEM_ISA_ARM64EC);
    context.pc = pc;
    context.sp = kStackBase + kStackSize - 0x100U;
    context.x[30] = kHostReturn;
}

StageResult RunExitStage(const char *name, std::uint64_t export_va, std::uint64_t x0,
                         gem_arm64ec_runtime *runtime, Broker &broker) {
    gem_thread_context context{};
    gem_arm64ec_stop_info stop{};
    InitContext(context, export_va, reinterpret_cast<std::uint64_t>(NtCurrentTeb()));
    context.x[0] = x0;
    broker.entry_stage = false;
    broker.checker_calls = 0U;
    broker.dispatch_calls = 0U;
    const auto reason = gem_arm64ec_runtime_run(runtime, &context, 10000U);
    if (!gem_arm64ec_runtime_last_stop_info(runtime, &stop))
        Fail("missing exit-stage stop information");
    StageResult result{name};
    result.start = export_va;
    result.boundary = context.pc;
    result.retired = stop.instructions_retired;
    result.transitions = gem_arm64ec_runtime_transition_count(runtime);
    result.passed = reason == GEM_STOP_ARCH_TRANSITION && broker.checker_calls == 1U &&
                    broker.dispatch_calls == 1U && context.pc == context.x[9] &&
                    context.x[18] == context.teb && stop.access == GEM_ARM64EC_ACCESS_NONE;
    return result;
}

StageResult RunEntryStage(std::uint64_t export_va, gem_memory *memory, gem_arm64ec_target_map *map,
                          gem_arm64ec_runtime *runtime, Broker &broker) {
    gem_arm64ec_target_result body{};
    gem_arm64ec_target_result thunk{};
    if (gem_arm64ec_target_resolve(map, export_va, &body) != GEM_ARM64EC_TARGET_OK ||
        body.kind != GEM_ARM64EC_TARGET_ARM64EC || body.resolved_va < 4U)
        Fail("cannot resolve authentic ARM64EC function body");
    const std::uint64_t descriptor = body.resolved_va - 4U;
    if (gem_arm64ec_descriptor_resolve(map, memory, descriptor, nullptr, &thunk) !=
        GEM_ARM64EC_TARGET_OK)
        Fail("cannot resolve authentic entry descriptor");

    gem_thread_context context{};
    gem_arm64ec_stop_info stop{};
    InitContext(context, thunk.resolved_va, reinterpret_cast<std::uint64_t>(NtCurrentTeb()));
    context.x[0] = 0x100U;
    context.x[9] = body.resolved_va;
    broker.entry_stage = true;
    broker.checker_calls = 0U;
    broker.dispatch_calls = 0U;
    const auto reason = gem_arm64ec_runtime_run(runtime, &context, 10000U);
    if (!gem_arm64ec_runtime_last_stop_info(runtime, &stop))
        Fail("missing entry-stage stop information");
    StageResult result{"entryInteger"};
    result.start = thunk.resolved_va;
    result.boundary = context.pc;
    result.retired = stop.instructions_retired;
    result.transitions = gem_arm64ec_runtime_transition_count(runtime);
    result.descriptor = descriptor;
    result.thunk = thunk.resolved_va;
    result.passed = reason == GEM_STOP_HOST_RETURN && broker.checker_calls == 0U &&
                    broker.dispatch_calls == 1U && context.x[18] == context.teb;
    return result;
}

void PrintStage(std::FILE *output, const StageResult &stage, bool comma) {
    std::fprintf(output,
                 "%s{\"name\":\"%s\",\"passed\":%s,\"startVa\":%llu,\"boundaryVa\":%llu,"
                 "\"instructionsRetired\":%llu,\"transitions\":%llu,\"descriptorVa\":%llu,"
                 "\"entryThunkVa\":%llu}",
                 comma ? "," : "", stage.name, stage.passed ? "true" : "false",
                 static_cast<unsigned long long>(stage.start),
                 static_cast<unsigned long long>(stage.boundary),
                 static_cast<unsigned long long>(stage.retired),
                 static_cast<unsigned long long>(stage.transitions),
                 static_cast<unsigned long long>(stage.descriptor),
                 static_cast<unsigned long long>(stage.thunk));
}
} // namespace

int wmain(int argc, wchar_t **argv) {
    if (argc != 5)
        Fail("usage: probe <dll> <dll-sha256> <inspection-sha256> <output-json>");
    const auto file_bytes = ReadFile(argv[1]);
    gem_pe_arm64x_image *image = nullptr;
    if (gem_pe_arm64x_parse(file_bytes.data(), file_bytes.size(), nullptr, &image) != GEM_PE_OK)
        Fail("repository parser rejected linked DLL");
    gem_pe_arm64x_summary summary{};
    if (gem_pe_arm64x_get_summary(image, &summary) != GEM_PE_OK)
        Fail("cannot read linked image summary");

    HMODULE module = LoadLibraryExW(
        argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr)
        Fail("Windows loader rejected linked DLL");
    const auto loaded_base = reinterpret_cast<std::uint64_t>(module);
    gem_memory *memory = gem_memory_create();
    if (memory == nullptr)
        Fail("cannot create GEM memory");
    MapLoadedImage(memory, loaded_base, summary.size_of_image);
    std::uint64_t stack = kStackBase;
    if (gem_memory_reserve(memory, &stack, kStackSize) != GEM_MEMORY_OK ||
        gem_memory_commit(memory, stack, kStackSize, GEM_PAGE_READWRITE) != GEM_MEMORY_OK)
        Fail("cannot create GEM stack");

    gem_arm64ec_target_map *map = nullptr;
    if (gem_arm64ec_target_map_create(image, loaded_base, &map) != GEM_ARM64EC_TARGET_OK)
        Fail("cannot create checked target map");
    gem_arm64ec_runtime_config config{};
    config.host_return_sentinel = kHostReturn;
    config.arch_transition_sentinel = UINT64_C(0xffffffffffffffe0);
    config.max_budget = 100000U;
    config.max_transitions = 8U;
    gem_arm64ec_runtime *runtime = gem_arm64ec_runtime_create(memory, &config);
    if (runtime == nullptr || !gem_arm64ec_runtime_attach_arm64x(runtime, image, loaded_base))
        Fail("cannot create metadata-bound Dynarmic runtime");
    Broker broker{map, loaded_base, loaded_base + summary.size_of_image};
    if (!gem_arm64ec_runtime_set_boundary_broker(runtime, Boundary, &broker))
        Fail("cannot install transition broker");

    struct ExportStage {
        const char *stage;
        const char *symbol;
        std::uint64_t x0;
    };
    constexpr std::array<ExportStage, 4> exports = {
        {{"integerExit", "fixture_indirect_x64", 12U},
         {"floatingExit", "fixture_indirect_x64_floating", 0U},
         {"aggregateExit", "fixture_indirect_x64_aggregate", 0U},
         {"variadicExit", "fixture_indirect_x64_variadic", 4U}}};
    std::array<StageResult, 5> stages{};
    for (std::size_t i = 0; i < exports.size(); ++i) {
        const auto address =
            reinterpret_cast<std::uint64_t>(GetProcAddress(module, exports[i].symbol));
        if (address == 0U)
            Fail("linked fixture export is absent");
        stages[i] = RunExitStage(exports[i].stage, address, exports[i].x0, runtime, broker);
    }
    const auto integer_export =
        reinterpret_cast<std::uint64_t>(GetProcAddress(module, "fixture_integer"));
    if (integer_export == 0U)
        Fail("integer export is absent");
    stages[4] = RunEntryStage(integer_export, memory, map, runtime, broker);

    bool passed = true;
    for (const auto &stage : stages)
        passed = passed && stage.passed;
    std::FILE *output = nullptr;
    if (_wfopen_s(&output, argv[4], L"wb") != 0 || output == nullptr)
        Fail("cannot create execution evidence");
    std::fprintf(output,
                 "{\"schemaVersion\":1,\"distribution\":\"build-tree-only\","
                 "\"producer\":\"arm64x_issue11_probe\",\"dynarmicCommit\":\"%s\","
                 "\"dllSha256\":\"%ls\",\"inspectionSha256\":\"%ls\","
                 "\"nativeMachine\":\"arm64\",\"contextSize\":%zu,"
                 "\"imageBase\":%llu,\"loadedBase\":%llu,\"blinkLoaded\":false,"
                 "\"x64InstructionsFetched\":0,\"passed\":%s,\"stages\":[",
                 kDynarmicCommit, argv[2], argv[3], sizeof(gem_thread_context),
                 static_cast<unsigned long long>(summary.image_base),
                 static_cast<unsigned long long>(loaded_base), passed ? "true" : "false");
    for (std::size_t i = 0; i < stages.size(); ++i)
        PrintStage(output, stages[i], i != 0U);
    std::fprintf(output, "]}\n");
    std::fclose(output);

    gem_arm64ec_runtime_destroy(runtime);
    gem_arm64ec_target_map_destroy(map);
    gem_memory_destroy(memory);
    gem_pe_arm64x_image_destroy(image);
    FreeLibrary(module);
    return passed ? 0 : 1;
}
