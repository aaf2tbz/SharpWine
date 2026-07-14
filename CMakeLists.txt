# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.24)
project(metalsharp_wine_runtime VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
find_package(Threads REQUIRED)

option(MSWR_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(MSWR_ENABLE_ARM64EC_ENGINE "Build the selected ARM64EC correctness engine backend" OFF)
option(MSWR_ENGINE_DYNARMIC "Use Dynarmic as the ARM64EC correctness engine backend" ON)
option(MSWR_ENGINE_CONFORMANCE "Build ARM64EC engine conformance tests" OFF)
option(MSWR_ZERO_ROSETTA_AUDIT "Build/run native ARM64 macOS zero-Rosetta audit tests" OFF)
option(MSWR_FETCH_DYNARMIC "Fetch the pinned Dynarmic dependency when engine support is enabled" ON)
option(MSWR_ENABLE_X64_ENGINE "Build the pinned Blink GEM_x86_64 adapter" OFF)
option(MSWR_X64_ENGINE_CONFORMANCE "Build x64 engine conformance tests" OFF)
option(MSWR_BUILD_WINE_BRIDGE "Build the versioned native Wine/GEM bridge dylib" OFF)
option(MSWR_WINE_BRIDGE_CONFORMANCE "Build Wine/GEM bridge conformance tests" OFF)
option(MSWR_BUILD_ARM64X_ISSUE11_PROBE "Build the native Windows ARM64 issue #11 probe" OFF)
set(MSWR_ARM64X_ROUNDTRIP_ARTIFACT_DIR "" CACHE PATH
    "Validated run-scoped Issue #14 artifact directory (opt-in)")
# Raw ARM64EC COFF is structural research only: it is not a linked ARM64X fixture.
option(MSWR_GENERATE_ARM64EC_THUNK_FIXTURES "Generate non-binding LLVM ARM64EC COFF research evidence" OFF)

if(MSWR_GENERATE_ARM64EC_THUNK_FIXTURES AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(MSWR_ARM64EC_THUNK_ASM "${CMAKE_CURRENT_BINARY_DIR}/fixtures/arm64ec_thunks.s")
    set(MSWR_ARM64EC_THUNK_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/fixtures/arm64ec_thunks.obj")
    set(MSWR_ARM64EC_THUNK_PROVENANCE
        "${CMAKE_CURRENT_BINARY_DIR}/fixtures/arm64ec_thunks.provenance.json")
    add_custom_command(OUTPUT "${MSWR_ARM64EC_THUNK_ASM}" "${MSWR_ARM64EC_THUNK_OBJECT}"
                              "${MSWR_ARM64EC_THUNK_PROVENANCE}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_arm64ec_thunk_fixture.py"
            --clang "${CMAKE_C_COMPILER}" --source "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/arm64ec_thunks.c"
            --output "${MSWR_ARM64EC_THUNK_ASM}" --object "${MSWR_ARM64EC_THUNK_OBJECT}"
            --llvm-provenance "${CMAKE_CURRENT_SOURCE_DIR}/docs/architecture/adr/llvm-arm64ec-fixture.provenance.json"
        DEPENDS tests/fixtures/arm64ec_thunks.c tools/generate_arm64ec_thunk_fixture.py
                docs/architecture/adr/llvm-arm64ec-fixture.provenance.json
        VERBATIM)
    add_custom_target(arm64ec_llvm_thunk_fixtures ALL DEPENDS "${MSWR_ARM64EC_THUNK_ASM}"
                                                               "${MSWR_ARM64EC_THUNK_OBJECT}"
                                                               "${MSWR_ARM64EC_THUNK_PROVENANCE}")
elseif(MSWR_GENERATE_ARM64EC_THUNK_FIXTURES)
    message(STATUS "ARM64EC LLVM thunk generation requires Clang; source fixture remains available")
endif()

function(mswr_enable_warnings target)
    if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow;-Wstrict-prototypes>
            $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>)
        if(MSWR_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    elseif(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(MSWR_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    endif()
endfunction()

add_library(metalsharp_gem STATIC
    src/gem/arm64ec_engine.c
    src/gem/arm64ec_target.c
    src/gem/context.c
    src/gem/context_conversion.c
    src/gem/context_serialization.c
    src/gem/memory.c
    src/gem/pe_arm64x.c
    src/gem/pe_arm64x_loader.c)
target_include_directories(metalsharp_gem PUBLIC include)
target_compile_features(metalsharp_gem PUBLIC c_std_11)
target_link_libraries(metalsharp_gem PUBLIC Threads::Threads)

if(MSWR_ENABLE_ARM64EC_ENGINE)
    if(NOT MSWR_ENGINE_DYNARMIC)
        message(FATAL_ERROR "MSWR_ENABLE_ARM64EC_ENGINE currently requires MSWR_ENGINE_DYNARMIC=ON")
    endif()
    if(NOT MSWR_FETCH_DYNARMIC)
        if(MSWR_ENGINE_CONFORMANCE)
            message(FATAL_ERROR "MSWR_ENGINE_CONFORMANCE requires pinned FetchContent Dynarmic")
        endif()
        message(WARNING "system Dynarmic is a non-conformance developer mode; provenance is not pinned")
        find_package(dynarmic 6.7 CONFIG REQUIRED)
    else()
        include(FetchContent)
        set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)
        set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
        set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
        set(DYNARMIC_TESTS_USE_UNICORN OFF CACHE BOOL "" FORCE)
        set(DYNARMIC_FRONTENDS A64 CACHE STRING "" FORCE)
        set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
        set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)
        set(DYNARMIC_USE_LLVM OFF CACHE BOOL "" FORCE)
        set(DYNARMIC_USE_PRECOMPILED_HEADERS ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
            dynarmic
            URL https://github.com/lioncash/dynarmic/archive/a41c380246d3d9f9874f0f792d234dc0cc17c180.tar.gz
            URL_HASH SHA256=cc0dfec19b7cfb80a649bd994bd0569c0482de1f49448773d2899f30b6a180c3
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            PATCH_COMMAND
                "${CMAKE_COMMAND}"
                "-DDYNARMIC_SOURCE_DIR=<SOURCE_DIR>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch-dynarmic-windows-arm64.cmake")
        FetchContent_MakeAvailable(dynarmic)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        set(MSWR_ARM64EC_DECODER_HEADER
            "${CMAKE_CURRENT_BINARY_DIR}/generated/arm64ec_forbidden_register_decoder.h")
        execute_process(
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_arm64ec_forbidden_decoder.py"
                "${dynarmic_SOURCE_DIR}/src/dynarmic/frontend/A64/translate/impl/impl.h"
                "${MSWR_ARM64EC_DECODER_HEADER}"
            RESULT_VARIABLE mswr_decoder_generator_result)
        if(NOT mswr_decoder_generator_result EQUAL 0)
            message(FATAL_ERROR "failed to generate pinned ARM64EC operand decoder visitor")
        endif()
        if(TARGET fmt)
            target_compile_definitions(fmt PUBLIC FMT_CONSTEVAL=)
        endif()
    endif()
    if(TARGET dynarmic::dynarmic AND NOT TARGET dynarmic)
        add_library(dynarmic ALIAS dynarmic::dynarmic)
    endif()
    target_sources(metalsharp_gem PRIVATE src/gem/arm64ec_dynarmic.cpp)
    target_compile_definitions(metalsharp_gem PRIVATE MSWR_ARM64EC_DYNARMIC_ENABLED=1)
    if(NOT MSWR_FETCH_DYNARMIC)
        target_compile_definitions(metalsharp_gem PRIVATE MSWR_DYNARMIC_SYSTEM=1)
    endif()
    target_compile_features(metalsharp_gem PRIVATE cxx_std_20)
    if(MSWR_FETCH_DYNARMIC)
        target_include_directories(metalsharp_gem PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${dynarmic_SOURCE_DIR}/src")
        target_include_directories(metalsharp_gem SYSTEM PRIVATE
            "${dynarmic_SOURCE_DIR}/externals/mcl/include"
            "${dynarmic_SOURCE_DIR}/externals/fmt/include")
    endif()
    target_link_libraries(metalsharp_gem PRIVATE dynarmic)
endif()

if(MSWR_ENABLE_X64_ENGINE)
    include(FetchContent)
    FetchContent_Declare(blink_gem
        URL https://github.com/jart/blink/archive/f006a4fc6f9b8de9272504fdff0dbbe5ce5dc580.tar.gz
        URL_HASH SHA256=e0bad68ba2927a1ca1d53537afee1644e11a1e683d26676a36e5b9b17a63d6af
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        PATCH_COMMAND "${CMAKE_COMMAND}" "-DBLINK_SOURCE_DIR=<SOURCE_DIR>"
            "-DMSWR_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch-blink-gem.cmake")
    FetchContent_MakeAvailable(blink_gem)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/audit_blink_embedding.py"
        --source "${blink_gem_SOURCE_DIR}"
        --patch "${CMAKE_CURRENT_SOURCE_DIR}/third_party/patches/blink/0001-gem-real-interpreter-embedding.patch"
        --jit-patch "${CMAKE_CURRENT_SOURCE_DIR}/third_party/patches/blink/0002-gem-bounded-jit-embedding.patch"
        --provenance "${CMAKE_CURRENT_SOURCE_DIR}/docs/architecture/adr/0008-blink-embedding.provenance.json"
        RESULT_VARIABLE blink_audit_result)
    if(NOT blink_audit_result EQUAL 0)
        message(FATAL_ERROR "real Blink bounded embedding audit failed")
    endif()
    include(cmake/blink-gem-native.cmake)
    mswr_add_blink_gem_library("${blink_gem_SOURCE_DIR}")
    add_library(GEM_x86_64 OBJECT src/gem/x64_engine.c src/gem/x64_blink.c)
    target_include_directories(GEM_x86_64 PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include" "${blink_gem_SOURCE_DIR}")
    target_compile_features(GEM_x86_64 PRIVATE c_std_11)
    set_property(TARGET GEM_x86_64 PROPERTY POSITION_INDEPENDENT_CODE ON)
    mswr_enable_warnings(GEM_x86_64)
    target_sources(metalsharp_gem PRIVATE $<TARGET_OBJECTS:GEM_x86_64>)
    if(MSWR_ENABLE_ARM64EC_ENGINE)
        target_sources(metalsharp_gem PRIVATE src/gem/hybrid_runtime.c)
    endif()
    target_include_directories(metalsharp_gem PRIVATE "${blink_gem_SOURCE_DIR}")
    target_link_libraries(metalsharp_gem PRIVATE blink_gem_archive m)
elseif(MSWR_X64_ENGINE_CONFORMANCE)
    message(FATAL_ERROR "MSWR_X64_ENGINE_CONFORMANCE requires MSWR_ENABLE_X64_ENGINE")
endif()
mswr_enable_warnings(metalsharp_gem)

if(MSWR_BUILD_WINE_BRIDGE)
    if(NOT MSWR_ENABLE_ARM64EC_ENGINE OR NOT MSWR_ENABLE_X64_ENGINE)
        message(FATAL_ERROR
            "MSWR_BUILD_WINE_BRIDGE requires both ARM64EC and GEM_x86_64 engines")
    endif()
    set_property(TARGET metalsharp_gem PROPERTY POSITION_INDEPENDENT_CODE ON)
    add_library(metalsharp_gem_wine SHARED src/gem/wine_bridge.c)
    if(APPLE)
        target_sources(metalsharp_gem_wine PRIVATE src/gem/macos_fd_compat.c)
    endif()
    target_include_directories(metalsharp_gem_wine PUBLIC include)
    target_compile_features(metalsharp_gem_wine PUBLIC c_std_11)
    target_compile_definitions(metalsharp_gem_wine PRIVATE GEM_WINE_BUILD=1)
    target_link_libraries(metalsharp_gem_wine PRIVATE metalsharp_gem Threads::Threads)
    set_target_properties(metalsharp_gem_wine PROPERTIES
        OUTPUT_NAME "metalsharp-gem-wine"
        VERSION "0.1.0"
        SOVERSION "0"
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)
    if(APPLE)
        target_link_options(metalsharp_gem_wine PRIVATE
            "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/cmake/metalsharp-gem-wine.exports")
    endif()
    mswr_enable_warnings(metalsharp_gem_wine)
    install(TARGETS metalsharp_gem_wine
        LIBRARY DESTINATION lib
        COMPONENT metalsharp-gem-wine)
    install(FILES
        include/metalsharp/gem/context.h
        include/metalsharp/gem/wine_bridge.h
        DESTINATION include/metalsharp/gem
        COMPONENT metalsharp-gem-wine)
elseif(MSWR_WINE_BRIDGE_CONFORMANCE)
    message(FATAL_ERROR "MSWR_WINE_BRIDGE_CONFORMANCE requires MSWR_BUILD_WINE_BRIDGE=ON")
endif()

if(MSWR_BUILD_ARM64X_ISSUE11_PROBE)
    if(NOT WIN32 OR NOT MSWR_ENABLE_ARM64EC_ENGINE)
        message(FATAL_ERROR "MSWR_BUILD_ARM64X_ISSUE11_PROBE requires Windows and the ARM64EC engine")
    endif()
    add_executable(arm64x_issue11_probe tools/ci/arm64x-issue11-probe.cpp)
    target_link_libraries(arm64x_issue11_probe PRIVATE metalsharp_gem)
    target_compile_features(arm64x_issue11_probe PRIVATE cxx_std_20)
    mswr_enable_warnings(arm64x_issue11_probe)
endif()

if(BUILD_TESTING)
    add_executable(context_test tests/context_test.c)
    target_link_libraries(context_test PRIVATE metalsharp_gem)
    mswr_enable_warnings(context_test)
    add_test(NAME gem.context COMMAND context_test)

    add_executable(context_layout_test tests/context_layout_test.c)
    target_link_libraries(context_layout_test PRIVATE metalsharp_gem)
    mswr_enable_warnings(context_layout_test)
    add_test(NAME gem.context_layout COMMAND context_layout_test)

    add_executable(gem_headers_cxx_test tests/gem_headers_cxx_test.cpp)
    target_link_libraries(gem_headers_cxx_test PRIVATE metalsharp_gem)
    mswr_enable_warnings(gem_headers_cxx_test)
    add_test(NAME gem.headers_cxx COMMAND gem_headers_cxx_test)

    foreach(test_name context_conversion_test context_serialization_test memory_test)
        add_executable(${test_name} tests/${test_name}.c)
        target_link_libraries(${test_name} PRIVATE metalsharp_gem)
        mswr_enable_warnings(${test_name})
        add_test(NAME gem.${test_name} COMMAND ${test_name})
    endforeach()

    add_executable(memory_page_isolation_test tests/memory_page_isolation_test.cpp)
    target_link_libraries(memory_page_isolation_test PRIVATE metalsharp_gem)
    target_include_directories(memory_page_isolation_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/gem")
    target_compile_features(memory_page_isolation_test PRIVATE cxx_std_17)
    mswr_enable_warnings(memory_page_isolation_test)
    add_test(NAME gem.memory_page_isolation COMMAND memory_page_isolation_test)
    set_tests_properties(gem.memory_page_isolation PROPERTIES LABELS "page-isolation;zero-rosetta")

    if(APPLE)
        add_executable(macos_tso_api_probe tests/macos_tso_api_probe.c)
        target_link_libraries(macos_tso_api_probe PRIVATE "${CMAKE_DL_LIBS}")
        mswr_enable_warnings(macos_tso_api_probe)
        add_test(NAME gem.macos_tso_api_probe COMMAND macos_tso_api_probe)
        set_tests_properties(gem.macos_tso_api_probe PROPERTIES LABELS "zero-rosetta;tso")
    endif()

    if(MSWR_ENGINE_CONFORMANCE)
        if(NOT MSWR_ENABLE_ARM64EC_ENGINE)
            message(FATAL_ERROR "MSWR_ENGINE_CONFORMANCE requires MSWR_ENABLE_ARM64EC_ENGINE=ON")
        endif()
        add_executable(arm64ec_engine_conformance tests/arm64ec_engine_conformance.cpp)
        target_link_libraries(arm64ec_engine_conformance PRIVATE metalsharp_gem)
        target_compile_features(arm64ec_engine_conformance PRIVATE cxx_std_20)
        mswr_enable_warnings(arm64ec_engine_conformance)
        add_test(NAME gem.arm64ec_engine_conformance COMMAND arm64ec_engine_conformance)
        set_tests_properties(gem.arm64ec_engine_conformance PROPERTIES LABELS "gem.engine.conformance")
    endif()

    if(MSWR_WINE_BRIDGE_CONFORMANCE)
        add_executable(wine_bridge_conformance tests/wine_bridge_conformance.c)
        target_link_libraries(wine_bridge_conformance PRIVATE metalsharp_gem_wine)
        mswr_enable_warnings(wine_bridge_conformance)
        add_test(NAME gem.wine_bridge_conformance COMMAND wine_bridge_conformance)
        set_tests_properties(gem.wine_bridge_conformance PROPERTIES LABELS "zero-rosetta;wine-bridge")

        add_executable(wine_x86_64_bridge_conformance tests/wine_x86_64_bridge_conformance.c)
        target_link_libraries(wine_x86_64_bridge_conformance PRIVATE metalsharp_gem_wine)
        mswr_enable_warnings(wine_x86_64_bridge_conformance)
        add_test(NAME gem.wine_x86_64_bridge_conformance COMMAND wine_x86_64_bridge_conformance)
        set_tests_properties(gem.wine_x86_64_bridge_conformance PROPERTIES
            LABELS "zero-rosetta;wine-bridge;production-jit;interpreter-oracle")
    endif()

    if(MSWR_X64_ENGINE_CONFORMANCE)
        add_executable(x64_engine_conformance tests/x64_engine_conformance.cpp)
        target_link_libraries(x64_engine_conformance PRIVATE metalsharp_gem)
        target_include_directories(x64_engine_conformance PRIVATE "${blink_gem_SOURCE_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/gem")
        target_compile_features(x64_engine_conformance PRIVATE cxx_std_17)
        mswr_enable_warnings(x64_engine_conformance)
        add_test(NAME gem.x64_engine_conformance COMMAND x64_engine_conformance)
        set_tests_properties(gem.x64_engine_conformance PROPERTIES
            LABELS "zero-rosetta;gem.engine;interpreter-oracle")

        add_executable(x86_64_jit_conformance tests/x86_64_jit_conformance.cpp)
        target_link_libraries(x86_64_jit_conformance PRIVATE metalsharp_gem)
        target_compile_features(x86_64_jit_conformance PRIVATE cxx_std_17)
        mswr_enable_warnings(x86_64_jit_conformance)
        add_test(NAME gem.x86_64_jit_conformance COMMAND x86_64_jit_conformance)
        set_tests_properties(gem.x86_64_jit_conformance PROPERTIES
            LABELS "zero-rosetta;gem.engine;production-jit")
    endif()

    if(MSWR_ARM64X_ROUNDTRIP_ARTIFACT_DIR)
        if(NOT MSWR_ENABLE_ARM64EC_ENGINE OR NOT MSWR_ENABLE_X64_ENGINE)
            message(FATAL_ERROR "Issue #14 round-trip artifacts require both engines")
        endif()
        set(mswr_roundtrip_dll
            "${MSWR_ARM64X_ROUNDTRIP_ARTIFACT_DIR}/arm64x_fixture.dll")
        set(mswr_roundtrip_map
            "${MSWR_ARM64X_ROUNDTRIP_ARTIFACT_DIR}/arm64ec-entry-map.txt")
        set(mswr_roundtrip_native_oracle
            "${MSWR_ARM64X_ROUNDTRIP_ARTIFACT_DIR}/native-evidence.json")
        if(NOT EXISTS "${mswr_roundtrip_dll}" OR NOT EXISTS "${mswr_roundtrip_map}" OR
                NOT EXISTS "${mswr_roundtrip_native_oracle}")
            message(FATAL_ERROR "Issue #14 artifact directory is missing validated inputs")
        endif()
        add_executable(arm64x_roundtrip_conformance tests/arm64x_roundtrip_conformance.cpp)
        target_link_libraries(arm64x_roundtrip_conformance PRIVATE metalsharp_gem)
        target_include_directories(arm64x_roundtrip_conformance PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/gem" "${blink_gem_SOURCE_DIR}")
        target_compile_features(arm64x_roundtrip_conformance PRIVATE cxx_std_17)
        mswr_enable_warnings(arm64x_roundtrip_conformance)
        add_test(NAME gem.arm64x_roundtrip COMMAND arm64x_roundtrip_conformance
            "${mswr_roundtrip_dll}" "${mswr_roundtrip_map}" "${mswr_roundtrip_native_oracle}")
        set_tests_properties(gem.arm64x_roundtrip PROPERTIES
            LABELS "zero-rosetta;gem.engine;authentic-arm64x")
        if(APPLE AND MSWR_BUILD_WINE_BRIDGE)
            add_executable(wine_arm64x_conformance tests/wine_arm64x_conformance.cpp)
            target_link_libraries(wine_arm64x_conformance PRIVATE metalsharp_gem_wine metalsharp_gem)
            target_compile_features(wine_arm64x_conformance PRIVATE cxx_std_17)
            mswr_enable_warnings(wine_arm64x_conformance)
            add_test(NAME gem.wine_arm64x_conformance COMMAND wine_arm64x_conformance
                "${mswr_roundtrip_dll}")
            set_tests_properties(gem.wine_arm64x_conformance PROPERTIES
                LABELS "zero-rosetta;wine-bridge;authentic-arm64x")
        endif()
    endif()

    if(MSWR_ZERO_ROSETTA_AUDIT)
        add_executable(arm64ec_engine_zero_rosetta tests/arm64ec_engine_zero_rosetta.cpp)
        mswr_enable_warnings(arm64ec_engine_zero_rosetta)
        add_test(NAME gem.arm64ec_engine_zero_rosetta COMMAND arm64ec_engine_zero_rosetta)
        set_tests_properties(gem.arm64ec_engine_zero_rosetta PROPERTIES LABELS "zero-rosetta")
    endif()

    add_library(pe_arm64x_fixture STATIC tests/pe_arm64x_fixture_builder.c)
    target_include_directories(pe_arm64x_fixture PUBLIC tests)
    mswr_enable_warnings(pe_arm64x_fixture)
    if(TARGET arm64ec_engine_conformance)
        target_link_libraries(arm64ec_engine_conformance PRIVATE pe_arm64x_fixture)
    endif()
    add_executable(arm64ec_target_test tests/arm64ec_target_test.c)
    target_link_libraries(arm64ec_target_test PRIVATE metalsharp_gem pe_arm64x_fixture)
    mswr_enable_warnings(arm64ec_target_test)
    add_test(NAME gem.arm64ec_target COMMAND arm64ec_target_test)

    foreach(test_name pe_arm64x_test pe_arm64x_malformed_test pe_arm64x_fuzz_test
                      pe_arm64x_loader_test)
        add_executable(${test_name} tests/${test_name}.c)
        target_link_libraries(${test_name} PRIVATE metalsharp_gem pe_arm64x_fixture)
        mswr_enable_warnings(${test_name})
        add_test(NAME gem.${test_name} COMMAND ${test_name})
    endforeach()

    # Conformance checks intentionally use assert() as their executable oracle.
    # Keep that oracle active in optimized configurations so Release builds do
    # not compile away both validation and the values consumed only by it.
    set(mswr_assert_test_targets
        context_test context_layout_test gem_headers_cxx_test
        context_conversion_test context_serialization_test memory_test
        memory_page_isolation_test macos_tso_api_probe
        arm64ec_engine_conformance wine_bridge_conformance x64_engine_conformance
        x86_64_jit_conformance wine_x86_64_bridge_conformance
        arm64x_roundtrip_conformance wine_arm64x_conformance
        arm64ec_engine_zero_rosetta arm64ec_target_test
        pe_arm64x_test pe_arm64x_malformed_test pe_arm64x_fuzz_test
        pe_arm64x_loader_test)
    foreach(test_target IN LISTS mswr_assert_test_targets)
        if(TARGET ${test_target})
            if(MSVC)
                target_compile_options(${test_target} PRIVATE $<$<CONFIG:Release>:/UNDEBUG>)
            else()
                target_compile_options(${test_target} PRIVATE $<$<CONFIG:Release>:-UNDEBUG>)
            endif()
        endif()
    endforeach()
endif()

add_executable(pe_arm64x_probe tools/pe_arm64x_probe.c)
target_link_libraries(pe_arm64x_probe PRIVATE metalsharp_gem)
mswr_enable_warnings(pe_arm64x_probe)
