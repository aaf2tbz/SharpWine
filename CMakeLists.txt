# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.24)
project(metalsharp_wine_runtime VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)

option(MSWR_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

function(mswr_enable_warnings target)
    if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes)
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

add_library(metalsharp_gem STATIC src/gem/context.c src/gem/context_conversion.c
                                  src/gem/context_serialization.c src/gem/memory.c src/gem/pe_arm64x.c)
target_include_directories(metalsharp_gem PUBLIC include)
target_compile_features(metalsharp_gem PUBLIC c_std_11)
mswr_enable_warnings(metalsharp_gem)

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

    add_library(pe_arm64x_fixture STATIC tests/pe_arm64x_fixture_builder.c)
    target_include_directories(pe_arm64x_fixture PUBLIC tests)
    mswr_enable_warnings(pe_arm64x_fixture)
    foreach(test_name pe_arm64x_test pe_arm64x_malformed_test pe_arm64x_fuzz_test)
        add_executable(${test_name} tests/${test_name}.c)
        target_link_libraries(${test_name} PRIVATE metalsharp_gem pe_arm64x_fixture)
        mswr_enable_warnings(${test_name})
        add_test(NAME gem.${test_name} COMMAND ${test_name})
    endforeach()
endif()

add_executable(pe_arm64x_probe tools/pe_arm64x_probe.c)
target_link_libraries(pe_arm64x_probe PRIVATE metalsharp_gem)
mswr_enable_warnings(pe_arm64x_probe)
