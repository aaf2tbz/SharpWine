# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.24)
project(metalsharp_wine_runtime VERSION 0.1.0 LANGUAGES C)

include(CTest)

option(MSWR_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

add_library(metalsharp_gem STATIC src/gem/context.c)
target_include_directories(metalsharp_gem PUBLIC include)
target_compile_features(metalsharp_gem PUBLIC c_std_11)

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
    target_compile_options(metalsharp_gem PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes)
    if(MSWR_WARNINGS_AS_ERRORS)
        target_compile_options(metalsharp_gem PRIVATE -Werror)
    endif()
elseif(MSVC)
    target_compile_options(metalsharp_gem PRIVATE /W4)
    if(MSWR_WARNINGS_AS_ERRORS)
        target_compile_options(metalsharp_gem PRIVATE /WX)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(context_test tests/context_test.c)
    target_link_libraries(context_test PRIVATE metalsharp_gem)
    if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU" AND MSWR_WARNINGS_AS_ERRORS)
        target_compile_options(context_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME gem.context COMMAND context_test)
endif()
