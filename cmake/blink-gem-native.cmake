# SPDX-License-Identifier: Apache-2.0

function(mswr_add_blink_gem_library blink_source)
    if(NOT APPLE OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        message(FATAL_ERROR "GEM_x86_64 Blink JIT requires native Apple Silicon")
    endif()
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
        message(FATAL_ERROR "GEM_x86_64 Blink JIT requires Apple Clang")
    endif()
    find_package(ZLIB REQUIRED)

    file(STRINGS "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/blink-gem-sources.txt"
        blink_relative_sources)
    set(blink_sources)
    foreach(relative IN LISTS blink_relative_sources)
        if(NOT relative MATCHES "^blink/[a-z0-9_]+\\.c$")
            message(FATAL_ERROR "invalid Blink source manifest entry: ${relative}")
        endif()
        if(NOT EXISTS "${blink_source}/${relative}")
            message(FATAL_ERROR "pinned Blink source is absent: ${relative}")
        endif()
        list(APPEND blink_sources "${blink_source}/${relative}")
    endforeach()
    file(GLOB blink_actual_sources RELATIVE "${blink_source}"
        "${blink_source}/blink/*.c")
    list(REMOVE_ITEM blink_actual_sources blink/blink.c blink/blinkenlights.c)
    list(SORT blink_actual_sources)
    set(blink_manifest_sources ${blink_relative_sources})
    list(SORT blink_manifest_sources)
    if(NOT blink_actual_sources STREQUAL blink_manifest_sources)
        message(FATAL_ERROR "pinned Blink C source inventory drifted from reviewed manifest")
    endif()

    set(blink_generated "${CMAKE_CURRENT_BINARY_DIR}/generated/blink-gem")
    file(MAKE_DIRECTORY "${blink_generated}")
    configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/blink-gem-config.h.in"
        "${blink_generated}/config.h" @ONLY)

    add_library(blink_gem_archive STATIC ${blink_sources})
    set_target_properties(blink_gem_archive PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS YES)
    target_include_directories(blink_gem_archive PRIVATE
        "${blink_generated}" "${blink_source}")
    target_compile_definitions(blink_gem_archive PRIVATE
        _FILE_OFFSET_BITS=64
        _DARWIN_C_SOURCE
        _DEFAULT_SOURCE
        _BSD_SOURCE
        _GNU_SOURCE
        BLINK_GEM_EMBEDDING=1
        BLINK_COMMITS="f006a4fc"
        BLINK_UNAME_V="GEM_JIT"
        BUILD_TIMESTAMP="1970-01-01")
    target_compile_options(blink_gem_archive PRIVATE
        -fno-align-functions
        -fno-common
        -fno-omit-frame-pointer
        -fno-optimize-sibling-calls
        -fcf-protection=none
        -U_FORTIFY_SOURCE)
    set_source_files_properties("${blink_source}/blink/uop.c" PROPERTIES
        COMPILE_OPTIONS
        "-fpatchable-function-entry=0,0;-fno-stack-protector;-fno-sanitize=all;-O2;-fomit-frame-pointer")
    target_link_libraries(blink_gem_archive PRIVATE Threads::Threads ZLIB::ZLIB m)
endfunction()
