# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.24)
project(metalsharp_arm64x_linked_fixture C)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "The linked ARM64X fixture requires the pinned Microsoft Windows toolchain")
endif()
if(NOT DEFINED BUILD_AS_ARM64X)
  message(FATAL_ERROR "BUILD_AS_ARM64X must be ARM64 or ARM64EC")
endif()

set(fixture_exports fixture.def)
if(BUILD_AS_ARM64X STREQUAL "ARM64")
  set(fixture_exports "${CMAKE_CURRENT_BINARY_DIR}/fixture_arm64.def")
  file(
    WRITE "${fixture_exports}"
    "LIBRARY arm64x_fixture\nEXPORTS\n    fixture_integer\n    fixture_floating\n    fixture_aggregate\n    fixture_variadic\n    fixture_import_probe\n")
endif()
add_library(arm64x_fixture SHARED fixture.c "${fixture_exports}")
target_compile_definitions(arm64x_fixture PRIVATE ARM64X_FIXTURE_EXPORTS)
target_compile_options(arm64x_fixture PRIVATE /W4 /WX /guard:cf)
target_link_options(arm64x_fixture PRIVATE /WX /DYNAMICBASE /GUARD:CF /Brepro)
set_target_properties(arm64x_fixture PROPERTIES OUTPUT_NAME arm64x_fixture)

get_filename_component(mswr_root "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
add_executable(
  arm64x_fixture_inspector
  "${mswr_root}/tools/ci/pe-arm64x-inspector.c"
  "${mswr_root}/src/gem/pe_arm64x.c")
target_include_directories(arm64x_fixture_inspector PRIVATE "${mswr_root}/include")
target_compile_definitions(
  arm64x_fixture_inspector PRIVATE _CRT_SECURE_NO_WARNINGS MSWR_PE_ARM64X_DIAGNOSTICS)
target_compile_options(arm64x_fixture_inspector PRIVATE /W4 /WX)

if(BUILD_AS_ARM64X STREQUAL "ARM64EC")
  if(NOT DEFINED MSWR_X64_CL OR NOT EXISTS "${MSWR_X64_CL}")
    message(FATAL_ERROR "MSWR_X64_CL must identify the pinned x64 compiler")
  endif()
  set(x64_object "${CMAKE_CURRENT_BINARY_DIR}/fixture_x64.obj")
  add_custom_command(
    OUTPUT "${x64_object}"
    COMMAND "${MSWR_X64_CL}" /nologo /c /W4 /WX /O2 /GS- /Zl /guard:cf
            "/Fo${x64_object}" "${CMAKE_CURRENT_SOURCE_DIR}/fixture_x64.c"
    DEPENDS fixture_x64.c
    VERBATIM)
  set_source_files_properties("${x64_object}" PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
  target_sources(arm64x_fixture PRIVATE "${x64_object}")

  add_executable(arm64x_fixture_host host.c)
  target_compile_options(arm64x_fixture_host PRIVATE /W4 /WX /guard:cf)
  target_link_options(arm64x_fixture_host PRIVATE /WX /DYNAMICBASE /GUARD:CF /Brepro)
  target_link_libraries(arm64x_fixture_host PRIVATE arm64x_fixture)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/arm64x.cmake")
