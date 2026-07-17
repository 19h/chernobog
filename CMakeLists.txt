cmake_minimum_required(VERSION 3.27)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

# CMake initializes compiler deployment flags during project(). Set the
# default beforehand so bundled dependencies and the plugin use one minimum.
# Z3 4.16's C++20 formatting path requires Apple floating-point to_chars,
# available from macOS 13.3; the IDA 9.x arm64 SDK library has a lower 12.0
# floor and is therefore compatible. Explicit caller values win.
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" AND
   (NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR
    CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL ""))
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.3" CACHE STRING
        "Minimum supported macOS version" FORCE)
endif()

project(chernobog LANGUAGES C CXX)

include(FetchContent)

# Find IDA SDK
SET(IDASDK_VER "92" CACHE STRING "92")
SET(IDASDK $ENV{IDASDK})
MESSAGE("${PROJECT_NAME}")
MESSAGE("Using IDA SDK dir: ${IDASDK}")
MESSAGE("-------------------")

IF( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
ENDIF()
SET(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ============================================================================
# Z3 Theorem Prover Integration
# ============================================================================

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Do not re-check FetchContent remotes on every build" FORCE)

message(STATUS "Building bundled Z3 from source")

FetchContent_Declare(
    z3
    GIT_REPOSITORY https://github.com/Z3Prover/z3.git
    GIT_TAG        z3-4.16.0
)

set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "Build static Z3" FORCE)
set(Z3_BUILD_LIBZ3_MSVC_STATIC ON CACHE BOOL "Use static MSVC runtime for Z3" FORCE)
set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "Skip Z3 executable" FORCE)
set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "Skip Z3 tests" FORCE)
set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "Skip Z3 examples" FORCE)
set(Z3_BUILD_DOCUMENTATION OFF CACHE BOOL "Skip Z3 docs" FORCE)
set(WARNINGS_AS_ERRORS "OFF" CACHE STRING "Disable Z3 warnings as errors" FORCE)

FetchContent_MakeAvailable(z3)

if(NOT TARGET libz3)
    message(FATAL_ERROR "Expected Z3 target 'libz3' was not created")
endif()

if(TARGET libz3 AND MSVC)
    target_compile_options(libz3 PRIVATE $<$<CONFIG:Release>:/O2>)
elseif(TARGET libz3 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(libz3 PRIVATE $<$<CONFIG:Release>:-O3>)
endif()

set(CHERNOBOG_Z3_INCLUDE_DIRS
    "${z3_SOURCE_DIR}/src/api"
    "${z3_SOURCE_DIR}/src/api/c++"
)

include(${CMAKE_CURRENT_LIST_DIR}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Set plugin variables before including addons.cmake
ida_add_plugin(chernobog
  SOURCES
    # Plugin core
    src/plugin/deobf_plugin.cpp
    src/plugin/component_registry.cpp
    src/deobf/deobf_main.cpp
    src/deobf/deobf_utils.cpp

    # Analysis modules (existing)
    src/deobf/analysis/pattern_match.cpp
    src/deobf/analysis/opaque_eval.cpp
    src/deobf/analysis/stack_tracker.cpp
    src/deobf/analysis/z3_solver.cpp
    src/deobf/analysis/arch_utils.cpp

    # NEW: AST-based pattern matching system
    src/deobf/analysis/ast.cpp
    src/deobf/analysis/ast_builder.cpp
    src/deobf/analysis/pattern_storage.cpp
    src/deobf/analysis/chain_simplify.cpp

    # NEW: MBA rule system
    src/deobf/rules/pattern_rule.cpp
    src/deobf/rules/rule_verifier.cpp
    src/deobf/rules/rule_registry.cpp
    src/deobf/rules/rules_add.cpp
    src/deobf/rules/rules_sub.cpp
    src/deobf/rules/rules_xor.cpp
    src/deobf/rules/rules_and.cpp
    src/deobf/rules/rules_or.cpp
    src/deobf/rules/rules_misc.cpp
    src/deobf/rules/jump_rules.cpp
    src/deobf/rules/rules_predicate.cpp

    # Handlers
    src/deobf/handlers/peephole.cpp
    src/deobf/handlers/jump_optimizer.cpp
    src/deobf/handlers/deflatten.cpp
    src/deobf/handlers/bogus_cf.cpp
    src/deobf/handlers/string_decrypt.cpp
    src/deobf/handlers/const_decrypt.cpp
    src/deobf/handlers/indirect_branch.cpp
    src/deobf/handlers/indirect_call.cpp
    src/deobf/handlers/block_merge.cpp
    src/deobf/handlers/mba_simplify.cpp
    src/deobf/handlers/identity_call.cpp
    src/deobf/handlers/stack_string.cpp
    src/deobf/handlers/hikari_wrapper.cpp
    src/deobf/handlers/savedregs.cpp
    src/deobf/handlers/objc_resolve.cpp
    src/deobf/handlers/global_const.cpp
    src/deobf/handlers/ptr_resolve.cpp
    src/deobf/handlers/ctree_const_fold.cpp
    src/deobf/handlers/ctree_switch_fold.cpp
    src/deobf/handlers/ctree_indirect_call.cpp
    src/deobf/handlers/ctree_string_decrypt.cpp
)

target_include_directories(chernobog SYSTEM PRIVATE ${CHERNOBOG_Z3_INCLUDE_DIRS})
target_link_libraries(chernobog PRIVATE libz3)

# Keep diagnostics enabled for project sources. The IDA SDK is a system include,
# so these flags do not turn third-party header diagnostics into project noise.
if(MSVC)
    target_compile_options(chernobog PRIVATE /W4)
else()
    target_compile_options(chernobog PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow
        -Wformat -Wparentheses -Wswitch
        -Wunused-variable -Wunused-function -Wunused-private-field
        "SHELL:-Wno-unused-parameter -Wno-sign-compare")
endif()

# Portable core regression tests do not require an IDA runtime. They exercise
# bitvector semantics and the alignment-sensitive hashing utilities used by
# the AST matcher.
include(CTest)
if(BUILD_TESTING)
    add_executable(chernobog_core_tests tests/core_tests.cpp)
    target_include_directories(chernobog_core_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_features(chernobog_core_tests PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(chernobog_core_tests PRIVATE /W4)
    else()
        target_compile_options(chernobog_core_tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME chernobog.core COMMAND chernobog_core_tests)

    add_executable(chernobog_z3_tests tests/z3_tests.cpp)
    target_include_directories(chernobog_z3_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_include_directories(chernobog_z3_tests SYSTEM PRIVATE
        ${CHERNOBOG_Z3_INCLUDE_DIRS})
    target_link_libraries(chernobog_z3_tests PRIVATE libz3)
    target_compile_features(chernobog_z3_tests PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(chernobog_z3_tests PRIVATE /W4)
    else()
        target_compile_options(chernobog_z3_tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME chernobog.z3 COMMAND chernobog_z3_tests)

    # Compile and execute the exact statically-registered MBA catalog through
    # its fail-closed Z3 verifier. Only the catalog's IDA-independent runtime
    # is linked, avoiding unrelated plugin initializers in the SDK stub test.
    add_executable(chernobog_catalog_tests
        tests/catalog_tests.cpp
        src/deobf/analysis/ast.cpp
        src/deobf/analysis/ast_builder.cpp
        src/deobf/analysis/pattern_storage.cpp
        src/deobf/rules/pattern_rule.cpp
        src/deobf/rules/rule_verifier.cpp
        src/deobf/rules/rule_registry.cpp
        src/deobf/rules/rules_add.cpp
        src/deobf/rules/rules_sub.cpp
        src/deobf/rules/rules_xor.cpp
        src/deobf/rules/rules_and.cpp
        src/deobf/rules/rules_or.cpp
        src/deobf/rules/rules_misc.cpp)
    target_include_directories(chernobog_catalog_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_include_directories(chernobog_catalog_tests SYSTEM PRIVATE
        ${CHERNOBOG_Z3_INCLUDE_DIRS})
    target_link_libraries(chernobog_catalog_tests PRIVATE libz3 idasdk::plugin)
    target_compile_definitions(chernobog_catalog_tests PRIVATE
        CHERNOBOG_CATALOG_TEST=1)
    target_compile_features(chernobog_catalog_tests PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(chernobog_catalog_tests PRIVATE /W4)
    else()
        target_compile_options(chernobog_catalog_tests PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow
            "SHELL:-Wno-unused-parameter -Wno-unused-function -Wno-sign-compare")
    endif()
    add_test(NAME chernobog.mba_catalog COMMAND chernobog_catalog_tests)
    if(APPLE)
        set_tests_properties(chernobog.mba_catalog PROPERTIES
            ENVIRONMENT "DYLD_LIBRARY_PATH=${IDA_LIB_DIR}")
    elseif(UNIX)
        set_tests_properties(chernobog.mba_catalog PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${IDA_LIB_DIR}")
    endif()
endif()
