cmake_minimum_required(VERSION 3.27)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
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
set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Disable warnings as errors" FORCE)

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
    src/deobf/analysis/expr_simplify.cpp
    src/deobf/analysis/cfg_analysis.cpp
    src/deobf/analysis/opaque_eval.cpp
    src/deobf/analysis/stack_tracker.cpp
    src/deobf/analysis/z3_solver.cpp
    src/deobf/analysis/arch_utils.cpp

    # NEW: AST-based pattern matching system
    src/deobf/analysis/ast.cpp
    src/deobf/analysis/ast_builder.cpp
    src/deobf/analysis/pattern_storage.cpp
    src/deobf/analysis/pattern_fuzzer.cpp
    src/deobf/analysis/chain_simplify.cpp

    # NEW: MBA rule system
    src/deobf/rules/pattern_rule.cpp
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
    src/deobf/handlers/unflattener_base.cpp
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

target_include_directories(chernobog PRIVATE ${CHERNOBOG_Z3_INCLUDE_DIRS})
target_link_libraries(chernobog PRIVATE libz3)
