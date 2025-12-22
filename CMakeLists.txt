cmake_minimum_required(VERSION 3.10)
project(chernobog)

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

# Find Z3 library
# First check if Z3_ROOT is set and use it preferentially
if(DEFINED ENV{Z3_ROOT})
    set(Z3_ROOT_DIR "$ENV{Z3_ROOT}")
    message(STATUS "Using Z3_ROOT: ${Z3_ROOT_DIR}")

    find_library(Z3_LIBRARY NAMES z3 libz3
        PATHS
            "${Z3_ROOT_DIR}/install/lib"
            "${Z3_ROOT_DIR}/lib"
            "${Z3_ROOT_DIR}/bin"
            "${Z3_ROOT_DIR}/build"
        NO_DEFAULT_PATH
    )
    find_path(Z3_INCLUDE_DIR z3++.h
        PATHS
            "${Z3_ROOT_DIR}/install/include"
            "${Z3_ROOT_DIR}/include"
            "${Z3_ROOT_DIR}/src/api/c++"
            "${Z3_ROOT_DIR}/src/api"
        NO_DEFAULT_PATH
    )
endif()

# Fall back to system search if not found via Z3_ROOT
if(NOT Z3_LIBRARY OR NOT Z3_INCLUDE_DIR)
    find_package(Z3 CONFIG QUIET)
    if(NOT Z3_FOUND)
        find_library(Z3_LIBRARY NAMES z3 libz3
            PATHS
                /usr/lib
                /usr/lib/x86_64-linux-gnu
                /usr/local/lib
                /opt/homebrew/lib
        )
        find_path(Z3_INCLUDE_DIR z3++.h
            PATHS
                /usr/include
                /usr/local/include
                /opt/homebrew/include
        )
    endif()
endif()

if(Z3_LIBRARY AND Z3_INCLUDE_DIR)
    set(Z3_FOUND TRUE)
    message(STATUS "Found Z3 library: ${Z3_LIBRARY}")
    message(STATUS "Found Z3 include: ${Z3_INCLUDE_DIR}")
elseif(NOT Z3_FOUND)
    message(FATAL_ERROR "Z3 not found. Please install Z3 or set Z3_ROOT environment variable.")
endif()

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
)

# Link Z3 library
if(Z3_FOUND)
    if(TARGET z3::libz3)
        target_link_libraries(chernobog PRIVATE z3::libz3)
    else()
        target_include_directories(chernobog PRIVATE ${Z3_INCLUDE_DIR})
        target_link_libraries(chernobog PRIVATE ${Z3_LIBRARY})
    endif()
endif()
