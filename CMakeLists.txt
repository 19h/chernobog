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

if(MSVC AND (NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY
             OR CMAKE_MSVC_RUNTIME_LIBRARY STREQUAL ""))
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING
        "MSVC runtime library" FORCE)
endif()

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

# ============================================================================
# rax exploratory emulator (pinned Rust staticlib, no runtime DLL/dylib/so)
# ============================================================================

if(WIN32)
    # std::thread is provided by the MSVC runtime.  CMake's cross-compiling
    # Threads probe can otherwise accept a host libpthreads and leak
    # "-lpthreads" into an lld-link command.
    set(_chernobog_thread_libraries "")
else()
    find_package(Threads REQUIRED)
    set(_chernobog_thread_libraries Threads::Threads)
endif()

# The gitlink and this configure-time check jointly pin the embedded source.
# A missing or differently checked-out submodule fails configuration instead
# of fetching or borrowing a checkout from another repository.
set(CHERNOBOG_RAX_GIT_REVISION
    "776cec9d64e6bbeea43f77edd3f0e402f3b60cad")
set(_chernobog_rax_root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/rax")
if(NOT EXISTS "${_chernobog_rax_root}/capi/include/rax.h" OR
   NOT EXISTS "${_chernobog_rax_root}/capi/Cargo.toml")
    message(FATAL_ERROR
        "The pinned rax submodule is not initialized. Run: "
        "git submodule update --init --recursive vendor/rax")
endif()

find_package(Git REQUIRED)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${_chernobog_rax_root}" rev-parse HEAD
    RESULT_VARIABLE _chernobog_rax_git_result
    OUTPUT_VARIABLE _chernobog_rax_git_head
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _chernobog_rax_git_result EQUAL 0)
    message(FATAL_ERROR
        "Unable to determine the vendor/rax submodule revision")
endif()
if(NOT _chernobog_rax_git_head STREQUAL CHERNOBOG_RAX_GIT_REVISION)
    message(FATAL_ERROR
        "vendor/rax is at ${_chernobog_rax_git_head}; expected pinned revision "
        "${CHERNOBOG_RAX_GIT_REVISION}. Run: git submodule update --init "
        "vendor/rax")
endif()
execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${_chernobog_rax_root}"
            status --porcelain --untracked-files=all
    RESULT_VARIABLE _chernobog_rax_status_result
    OUTPUT_VARIABLE _chernobog_rax_status
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _chernobog_rax_status_result EQUAL 0)
    message(FATAL_ERROR "Unable to inspect the vendor/rax worktree")
endif()
if(NOT _chernobog_rax_status STREQUAL "")
    message(FATAL_ERROR
        "vendor/rax contains uncommitted or untracked files; embedded-source "
        "provenance would not match ${CHERNOBOG_RAX_GIT_REVISION}:\n"
        "${_chernobog_rax_status}")
endif()
set(_chernobog_rax_source_provenance
    "submodule:vendor/rax@${_chernobog_rax_git_head}")

if(EXISTS "${_chernobog_rax_root}/capi/include/rax.h")
    set(_chernobog_rax_capi "${_chernobog_rax_root}/capi")
elseif(EXISTS "${_chernobog_rax_root}/include/rax.h")
    set(_chernobog_rax_capi "${_chernobog_rax_root}")
    get_filename_component(_chernobog_rax_root
        "${_chernobog_rax_capi}/.." ABSOLUTE)
else()
    message(FATAL_ERROR
        "rax.h was not found under '${_chernobog_rax_root}/capi/include' "
        "or '${_chernobog_rax_root}/include'")
endif()
if(NOT EXISTS "${_chernobog_rax_capi}/Cargo.toml")
    message(FATAL_ERROR "rax C API Cargo.toml is missing: ${_chernobog_rax_capi}")
endif()

find_program(CHERNOBOG_CARGO_EXECUTABLE cargo REQUIRED)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _chernobog_target_processor)
if(APPLE)
    set(_chernobog_apple_arches ${CMAKE_OSX_ARCHITECTURES})
    list(LENGTH _chernobog_apple_arches _chernobog_apple_arch_count)
    if(_chernobog_apple_arch_count GREATER 1)
        message(FATAL_ERROR
            "Embedded rax requires one architecture per build; configure "
            "separate arm64 and x86_64 build directories")
    endif()
    if(_chernobog_apple_arch_count EQUAL 1)
        list(GET _chernobog_apple_arches 0 _chernobog_target_processor)
    endif()
    if(_chernobog_target_processor MATCHES "^(arm64|aarch64)$")
        set(CHERNOBOG_RAX_RUST_TARGET "aarch64-apple-darwin")
    elseif(_chernobog_target_processor MATCHES "^(x86_64|amd64)$")
        set(CHERNOBOG_RAX_RUST_TARGET "x86_64-apple-darwin")
    else()
        message(FATAL_ERROR "Unsupported macOS rax target: ${_chernobog_target_processor}")
    endif()
elseif(WIN32)
    if(NOT _chernobog_target_processor MATCHES "^(x86_64|amd64)$")
        message(FATAL_ERROR "Only x86_64 Windows is supported by this build matrix")
    endif()
    set(CHERNOBOG_RAX_RUST_TARGET "x86_64-pc-windows-msvc")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(_chernobog_target_processor MATCHES "^(x86_64|amd64)$")
        set(CHERNOBOG_RAX_RUST_TARGET "x86_64-unknown-linux-gnu")
    elseif(_chernobog_target_processor MATCHES "^(arm64|aarch64)$")
        set(CHERNOBOG_RAX_RUST_TARGET "aarch64-unknown-linux-gnu")
    else()
        message(FATAL_ERROR "Unsupported Linux rax target: ${_chernobog_target_processor}")
    endif()
else()
    message(FATAL_ERROR "Unsupported rax target system: ${CMAKE_SYSTEM_NAME}")
endif()

set(_chernobog_rax_target_dir "${CMAKE_CURRENT_BINARY_DIR}/rax-capi/cargo")
if(WIN32)
    set(_chernobog_rax_archive
        "${_chernobog_rax_target_dir}/${CHERNOBOG_RAX_RUST_TARGET}/release/rax.lib")
else()
    set(_chernobog_rax_archive
        "${_chernobog_rax_target_dir}/${CHERNOBOG_RAX_RUST_TARGET}/release/librax.a")
endif()

set(_chernobog_rax_environment
    "CARGO_TARGET_DIR=${_chernobog_rax_target_dir}")
if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
    list(APPEND _chernobog_rax_environment
        "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()
if(WIN32)
    # Chernobog and bundled Z3 use the static MSVC runtime. Keep Rust and C
    # dependencies compiled by Cargo (notably zstd) on the same CRT for both
    # native and cross builds.
    set(_chernobog_rax_cflags "/MT")
    set(_chernobog_rax_rustflags "-Ctarget-feature=+crt-static")
    if(CMAKE_CROSSCOMPILING)
        string(TOUPPER "${CHERNOBOG_RAX_RUST_TARGET}" _chernobog_rust_env_target)
        string(REPLACE "-" "_" _chernobog_rust_env_target
            "${_chernobog_rust_env_target}")
        if(CMAKE_LINKER)
            list(APPEND _chernobog_rax_environment
                "CARGO_TARGET_${_chernobog_rust_env_target}_LINKER=${CMAKE_LINKER}")
        endif()
        list(APPEND _chernobog_rax_environment
            "CC_x86_64_pc_windows_msvc=${CMAKE_C_COMPILER}"
            "CXX_x86_64_pc_windows_msvc=${CMAKE_CXX_COMPILER}"
            "AR_x86_64_pc_windows_msvc=${CMAKE_AR}")
        if(XWIN_ROOT)
            string(APPEND _chernobog_rax_cflags
                " /imsvc${XWIN_ROOT}/crt/include /imsvc${XWIN_ROOT}/sdk/include/ucrt /imsvc${XWIN_ROOT}/sdk/include/shared /imsvc${XWIN_ROOT}/sdk/include/um")
            string(APPEND _chernobog_rax_rustflags
                " -Lnative=${XWIN_ROOT}/crt/lib/x86_64 -Lnative=${XWIN_ROOT}/sdk/lib/ucrt/x86_64 -Lnative=${XWIN_ROOT}/sdk/lib/um/x86_64")
        endif()
    endif()
    list(APPEND _chernobog_rax_environment
        "CFLAGS_x86_64_pc_windows_msvc=${_chernobog_rax_cflags}"
        "CXXFLAGS_x86_64_pc_windows_msvc=${_chernobog_rax_cflags}"
        "RUSTFLAGS=${_chernobog_rax_rustflags}")
endif()

add_custom_target(chernobog_rax_cargo
    COMMAND ${CMAKE_COMMAND} -E env ${_chernobog_rax_environment}
            ${CHERNOBOG_CARGO_EXECUTABLE} build --locked --release
            --package rax-capi
            --manifest-path "${_chernobog_rax_capi}/Cargo.toml"
            --target "${CHERNOBOG_RAX_RUST_TARGET}"
    BYPRODUCTS "${_chernobog_rax_archive}"
    WORKING_DIRECTORY "${_chernobog_rax_root}"
    COMMENT "Building embedded rax (${CHERNOBOG_RAX_RUST_TARGET})"
    VERBATIM)

set(_chernobog_rax_system_libraries "")
if(APPLE)
    find_library(_chernobog_corefoundation CoreFoundation REQUIRED)
    find_library(_chernobog_security Security REQUIRED)
    find_library(_chernobog_systemconfiguration SystemConfiguration REQUIRED)
    find_library(_chernobog_iconv iconv REQUIRED)
    find_library(_chernobog_objc objc REQUIRED)
    set(_chernobog_rax_system_libraries
        "${_chernobog_corefoundation}" "${_chernobog_security}"
        "${_chernobog_systemconfiguration}" "${_chernobog_iconv}"
        "${_chernobog_objc}" ${_chernobog_thread_libraries})
elseif(WIN32)
    set(_chernobog_rax_system_libraries ws2_32 userenv ntdll bcrypt)
else()
    set(_chernobog_rax_system_libraries
        ${_chernobog_thread_libraries} ${CMAKE_DL_LIBS} m rt util)
endif()

add_library(chernobog_rax_static STATIC IMPORTED GLOBAL)
set_target_properties(chernobog_rax_static PROPERTIES
    IMPORTED_LOCATION "${_chernobog_rax_archive}"
    INTERFACE_INCLUDE_DIRECTORIES "${_chernobog_rax_capi}/include"
    INTERFACE_LINK_LIBRARIES "${_chernobog_rax_system_libraries}")
add_dependencies(chernobog_rax_static chernobog_rax_cargo)
add_library(chernobog::rax ALIAS chernobog_rax_static)

message(STATUS
    "Embedded rax: provenance=${_chernobog_rax_source_provenance}, "
    "target=${CHERNOBOG_RAX_RUST_TARGET}, source=${_chernobog_rax_root}")

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
    src/deobf/handlers/select_chain.cpp
    src/deobf/handlers/mba_simplify.cpp
    src/deobf/handlers/vm_mba.cpp
    src/deobf/handlers/identity_call.cpp
    src/deobf/handlers/stack_string.cpp
    src/deobf/handlers/hikari_wrapper.cpp
    src/deobf/handlers/hikari_cfg.cpp
    src/deobf/handlers/native_opaque.cpp
    src/deobf/handlers/savedregs.cpp
    src/deobf/handlers/objc_resolve.cpp
    src/deobf/handlers/global_const.cpp
    src/deobf/handlers/ptr_resolve.cpp
    src/deobf/handlers/ctree_const_fold.cpp
    src/deobf/handlers/ctree_switch_fold.cpp
    src/deobf/handlers/ctree_indirect_call.cpp
    src/deobf/handlers/ctree_string_decrypt.cpp

    # Current-function rax hybrid analysis (never a database sweep)
    src/hybrid/rax_loader.cpp
    src/hybrid/hybrid_config.cpp
    src/hybrid/program_model.cpp
    src/hybrid/program_model_core.cpp
    src/hybrid/abi_policy.cpp
    src/hybrid/emu_driver.cpp
    src/hybrid/emulation_workers.cpp
    src/hybrid/emulation_rax_executor.cpp
    src/hybrid/entry_state.cpp
    src/hybrid/call_summary.cpp
    src/hybrid/call_summary_policy.cpp
    src/hybrid/decoder_core.cpp
    src/hybrid/smir_analysis.cpp
    src/hybrid/static_analysis.cpp
    src/hybrid/evidence.cpp
    src/hybrid/z3_bridge.cpp
    src/hybrid/session.cpp
)

target_include_directories(chernobog SYSTEM PRIVATE
    ${CHERNOBOG_Z3_INCLUDE_DIRS}
    "${_chernobog_rax_capi}/include")
target_link_libraries(chernobog PRIVATE
    libz3 chernobog::rax ${_chernobog_thread_libraries})

# Keep the embedded C ABI private. This prevents symbol interposition if viy
# and Chernobog, each with a potentially different pinned rax, are loaded into
# the same IDA process.
if(APPLE)
    target_link_options(chernobog PRIVATE
        "LINKER:-load_hidden,$<TARGET_FILE:chernobog_rax_static>")
elseif(UNIX)
    target_link_options(chernobog PRIVATE "LINKER:--exclude-libs,librax.a")
endif()

# Keep diagnostics enabled for project sources. The IDA SDK is a system include,
# so these flags do not turn third-party header diagnostics into project noise.
if(MSVC)
    target_compile_options(chernobog PRIVATE /W4)
else()
    target_compile_options(chernobog PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow
        -Wformat -Wparentheses -Wswitch
        -Wunused-variable -Wunused-function
        "SHELL:-Wno-unused-parameter -Wno-sign-compare")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(chernobog PRIVATE -Wunused-private-field)
    endif()
endif()

# Portable core regression tests do not require an IDA runtime. They exercise
# bitvector semantics and the alignment-sensitive hashing utilities used by
# the AST matcher.
include(CTest)
if(BUILD_TESTING)
    add_executable(chernobog_hybrid_tests
        tests/hybrid_tests.cpp
        src/hybrid/rax_loader.cpp
        src/hybrid/hybrid_config.cpp
        src/hybrid/program_model_core.cpp
        src/hybrid/abi_policy.cpp
        src/hybrid/call_summary_policy.cpp
        src/hybrid/decoder_core.cpp
        src/hybrid/smir_analysis.cpp
        src/hybrid/emu_driver.cpp
        src/hybrid/emulation_workers.cpp
        src/hybrid/emulation_rax_executor.cpp
        src/hybrid/evidence.cpp)
    target_include_directories(chernobog_hybrid_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${_chernobog_rax_capi}/include")
    target_link_libraries(chernobog_hybrid_tests PRIVATE
        chernobog::rax ${_chernobog_thread_libraries})
    target_compile_features(chernobog_hybrid_tests PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(chernobog_hybrid_tests PRIVATE /W4)
    else()
        target_compile_options(chernobog_hybrid_tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME chernobog.rax_hybrid COMMAND chernobog_hybrid_tests)

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
