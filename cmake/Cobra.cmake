option(CHERNOBOG_WITH_COBRA "Build the private CoBRA algebraic backend" ON)

function(chernobog_clean_dependency path expected)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${PROJECT_SOURCE_DIR}/${path}" rev-parse HEAD
        RESULT_VARIABLE result
        OUTPUT_VARIABLE head
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT result EQUAL 0 OR NOT head STREQUAL expected)
        message(FATAL_ERROR "${path} does not match its pinned upstream commit")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${PROJECT_SOURCE_DIR}/${path}" status --porcelain
                --untracked-files=all
        RESULT_VARIABLE result
        OUTPUT_VARIABLE status
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT result EQUAL 0 OR NOT status STREQUAL "")
        message(FATAL_ERROR "${path} must have a clean worktree")
    endif()
endfunction()

function(chernobog_add_cobra)
    set(CMAKE_CXX_STANDARD 17)
    set(ABSL_BUILD_TESTING
        OFF
        CACHE BOOL "" FORCE)
    set(ABSL_BUILD_TEST_HELPERS
        OFF
        CACHE BOOL "" FORCE)
    set(ABSL_PROPAGATE_CXX_STD
        ON
        CACHE BOOL "" FORCE)
    set(ABSL_MSVC_STATIC_RUNTIME
        ON
        CACHE BOOL "" FORCE)
    set(HWY_ENABLE_TESTS
        OFF
        CACHE BOOL "" FORCE)
    set(HWY_ENABLE_EXAMPLES
        OFF
        CACHE BOOL "" FORCE)
    set(HWY_ENABLE_CONTRIB
        OFF
        CACHE BOOL "" FORCE)
    set(HWY_FORCE_STATIC_LIBS
        ON
        CACHE BOOL "" FORCE)
    add_subdirectory("${PROJECT_SOURCE_DIR}/vendor/abseil-cpp" "${PROJECT_BINARY_DIR}/cobra/abseil")
    add_subdirectory("${PROJECT_SOURCE_DIR}/vendor/highway" "${PROJECT_BINARY_DIR}/cobra/highway")
    add_subdirectory("${PROJECT_SOURCE_DIR}/vendor/cobra/lib/core"
                     "${PROJECT_BINARY_DIR}/cobra/core")
endfunction()

set(CHERNOBOG_COBRA_PROVENANCE "disabled")
set(CHERNOBOG_COBRA_TREE "disabled")
if(CHERNOBOG_WITH_COBRA)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    include("${PROJECT_SOURCE_DIR}/vendor/cobra.provenance.cmake")
    chernobog_clean_dependency(vendor/abseil-cpp "255c84dadd029fd8ad25c5efb5933e47beaa00c7")
    chernobog_clean_dependency(vendor/highway "ac0d5d297b13ab1b89f48484fc7911082d76a93f")
    set(replay_arguments "")
    foreach(entry IN LISTS COBRA_PATCH_SERIES)
        string(REPLACE "|" ";" pair "${entry}")
        list(LENGTH pair count)
        if(NOT count EQUAL 2)
            message(FATAL_ERROR "Invalid CoBRA patch manifest entry")
        endif()
        list(GET pair 0 patch)
        list(GET pair 1 digest)
        list(APPEND replay_arguments --patch "${patch}" "${digest}")
    endforeach()
    execute_process(
        COMMAND
            "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/cmake/verify_cobra_provenance.py" --root
            "${PROJECT_SOURCE_DIR}" --storage "${PROJECT_BINARY_DIR}/cobra/provenance" --base
            "${COBRA_UPSTREAM_BASE_COMMIT}" --expected "${COBRA_EXPECTED_TREE_HASH}"
            ${replay_arguments}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${output}${error}")
    endif()
    message(STATUS "${output}")
    set(CHERNOBOG_COBRA_TREE "${COBRA_EXPECTED_TREE_HASH}")
    chernobog_add_cobra()
    add_library(
        chernobog_mba_cobra STATIC "${PROJECT_SOURCE_DIR}/src/deobf/analysis/mba_cobra.cpp"
                                   "${PROJECT_SOURCE_DIR}/src/deobf/analysis/mba_cobra_budget.cpp")
    target_link_libraries(chernobog_mba_cobra PRIVATE cobra-core)
    target_compile_features(chernobog_mba_cobra PRIVATE cxx_std_23)
    set(CHERNOBOG_COBRA_PROVENANCE
        "base:${COBRA_UPSTREAM_BASE_COMMIT};tree:${COBRA_EXPECTED_TREE_HASH};patches:${COBRA_PATCH_SERIES};abseil:255c84dadd029fd8ad25c5efb5933e47beaa00c7;highway:ac0d5d297b13ab1b89f48484fc7911082d76a93f"
    )
else()
    add_library(
        chernobog_mba_cobra STATIC "${PROJECT_SOURCE_DIR}/src/deobf/analysis/mba_cobra_stub.cpp"
                                   "${PROJECT_SOURCE_DIR}/src/deobf/analysis/mba_cobra_budget.cpp")
    target_compile_features(chernobog_mba_cobra PRIVATE cxx_std_17)
endif()

target_sources(chernobog_mba_cobra
               PRIVATE "${PROJECT_SOURCE_DIR}/src/deobf/analysis/mba_cobra_config.cpp")
