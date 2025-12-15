# idasdkConfig.cmake
# CMake package configuration for IDA SDK

# Set IDASDK directory
if(NOT DEFINED IDASDK)
    if(DEFINED ENV{IDASDK})
        set(IDASDK "$ENV{IDASDK}")
    else()
        message(FATAL_ERROR "IDASDK environment variable not set")
    endif()
endif()

# Set IDABIN directory (default to $IDASDK/bin if not specified)
if(NOT DEFINED IDABIN)
    if(DEFINED ENV{IDABIN})
        set(IDABIN "$ENV{IDABIN}")
    else()
        set(IDABIN "${IDASDK}/bin")
    endif()
endif()

# Normalize paths
file(TO_CMAKE_PATH "${IDASDK}" IDASDK)
file(TO_CMAKE_PATH "${IDABIN}" IDABIN)

# Export ida-cmake directory for use by templates and projects
set(IDA_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH "Path to ida-cmake directory")

# Always use EA64 (64-bit addressing)

# Include our CMake modules
include(${CMAKE_CURRENT_LIST_DIR}/cmake/platform.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/compiler.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/targets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/utilities.cmake)

# Handle macOS universal binary library merging
if(IDA_UNIVERSAL_BINARY)
    # Map CMake architectures to IDA SDK architecture names
    set(_ida_arch_map_arm64 "arm64")
    set(_ida_arch_map_x86_64 "x64")

    # Create universal libraries for each IDA library
    foreach(_lib_basename "ida" "idalib")
        set(_arch_libs "")
        foreach(_arch ${CMAKE_OSX_ARCHITECTURES})
            set(_ida_arch "${_ida_arch_map_${_arch}}")
            if(NOT _ida_arch)
                message(FATAL_ERROR "Unsupported architecture for universal binary: ${_arch}")
            endif()

            set(_lib_dir "${IDASDK}/lib/${_ida_arch}_${IDA_PLATFORM_NAME}_${IDA_COMPILER}_64")
            set(_lib_path "${_lib_dir}/lib${_lib_basename}.dylib")

            if(NOT EXISTS "${_lib_path}")
                message(WARNING "Library not found for ${_arch}: ${_lib_path}")
            else()
                list(APPEND _arch_libs "${_lib_path}")
            endif()
        endforeach()

        if(_arch_libs)
            # Create output directory for merged libraries
            set(_merged_lib_dir "${CMAKE_BINARY_DIR}/ida-universal-libs")
            file(MAKE_DIRECTORY "${_merged_lib_dir}")

            set(_merged_lib "${_merged_lib_dir}/lib${_lib_basename}.dylib")

            # Use lipo to create universal library
            execute_process(
                COMMAND lipo -create ${_arch_libs} -output "${_merged_lib}"
                RESULT_VARIABLE _lipo_result
                ERROR_VARIABLE _lipo_error
            )

            if(_lipo_result EQUAL 0)
                message(STATUS "Created universal ${_lib_basename} library: ${_merged_lib}")
                # Store the merged library path
                set(IDA_${_lib_basename}_UNIVERSAL_LIB "${_merged_lib}" CACHE INTERNAL "")
            else()
                message(FATAL_ERROR "Failed to create universal ${_lib_basename} library: ${_lipo_error}")
            endif()
        endif()
    endforeach()

    # Set library paths to use the merged universal libraries
    set(IDA_LIB_PATH "${IDA_ida_UNIVERSAL_LIB}")
    set(IDALIB_PATH "${IDA_idalib_UNIVERSAL_LIB}")
else()
    # Single architecture build - use standard library paths
    set(IDA_LIB_DIR "${IDASDK}/lib/${IDA_LIB_SUFFIX}")
    set(IDA_LIB_PATH "${IDA_LIB_DIR}/${IDA_LIB_NAME}")
    set(IDALIB_PATH "${IDA_LIB_DIR}/${IDALIB_NAME}")
endif()

# Create interface targets
if(NOT TARGET idasdk::plugin)
    add_library(idasdk::plugin INTERFACE IMPORTED)
    set_target_properties(idasdk::plugin PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${IDASDK}/include"
        INTERFACE_COMPILE_DEFINITIONS "__IDP__"
    )

    # Always use EA64
    target_compile_definitions(idasdk::plugin INTERFACE __EA64__)

    # Link to platform and compiler settings
    target_link_libraries(idasdk::plugin INTERFACE
        ida_platform_settings
        ida_compiler_settings
        "${IDA_LIB_PATH}")
endif()

if(NOT TARGET idasdk::loader)
    add_library(idasdk::loader INTERFACE IMPORTED)
    set_target_properties(idasdk::loader PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${IDASDK}/include;${IDASDK}/ldr"
        INTERFACE_COMPILE_DEFINITIONS "__LOADER__"
    )

    # Loaders inherit all settings from plugins
    target_link_libraries(idasdk::loader INTERFACE idasdk::plugin)
endif()

if(NOT TARGET idasdk::procmod)
    add_library(idasdk::procmod INTERFACE IMPORTED)
    set_target_properties(idasdk::procmod PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${IDASDK}/include;${IDASDK}/module"
        INTERFACE_COMPILE_DEFINITIONS "__IDP__"
    )

    # Processor modules inherit all settings from plugins
    target_link_libraries(idasdk::procmod INTERFACE idasdk::plugin)
endif()

# IDALib support
if(NOT TARGET idasdk::idalib)
    add_library(idasdk::idalib INTERFACE IMPORTED)
    set_target_properties(idasdk::idalib PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${IDASDK}/include"
        INTERFACE_COMPILE_DEFINITIONS "IDALIB_IMPL"
    )

    # Link to platform and compiler settings, plus BOTH idalib and ida libraries
    # Note: idalib.lib requires ida.lib for some symbols
    target_link_libraries(idasdk::idalib INTERFACE
        ida_platform_settings
        ida_compiler_settings
        "${IDALIB_PATH}"
        "${IDA_LIB_PATH}")
endif()

# Detect SDK version
ida_check_sdk_version()

# Export package variables
set(idasdk_FOUND TRUE)
if(NOT DEFINED IDA_SDK_VERSION)
    set(idasdk_VERSION "unknown")
else()
    set(idasdk_VERSION "${IDA_SDK_VERSION}")
endif()
set(idasdk_INCLUDE_DIRS "${IDASDK}/include")
set(idasdk_LIBRARY_DIRS "${IDASDK}/lib")
