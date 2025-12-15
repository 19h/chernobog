# IDA SDK CMake Bootstrap
# This file sets up the CMAKE_PREFIX_PATH and MODULE_PATH to find the IDASDK package
# Usage: include(${CMAKE_CURRENT_LIST_DIR}/ida-cmake/bootstrap.cmake)

if(NOT DEFINED ENV{IDASDK})
    message(FATAL_ERROR "IDASDK environment variable not set. Please set it to your IDA SDK directory.")
endif()

# Validate IDASDK path exists and contains expected files
if(NOT EXISTS "$ENV{IDASDK}")
    message(FATAL_ERROR "IDASDK path does not exist: $ENV{IDASDK}")
endif()

# Auto-detect SDK structure: GitHub clone has files under src/, zip distribution at root
set(_IDASDK_ACTUAL "$ENV{IDASDK}")
if(NOT EXISTS "${_IDASDK_ACTUAL}/include/pro.h")
    # Check if this is a GitHub clone with src/ subdirectory
    if(EXISTS "${_IDASDK_ACTUAL}/src/include/pro.h")
        set(_IDASDK_ACTUAL "${_IDASDK_ACTUAL}/src")
        message(STATUS "Detected GitHub SDK structure, using: ${_IDASDK_ACTUAL}")
    else()
        message(FATAL_ERROR "Invalid IDASDK directory (missing include/pro.h): $ENV{IDASDK}")
    endif()
endif()

# Override IDASDK environment variable for this CMake run with the adjusted path
set(ENV{IDASDK} "${_IDASDK_ACTUAL}")
# Also set the CMake variable so idasdkConfig.cmake uses the adjusted path
set(IDASDK "${_IDASDK_ACTUAL}")

# Add ida-cmake to the package search path
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_CURRENT_LIST_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# Set default minimum CMake version if not already set
if(CMAKE_MINIMUM_REQUIRED_VERSION VERSION_LESS 3.27)
    cmake_minimum_required(VERSION 3.27)
endif()
