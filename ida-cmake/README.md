# IDA CMake Build System

This directory contains the CMake build system for IDA SDK plugins and extensions. It provides a modern, cross-platform way to build IDA plugins using CMake.

## Files

- `bootstrap.cmake` - Entry point that sets up paths and detects SDK structure
- `idasdkConfig.cmake` - Main configuration file that creates IDA SDK targets
- `idasdkConfigVersion.cmake` - Version compatibility checking
- `cmake/platform.cmake` - Platform and OS detection
- `cmake/compiler.cmake` - Compiler configuration and warning settings
- `cmake/targets.cmake` - Functions for creating plugins, loaders, and proc modules
- `cmake/utilities.cmake` - Utility functions for SDK version detection

## Usage

In your CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.10)
project(my_plugin)

# Include the bootstrap to set up IDA SDK
include(${CMAKE_CURRENT_LIST_DIR}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Create your plugin
ida_add_plugin(my_plugin
  SOURCES
    src/plugin.cpp
)
```

## Requirements

- CMake 3.10 or later (3.27 recommended)
- IDA SDK (set via IDASDK environment variable)
- Supported compilers: MSVC (Windows), Clang (macOS), GCC/Clang (Linux)

## Environment Variables

- `IDASDK` - Path to IDA SDK directory (required)
- `IDABIN` - Path to IDA installation binary directory (optional, defaults to $IDASDK/bin)

## Origin

This is a customized version of the ida-cmake build system, adapted specifically for this project.
