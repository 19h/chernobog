# platform.cmake - Platform and OS detection for IDA SDK

# Detect target platform
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(IDA_PLATFORM "WIN32")
    set(IDA_PLATFORM_NAME "win")
    set(IDAPROPLAT "__NT__")

    # Detect architecture
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(IDA_ARCH "arm64")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(IDA_ARCH "x64")
    else()
        set(IDA_ARCH "x86")
    endif()

    # Compiler detection for Windows
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set(IDA_COMPILER "vc")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND MINGW)
        set(IDA_COMPILER "mingw")
    else()
        message(WARNING "Unsupported Windows compiler: ${CMAKE_CXX_COMPILER_ID}")
        set(IDA_COMPILER "unknown")
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(IDA_PLATFORM "MACOS")
    set(IDA_PLATFORM_NAME "mac")
    set(IDAPROPLAT "__MAC__")

    # Compiler detection for macOS
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(IDA_COMPILER "clang")
    else()
        message(WARNING "Unexpected macOS compiler: ${CMAKE_CXX_COMPILER_ID}")
        set(IDA_COMPILER "clang")  # Default to clang
    endif()

    # Set deployment target
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")
    endif()

    # Handle universal binary builds (multiple architectures)
    if(CMAKE_OSX_ARCHITECTURES)
        list(LENGTH CMAKE_OSX_ARCHITECTURES _arch_count)
        if(_arch_count GREATER 1)
            # Universal binary build - need to merge libraries with lipo
            set(IDA_UNIVERSAL_BINARY TRUE)
            message(STATUS "Building macOS universal binary for architectures: ${CMAKE_OSX_ARCHITECTURES}")

            # We'll set IDA_ARCH to a placeholder since we have multiple
            # The actual library paths will be handled in idasdkConfig.cmake
            set(IDA_ARCH "universal")
        else()
            # Single architecture from CMAKE_OSX_ARCHITECTURES
            set(IDA_UNIVERSAL_BINARY FALSE)
            list(GET CMAKE_OSX_ARCHITECTURES 0 _cmake_arch)
            if(_cmake_arch STREQUAL "arm64")
                set(IDA_ARCH "arm64")
            elseif(_cmake_arch MATCHES "x86_64|i386")
                set(IDA_ARCH "x64")
            else()
                message(FATAL_ERROR "Unsupported macOS architecture: ${_cmake_arch}")
            endif()
        endif()
    else()
        # Detect architecture from host system
        set(IDA_UNIVERSAL_BINARY FALSE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
            set(IDA_ARCH "arm64")
        else()
            set(IDA_ARCH "x64")
        endif()
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(IDA_PLATFORM "LINUX")
    set(IDA_PLATFORM_NAME "linux")
    set(IDAPROPLAT "__LINUX__")

    # Detect architecture
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(IDA_ARCH "arm64")
    else()
        set(IDA_ARCH "x64")
    endif()

    # Compiler detection for Linux
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(IDA_COMPILER "gcc")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(IDA_COMPILER "clang")
    else()
        message(WARNING "Unsupported Linux compiler: ${CMAKE_CXX_COMPILER_ID}")
        set(IDA_COMPILER "gcc")  # Default to gcc
    endif()

else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# Construct library directory (always EA64)
set(IDA_EA_SIZE "64")
set(IDA_LIB_SUFFIX "${IDA_ARCH}_${IDA_PLATFORM_NAME}_${IDA_COMPILER}_64")
set(IDA_LIB_DIR "${IDASDK}/lib/${IDA_LIB_SUFFIX}")

# Platform-specific library names (using consistent platform detection)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(IDA_LIB_NAME "ida.lib")
    set(IDA_PRO_LIB_NAME "pro.lib")
    set(IDALIB_NAME "idalib.lib")
    set(IDA_SHARED_EXT ".dll")
    set(IDA_STATIC_EXT ".lib")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(IDA_LIB_NAME "libida.dylib")
    set(IDA_PRO_LIB_NAME "libpro.dylib")
    set(IDALIB_NAME "libidalib.dylib")
    set(IDA_SHARED_EXT ".dylib")
    set(IDA_STATIC_EXT ".a")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(IDA_LIB_NAME "libida.so")
    set(IDA_PRO_LIB_NAME "libpro.so")
    set(IDALIB_NAME "libidalib.so")
    set(IDA_SHARED_EXT ".so")
    set(IDA_STATIC_EXT ".a")
endif()

# Output directories for different addon types
set(IDA_PLUGIN_DIR "${IDABIN}/plugins")
set(IDA_LOADER_DIR "${IDABIN}/loaders")
set(IDA_PROCMOD_DIR "${IDABIN}/procs")
set(IDA_TIL_DIR "${IDABIN}/til")
set(IDA_SIG_DIR "${IDABIN}/sig")
set(IDA_IDS_DIR "${IDABIN}/ids")

# Interface library for platform-specific settings
# This allows targets to inherit platform settings cleanly
add_library(ida_platform_settings INTERFACE)

# Platform-specific compile definitions using generator expressions
target_compile_definitions(ida_platform_settings INTERFACE
    ${IDAPROPLAT}  # Platform macro (__NT__, __MAC__, or __LINUX__)
    $<$<PLATFORM_ID:Windows>:WIN32 _WINDOWS>
)

# Export platform variables for backward compatibility
# Variables are already in the correct scope when included
