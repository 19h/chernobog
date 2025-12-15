# compiler.cmake - Compiler configuration for IDA SDK

# C++ Standard
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Create interface library for IDA SDK compiler settings
# This  approach allows targets to opt-in to these settings
add_library(ida_compiler_settings INTERFACE)

# Common compile definitions
# Note: Platform-specific defines (IDAPROPLAT) are handled by the interface libraries
target_compile_definitions(ida_compiler_settings INTERFACE
    __IDP__
    __EA64__=1  # Always use EA64 (64-bit addressing)
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
)

# Platform-specific compiler configurations
if(MSVC)
    # MSVC specific flags
    target_compile_options(ida_compiler_settings INTERFACE
        /W3             # Warning level 3
        /MP             # Multi-processor compilation
        /GF             # String pooling
        /Gy             # Function-level linking
        /EHsc           # C++ exceptions
        /permissive-    # Standards conformance
        /Zc:__cplusplus # Report correct __cplusplus
        /utf-8          # UTF-8 source and execution character sets
        # Configuration-specific flags
        $<$<CONFIG:Debug>:/Od>          # No optimization
        $<$<CONFIG:Debug>:/RTC1>        # Runtime checks
        $<$<CONFIG:Debug>:/Zi>          # Debug info
        $<$<CONFIG:Release>:/O2>        # Optimize for speed
        $<$<CONFIG:Release>:/GL>        # Whole program optimization
        $<$<CONFIG:Release>:/Oi>        # Intrinsic functions
    )

    # Linker flags
    target_link_options(ida_compiler_settings INTERFACE
        $<$<CONFIG:Release>:/LTCG>      # Link-time code generation
        $<$<CONFIG:Release>:/OPT:REF>   # Remove unreferenced code
        $<$<CONFIG:Release>:/OPT:ICF>   # Remove duplicate code
    )

    # Create a separate interface library for warning suppression
    add_library(ida_warnings_disabled INTERFACE)
    target_compile_options(ida_warnings_disabled INTERFACE
        /wd4244     # conversion from 'type1' to 'type2', possible loss of data
        /wd4267     # conversion from 'size_t' to 'type', possible loss of data
        /wd4996     # deprecated functions
        /wd4018     # signed/unsigned mismatch
        /wd4146     # unary minus operator applied to unsigned type
    )

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # GCC/Clang specific flags
    target_compile_options(ida_compiler_settings INTERFACE
        -Wall
        -Wextra
        -fPIC
        -ffunction-sections
        -fdata-sections
        -pthread
        # Configuration-specific flags
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Release>:-O3>
        # $<$<CONFIG:Release>:-flto>  # LTO disabled due to linker issues
    )

    # Linker flags
    target_link_options(ida_compiler_settings INTERFACE
        -Wl,--gc-sections
        # $<$<CONFIG:Release>:-flto>  # LTO disabled due to linker issues
    )

    # Create a separate interface library for warning suppression
    add_library(ida_warnings_disabled INTERFACE)
    target_compile_options(ida_warnings_disabled INTERFACE
        -Wno-unused-parameter
        -Wno-sign-compare
        -Wno-deprecated-declarations
        -Wno-format
    )

    # macOS specific
    if(APPLE)
        target_compile_options(ida_compiler_settings INTERFACE
            -stdlib=libc++
            -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}
        )
        target_link_options(ida_compiler_settings INTERFACE
            -stdlib=libc++
            -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}
        )
    endif()
endif()

# Compiler settings are now applied through target linking
# Targets link to ida_compiler_settings via idasdk::plugin, idasdk::loader, etc.

# Function to disable IDA SDK warnings for a target
# Apply warning suppression flags directly
function(ida_disable_warnings TARGET)
    if(MSVC)
        target_compile_options(${TARGET} PRIVATE
            /wd4244     # conversion from 'type1' to 'type2', possible loss of data
            /wd4267     # conversion from 'size_t' to 'type', possible loss of data
            /wd4996     # deprecated functions
            /wd4018     # signed/unsigned mismatch
            /wd4146     # unary minus operator applied to unsigned type
            /wd4800 /wd4251 /wd4005 /wd4099 /wd4065
        )
    else()
        target_compile_options(${TARGET} PRIVATE
            -Wno-unused-parameter
            -Wno-sign-compare
            -Wno-deprecated-declarations
            -Wno-format
            -Wno-parentheses
            -Wno-unused-variable
            -Wno-unused-function
            -Wno-switch
        )
    endif()
endfunction()

# Function to set strict warnings for a target
function(ida_enable_strict_warnings TARGET)
    if(MSVC)
        target_compile_options(${TARGET} PRIVATE /W4 /WX)
    else()
        target_compile_options(${TARGET} PRIVATE -Wall -Wextra -Werror -pedantic)
    endif()
endfunction()
