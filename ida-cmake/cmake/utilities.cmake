# utilities.cmake - Utility functions for IDA SDK

# REMOVED: ida_bundle_addon - bundling/packaging is unnecessary complexity

# REMOVED: ida_find_installation - we don't need to locate IDA paths

# Function to check IDA SDK version
function(ida_check_sdk_version)
    if(EXISTS "${IDASDK}/include/pro.h")
        file(STRINGS "${IDASDK}/include/pro.h" IDA_VERSION_LINE REGEX "^#define IDA_SDK_VERSION")
        if(IDA_VERSION_LINE)
            string(REGEX REPLACE ".*IDA_SDK_VERSION[ \\t]+([0-9]+)" "\\1" IDA_SDK_VERSION_NUM "${IDA_VERSION_LINE}")
            math(EXPR IDA_SDK_MAJOR "${IDA_SDK_VERSION_NUM} / 100")
            math(EXPR IDA_SDK_MINOR "${IDA_SDK_VERSION_NUM} % 100")
            set(IDA_SDK_VERSION "${IDA_SDK_MAJOR}.${IDA_SDK_MINOR}" CACHE STRING "IDA SDK Version")
            set(IDA_SDK_VERSION "${IDA_SDK_VERSION}" PARENT_SCOPE)
            message(STATUS "Detected IDA SDK version: ${IDA_SDK_VERSION}")
        else()
            message(WARNING "Could not detect IDA SDK version from pro.h")
        endif()
    else()
        message(WARNING "IDA SDK pro.h not found at: ${IDASDK}/include/pro.h")
    endif()
endfunction()

# Function to validate environment
function(ida_validate_environment)
    # Check IDASDK
    if(NOT EXISTS "${IDASDK}")
        message(FATAL_ERROR "IDASDK directory does not exist: ${IDASDK}")
    endif()

    if(NOT EXISTS "${IDASDK}/include/pro.h")
        message(FATAL_ERROR "Invalid IDASDK directory (missing ${IDASDK}/include/pro.h)")
    endif()

    # Check IDABIN if specified
    if(DEFINED IDABIN)
        if(NOT EXISTS "${IDABIN}")
            message(WARNING "IDABIN directory does not exist: ${IDABIN}")
        endif()
    endif()

    # Check for required SDK libraries
    if(NOT EXISTS "${IDA_LIB_DIR}")
        message(FATAL_ERROR "IDA SDK library directory does not exist: ${IDA_LIB_DIR}")
    endif()

    if(NOT EXISTS "${IDA_LIB_DIR}/${IDA_LIB_NAME}")
        message(FATAL_ERROR "IDA SDK library not found: ${IDA_LIB_DIR}/${IDA_LIB_NAME}")
    endif()

    message(STATUS "IDA SDK validation passed")
    message(STATUS "  IDASDK: ${IDASDK}")
    message(STATUS "  IDABIN: ${IDABIN}")
    message(STATUS "  Platform: ${IDA_PLATFORM}")
    message(STATUS "  Architecture: ${IDA_ARCH}")
    message(STATUS "  Compiler: ${IDA_COMPILER}")
    message(STATUS "  EA Size: ${IDA_EA_SIZE}")
endfunction()

# Function to print configuration summary
function(ida_print_config)
    message(STATUS "")
    message(STATUS "IDA SDK Configuration Summary:")
    message(STATUS "==============================")
    message(STATUS "  SDK Path: ${IDASDK}")
    message(STATUS "  BIN Path: ${IDABIN}")
    message(STATUS "  Platform: ${IDA_PLATFORM_NAME}")
    message(STATUS "  Architecture: ${IDA_ARCH}")
    message(STATUS "  Compiler: ${IDA_COMPILER}")
    message(STATUS "  EA Size: ${IDA_EA_SIZE}-bit")
    message(STATUS "  Library Directory: ${IDA_LIB_DIR}")
    message(STATUS "  Plugin Directory: ${IDA_PLUGIN_DIR}")
    message(STATUS "  Loader Directory: ${IDA_LOADER_DIR}")
    message(STATUS "  ProcMod Directory: ${IDA_PROCMOD_DIR}")
    if(IDA_SDK_VERSION)
        message(STATUS "  SDK Version: ${IDA_SDK_VERSION}")
    endif()
    message(STATUS "==============================")
    message(STATUS "")
endfunction()
