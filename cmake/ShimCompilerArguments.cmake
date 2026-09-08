# The Python shim suites compile production sources at test time. Preserve the
# selected CMake toolchain instead of accidentally using the compiler's host
# defaults (notably for an x86_64 build on an arm64 Mac).
function(_chernobog_literal_shim_flag output token)
    # add_test evaluates generator expressions. Flags themselves are literal
    # compiler arguments; a macro containing '>' or '$<' must not alter the
    # surrounding configuration expression or become a CMake expression.
    set(_encoded)
    string(LENGTH "${token}" _length)
    if(_length GREATER 0)
        math(EXPR _last "${_length} - 1")
        foreach(_index RANGE ${_last})
            string(SUBSTRING "${token}" ${_index} 1 _character)
            if(_character STREQUAL "$")
                string(APPEND _encoded "$<1:$>")
            elseif(_character STREQUAL ">")
                string(APPEND _encoded "$<ANGLE-R>")
            else()
                string(APPEND _encoded "${_character}")
            endif()
        endforeach()
    endif()
    string(REPLACE ";" "\\;" _encoded "${_encoded}")
    set(${output} "${_encoded}" PARENT_SCOPE)
endfunction()

function(chernobog_shim_compiler_arguments output)
    set(_arguments)
    foreach(_setting CMAKE_CXX_COMPILER_ARG1 CMAKE_CXX_FLAGS)
        separate_arguments(_tokens NATIVE_COMMAND "${${_setting}}")
        foreach(_token IN LISTS _tokens)
            _chernobog_literal_shim_flag(_escaped "${_token}")
            list(APPEND _arguments "--cxx-flag=${_escaped}")
        endforeach()
    endforeach()

    if(CMAKE_CONFIGURATION_TYPES)
        set(_configurations ${CMAKE_CONFIGURATION_TYPES})
    else()
        set(_configurations "${CMAKE_BUILD_TYPE}")
    endif()
    foreach(_configuration IN LISTS _configurations)
        string(TOUPPER "${_configuration}" _upper_configuration)
        separate_arguments(_tokens NATIVE_COMMAND
            "${CMAKE_CXX_FLAGS_${_upper_configuration}}")
        foreach(_token IN LISTS _tokens)
            _chernobog_literal_shim_flag(_escaped "${_token}")
            # Nonselected configurations produce --cxx-flag=; runners discard
            # that placeholder rather than passing an empty compiler argument.
            list(APPEND _arguments
                "--cxx-flag=$<$<CONFIG:${_configuration}>:${_escaped}>")
        endforeach()
    endforeach()

    set(_toolchain_flags)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        if(CMAKE_CXX_COMPILER_TARGET)
            list(APPEND _toolchain_flags "--target=${CMAKE_CXX_COMPILER_TARGET}")
        endif()
        if(CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN)
            list(APPEND _toolchain_flags
                "--gcc-toolchain=${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}")
        endif()
    endif()
    if(CMAKE_SYSROOT)
        list(APPEND _toolchain_flags "--sysroot=${CMAKE_SYSROOT}")
    endif()
    if(APPLE)
        foreach(_architecture IN LISTS CMAKE_OSX_ARCHITECTURES)
            list(APPEND _toolchain_flags -arch "${_architecture}")
        endforeach()
        if(CMAKE_OSX_SYSROOT)
            set(_osx_sysroot "${CMAKE_OSX_SYSROOT}")
            if(NOT IS_ABSOLUTE "${_osx_sysroot}")
                execute_process(
                    COMMAND xcrun --sdk "${_osx_sysroot}" --show-sdk-path
                    RESULT_VARIABLE _sdk_status
                    OUTPUT_VARIABLE _osx_sysroot
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
                if(NOT _sdk_status EQUAL 0 OR _osx_sysroot STREQUAL "")
                    message(FATAL_ERROR
                        "Cannot resolve shim-test SDK '${CMAKE_OSX_SYSROOT}'")
                endif()
            endif()
            list(APPEND _toolchain_flags -isysroot "${_osx_sysroot}")
        endif()
        if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND CMAKE_OSX_DEPLOYMENT_TARGET)
            list(APPEND _toolchain_flags
                "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
        endif()
    endif()
    foreach(_token IN LISTS _toolchain_flags)
        _chernobog_literal_shim_flag(_escaped "${_token}")
        list(APPEND _arguments "--cxx-flag=${_escaped}")
    endforeach()
    set(${output} "${_arguments}" PARENT_SCOPE)
endfunction()
