set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING
    "MSVC runtime library" FORCE)

# FindThreads performs POSIX library link probes before recognizing Windows.
# Static-library try-compiles cannot validate those links and can therefore
# report a host `-lpthreads` dependency while cross-compiling.  Preseed the
# POSIX probes as unavailable; the module will select native Win32 threads,
# which require no extra link library for C++ std::thread.
set(CMAKE_HAVE_LIBC_PTHREAD FALSE CACHE INTERNAL "No POSIX pthreads on MSVC" FORCE)
set(CMAKE_HAVE_PTHREADS_CREATE FALSE CACHE INTERNAL "No host libpthreads" FORCE)
set(CMAKE_HAVE_PTHREAD_CREATE FALSE CACHE INTERNAL "No host libpthread" FORCE)
set(THREADS_HAVE_PTHREAD_ARG FALSE CACHE INTERNAL "MSVC has no -pthread" FORCE)

set(CHERNOBOG_WINDOWS_TRIPLE "x86_64-pc-windows-msvc" CACHE STRING "LLVM target triple for Windows builds")

if(DEFINED ENV{XWIN_ROOT} AND NOT "$ENV{XWIN_ROOT}" STREQUAL "")
    file(TO_CMAKE_PATH "$ENV{XWIN_ROOT}" _chernobog_xwin_root_from_env)
    set(XWIN_ROOT "${_chernobog_xwin_root_from_env}" CACHE PATH "Path to the xwin CRT/SDK root" FORCE)
elseif(NOT DEFINED XWIN_ROOT)
    set(XWIN_ROOT "" CACHE PATH "Path to the xwin CRT/SDK root")
endif()

if(NOT XWIN_ROOT)
    message(FATAL_ERROR "XWIN_ROOT is not set. Run xwin splat and point XWIN_ROOT at the output directory.")
endif()

set(_chernobog_xwin_required_paths
    "${XWIN_ROOT}/crt/include"
    "${XWIN_ROOT}/crt/lib/x86_64"
    "${XWIN_ROOT}/sdk/include/ucrt"
    "${XWIN_ROOT}/sdk/include/shared"
    "${XWIN_ROOT}/sdk/include/um"
    "${XWIN_ROOT}/sdk/lib/ucrt/x86_64"
    "${XWIN_ROOT}/sdk/lib/um/x86_64"
)

foreach(_path IN LISTS _chernobog_xwin_required_paths)
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "XWIN_ROOT is missing required path: ${_path}")
    endif()
endforeach()

find_program(CHERNOBOG_CLANG_CL
    NAMES clang-cl clang-cl-20 clang-cl-19 clang-cl-18 clang-cl-17 clang-cl-16 clang-cl-15
    REQUIRED)
find_program(CHERNOBOG_LLD_LINK
    NAMES lld-link lld-link-20 lld-link-19 lld-link-18 lld-link-17 lld-link-16 lld-link-15
    REQUIRED)
find_program(CHERNOBOG_LLVM_LIB
    NAMES llvm-lib llvm-lib-20 llvm-lib-19 llvm-lib-18 llvm-lib-17 llvm-lib-16 llvm-lib-15
    REQUIRED)
find_program(CHERNOBOG_LLVM_RC
    NAMES llvm-rc llvm-rc-20 llvm-rc-19 llvm-rc-18 llvm-rc-17 llvm-rc-16 llvm-rc-15
    REQUIRED)
find_program(CHERNOBOG_LLVM_MT
    NAMES llvm-mt llvm-mt-20 llvm-mt-19 llvm-mt-18 llvm-mt-17 llvm-mt-16 llvm-mt-15)

set(CMAKE_C_COMPILER "${CHERNOBOG_CLANG_CL}" CACHE FILEPATH "Clang C compiler" FORCE)
set(CMAKE_CXX_COMPILER "${CHERNOBOG_CLANG_CL}" CACHE FILEPATH "Clang CXX compiler" FORCE)
set(CMAKE_LINKER "${CHERNOBOG_LLD_LINK}" CACHE FILEPATH "LLD linker" FORCE)
set(CMAKE_AR "${CHERNOBOG_LLVM_LIB}" CACHE FILEPATH "LLVM librarian" FORCE)
set(CMAKE_RC_COMPILER "${CHERNOBOG_LLVM_RC}" CACHE FILEPATH "LLVM resource compiler" FORCE)
if(CHERNOBOG_LLVM_MT)
    set(CMAKE_MT "${CHERNOBOG_LLVM_MT}" CACHE FILEPATH "LLVM manifest tool" FORCE)
endif()

set(CMAKE_C_COMPILER_TARGET "${CHERNOBOG_WINDOWS_TRIPLE}" CACHE STRING "C target triple" FORCE)
set(CMAKE_CXX_COMPILER_TARGET "${CHERNOBOG_WINDOWS_TRIPLE}" CACHE STRING "CXX target triple" FORCE)

set(_chernobog_xwin_includes
    "${XWIN_ROOT}/crt/include"
    "${XWIN_ROOT}/sdk/include/ucrt"
    "${XWIN_ROOT}/sdk/include/shared"
    "${XWIN_ROOT}/sdk/include/um"
)

set(_chernobog_xwin_libs
    "${XWIN_ROOT}/crt/lib/x86_64"
    "${XWIN_ROOT}/sdk/lib/ucrt/x86_64"
    "${XWIN_ROOT}/sdk/lib/um/x86_64"
)

set(_chernobog_xwin_compile_flags
    "-Wno-unused-command-line-argument"
    "-w"
    "-fuse-ld=lld-link"
    "/imsvc${XWIN_ROOT}/crt/include"
    "/imsvc${XWIN_ROOT}/sdk/include/ucrt"
    "/imsvc${XWIN_ROOT}/sdk/include/shared"
    "/imsvc${XWIN_ROOT}/sdk/include/um"
)
string(JOIN " " _chernobog_xwin_compile_flags_string ${_chernobog_xwin_compile_flags})

set(CMAKE_C_STANDARD_INCLUDE_DIRECTORIES ${_chernobog_xwin_includes})
set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES ${_chernobog_xwin_includes})
set(CMAKE_SYSTEM_INCLUDE_PATH ${_chernobog_xwin_includes})
set(CMAKE_SYSTEM_LIBRARY_PATH ${_chernobog_xwin_libs})
set(CMAKE_FIND_ROOT_PATH ${XWIN_ROOT})
set(CMAKE_C_FLAGS_INIT "${_chernobog_xwin_compile_flags_string}")
set(CMAKE_CXX_FLAGS_INIT "${_chernobog_xwin_compile_flags_string}")

set(_chernobog_xwin_link_flags
    "/libpath:${XWIN_ROOT}/crt/lib/x86_64"
    "/libpath:${XWIN_ROOT}/sdk/lib/ucrt/x86_64"
    "/libpath:${XWIN_ROOT}/sdk/lib/um/x86_64"
)
string(JOIN " " _chernobog_xwin_link_flags_string ${_chernobog_xwin_link_flags})

set(CMAKE_EXE_LINKER_FLAGS_INIT "${_chernobog_xwin_link_flags_string}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_chernobog_xwin_link_flags_string}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_chernobog_xwin_link_flags_string}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
