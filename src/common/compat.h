// Platform compatibility layer for cross-platform builds
#ifndef CHERNOBOG_COMPAT_H
#define CHERNOBOG_COMPAT_H

#ifdef _WIN32
    // Windows
    #include <io.h>
    #include <fcntl.h>
    #include <intrin.h>
    
    // Map POSIX file I/O to Windows equivalents
    #define open _open
    #define write _write
    #define close _close
    #define O_WRONLY _O_WRONLY
    #define O_CREAT _O_CREAT
    #define O_APPEND _O_APPEND
    #define O_TRUNC _O_TRUNC
    
    // Portable popcount - MSVC uses __popcnt
    inline int portable_popcount(uint32_t val) {
        return (int)__popcnt(val);
    }
    
    // MSVC doesn't support __attribute__((constructor))
    // We use a different mechanism for global init on Windows
    #define ATTRIBUTE_CONSTRUCTOR
    
#else
    // Unix (Linux/macOS)
    #include <unistd.h>
    #include <fcntl.h>
    
    // Portable popcount - GCC/Clang use __builtin_popcount
    inline int portable_popcount(uint32_t val) {
        return __builtin_popcount(val);
    }
    
    #define ATTRIBUTE_CONSTRUCTOR __attribute__((constructor))
#endif

#endif // CHERNOBOG_COMPAT_H
