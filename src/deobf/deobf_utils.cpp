#include "deobf_types.h"
#include "../common/compat.h"
#include <stdarg.h>
#include <algorithm>

namespace deobf {

static bool g_verbose = false;

bool debug_enabled()
{
    static const bool enabled = []() {
        qstring value;
        return qgetenv("CHERNOBOG_DEBUG", &value) &&
               !value.empty() && value[0] == '1';
    }();
    return enabled;
}

void debug_vlog(const char *path, const char *fmt, va_list va)
{
#ifndef _WIN32
    if ( !debug_enabled() || !path || !fmt )
        return;

    char buf[4096];
    va_list copy;
    va_copy(copy, va);
    const int len = qvsnprintf(buf, sizeof(buf), fmt, copy);
    va_end(copy);
    if ( len <= 0 )
        return;

    // qvsnprintf may return the number of bytes that would have been written.
    // Never pass that uncapped value to write(), because it can exceed buf.
    size_t remaining = std::min(static_cast<size_t>(len), sizeof(buf) - 1);
    const char *cursor = buf;

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if ( fd < 0 )
        return;

    while ( remaining > 0 )
    {
        const ssize_t written = write(fd, cursor, remaining);
        if ( written <= 0 )
            break;
        cursor += written;
        remaining -= static_cast<size_t>(written);
    }
    close(fd);
#else
    (void)path;
    (void)fmt;
    (void)va;
#endif
}

void set_verbose(bool v)
{
    g_verbose = v;
}

void log(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vmsg(fmt, va);
    va_end(va);
}

void log_verbose(const char *fmt, ...)
{
    if ( !g_verbose )
        return;
    va_list va;
    va_start(va, fmt);
    vmsg(fmt, va);
    va_end(va);
}

bool set_cmt_if_changed(ea_t address, const char *comment, bool repeatable)
{
    if ( address == BADADDR || comment == nullptr )
        return false;
    qstring existing;
    if ( get_cmt(&existing, address, repeatable) >= 0
      && existing == comment )
    {
        return false;
    }
    return set_cmt(address, comment, repeatable);
}

bool is_jcc(mcode_t op)
{
    return op >= m_jcnd && op <= m_jle;
}

} // namespace deobf
