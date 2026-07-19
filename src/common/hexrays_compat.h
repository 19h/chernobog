#ifndef CHERNOBOG_HEXRAYS_COMPAT_H
#define CHERNOBOG_HEXRAYS_COMPAT_H

#include <limits>

namespace chernobog::hexrays_compat {

struct decompiler_version_t
{
    unsigned major = 0;
    unsigned minor = 0;
    unsigned revision = 0;
    unsigned build_date = 0;
};

inline bool parse_version_component(const char *&cursor, unsigned *value)
{
    if ( cursor == nullptr || value == nullptr
      || *cursor < '0' || *cursor > '9' )
    {
        return false;
    }

    unsigned parsed = 0;
    do
    {
        const unsigned digit = static_cast<unsigned>(*cursor - '0');
        if ( parsed > (std::numeric_limits<unsigned>::max() - digit) / 10U )
            return false;
        parsed = parsed * 10U + digit;
        ++cursor;
    }
    while ( *cursor >= '0' && *cursor <= '9' );

    *value = parsed;
    return true;
}

// get_hexrays_version() documents this exact representation:
// <major>.<minor>.<revision>.<build-date>.
inline bool parse_decompiler_version(
    const char *text,
    decompiler_version_t *version)
{
    if ( text == nullptr || version == nullptr )
        return false;

    const char *cursor = text;
    decompiler_version_t parsed;
    if ( !parse_version_component(cursor, &parsed.major)
      || *cursor++ != '.'
      || !parse_version_component(cursor, &parsed.minor)
      || *cursor++ != '.'
      || !parse_version_component(cursor, &parsed.revision)
      || *cursor++ != '.'
      || !parse_version_component(cursor, &parsed.build_date)
      || *cursor != '\0' )
    {
        return false;
    }

    *version = parsed;
    return true;
}

// Hex-Rays commit e6b9fe2ef765f04feab2ab3cd63884b3103825cf,
// committed on 2026-06-30, inserted MERR_TIMEOUT before the internal
// MERR_LOOP value. Some 9.4 SDK headers predate that enum-layout change while
// loading a newer 9.4 decompiler at runtime.
inline bool uses_timeout_merror_layout(const char *runtime_version)
{
    decompiler_version_t version;
    if ( !parse_decompiler_version(runtime_version, &version) )
        return false;

    constexpr decompiler_version_t first_timeout_layout{9, 4, 0, 260630};
    if ( version.major != first_timeout_layout.major )
        return version.major > first_timeout_layout.major;
    if ( version.minor != first_timeout_layout.minor )
        return version.minor > first_timeout_layout.minor;
    if ( version.revision != first_timeout_layout.revision )
        return version.revision > first_timeout_layout.revision;
    return version.build_date >= first_timeout_layout.build_date;
}

} // namespace chernobog::hexrays_compat

#endif // CHERNOBOG_HEXRAYS_COMPAT_H
