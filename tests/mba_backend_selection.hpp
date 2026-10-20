#pragma once
#include "deobf/analysis/mba_cobra.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

inline int mba_test_backend_selection()
{
    using namespace chernobog::mba_smt;
    int failures = 0;
    const auto check = [&](bool condition, const char *description)
    {
        if (!condition)
        {
            std::fprintf(stderr, "FAIL: backend selection: %s\n", description);
            ++failures;
        }
    };
    const auto select = [](const char *value)
    {
#if defined(_WIN32)
        return _putenv_s("CHERNOBOG_MBA_BACKEND", value ? value : "") == 0;
#else
        return value ? setenv("CHERNOBOG_MBA_BACKEND", value, 1) == 0
                     : unsetenv("CHERNOBOG_MBA_BACKEND") == 0;
#endif
    };
    const Backend expected = cobra_backend::available() ? Backend::Cobra : Backend::Legacy;
    check(select(nullptr), "clear inherited override");
    check(selected_backend() == expected && std::strcmp(backend_diagnostic(), "none") == 0,
          "compiled release default");
    check(select("legacy"), "set explicit legacy override");
    check(selected_backend() == Backend::Legacy && std::strcmp(backend_diagnostic(), "none") == 0,
          "legacy rollback");
    check(select("cobra"), "set explicit cobra override");
    check(selected_backend() == expected &&
              std::strcmp(backend_diagnostic(),
                          cobra_backend::available() ? "none" : "cobra_unavailable") == 0,
          "cobra availability and diagnostic");
    check(select("invalid"), "set invalid override");
    check(selected_backend() == expected &&
              std::strcmp(backend_diagnostic(), "invalid_backend") == 0,
          "invalid override uses release default with diagnostic");
    check(select("legacy"), "pin required legacy regression suite");
    return failures;
}
