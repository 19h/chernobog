#include "deobf/analysis/mba_cobra.hpp"
#include <type_traits>
#if defined(_MSVC_LANG)
#define CHERNOBOG_HEADER_LANGUAGE _MSVC_LANG
#else
#define CHERNOBOG_HEADER_LANGUAGE __cplusplus
#endif
static_assert(CHERNOBOG_HEADER_LANGUAGE >= 201703L && CHERNOBOG_HEADER_LANGUAGE < 202002L,
              "CoBRA public interface must compile as C++17");
static_assert(std::is_default_constructible<chernobog::mba_smt::cobra_backend::Request>::value);
