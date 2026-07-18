#include "call_summary_policy.hpp"

#include <algorithm>
#include <cctype>

namespace chernobog::hybrid {

std::string hybrid_canonical_call_name(const std::string &raw)
{
  std::string name = raw;
  std::transform(name.begin(), name.end(), name.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  bool changed = true;
  while ( changed && !name.empty() )
  {
    changed = false;
    for ( const char *prefix : { "__imp_", "imp_", "j_", "__", "_" } )
    {
      const size_t n = std::char_traits<char>::length(prefix);
      if ( name.compare(0, n, prefix) == 0 )
      {
        name.erase(0, n);
        changed = true;
        break;
      }
    }
  }
  if ( const size_t at = name.find('@'); at != std::string::npos )
    name.resize(at);
  return name;
}

std::optional<EmuSummaryKind> hybrid_classify_call_summary_name(
    const std::string &raw)
{
  const std::string name = hybrid_canonical_call_name(raw);
  const auto starts_with = [&](const char *prefix)
  { return name.compare(0, std::char_traits<char>::length(prefix), prefix) == 0; };
  if ( name == "memcpy" ) return EmuSummaryKind::MEMCPY;
  if ( name == "memmove" ) return EmuSummaryKind::MEMMOVE;
  if ( name == "memset" ) return EmuSummaryKind::MEMSET;
  if ( name == "strcpy" ) return EmuSummaryKind::STRCPY;
  if ( name == "strncpy" ) return EmuSummaryKind::STRNCPY;
  if ( name == "strlen" ) return EmuSummaryKind::STRLEN;
  if ( name == "strcmp" ) return EmuSummaryKind::STRCMP;
  if ( name == "malloc" || starts_with("operator new(")
    || starts_with("operator new[](") || name == "znwm" || name == "znwj"
    || name == "znam" || name == "znaj" )
    return EmuSummaryKind::ALLOCATE;
  if ( name == "calloc" ) return EmuSummaryKind::CALLOCATE;
  if ( name == "free" || starts_with("operator delete(")
    || starts_with("operator delete[](") || starts_with("zdlpv")
    || starts_with("zdapv") )
    return EmuSummaryKind::DEALLOCATE;
  if ( name == "exit" || name == "abort" || name == "terminate"
    || name == "quick_exit" || name == "fatal" || name == "panic"
    || name == "stack_chk_fail" )
    return EmuSummaryKind::TERMINATE;

  if ( name == "objc_retain" || name == "objc_retainblock"
    || name == "objc_retainautorelease"
    || name == "objc_retainautoreleasereturnvalue"
    || name == "objc_retainautoreleasedreturnvalue"
    || name == "objc_autorelease" || name == "objc_autoreleasereturnvalue"
    || name == "objc_claimautoreleasedreturnvalue"
    || name == "objc_unsafeclaimautoreleasedreturnvalue" )
    return EmuSummaryKind::RETURN_ARG0;
  if ( name == "objc_release" || name == "objc_autoreleasepoolpop"
    || name == "objc_destroyweak" )
    return EmuSummaryKind::RETURN_ZERO;
  if ( name == "objc_storestrong" )
    return EmuSummaryKind::STORE_POINTER_ARG1;
  if ( name == "objc_alloc" || name == "objc_alloc_init"
    || name == "objc_autoreleasepoolpush" )
    return EmuSummaryKind::ALLOCATE_OBJECT;
  if ( name == "arc4random" ) return EmuSummaryKind::RANDOM_U32;
  if ( name == "arc4random_uniform" ) return EmuSummaryKind::RANDOM_UNIFORM;
  return std::nullopt;
}

} // namespace chernobog::hybrid
