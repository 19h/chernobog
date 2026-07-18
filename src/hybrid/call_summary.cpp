#include "call_summary.hpp"

#include <algorithm>
#include <cctype>
#include <string>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <xref.hpp>

namespace chernobog::hybrid {

namespace {

std::string canonical_name(const char *raw)
{
  std::string name = raw != nullptr ? raw : "";
  std::transform(name.begin(), name.end(), name.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  // Import/thunk decorations can be nested (for example j___imp_memcpy), so
  // peel wrappers to a fixed point.  Keep one leading underscore on names
  // whose spelling is semantically significant only until classification:
  // `_exit` canonicalizes to `exit`, which has the same summary.
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
  // Covers ELF symbol versions and x86 stdcall suffixes.  Do this after
  // wrapper stripping so `_memcpy@12` and `memcpy@@GLIBC_2.14` converge.
  if ( const size_t at = name.find('@'); at != std::string::npos )
    name.resize(at);
  return name;
}

bool classify(const std::string &name, EmuSummaryKind *kind)
{
  const auto starts_with = [&](const char *prefix)
  { return name.compare(0, std::char_traits<char>::length(prefix), prefix) == 0; };
  if ( name == "memcpy" ) *kind = EmuSummaryKind::MEMCPY;
  else if ( name == "memmove" ) *kind = EmuSummaryKind::MEMMOVE;
  else if ( name == "memset" ) *kind = EmuSummaryKind::MEMSET;
  // stpcpy deliberately is not aliased to strcpy: its return value is the end
  // pointer, not the destination pointer.
  else if ( name == "strcpy" ) *kind = EmuSummaryKind::STRCPY;
  else if ( name == "strncpy" ) *kind = EmuSummaryKind::STRNCPY;
  else if ( name == "strlen" ) *kind = EmuSummaryKind::STRLEN;
  else if ( name == "strcmp" ) *kind = EmuSummaryKind::STRCMP;
  else if ( name == "malloc" || starts_with("operator new(")
         || starts_with("operator new[](") || name == "znwm" || name == "znwj"
         || name == "znam" || name == "znaj" )
    *kind = EmuSummaryKind::ALLOCATE;
  else if ( name == "calloc" ) *kind = EmuSummaryKind::CALLOCATE;
  else if ( name == "free" || starts_with("operator delete(")
         || starts_with("operator delete[](") || starts_with("zdlpv")
         || starts_with("zdapv") )
    *kind = EmuSummaryKind::DEALLOCATE;
  else if ( name == "exit" || name == "abort"
         || name == "terminate" || name == "quick_exit"
         || name == "fatal" || name == "panic" || name == "stack_chk_fail" )
    *kind = EmuSummaryKind::TERMINATE;
  else return false;
  return true;
}

} // namespace

std::vector<EmuCallSummary> hybrid_collect_call_summaries(
    const FuncRange &function, size_t maximum_instruction_heads)
{
  std::vector<EmuCallSummary> out;
  if ( maximum_instruction_heads == 0 )
    return out;
  size_t visited = 0;
  for ( const FuncChunk &chunk : function.chunks )
  {
    ea_t address = ea_t(chunk.start);
    const ea_t end = ea_t(chunk.end);
    while ( address != BADADDR && address < end
         && visited < maximum_instruction_heads )
    {
      const flags64_t flags = get_flags(address);
      if ( is_code(flags) && is_head(flags) )
      {
        ++visited;
        insn_t instruction;
        if ( decode_insn(&instruction, address) > 0
          && is_call_insn(instruction) )
        {
          xrefblk_t reference;
          for ( bool ok = reference.first_from(address, XREF_CODE);
                ok; ok = reference.next_from() )
          {
            if ( !reference.iscode || reference.type == fl_F
              || reference.to == BADADDR || !is_mapped(reference.to) )
              continue;
            qstring name;
            if ( get_name(&name, reference.to) <= 0 )
              continue;
            EmuSummaryKind kind;
            if ( classify(canonical_name(name.c_str()), &kind) )
              out.push_back(EmuCallSummary{ uint64_t(reference.to), kind });
          }
        }
      }
      const ea_t next = next_head(address, end);
      if ( next == BADADDR || next <= address )
        break;
      address = next;
    }
    if ( visited >= maximum_instruction_heads )
      break;
  }
  std::sort(out.begin(), out.end(), [](const EmuCallSummary &a, const EmuCallSummary &b)
  {
    return a.address < b.address;
  });
  out.erase(std::unique(out.begin(), out.end(), [](const EmuCallSummary &a,
                                                   const EmuCallSummary &b)
  { return a.address == b.address; }), out.end());
  return out;
}

} // namespace chernobog::hybrid
