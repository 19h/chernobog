#include "call_summary.hpp"
#include "call_summary_policy.hpp"

#include <algorithm>
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
            const std::optional<EmuSummaryKind> kind =
                hybrid_classify_call_summary_name(name.c_str());
            out.push_back(EmuCallSummary{
                uint64_t(reference.to), kind.value_or(EmuSummaryKind::UNMODELED),
                name.c_str() });
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
  {
    return a.address == b.address && a.kind == b.kind && a.name == b.name;
  }), out.end());
  return out;
}

} // namespace chernobog::hybrid
