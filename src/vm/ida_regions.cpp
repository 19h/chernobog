#include "ida_regions.hpp"
#include "region.hpp"
#include "summary_view.hpp"
#include "observations.hpp"
#include "../hybrid/evidence.hpp"
#include "../common/inspection_json.hpp"
#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include "../common/warn_on.h"
#include <map>
#include <sstream>

namespace chernobog::vm {
namespace {
std::string hex(uint64_t n) { std::ostringstream out; out << "0x" << std::hex << n; return out.str(); }
int canonical(int number, unsigned bits)
{
  if (number < 0 || (bits != 8 && bits != 16 && bits != 32 && bits != 64)) return -1;
  qstring name;
  if (get_reg_name(&name, number, bits/8) <= 0) return -1;
  static const char *names[][4] = {
    {"al","ax","eax","rax"}, {"cl","cx","ecx","rcx"}, {"dl","dx","edx","rdx"}, {"bl","bx","ebx","rbx"},
    {"spl","sp","esp","rsp"}, {"bpl","bp","ebp","rbp"}, {"sil","si","esi","rsi"}, {"dil","di","edi","rdi"},
    {"r8b","r8w","r8d","r8"}, {"r9b","r9w","r9d","r9"}, {"r10b","r10w","r10d","r10"}, {"r11b","r11w","r11d","r11"},
    {"r12b","r12w","r12d","r12"}, {"r13b","r13w","r13d","r13"}, {"r14b","r14w","r14d","r14"}, {"r15b","r15w","r15d","r15"}};
  for (int reg = 0; reg < 16; ++reg) for (const auto *part : names[reg]) if (name == part) return reg;
  return -1; // High-byte aliases deliberately unsupported.
}
Operand operand(const insn_t &i, const op_t &o, unsigned mode)
{
  Operand r; r.bits = unsigned(get_dtype_size(o.dtype) * 8);
  if (o.type == o_void) return {};
  if (o.type == o_reg) { r.kind = Kind::reg; r.reg = canonical(o.reg, r.bits); }
  else if (o.type == o_imm) { r.kind = Kind::immediate; r.value = o.value; }
  else if (o.type == o_phrase || o.type == o_displ || o.type == o_mem)
  {
    r.kind = Kind::memory; r.address_bits = ad64(i) ? 64 : ad32(i) ? 32 : 16;
    if (r.address_bits != mode) return {};
    const int base = x86_base_reg(i, o), index = x86_index_reg(i, o);
    r.base = base == R_none ? -1 : canonical(base, mode);
    r.index = index == R_none ? -1 : canonical(index, mode);
    if ((base != R_none && r.base == -1) || (index != R_none && r.index == -1)) return {};
    const int shift = x86_scale(o);
    if (shift < 0 || shift > 3) return {};
    r.scale = 1u << unsigned(shift); r.value = o.type == o_phrase ? 0 : uint64_t(o.addr);
  }
  return r;
}
Instruction decode(const insn_t &i, unsigned mode)
{
  Instruction r; r.address = i.ea; r.size = i.size;
  if (!natad(i) || i.segpref != 0 || (i.auxpref & (aux_lock | aux_rep | aux_repne))) return r;
  r.dst = operand(i, i.Op1, mode); r.src = operand(i, i.Op2, mode);
  switch (i.itype)
  {
    case NN_mov: case NN_movzx: r.op = Op::load; break;
    case NN_movsxd: r.op = Op::sign_extend; break;
    case NN_add: r.op = Op::add; break;
    case NN_sub: r.op = Op::sub; break;
    case NN_xor: r.op = Op::bit_xor; break;
    case NN_rol: r.op = Op::rotate_left; break;
    case NN_ror: r.op = Op::rotate_right; break;
    case NN_neg: r.op = Op::negate; break;
    case NN_not: r.op = Op::bit_not; break;
    case NN_bswap: r.op = Op::byte_swap; break;
    case NN_inc: r.op = Op::increment; break;
    case NN_dec: r.op = Op::decrement; break;
    case NN_push: r.op = Op::push; break;
    case NN_pop: r.op = Op::pop; break;
    case NN_jmp: case NN_jmpni: r.op = Op::jump; break;
    default: break;
  }
  return r;
}
std::string bytes(const Candidate &c)
{
  std::string result; static const char digits[] = "0123456789abcdef";
  for (uint64_t ea = c.start; ea < c.end; ++ea)
  { const auto byte = get_byte(ea_t(ea)); result += digits[byte >> 4]; result += digits[byte & 15]; }
  return result;
}
} // namespace

std::string inspect_regions(uint64_t function, bool include_summaries,
    const hybrid::TargetEvidence *source,uint64_t revision,bool fresh,bool validate_transitions)
{
  using Row = std::map<std::string,std::string>;
  std::vector<Row> rows;
  std::vector<Candidate> candidates;
  size_t visited = 0, omitted = 0; bool truncated = false;
  auto *owner = get_func(ea_t(function)); auto *segment = getseg(ea_t(function));
  const unsigned mode = segment && segment->bitness == 2 ? 64 : segment && segment->bitness == 1 ? 32 : 0;
  const bool available = owner && owner->start_ea == function && PH.id == PLFM_386 && mode != 0;
  std::map<std::string, size_t> shapes;
  if (available)
  {
    std::vector<Instruction> window;
    func_item_iterator_t iter(owner);
    for (bool ok = iter.first(); ok; ok = iter.next_code())
    {
      if (visited++ == 1024) { truncated = true; --visited; break; }
      const ea_t ea = iter.current(); insn_t insn;
      const auto *seg = getseg(ea); const auto *actual = get_func(ea);
      if (!actual || actual->start_ea != function || !seg || seg->bitness != segment->bitness
          || !(seg->perm & SEGPERM_EXEC) || !is_code(get_flags(ea)) || decode_insn(&insn, ea) <= 0)
      { window.clear(); continue; }
      bool loaded = true;
      for (unsigned j = 0; j < insn.size; ++j)
      {
        const auto *byte_owner = get_func(ea + j);
        if (!is_loaded(ea + j) || !byte_owner || byte_owner->start_ea != function) loaded = false;
      }
      if (!loaded) { window.clear(); continue; }
      auto i = decode(insn, mode);
      const uint64_t previous = window.empty() ? bad_address : window.back().address;
      i.alternate_entry = !is_flow(get_flags(ea));
      xrefblk_t xref;
      for (bool x = xref.first_to(ea, XREF_ALL); x; x = xref.next_to())
        if (xref.iscode && xref.from != previous) { i.alternate_entry = true; break; }
      if (!window.empty() && window.back().address + window.back().size != ea) window.clear();
      window.push_back(i);
      if (window.size() > 128) window.erase(window.begin());
      if (i.op != Op::jump) continue;
      for (size_t start = 0; start + 2 < window.size(); ++start)
      {
        const auto candidate = recognize({window.begin() + start, window.end()}, mode);
        if (!candidate) continue;
        if (rows.size() == 64) { ++omitted; break; }
        const auto &c = *candidate;
        if(include_summaries || source)candidates.push_back(c);
        const auto shape = normalized_shape(c);
        const auto group = shapes.emplace(shape, shapes.size() + 1).first->second;
        rows.push_back({{"vm_candidate", hex(c.start) + ":" + hex(c.dispatch)},
          {"site", hex(c.start)}, {"end", hex(c.end)}, {"read", hex(c.read)}, {"dispatch", hex(c.dispatch)},
          {"truth", "candidate"}, {"fresh", "true"}, {"address_bits", std::to_string(mode)},
          {"read_bits", std::to_string(c.read_bits)}, {"direction", c.direction == Direction::forward ? "forward" : "backward"},
          {"dispatch_kind", c.dispatch_kind == Dispatch::indexed_table ? "indexed table" : "relative register"},
          {"vip_register", std::to_string(c.vip)}, {"value_register", std::to_string(c.value)},
          {"key_register", std::to_string(c.key)}, {"dispatch_base_register", std::to_string(c.dispatch_base)},
          {"table_displacement", hex(c.table_displacement)}, {"stack_key_update", c.stack_key_update ? "true" : "false"},
          {"bytes", bytes(c)}, {"shape_group", std::to_string(group)}, {"normalized_shape", shape},
          {"classification", "local read/decode/dispatch candidate; VM identity unverified"},
          {"ownership", "selected IDA function only; no VM execution region admitted"},
          {"unresolved", "VM entry, virtual stack/context, memory contents, handler semantics, flags/exceptions and dispatch targets"},
          {"logical_state", "native address plus VIP, decoder key when present, virtual stack, dispatch base, context and memory epoch"},
          {"summary_reuse", "unproved; role-normalized syntax is indexing only"}});
        break;
      }
      window.clear();
    }
  }
  std::ostringstream out;
  out << "{\"schema\":1,\"available\":" << (available ? "true" : "false")
      << ",\"database\":" << inspection_json_quote(std::to_string(int64_t(get_dbctx_id())))
      << ",\"function\":" << inspection_json_quote(hex(function)) << ",\"instructions\":" << visited
      << ",\"truncated\":" << (truncated ? "true" : "false") << ",\"omitted\":" << omitted;
  inspection_json_rows(out, "records", rows);
  if(include_summaries)
  {
    const auto view=project_summaries(candidates,int64_t(get_dbctx_id()),function);
    out << ",\"summary_omitted\":" << view.omitted+omitted
        << ",\"comparison_attempts\":" << view.queries;
    inspection_json_rows(out,"summaries",view.references);
    inspection_json_rows(out,"summary_bindings",view.bindings);
  }
  if(source)
  {
    const auto view=project_observations(candidates,*source,function,revision,fresh && available,
        validate_transitions,int64_t(get_dbctx_id()));
    out << ",\"states_available\":" << (view.available?"true":"false")
        << ",\"states_reason\":" << inspection_json_quote(view.reason)
        << ",\"states_omitted\":" << view.omitted
        << ",\"transition_attempts\":" << view.transition_attempts
        << ",\"transition_queries\":" << view.queries
        << ",\"revision\":" << inspection_json_quote(hex(revision))
        << ",\"generation\":" << inspection_json_quote(hex(source->scope.generation));
    inspection_json_rows(out,"states",view.records);
  }
  out << '}'; return out.str();
}
} // namespace chernobog::vm
