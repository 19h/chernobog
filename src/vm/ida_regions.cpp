#include "ida_regions.hpp"
#include "region.hpp"
#include "boundary.hpp"
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
#include <algorithm>
#include <set>
#include <deque>
#include <sstream>

namespace chernobog::vm {
namespace {
std::string hex(uint64_t n) { std::ostringstream out; out << "0x" << std::hex << n; return out.str(); }
int canonical(int number, unsigned bits)
{
  if (number < 0 || (bits != 8 && bits != 16 && bits != 32 && bits != 64)) return -1;
  qstring name;
  if (get_reg_name(&name, number, bits/8) <= 0) return -1;
  if(bits==8)
  {
    if(name=="ah")return 0;if(name=="ch")return 1;
    if(name=="dh")return 2;if(name=="bh")return 3;
  }
  static const char *names[][4] = {
    {"al","ax","eax","rax"}, {"cl","cx","ecx","rcx"}, {"dl","dx","edx","rdx"}, {"bl","bx","ebx","rbx"},
    {"spl","sp","esp","rsp"}, {"bpl","bp","ebp","rbp"}, {"sil","si","esi","rsi"}, {"dil","di","edi","rdi"},
    {"r8b","r8w","r8d","r8"}, {"r9b","r9w","r9d","r9"}, {"r10b","r10w","r10d","r10"}, {"r11b","r11w","r11d","r11"},
    {"r12b","r12w","r12d","r12"}, {"r13b","r13w","r13d","r13"}, {"r14b","r14w","r14d","r14"}, {"r15b","r15w","r15d","r15"}};
  for (int reg = 0; reg < 16; ++reg) for (const auto *part : names[reg]) if (name == part) return reg;
  return -1;
}
Operand operand(const insn_t &i, const op_t &o, unsigned mode)
{
  Operand r; r.bits = unsigned(get_dtype_size(o.dtype) * 8);
  if (o.type == o_void) return {};
  if (o.type == o_reg)
  {
    r.kind = Kind::reg; r.reg = canonical(o.reg, r.bits);
    qstring name;
    if(r.bits==8 && get_reg_name(&name,o.reg,1)>0
        && (name=="ah" || name=="ch" || name=="dh" || name=="bh"))r.bit_offset=8;
  }
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
    case NN_retn:
      if(i.Op1.type==o_void && i.Op2.type==o_void && (mode==64?op64(i):op32(i)))
      {r.op=Op::near_return;r.stack_bits=mode;}
      break;
    case NN_jmp: case NN_jmpni:
      r.op = Op::jump;
      if(i.Op1.type==o_near)
      {r.op=Op::direct_jump;r.dst.kind=Kind::immediate;r.dst.bits=mode;r.dst.value=i.Op1.addr;}
      break;
    case NN_cmp:r.op=Op::compare;break;
    case NN_test:r.op=Op::test;break;
    case NN_stc:r.op=Op::carry_set;break;
    case NN_clc:r.op=Op::carry_clear;break;
    case NN_cmc:r.op=Op::carry_toggle;break;
    case NN_bsf:r.op=Op::scan_forward;break;
    default: break;
  }
  return r;
}
std::string bytes(const Candidate &c)
{
  std::string result; static const char digits[] = "0123456789abcdef";
  for(const auto &i:c.support)for(uint64_t ea=i.address;ea<i.address+i.size;++ea)
  { const auto byte = get_byte(ea_t(ea)); result += digits[byte >> 4]; result += digits[byte & 15]; }
  return result;
}
std::string spans(const Candidate &c)
{
  std::ostringstream out;
  for(const auto &i:c.support)out<<hex(i.address)<<":"<<i.size<<";";
  return out.str();
}
BoundaryNode boundary_node(uint64_t address,size_t incoming_budget)
{
  BoundaryNode node;node.address=address;
  const ea_t ea=ea_t(address);
  const auto *seg=getseg(ea);
  const auto *owner=get_func(ea);
  node.owner=owner?uint64_t(owner->start_ea):bad_address;
  const auto *chunk=get_fchunk(ea);
  node.shared_tail=chunk && (chunk->flags&FUNC_TAIL) && chunk->refqty>1;
  xrefblk_t xref;
  for(bool ok=xref.first_to(ea,XREF_CODE);ok;ok=xref.next_to())
  {
    if(node.incoming.size()==incoming_budget){node.incoming_complete=false;break;}
    node.incoming.push_back(uint64_t(xref.from));
  }
  if(!seg){node.rejection="unmapped_target";return node;}
  node.mode=seg->bitness==2?64:seg->bitness==1?32:16;
  if(!(seg->perm&SEGPERM_EXEC)){node.rejection="nonexecutable_target";return node;}
  if(!is_head(get_flags(ea)) || !is_code(get_flags(ea)))
  {node.rejection="missing_code_head";return node;}
  insn_t insn;
  if(decode_insn(&insn,ea)<=0){node.rejection="decode_failure";return node;}
  node.size=insn.size;
  if(!node.size || node.size>15 || address>=bad_address-node.size
      || address+node.size>seg->end_ea || get_item_end(ea)!=ea+node.size)
  {node.rejection="invalid_instruction_span";return node;}
  static const char digits[]="0123456789abcdef";
  for(unsigned offset=0;offset<node.size;++offset)
  {
    const auto *byte_owner=get_func(ea+offset);
    const uint64_t identity=byte_owner?uint64_t(byte_owner->start_ea):bad_address;
    if(!is_loaded(ea+offset)){node.rejection="unloaded_instruction_byte";return node;}
    if(identity!=node.owner || get_item_head(ea+offset)!=ea)
    {node.rejection="instruction_ownership_boundary";return node;}
    const unsigned byte=get_byte(ea+offset);
    node.bytes+=digits[byte>>4];node.bytes+=digits[byte&15];
  }
  // Deliberately exclude prefixed and non-native branch semantics. Native
  // linear instructions need no value/flag interpretation for this topology.
  if(insn.segpref || (insn.auxpref&(aux_lock|aux_rep|aux_repne)) || !natad(insn))
  {node.rejection="unsupported_prefix";return node;}
  const bool near=insn.Op1.type==o_near;
  if(near)node.target=uint64_t(to_ea(insn.cs,insn.Op1.addr));
  if(is_call_insn(insn))node.flow=BoundaryFlow::call;
  else if(is_ret_insn(insn))node.flow=BoundaryFlow::ret;
  else if(insn.itype==NN_jmp || insn.itype==NN_jmpshort || insn.itype==NN_jmpni)
    node.flow=near?BoundaryFlow::direct:BoundaryFlow::indirect;
  else if(insn_jcc(insn) || insn.itype==NN_jcxz || insn.itype==NN_jecxz
      || insn.itype==NN_jrcxz || insn.itype==NN_loop || insn.itype==NN_loopq
      || insn.itype==NN_loope || insn.itype==NN_loopqe
      || insn.itype==NN_loopne || insn.itype==NN_loopqne)
    node.flow=near?BoundaryFlow::conditional:BoundaryFlow::stop;
  else if(insn.itype==NN_int || insn.itype==NN_int3 || insn.itype==NN_into
      || insn.itype==NN_syscall || insn.itype==NN_sysenter || insn.itype==NN_sysexit
      || insn.itype==NN_sysret || insn.itype==NN_xbegin || insn.itype==NN_hlt
      || insn.itype==NN_ud2 || (insn.get_canon_feature(PH)&(CF_CALL|CF_JUMP|CF_STOP)))
    node.flow=BoundaryFlow::stop;
  else node.flow=BoundaryFlow::linear;
  return node;
}
void boundary_json(std::ostream &out,const BoundaryAudit &audit,bool available)
{
  using Row=std::map<std::string,std::string>;
  std::vector<Row> nodes,edges,frontiers;
  for(const auto &node:audit.nodes)
  {
    std::string incoming;
    for(uint64_t source:node.incoming){if(!incoming.empty())incoming+=';';incoming+=hex(source);}
    nodes.push_back({{"site",hex(node.address)},{"owner",node.owner==bad_address?"none":hex(node.owner)},
      {"size",std::to_string(node.size)},{"address_bits",std::to_string(node.mode)},
      {"bytes",node.bytes},{"flow",boundary_flow_name(node.flow)},
      {"target",node.target==bad_address?"unknown":hex(node.target)},{"rejection",node.rejection},
      {"shared_tail",node.shared_tail?"true":"false"},{"incoming",incoming},
      {"incoming_complete",node.incoming_complete?"true":"false"}});
  }
  for(const auto &edge:audit.edges)edges.push_back({{"source",hex(edge.from)},
    {"target",hex(edge.to)},{"kind",edge.fallthrough?"fallthrough":"decoded direct branch"}});
  for(const auto &frontier:audit.frontiers)frontiers.push_back({{"reason",frontier.reason},
    {"site",hex(frontier.site)},{"target",frontier.target==bad_address?"unknown":hex(frontier.target)}});
  out<<",\"boundary_audit\":{\"schema\":1,\"available\":"<<(available?"true":"false")
    <<",\"execution_admitted\":false,\"decoded_heads\":"<<audit.decoded
    <<",\"ownerless_heads\":"<<audit.ownerless<<",\"incoming_examined\":"<<audit.incoming_examined
    <<",\"entry_incoming\":"<<audit.entry_incoming
    <<",\"head_limit\":"<<(audit.head_limit?"true":"false")
    <<",\"incoming_limit\":"<<(audit.incoming_limit?"true":"false")
    <<",\"scope\":\"decoded native topology to first unmodeled transfer; IDB incoming code references; dynamic entries unknown\"";
  inspection_json_rows(out,"nodes",nodes);inspection_json_rows(out,"edges",edges);
  inspection_json_rows(out,"frontiers",frontiers);out<<'}';
}
} // namespace

bool decode_native_semantic_heads(const NativeRegion &region,unsigned mode,std::map<uint64_t,Instruction> &out)
{
  out.clear();
  if(!region.available() || (mode!=32 && mode!=64) || region.heads().size()>4096)return false;
  for(const auto &head:region.heads())
  {
    insn_t instruction;uint8_t data[15]={};
    if(decode_insn(&instruction,ea_t(head.address))<=0 || instruction.size!=head.bytes.size()
        || (mode==64?!mode64(instruction):!mode32(instruction)) || head.bytes.size()>sizeof(data)
        || get_bytes(data,head.bytes.size(),ea_t(head.address))!=ssize_t(head.bytes.size())
        || !std::equal(head.bytes.begin(),head.bytes.end(),data))
    {out.clear();return false;}
    out.emplace(head.address,decode(instruction,mode));
  }
  return true;
}

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
  std::map<uint64_t,Instruction> decoded_path_heads;
  std::set<std::pair<uint64_t,uint64_t>> recorded;
  size_t path_steps=0;bool path_truncated=false;
  size_t reachable_heads=0,reachability_edges=0,foreign_stops=0;
  bool reachability_truncated=false;
  auto record=[&](const Candidate &c)
  {
    if(!recorded.emplace(c.start,c.dispatch).second)return;
    if(rows.size()==64){++omitted;return;}
    if(include_summaries || source)candidates.push_back(c);
    const auto shape=normalized_shape(c);
    const auto group=shapes.emplace(shape,shapes.size()+1).first->second;
    rows.push_back({{"vm_candidate",hex(c.start)+":"+hex(c.dispatch)},
      {"site",hex(c.start)},{"end",hex(c.end)},{"read",hex(c.read)},{"dispatch",hex(c.dispatch)},
      {"truth","candidate"},{"fresh","true"},{"address_bits",std::to_string(mode)},
      {"read_bits",std::to_string(c.read_bits)},{"direction",c.direction==Direction::forward?"forward":"backward"},
      {"dispatch_kind",c.dispatch_kind==Dispatch::indexed_table?"indexed table":"relative register"},
      {"transfer_kind",c.stack_dispatch?"push/near-return":"indirect jump"},
      {"vip_register",std::to_string(c.vip)},{"value_register",std::to_string(c.value)},
      {"key_register",std::to_string(c.key)},{"dispatch_base_register",std::to_string(c.dispatch_base)},
      {"table_displacement",hex(c.table_displacement)},{"stack_key_update",c.stack_key_update?"true":"false"},
      {"bytes",bytes(c)},{"instruction_spans",spans(c)},{"shape_group",std::to_string(group)},{"normalized_shape",shape},
      {"classification","local read/decode/dispatch candidate; VM identity unverified"},
      {"ownership","selected function or ownerless code reached by existing xrefs; no VM execution region admitted"},
      {"unresolved","VM entry, virtual stack/context, memory contents, handler semantics, flags/exceptions and dispatch targets"},
      {"logical_state","native address plus VIP, decoder key when present, virtual stack, dispatch base, context and memory epoch"},
      {"summary_reuse","unproved; role-normalized syntax is indexing only"}});
  };
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
      decoded_path_heads.emplace(ea,i);
      const uint64_t previous = window.empty() ? bad_address : window.back().address;
      i.alternate_entry = !is_flow(get_flags(ea));
      xrefblk_t xref;size_t incoming=0;
      for (bool x = xref.first_to(ea, XREF_ALL); x; x = xref.next_to())
      {
        if(incoming==64){i.alternate_entry=true;truncated=true;break;}
        ++incoming;
        if (xref.iscode && xref.from != previous) { i.alternate_entry = true; break; }
      }
      if (!window.empty() && window.back().address + window.back().size != ea) window.clear();
      window.push_back(i);
      if (window.size() > 128) window.erase(window.begin());
      if (i.op != Op::jump && i.op != Op::near_return) continue;
      for (size_t start = 0; start + 2 < window.size(); ++start)
      {
        const auto candidate = recognize({window.begin() + start, window.end()}, mode);
        if (!candidate) continue;
        record(*candidate);
        break;
      }
      window.clear();
    }
    std::deque<uint64_t> pending{function};std::set<uint64_t> scheduled{function};
    while(!pending.empty())
    {
      const uint64_t ea=pending.front();pending.pop_front();++reachable_heads;
      const auto *actual=get_func(ea),*root=get_func(function);
      const auto *seg=getseg(ea);
      if(actual && (!root || actual->start_ea!=root->start_ea)){++foreign_stops;continue;}
      if(!seg || seg->bitness!=segment->bitness || !(seg->perm&SEGPERM_EXEC)
          || !is_code(get_flags(ea)) || !is_head(get_flags(ea)))continue;
      if(!decoded_path_heads.count(ea))
      {
        if(decoded_path_heads.size()==1024){reachability_truncated=true;break;}
        insn_t instruction;if(decode_insn(&instruction,ea)<=0)continue;
        bool loaded=ea+instruction.size<=seg->end_ea;
        for(unsigned i=0;i<instruction.size;++i)if(!is_loaded(ea+i))loaded=false;
        if(!loaded)continue;
        decoded_path_heads.emplace(ea,decode(instruction,mode));
      }
      xrefblk_t xref;
      for(bool x=xref.first_from(ea,XREF_ALL);x;x=xref.next_from())
      {
        if(reachability_edges++==4096){reachability_truncated=true;break;}
        const int type=int(xref.type)&XREF_MASK;
        if(!xref.iscode || (type!=fl_F && type!=fl_JN))continue;
        if(scheduled.count(xref.to))continue;
        if(scheduled.size()==1024){reachability_truncated=true;break;}
        scheduled.insert(xref.to);pending.push_back(xref.to);
      }
      if(reachability_truncated)break;
    }
    // Follow only current same-owner fallthrough/direct-jump links. No new
    // instructions, xrefs or function ownership are manufactured by inspection.
    for(const auto &head:decoded_path_heads)
    {
      if(rows.size()==64)break;
      const auto &first=head.second;
      if(!((first.op==Op::load && first.src.kind==Kind::memory)
          || (first.op==Op::sub && first.dst.kind==Kind::reg && first.src.kind==Kind::immediate
              && (first.src.value==1 || first.src.value==4))))continue;
      std::vector<Instruction> path;std::set<uint64_t> seen;
      uint64_t at=head.first;
      while(path.size()<128)
      {
        if(path_steps==8192){path_truncated=true;break;}
        ++path_steps;
        const auto found=decoded_path_heads.find(at);
        if(found==decoded_path_heads.end() || !seen.insert(at).second)break;
        auto current=found->second;
        if(current.op==Op::unsupported)break;
        if(!path.empty())
        {
          bool linked=false;current.alternate_entry=false;xrefblk_t xref;size_t incoming=0;
          for(bool x=xref.first_to(at,XREF_ALL);x;x=xref.next_to())
          {
            if(incoming++==64){current.alternate_entry=true;path_truncated=true;break;}
            if(xref.iscode)
            {
              if(xref.from==path.back().address)linked=true;
              else current.alternate_entry=true;
            }
          }
          if(!linked || current.alternate_entry)break;
        }
        path.push_back(current);
        if(current.op==Op::jump || current.op==Op::near_return)
        {
          if(const auto candidate=recognize(path,mode))record(*candidate);
          break;
        }
        at=current.op==Op::direct_jump?current.dst.value:current.address+current.size;
      }
      if(path.size()==128 && path.back().op!=Op::jump && path.back().op!=Op::near_return)path_truncated=true;
      if(path_truncated)break;
    }
  }
  std::ostringstream out;
  out << "{\"schema\":1,\"available\":" << (available ? "true" : "false")
      << ",\"database\":" << inspection_json_quote(std::to_string(int64_t(get_dbctx_id())))
      << ",\"function\":" << inspection_json_quote(hex(function)) << ",\"instructions\":" << visited
      << ",\"truncated\":" << (truncated ? "true" : "false") << ",\"omitted\":" << omitted;
  out<<",\"path_steps\":"<<path_steps<<",\"path_scan_truncated\":"<<(path_truncated?"true":"false");
  out<<",\"reachable_heads\":"<<reachable_heads<<",\"foreign_function_stops\":"<<foreign_stops
      <<",\"reachability_truncated\":"<<(reachability_truncated?"true":"false");
  inspection_json_rows(out, "records", rows);
  boundary_json(out,available?audit_boundaries(function,mode,boundary_node):BoundaryAudit{},available);
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
