#include "summary_view.hpp"
#include "semantics.hpp"
#include "../common/solver_evidence.hpp"
#include <sstream>

namespace chernobog::vm {
namespace {
std::string hex(uint64_t n){std::ostringstream out;out<<"0x"<<std::hex<<n;return out.str();}
std::string id(const Candidate &c){return hex(c.start)+":"+hex(c.dispatch);}
bool printable(const z3::expr &e,size_t &visits,unsigned depth=0)
{
  if(++visits>512 || depth>64 || !e.is_app())return false;
  for(unsigned i=0;i<e.num_args();++i)if(!printable(e.arg(i),visits,depth+1))return false;
  return true;
}
SummaryRow describe(const Summary &s,size_t reference)
{
  SummaryRow row{{"summary_id",std::to_string(reference)},{"vm_candidate",id(s.candidate)},
    {"site",hex(s.candidate.start)},{"address_bits",std::to_string(s.candidate.address_bits)},
    {"contract","normal completion; unchanged instruction stream; valid flat little-endian memory accesses; no concurrency, device, segment-base or exception effects"},
    {"frame","all architectural GPRs compared under a bijective role map; all unmodified roles preserved"},
    {"memory","ordered data reads/writes and final byte-addressed array; arbitrary data aliasing retained"},
    {"transition","one local dispatch; target execution and VM-region ownership not admitted"},
    {"flags","final CF/PF/AF/ZF/SF/OF; architecturally undefined outputs excluded only when both contracts agree"}};
  if(s.candidate.stack_dispatch)
    row["contract"] += "; near-return stack width equals address width; CET shadow stack disabled";
  size_t payload=0,omitted=0;
  for(const auto &field:row)payload+=field.first.size()+field.second.size();
  auto expression=[&](const std::string &name,const z3::expr &value)
  {
    size_t visits=0;
    // Reserve 1 KiB for the small access/flag metadata added below. The
    // expression accounting includes both field names and completeness text.
    if(!printable(value,visits) || payload+name.size()*2+2080>31744){++omitted;return;}
    const auto text=value.to_string();
    const auto retained=text.substr(0,2048);
    row[name]=retained;row[name+"_complete"]=text.size()<=2048?"true":"false";
    payload+=name.size()*2+retained.size()+20;
  };
  for(size_t i=0;i<s.roles.size();++i)
    if(s.roles[i].find("preserved_")!=0)expression("out_"+s.roles[i],s.registers[i]);
  expression("next_pc",s.next_pc);
  static const char *names[]={"CF","PF","AF","ZF","SF","OF"};
  for(unsigned i=0;i<6;++i)
    if(s.defined[i])expression(std::string("flag_")+names[i],s.flags[i]);
    else row[std::string("flag_")+names[i]]="undefined";
  row["accesses"]=std::to_string(s.accesses.size());
  for(size_t i=0;i<s.accesses.size();++i)
  {
    const auto prefix="access_"+std::to_string(i);
    row[prefix+"_kind"]=s.accesses[i].write?"write":"read";
    row[prefix+"_bits"]=std::to_string(s.accesses[i].bits);
    expression(prefix+"_address",s.accesses[i].address);
    expression(prefix+"_value",s.accesses[i].value);
  }
  row["expressions_omitted"]=std::to_string(omitted);return row;
}
}

SummaryView project_summaries(const std::vector<Candidate> &candidates,int64_t database,uint64_t function)
{
  SummaryView view;z3::context ctx;
  std::vector<std::unique_ptr<Summary>> references;
  for(size_t index=0;index<candidates.size();++index)
  {
    if(index==16){view.omitted=candidates.size()-index;break;}
    const auto &c=candidates[index];
    SummaryRow binding{{"vm_candidate",id(c)},{"site",hex(c.start)}};
    auto summary=summarize(ctx,c);
    if(!summary)
    {binding["status"]="unsupported; no summary";view.bindings.push_back(std::move(binding));continue;}
    size_t match=references.size();std::string reason="new modeled-effect reference; no reuse";
    for(size_t i=0;i<references.size() && view.queries<32;++i)
    {
      const auto &r=references[i]->candidate;
      if(r.address_bits!=c.address_bits || (r.key>=0)!=(c.key>=0)
          || (r.dispatch_base>=0)!=(c.dispatch_base>=0))continue;
      solver_evidence::Scope scope({database,function,c.start,-1,"vm-local-summary"});
      // This is a comparison-attempt budget; contract-incompatible pairs can
      // return before invoking Z3. The API does not overstate actual SMT checks.
      ++view.queries;
      const auto comparison=compare(*summary,*references[i]);
      if(comparison.result==Equivalence::equivalent){match=i;reason=comparison.reason;break;}
      reason="new reference; prior comparison: "+comparison.reason;
    }
    if(match==references.size())
    {
      if(view.queries==32)reason="new reference; comparison budget exhausted; no reuse";
      view.references.push_back(describe(*summary,references.size()+1));
      references.push_back(std::move(summary));
      binding["status"]="reference";
    }
    else binding["status"]="reused after UNSAT";
    binding["summary_id"]=std::to_string(match+1);
    binding["reference_candidate"]=id(references[match]->candidate);
    binding["reason"]=reason;
    std::string mapping;
    const auto &roles_for_binding=summary?summary->roles:references[match]->roles;
    for(size_t reg=0;reg<roles_for_binding.size();++reg)
      if(roles_for_binding[reg].find("preserved_")!=0)
        mapping+=roles_for_binding[reg]+"=GPR"+std::to_string(reg)+";";
    binding["register_map"]=mapping;
    view.bindings.push_back(std::move(binding));
  }
  return view;
}
} // namespace chernobog::vm
