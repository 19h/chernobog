#include "transition.hpp"
#include "semantics.hpp"
#include "../common/solver_evidence.hpp"
#include <algorithm>
#include <map>

namespace chernobog::vm {
namespace {
std::optional<uint64_t> register_value(const hybrid::StatePoint &s,int id,unsigned mode)
{
  std::optional<uint64_t> value;
  for(const auto &r:s.regs)if(r.reg==id)
  {
    if(r.width!=mode/8 || (mode==32 && r.value>UINT32_MAX) || (value && *value!=r.value))return {};
    value=r.value;
  }
  return value;
}
}
const char *transition_result_name(TransitionResult r)
{
  switch(r)
  {
    case TransitionResult::corroborated:return "corroborated for captured transition";
    case TransitionResult::different:return "modeled transition counterexample";
    case TransitionResult::inconsistent:return "inconsistent captured inputs";
    case TransitionResult::unknown:return "solver unresolved";
    case TransitionResult::unsupported:return "transition not checked";
  }
  return "transition not checked";
}
TransitionCheck check_transition(const Candidate &candidate,const hybrid::StatePoint &entry,
    const hybrid::StatePoint &output,const std::vector<hybrid::DataAcc> &data,
    unsigned timeout,unsigned resource)
{
  using Result=TransitionResult;
  TransitionCheck answer;
  auto reject=[&](Result result,const std::string &reason){answer.result=result;answer.reason=reason;return answer;};
  if(entry.regs.size()>64 || output.regs.size()>64 || data.size()>64)
    return reject(Result::unsupported,"transition input budget exceeded");
  if(entry.run_id!=output.run_id || entry.seed!=output.seed || entry.sequence>=output.sequence
      || (entry.kind!=hybrid::StatePoint::Kind::TransferTarget
          && entry.kind!=hybrid::StatePoint::Kind::NativeInstructionEntry)
      || output.kind!=hybrid::StatePoint::Kind::TransferTarget)
    return reject(Result::unsupported,"entry/output identity or order differs");
  try
  {
    z3::context ctx;const auto summary=summarize(ctx,candidate);
    if(!summary)return reject(Result::unsupported,"candidate has no complete local model");
    const auto &c=summary->candidate;const unsigned mode=c.address_bits;
    if(entry.pc!=c.start || output.source!=c.dispatch)
      return reject(Result::unsupported,"entry/output does not bound the candidate");
    if(data.size()!=summary->accesses.size())return reject(Result::different,"ordered access count differs");
    const uint64_t address_mask=mode==32?UINT32_MAX:UINT64_MAX;
    if(output.pc>address_mask)return reject(Result::unsupported,"target exceeds address width");
    z3::solver solver(ctx);z3::params params(ctx);
    params.set("timeout",std::max(1u,timeout));params.set("rlimit",std::max(1u,resource));solver.set(params);
    const auto settings="timeout_ms="+std::to_string(std::max(1u,timeout))+";rlimit="+std::to_string(std::max(1u,resource));
    auto mismatch=summary->next_pc!=ctx.bv_val(output.pc,mode);
    for(size_t i=0;i<summary->roles.size();++i)
    {
      const int id=mode==64?RAX_X86_GPR64(i):RAX_X86_GPR32(i);
      const auto before=register_value(entry,id,mode),after=register_value(output,id,mode);
      if(!before || !after)return reject(Result::unsupported,"missing/conflicting GPR value or width");
      solver.add(ctx.bv_const(("input_"+summary->roles[i]).c_str(),mode)==ctx.bv_val(*before,mode));
      mismatch=mismatch || summary->registers[i]!=ctx.bv_val(*after,mode);
    }
    const int flags_id=mode==64?RAX_X86_REG_RFLAGS:RAX_X86_REG_EFLAGS;
    const auto before_flags=register_value(entry,flags_id,mode),after_flags=register_value(output,flags_id,mode);
    if(!before_flags || !after_flags)return reject(Result::unsupported,"missing/conflicting flags value or width");
    static constexpr unsigned positions[]={0,2,4,6,7,11};
    for(unsigned i=0;i<6;++i)
    {
      solver.add(ctx.bool_const(("input_flag_"+std::to_string(i)).c_str())==ctx.bool_val(((*before_flags>>positions[i])&1)!=0));
      if(summary->defined[i])mismatch=mismatch || summary->flags[i]!=ctx.bool_val(((*after_flags>>positions[i])&1)!=0);
    }
    const auto memory=ctx.constant("input_memory",ctx.array_sort(ctx.bv_sort(mode),ctx.bv_sort(8)));
    std::map<uint64_t,uint8_t> writes;
    uint64_t previous=entry.sequence;
    for(size_t i=0;i<data.size();++i)
    {
      const auto &a=data[i];const auto &effect=summary->accesses[i];
      if(a.run_id!=entry.run_id || a.seed!=entry.seed || a.sequence<=previous || a.sequence>=output.sequence
          || a.addr>address_mask || a.size==0 || a.size>8 || (a.kind!=RAX_MEM_READ && a.kind!=RAX_MEM_WRITE))
        return reject(Result::unsupported,"access identity, order, width or kind unsupported");
      previous=a.sequence;
      if(a.from!=effect.site || a.size*8!=effect.bits || (a.kind==RAX_MEM_WRITE)!=effect.write)
        return reject(Result::different,"ordered access source/kind/width differs");
      for(unsigned j=0;j<a.size;++j)
      {
        const uint64_t address=(a.addr+j)&address_mask;const auto byte=uint8_t(a.value>>(8*j));
        if(a.kind==RAX_MEM_WRITE)writes[address]=byte;
        else if(const auto found=writes.find(address);found!=writes.end())
        {
          if(found->second!=byte)return reject(Result::inconsistent,"read disagrees with earlier observed write");
        }
        else solver.add(z3::select(memory,ctx.bv_val(address,mode))==ctx.bv_val(byte,8));
      }
      mismatch=mismatch || effect.address!=ctx.bv_val(a.addr,mode) || effect.value!=ctx.bv_val(a.value,effect.bits);
    }
    ++answer.queries;
    const auto consistency=solver_evidence::check(solver,"VM observed input consistency",settings.c_str());
    if(consistency==z3::unsat)return reject(Result::inconsistent,"UNSAT: captured initial reads conflict");
    if(consistency==z3::unknown)return reject(Result::unknown,solver.reason_unknown().substr(0,512));
    solver.add(mismatch);++answer.queries;
    const auto result=solver_evidence::check(solver,"VM observed output mismatch",settings.c_str());
    if(result==z3::unsat)return reject(Result::corroborated,"SAT inputs then UNSAT mismatch: all GPRs, defined arithmetic flags, dispatch and ordered accesses agree under the local model");
    if(result==z3::sat)return reject(Result::different,"SAT: modeled outputs or accesses can disagree under captured initial reads");
    return reject(Result::unknown,solver.reason_unknown().substr(0,512));
  }
  catch(const z3::exception &){return reject(Result::unknown,"solver exception");}
}
}
