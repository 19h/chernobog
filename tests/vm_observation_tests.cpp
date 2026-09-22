#include "vm_test_candidates.hpp"
#include "vm/observations.hpp"
#include "hybrid/evidence.hpp"
#include <algorithm>
#include <iostream>
#include <set>
#include <stdexcept>
using namespace chernobog;
namespace {
unsigned checks=0;
void check(bool condition,const char *name)
{++checks;if(!condition)throw std::runtime_error(name);}
hybrid::StatePoint state(const vm::Candidate &c,uint64_t seq,uint64_t vip)
{
  hybrid::StatePoint s;s.pc=c.start;s.source=0x800;s.sequence=seq;s.run_id=1;s.seed=9;
  for(int i=0;i<(c.address_bits==64?16:8);++i)
    s.regs.push_back({c.address_bits==64?RAX_X86_GPR64(i):RAX_X86_GPR32(i),i==c.vip?vip:uint64_t(i),uint8_t(c.address_bits/8)});
  s.regs.push_back({c.address_bits==64?RAX_X86_REG_RFLAGS:RAX_X86_REG_EFLAGS,0x202,uint8_t(c.address_bits/8)});
  return s;
}
hybrid::TargetEvidence fixture(const vm::Candidate &c)
{
  hybrid::TargetEvidence e;e.architecture=c.address_bits==64?hybrid::HybridArch::X86_64:hybrid::HybridArch::X86_32;
  e.scope.function_start=0x800;e.scope.generation=17;
  hybrid::RunObservation r;r.ran=true;r.provenance=e.scope;r.provenance.run_id=1;r.provenance.seed=9;
  e.runs.push_back(r);
  for(unsigned visit=0;visit<3;++visit)
  {
    const uint64_t sequence=10+visit*100;
    auto s=state(c,sequence,0x2000+visit);e.events.states.push_back(s);
    for(size_t j=0;j<c.support.size();++j)e.events.execution.push_back({c.support[j].address,c.support[j].size,sequence+j*2,1,9});
    s.source=c.dispatch;s.pc=0x1800;s.sequence=sequence+50;
    for(auto &reg:s.regs)if(reg.reg==RAX_X86_GPR64(c.vip) || reg.reg==RAX_X86_GPR32(c.vip))++reg.value;
    e.events.states.push_back(s);
    e.events.data.push_back({c.read,0x2000+visit,0x25,1,RAX_MEM_READ,hybrid::DataScope::IMAGE,sequence+1,1,9});
  }
  return e;
}
vm::ObservationView project(const vm::Candidate &c,const hybrid::TargetEvidence &e)
{return vm::project_observations({c},e,0x800,12,true);}
}
int main()
{
  try
  {
    {
      const auto c=vm_test::path_candidate(64,true);auto e=fixture(c);
      auto v=project(c,e);check(v.records.size()==3,"discontiguous observations retained");
      check(v.records.front().at("path")=="sampled local address/size path","ordered discontiguous support observed");
      e.events.data.push_back({0x900,c.support.back().address,0,1,RAX_MEM_WRITE,hybrid::DataScope::IMAGE,5,1,9});
      v=project(c,e);
      check(v.records.front().at("runtime_code_identity").find("recorded write overlaps")!=std::string::npos,"write to lower-address path segment invalidates code identity");
      e.events.data.back().addr=0x7800;
      v=project(c,e);
      check(v.records.front().at("runtime_code_identity").find("recorded write overlaps")==std::string::npos,"unvisited address gap is not candidate code");
    }
    for(unsigned mode:{32u,64u})
    {
      const auto c=vm_test::candidate(mode,false,false,true);auto e=fixture(c);auto v=project(c,e);
      check(v.available && v.records.size()==3,"three visits");
      std::set<std::string> ids,vips;
      for(const auto &r:v.records)
      {
        ids.insert(r.at("vm_state"));vips.insert(r.at("entry_vip"));
        check(r.at("path")=="sampled local address/size path","native path association");
        check(r.at("virtual_stack")=="unknown" && r.at("vm_context")=="unknown" && r.at("memory_epoch")=="unknown","unknown roles retained");
        check(r.at("merge")=="not admitted" && r.at("semantic_validation")=="not performed","no promotion");
        check(r.at("access_0_value_low64")=="0x25" && r.at("data_capture_complete")=="false","bounded memory observations");
      }
      check(ids.size()==3 && vips.size()==3,"same native address distinct states");
      std::reverse(e.events.states.begin(),e.events.states.end());std::reverse(e.events.execution.begin(),e.events.execution.end());
      check(project(c,e).records==v.records,"input normalization independent");e=fixture(c);
      check(!vm::project_observations({c},e,0x800,0,true).available,"zero publication");
      check(!vm::project_observations({c},e,0x800,12,false).available,"stale capture");
      check(!vm::project_observations({c},e,0x801,12,true).available,"foreign function");
      e.events.states[0].regs.clear();check(project(c,e).records[0].at("entry_vip").find("unknown")==0,"missing register");e=fixture(c);
      auto bad=e.events.states[0].regs[size_t(c.vip)];++bad.value;e.events.states[0].regs.push_back(bad);
      check(project(c,e).records[0].at("entry_vip").find("conflicting")!=std::string::npos,"conflicting register");e=fixture(c);
      e.events.states[0].regs[size_t(c.vip)].width=2;
      check(project(c,e).records[0].at("entry_vip").find("unknown")==0,"wrong register width");e=fixture(c);
      e.events.execution.erase(e.events.execution.begin()+1);
      check(project(c,e).records[0].at("path").find("unresolved")==0,"missing instruction");e=fixture(c);
      ++e.events.execution[0].size;check(project(c,e).records[0].at("path").find("unresolved")==0,"wrong instruction size");e=fixture(c);
      e.events.execution.push_back(e.events.execution[0]);check(project(c,e).records[0].at("path").find("unresolved")==0,"extra execution record");e=fixture(c);
      e.events.execution[1].sequence=e.events.execution[0].sequence;
      check(project(c,e).records[0].at("path").find("unresolved")==0,"duplicate instruction sequence");e=fixture(c);
      e.events.states[1].source=0x900;check(project(c,e).records[0].at("path").find("unresolved")==0,"intervening transfer");e=fixture(c);
      e.events.states.push_back(e.events.states[0]);v=project(c,e);
      check(v.records.size()==4 && v.records[0].at("path").find("duplicate")!=std::string::npos,"ambiguous sequence");e=fixture(c);
      e.runs.push_back(e.runs[0]);check(project(c,e).records[0].at("path").find("unresolved")==0,"ambiguous run");e=fixture(c);
      e.runs[0].provenance.generation=18;check(project(c,e).records[0].at("run_provenance")!="matched","foreign generation");e=fixture(c);
      e.runs[0].provenance.ticket=999;check(project(c,e).records[0].at("run_provenance")!="matched","foreign ticket");e=fixture(c);
      e.runs[0].provenance.function_hash=999;check(project(c,e).records[0].at("run_provenance")!="matched","foreign function bytes");e=fixture(c);
      e.events.data.push_back({0x900,c.start,0x90,1,RAX_MEM_WRITE,hybrid::DataScope::IMAGE,1,1,9});
      check(project(c,e).records[0].at("runtime_code_identity").find("recorded write")==0,"prior code write");e=fixture(c);
      e.runs[0].outcome.function_boundary=true;e.runs[0].outcome.function_boundary_source=c.dispatch;e.runs[0].outcome.function_boundary_target=0x1800;
      v=project(c,e);check(v.records[2].at("exit").find("function-boundary")==0 && v.records[0].at("exit")=="sampled transfer target","boundary only final transfer");
      e=fixture(c);for(unsigned i=0;i<20;++i)e.events.data.push_back({c.read,0x3000+i,i,1,RAX_MEM_READ,hybrid::DataScope::IMAGE,11+i,1,9});
      v=project(c,e);check(v.records[0].at("accesses_captured")=="21" && v.records[0].at("accesses_omitted")=="5","exact access omissions");
      e=fixture(c);const auto sample=e.events.states[0];e.events.states.clear();for(unsigned i=0;i<140;++i){auto s=sample;s.sequence=i;e.events.states.push_back(s);}
      v=project(c,e);check(v.records.size()==128 && v.omitted==12,"exact state omissions");
      e=fixture(c);e.events.execution.resize(262144);check(!project(c,e).available,"input work budget");
      e=fixture(c);check(!vm::project_observations({c,c},e,0x800,12,true).available,"duplicate candidates");
      auto unchecked=vm::project_observations({c},e,0x800,12,true,true);
      check(unchecked.transition_attempts==0 && unchecked.queries==0
          && unchecked.records[0].at("transition_reason")=="complete direct data trace required","incomplete trace does not reach solver");
      e.runs[0].outcome.data_trace_complete=true;
      e.events.data.push_back({0x900,c.start,0x90,1,RAX_MEM_WRITE,hybrid::DataScope::IMAGE,1,1,9});
      unchecked=vm::project_observations({c},e,0x800,12,true,true);
      check(unchecked.transition_attempts==0 && unchecked.queries==0
          && unchecked.records[0].at("transition_reason")=="recorded candidate code write","code writes veto transition checks");
      e=fixture(c);auto many=e;e.runs.clear();e.events={};
      for(uint32_t run=1;run<=7;++run)
      {
        auto r=many.runs[0];r.provenance.run_id=run;r.outcome.data_trace_complete=true;e.runs.push_back(r);
        for(auto s:many.events.states){s.run_id=run;e.events.states.push_back(s);}
        for(auto x:many.events.execution){x.run_id=run;e.events.execution.push_back(x);}
        for(auto d:many.events.data){d.run_id=run;e.events.data.push_back(d);}
      }
      unchecked=vm::project_observations({c},e,0x800,12,true,true);
      check(unchecked.transition_attempts==16 && unchecked.records.size()==21
          && unchecked.records.back().at("transition_reason")=="transition attempt budget exhausted","transition attempt quota");
      e=fixture(c);
      e.events.states[0].regs.resize(65);check(!project(c,e).available,"register work budget");e=fixture(c);
      e.architecture=hybrid::HybridArch::UNSUPPORTED;check(!project(c,e).available,"unsupported architecture");
      if(mode==32)
      {
        e=fixture(c);e.events.states[0].regs[size_t(c.vip)].value=UINT64_C(1)<<32;
        check(project(c,e).records[0].at("entry_vip").find("unknown")==0,"noncanonical 32-bit value");
      }
    }
    std::cout<<checks<<" VM observation checks passed\n";
  }
  catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
}
