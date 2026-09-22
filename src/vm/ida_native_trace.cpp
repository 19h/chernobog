#include "ida_native_trace.hpp"
#include "native_region.hpp"
#include "native_observations.hpp"
#include "ida_regions.hpp"
#include "../hybrid/emu_driver.hpp"
#include "../common/inspection_json.hpp"
#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <funcs.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <ua.hpp>
#include <parsejson.hpp>
#include "../common/warn_on.h"
#include <atomic>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace chernobog::vm {
namespace {
std::string hex(uint64_t value){std::ostringstream out;out<<"0x"<<std::hex<<value;return out.str();}
std::string bytes(const std::vector<uint8_t> &data)
{
  static const char digits[]="0123456789abcdef";std::string text;
  for(uint8_t byte:data){text+=digits[byte>>4];text+=digits[byte&15];}return text;
}
std::string unavailable(const char *reason)
{
  return "{\"schema\":1,\"available\":false,\"scope\":\"native-region\",\"reason\":"
      +inspection_json_quote(reason)+"}";
}
bool keys(const jobj_t &object,std::initializer_list<const char *> required)
{
  if(object.size()!=required.size())return false;
  std::set<std::string> seen;
  for(const auto &kv:object)
  {
    if(!seen.insert(kv.key.c_str()).second)return false;
    if(std::none_of(required.begin(),required.end(),[&](const char *key){return kv.key==key;}))return false;
  }
  return true;
}
int digit(char c)
{
  if(c>='0' && c<='9')return c-'0';
  if(c>='a' && c<='f')return c-'a'+10;
  if(c>='A' && c<='F')return c-'A'+10;
  return -1;
}
bool parse_input(const std::string &request,hybrid::EmuInput &input)
{
  // Bound bytes and nesting before invoking the SDK parser. Never return parser
  // diagnostics containing input material or paths to the UI.
  if(request.empty() || request.size()>140000 || request.find('\0')!=std::string::npos)return false;
  unsigned depth=0;bool quoted=false,escaped=false;
  for(char c:request)
  {
    if(quoted)
    {if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;continue;}
    if(c=='"')quoted=true;
    else if(c=='[' || c=='{'){if(++depth>8)return false;}
    else if(c==']' || c=='}'){if(!depth)return false;--depth;}
  }
  if(depth || quoted)return false;
  jvalue_t root;
  if(parse_json_string(&root,request.c_str())!=eOk || root.type()!=JT_OBJ
      || !keys(root.obj(),{"args","objects"}))return false;
  const auto *args=root.obj().get_value("args",JT_ARR);
  const auto *objects=root.obj().get_value("objects",JT_ARR);
  if(!args || !objects || args->arr().values.size()>32 || objects->arr().values.size()>16)return false;
  for(const auto &arg:args->arr().values)
  {
    if(arg.type()!=JT_STR)return false;
    const auto &s=arg.qstr();
    if(s.length()<3 || s.length()>18 || s[0]!='0' || s[1]!='x')return false;
    uint64_t value=0;
    for(size_t i=2;i<s.length();++i)
    {const int d=digit(s[i]);if(d<0)return false;value=(value<<4)|unsigned(d);}
    input.args.push_back(value);
  }
  size_t total=0;std::set<uint32_t> used;
  for(const auto &object:objects->arr().values)
  {
    if(object.type()!=JT_OBJ || !keys(object.obj(),{"argument","offset","bytes"}))return false;
    const auto *arg=object.obj().get_value("argument",JT_NUM);
    const auto *offset=object.obj().get_value("offset",JT_NUM);
    const auto *data=object.obj().get_value("bytes",JT_STR);
    if(!arg || !offset || !data || arg->num()<0 || arg->num()>=int64_t(input.args.size())
        || offset->num()<0 || offset->num()>4095)return false;
    hybrid::EmuInput::NativeObject value;
    value.argument=uint32_t(arg->num());value.offset=uint32_t(offset->num());
    const auto &s=data->qstr();
    if(s.empty() || s.length()>8192 || s.length()%2 || value.offset>=s.length()/2
        || input.args[value.argument]!=0 || !used.insert(value.argument).second)return false;
    for(size_t i=0;i<s.length();i+=2)
    {const int hi=digit(s[i]),lo=digit(s[i+1]);if(hi<0 || lo<0)return false;value.bytes.push_back(uint8_t(hi*16+lo));}
    total+=value.bytes.size();if(total>65536)return false;
    input.native_objects.push_back(std::move(value));
  }
  return true;
}
bool decode_native(uint64_t ea,const uint8_t *expected,size_t offered,rax_decoded &out,unsigned mode)
{
  insn_t insn;
  if(decode_insn(&insn,ea_t(ea))<=0 || !insn.size || insn.size>offered
      || (mode==64?!mode64(insn):!mode32(insn)))return false;
  uint8_t actual[15]={};
  if(insn.size>sizeof(actual) || get_bytes(actual,insn.size,ea_t(ea))!=insn.size
      || !std::equal(actual,actual+insn.size,expected))return false;
  // Segment/privilege transitions are outside the flat user-mode snapshot.
  if(insn.Op1.type==o_far || insn.itype==NN_callfi || insn.itype==NN_jmpfi
      || insn.itype==NN_retf || insn.itype==NN_retfw || insn.itype==NN_retfd || insn.itype==NN_retfq
      || insn.itype==NN_iret || insn.itype==NN_iretw || insn.itype==NN_iretd || insn.itype==NN_iretq)
    return false;
  // The 16-bit BSWAP encoding has undefined architectural results. The native
  // capture contract does not choose the emulator's result as hardware truth.
  if(insn.itype==NN_bswap && get_dtype_size(insn.Op1.dtype)!=4 && get_dtype_size(insn.Op1.dtype)!=8)
    return false;
  out={};out.valid=1;out.size=insn.size;out.flow=RAX_FLOW_FALLTHROUGH;
  const bool near=insn.Op1.type==o_near;
  if(near){out.has_target=1;out.target=to_ea(insn.cs,insn.Op1.addr);}
  if(is_call_insn(insn)){out.flow=near?RAX_FLOW_CALL:RAX_FLOW_INDIRECT_CALL;out.is_indirect=!near;}
  else if(is_ret_insn(insn))out.flow=RAX_FLOW_RETURN;
  else if(insn.itype==NN_jmp || insn.itype==NN_jmpshort || insn.itype==NN_jmpni)
  {out.flow=near?RAX_FLOW_BRANCH:RAX_FLOW_INDIRECT_JUMP;out.is_indirect=!near;}
  else if(insn_jcc(insn) || insn.itype==NN_jcxz || insn.itype==NN_jecxz
      || insn.itype==NN_jrcxz || insn.itype==NN_loop || insn.itype==NN_loopq
      || insn.itype==NN_loope || insn.itype==NN_loopqe || insn.itype==NN_loopne || insn.itype==NN_loopqne)
  {out.flow=near?RAX_FLOW_COND_BRANCH:RAX_FLOW_UNKNOWN;out.fallthrough=ea+insn.size;}
  else if(insn.itype==NN_int || insn.itype==NN_int3 || insn.itype==NN_into
      || insn.itype==NN_syscall || insn.itype==NN_sysenter || insn.itype==NN_sysexit
      || insn.itype==NN_sysret || insn.itype==NN_xbegin || insn.itype==NN_hlt || insn.itype==NN_ud2
      || (insn.get_canon_feature(PH)&(CF_CALL|CF_JUMP|CF_STOP)))out.flow=RAX_FLOW_TRAP;
  return true;
}
}
static std::string trace_native_region_impl(uint64_t function,uint64_t seed,const hybrid::EmuInput *explicit_input,
    bool walk=false,bool check=false)
{
  using namespace hybrid;
  const auto *api=rax_load();
  if(!api || !api->decode)return unavailable("native decoder/emulator unavailable");
  const auto *owner=get_func(ea_t(function));
  if(!owner || owner->start_ea!=function)return unavailable("selected function unavailable");
  HybridConfig config;
  config.max_image_bytes=64ull*1024*1024;
  config.max_insns=4096;config.timeout_ms=250;
  config.want_runtime_strings=false;config.want_import_summaries=false;
  config.max_runtime_bytes=65536;
  ProgramImage image;
  const auto snapshot=hybrid_snapshot_function(image,config,function);
  if(!snapshot.complete)return unavailable("incomplete or unsupported image snapshot");
  const unsigned mode=image.arch==HybridArch::X86_64?64:32;
  if(explicit_input && mode==32 && std::any_of(explicit_input->args.begin(),explicit_input->args.end(),
      [](uint64_t value){return value>UINT32_MAX;}))return unavailable("argument exceeds architecture width");
  const NativeDecoder decoder=[mode](uint64_t ea,const uint8_t *data,size_t size,rax_decoded &decoded)
      {return decode_native(ea,data,size,decoded,mode);};
  auto region=plan_native_region(image,api,function,4096,decoder);
  if(!region.available())return unavailable("entry has no admissible native instruction");
  EmuDriver driver(api,image,true,inf_get_filetype()==f_PE);
  EmuInput input=explicit_input?*explicit_input:EmuInput{};input.seed=seed;input.run_id=1;
  EmuEvents events;EmuOutcome outcome;
  const uint64_t initial_identity=region.identity();
  const bool ran=walk?driver.emulate_region_walk(region,config,events,outcome,decoder,64,&input,check)
      :driver.emulate_region(region,config,events,outcome,&input);
  static std::atomic<uint64_t> next_capture{1};
  uint64_t capture=next_capture.load();
  while(capture!=UINT64_MAX && !next_capture.compare_exchange_weak(capture,capture+1)){}
  if(capture==UINT64_MAX)return unavailable("capture identity exhausted");
  NativeObservationView observations;
  if(check && ran)
  {
    std::map<uint64_t,Instruction> instructions;
    if(!decode_native_semantic_heads(region,mode,instructions))
      observations.reason="semantic decode no longer matches native plan bytes/mode";
    else observations=project_native_observations(region,instructions,events,outcome,mode,capture,function,true,int64_t(get_dbctx_id()));
  }
  using Row=std::map<std::string,std::string>;
  std::vector<Row> heads,frontiers,execution,edges,states,data,writes,objects,final_registers,arguments,admissions;
  for(const auto &step:outcome.native_admissions)
    admissions.push_back({{"source",hex(step.source)},{"target",hex(step.target)},
      {"sequence",std::to_string(step.sequence)},{"before_identity",hex(step.before_identity)},
      {"after_identity",hex(step.after_identity)},{"added_heads",std::to_string(step.added_heads)},
      {"admitted",step.admitted?"true":"false"},{"reason",step.reason}});
  for(size_t index=0;index<input.args.size();++index)
    arguments.push_back({{"index",std::to_string(index)},{"value",hex(input.args[index])}});
  for(const auto &object:outcome.native_objects)
    objects.push_back({{"argument",std::to_string(object.argument)},{"offset",std::to_string(object.offset)},
      {"address",hex(object.address)},{"initial",bytes(object.initial)},{"final",bytes(object.final)},
      {"readable",object.readable?"true":"false"}});
  for(const auto &reg:outcome.native_final_registers)
    final_registers.push_back({{"reg",std::to_string(reg.reg)},{"width",std::to_string(reg.width)},
      {"value",hex(reg.value)}});
  for(const auto &head:region.heads())heads.push_back({{"site",hex(head.address)},
      {"bytes",bytes(head.bytes)},{"size",std::to_string(head.bytes.size())},{"flow",std::to_string(head.flow)}});
  for(const auto &f:region.frontiers())frontiers.push_back({{"site",hex(f.site)},{"reason",f.reason}});
  std::set<uint64_t> ownerless,foreign;
  for(const auto &point:events.execution)
  {
    const auto *actual=get_func(ea_t(point.pc));
    if(!actual)ownerless.insert(point.pc);
    else if(actual->start_ea!=function)foreign.insert(point.pc);
    execution.push_back({{"site",hex(point.pc)},{"size",std::to_string(point.size)},
      {"sequence",std::to_string(point.sequence)},{"owner",actual?hex(actual->start_ea):"none"}});
  }
  for(const auto &edge:events.edges)edges.push_back({{"source",hex(edge.from)},{"target",hex(edge.to)},
      {"sequence",std::to_string(edge.sequence)},{"kind",edge.kind==ExecEdge::Kind::Call?"call":
       edge.kind==ExecEdge::Kind::Return?"return":edge.kind==ExecEdge::Kind::Jump?"jump":"unknown"}});
  for(const auto &state:events.states)
  {
    std::string registers;
    for(const auto &reg:state.regs)
    {
      if(!registers.empty())registers+=';';
      registers+=std::to_string(reg.reg)+":"+std::to_string(reg.width)+":"+hex(reg.value);
    }
    states.push_back({{"site",hex(state.pc)},{"source",hex(state.source)},
      {"sequence",std::to_string(state.sequence)},{"registers",registers},
      {"kind",state.kind==StatePoint::Kind::RegionEntry?"seeded entry":
       state.kind==StatePoint::Kind::NativeInstructionEntry?"native instruction entry":
       state.kind==StatePoint::Kind::TransferTarget?"transfer target":"predicate input"}});
  }
  for(const auto &access:events.data)data.push_back({{"site",hex(access.from)},{"address",hex(access.addr)},
      {"size",std::to_string(access.size)},{"value",hex(access.value)},
      {"sequence",std::to_string(access.sequence)},{"kind",access.kind==RAX_MEM_WRITE?"write":"read"}});
  for(const auto &write:events.final_writes)writes.push_back({{"address",hex(write.addr)},{"bytes",bytes(write.bytes)}});
  std::ostringstream out;
  out<<"{\"schema\":1,\"available\":true,\"scope\":\"native-region\",\"capture\":"<<capture
      <<",\"database\":"<<inspection_json_quote(std::to_string(int64_t(get_dbctx_id())))
      <<",\"function\":"<<inspection_json_quote(hex(function))
      <<",\"seed\":"<<inspection_json_quote(hex(seed))
      <<",\"region_identity\":"<<inspection_json_quote(hex(region.identity()))
      <<",\"initial_region_identity\":"<<inspection_json_quote(hex(initial_identity))
      <<",\"native_walk\":"<<(walk?"true":"false")
      <<",\"native_walk_stop\":"<<inspection_json_quote(outcome.native_walk_stop)
      <<",\"native_state_capture_requested\":"<<(outcome.native_state_capture_requested?"true":"false")
      <<",\"native_state_capture_complete\":"<<(outcome.native_state_capture_complete?"true":"false")
      <<",\"image_hash\":"<<inspection_json_quote(hex(region.image_hash()))
      <<",\"generation\":"<<inspection_json_quote(hex(region.generation()))
      <<",\"address_bits\":"<<(image.arch==HybridArch::X86_64?64:32)
      <<",\"decoder\":\"IDA mode-aware native decoder, snapshot bytes checked\""
      <<",\"planned_heads\":"<<region.heads().size()
      <<",\"plan_truncated\":"<<(region.truncated()?"true":"false")
      <<",\"ran\":"<<(ran?"true":"false")
      <<",\"stop\":"<<inspection_json_quote(ran?hybrid_emu_outcome_name(outcome):"capture-unavailable")
      <<",\"stop_status\":"<<outcome.stop_status<<",\"stop_pc\":"<<inspection_json_quote(hex(outcome.stop_pc))
      <<",\"instruction_count\":"<<outcome.instruction_count
      <<",\"entry_sp\":"<<inspection_json_quote(hex(outcome.entry_sp))
      <<",\"explicit_input\":"<<(explicit_input?"true":"false")
      <<",\"sp_valid\":"<<(outcome.sp_valid?"true":"false")<<",\"sp_delta\":"<<outcome.sp_delta
      <<",\"final_registers_complete\":"<<(outcome.native_final_registers_complete?"true":"false")
      <<",\"reached_sentinel\":"<<(outcome.returned?"true":"false")
      <<",\"region_boundary\":"<<(outcome.region_boundary?"true":"false")
      <<",\"region_code_changed\":"<<(outcome.region_code_changed?"true":"false")
      <<",\"boundary_source\":"<<inspection_json_quote(hex(outcome.region_boundary_source))
      <<",\"boundary_target\":"<<inspection_json_quote(hex(outcome.region_boundary_target))
      <<",\"data_trace_complete\":"<<(outcome.data_trace_complete?"true":"false")
      <<",\"data_trace_truncated\":"<<(outcome.data_trace_truncated?"true":"false")
      <<",\"ownerless_executed_heads\":"<<ownerless.size()<<",\"foreign_executed_heads\":"<<foreign.size()
      <<",\"function_evidence_published\":false,\"vm_identity_proved\":false"
      <<",\"environment_contract\":\"backend-defined timestamp, randomness, processor and device state; explicit arguments do not establish replay determinism\""
      <<",\"backend_compatibility\":\"32-bit legacy INC/DEC materializes current EFLAGS before backend execution to preserve pending carry\""
      <<",\"contract\":\"ephemeral seeded native execution; exact fetched instruction bytes; separate from function evidence; logical VM state unknown\"";
  inspection_json_rows(out,"heads",heads);inspection_json_rows(out,"frontiers",frontiers);
  inspection_json_rows(out,"execution",execution);inspection_json_rows(out,"edges",edges);
  inspection_json_rows(out,"states",states);inspection_json_rows(out,"data",data);
  inspection_json_rows(out,"final_writes",writes);
  inspection_json_rows(out,"input_arguments",arguments);inspection_json_rows(out,"input_objects",objects);
  inspection_json_rows(out,"final_registers",final_registers);
  inspection_json_rows(out,"native_admissions",admissions);
  if(check)
  {
    out<<",\"native_observations\":{\"available\":"<<(observations.available?"true":"false")
       <<",\"reason\":"<<inspection_json_quote(observations.reason)
       <<",\"path_steps\":"<<observations.path_steps<<",\"path_limited\":"<<(observations.path_limited?"true":"false")
       <<",\"starts_examined\":"<<observations.starts_examined<<",\"candidate_visits\":"<<observations.candidate_visits
       <<",\"unsupported_path_stops\":"<<observations.unsupported_path_stops
       <<",\"recognizer_rejections\":"<<observations.recognizer_rejections
       <<",\"path_length_stops\":"<<observations.path_length_stops
       <<",\"capture_end_stops\":"<<observations.capture_end_stops
       <<",\"omitted\":"<<observations.omitted<<",\"transition_attempts\":"<<observations.transition_attempts
       <<",\"queries\":"<<observations.queries;
    inspection_json_rows(out,"records",observations.records);out<<'}';
  }
  out<<'}';return out.str();
}
std::string trace_native_region(uint64_t function,uint64_t seed)
{return trace_native_region_impl(function,seed,nullptr);}
std::string trace_native_region_input(uint64_t function,uint64_t seed,const std::string &request)
{
  hybrid::EmuInput input;
  if(!parse_input(request,input))return unavailable("invalid bounded native input");
  return trace_native_region_impl(function,seed,&input);
}
std::string trace_native_region_walk(uint64_t function,uint64_t seed,const std::string &request)
{
  hybrid::EmuInput input;
  if(!parse_input(request,input))return unavailable("invalid bounded native input");
  return trace_native_region_impl(function,seed,&input,true);
}
std::string trace_native_region_check(uint64_t function,uint64_t seed,const std::string &request)
{
  hybrid::EmuInput input;
  if(!parse_input(request,input))return unavailable("invalid bounded native input");
  return trace_native_region_impl(function,seed,&input,true,true);
}
} // namespace chernobog::vm
