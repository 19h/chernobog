#include "vm/semantics.hpp"
#include "vm/summary_view.hpp"
#include "common/x86_abstract.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include "vm_test_candidates.hpp"
using namespace chernobog::vm;
namespace {
size_t checks=0;
void require(bool value,const char *name)
{++checks;if(!value){std::cerr<<name<<'\n';std::exit(1);}}
uint64_t mask(unsigned bits){return bits==64?UINT64_MAX:(uint64_t{1}<<bits)-1;}
uint64_t rotate(uint64_t v,unsigned bits,unsigned n)
{n&=31;n%=bits;return n?((v<<n)|(v>>(bits-n)))&mask(bits):v;}
uint64_t number(z3::model &m,const z3::expr &e){return m.eval(e,true).get_numeral_uint64();}
void concrete(unsigned mode,bool back,bool relative,bool keyed,uint32_t encoded,uint64_t key,bool alias,
              Op transform=Op::rotate_left,unsigned count=3)
{
  z3::context ctx;
  auto c=vm_test::candidate(mode,back,relative,keyed);
  if(keyed)
  {
    c.support[3].op=transform;
    c.support[3].src=(transform==Op::rotate_left || transform==Op::rotate_right
      || transform==Op::add || transform==Op::sub || transform==Op::bit_xor)?vm_test::imm(count):Operand{};
  }
  auto s=summarize(ctx,c);require(bool(s),"summary built");
  const unsigned bits=relative?32:8;
  const uint64_t data=alias?0x2ff8:0x2000,sp=0x3000,base=0x4000;
  const uint64_t vip=back?data+bits/8:data;
  z3::solver solver(ctx);
  for(const auto &role:s->roles)
  {
    const uint64_t value=role=="vip"?vip:role=="key"?key:role=="sp"?sp:role=="base"?base:UINT64_C(0x1234567887654321);
    solver.add(ctx.bv_const(("input_"+role).c_str(),mode)==ctx.bv_val(value,mode));
  }
  auto memory=z3::const_array(ctx.bv_sort(mode),ctx.bv_val(0,8));
  for(unsigned i=0;i<bits/8;++i)memory=z3::store(memory,ctx.bv_val(data+i,mode),ctx.bv_val((encoded>>(i*8))&255,8));
  uint64_t decoded=encoded&mask(bits);
  if(keyed)
  {
    decoded^=key&mask(bits);
    switch(transform)
    {
      case Op::rotate_left:decoded=rotate(decoded,bits,count);break;
      case Op::rotate_right:decoded=rotate(decoded,bits,(bits-((count&31)%bits))%bits);break;
      case Op::increment:++decoded;break;
      case Op::decrement:--decoded;break;
      case Op::negate:decoded=0-decoded;break;
      case Op::bit_not:decoded=~decoded;break;
      case Op::byte_swap:decoded=((decoded&255)<<24)|((decoded&0xff00)<<8)|((decoded>>8)&0xff00)|((decoded>>24)&255);break;
      case Op::add:decoded+=count;break;
      case Op::sub:decoded-=count;break;
      case Op::bit_xor:decoded^=count;break;
      default:require(false,"oracle transform vocabulary");
    }
    decoded=(decoded+7)&mask(bits);
  }
  uint64_t wide=relative && mode==64?uint64_t(int64_t(int32_t(decoded))):decoded;
  const uint64_t next=(base+wide)&mask(mode);
  if(!relative)
  {
    const uint64_t table=(mode==64?base:0)+decoded*(mode/8);
    for(unsigned i=0;i<mode/8;++i)memory=z3::store(memory,ctx.bv_val(table+i,mode),ctx.bv_val((UINT64_C(0x1234567812345678)>>(i*8))&255,8));
    // A table entry can alias the bytecode. Keep this test's independently
    // chosen addresses disjoint; separate stack/bytecode alias controls follow.
    require(table+mode/8<=data || table>=data+bits/8,"oracle table disjoint");
  }
  solver.add(ctx.constant("input_memory",memory.get_sort())==memory);
  require(solver.check()==z3::sat,"concrete input admitted");auto model=solver.get_model();
  require(number(model,s->registers[c.vip])==(back?data:vip+bits/8),"VIP advance");
  require(number(model,s->registers[c.value])==wide,"decoded value and extension");
  require(number(model,s->registers[4])==sp,"net SP preserved");
  const uint64_t key_after=(key^decoded)&mask(mode);
  if(keyed)require(number(model,s->registers[c.key])==key_after,"key feedback retains upper bits");
  require(number(model,s->next_pc)==(relative?next:(UINT64_C(0x1234567812345678)&mask(mode))),"dispatch value");
  chernobog::x86_abstract::Flags flags;
  using Operation=chernobog::x86_abstract::Operation;
  if(relative)chernobog::x86_abstract::transfer(Operation::add,mode,base,wide,false,flags);
  else if(keyed)chernobog::x86_abstract::transfer(Operation::bit_xor,bits,key,decoded,false,flags);
  else chernobog::x86_abstract::transfer(back?Operation::sub:Operation::add,mode,vip,bits/8,false,flags);
  for(unsigned i=0;i<6;++i)
  {
    require(s->defined[i]==bool(flags.known&(1u<<i)),"defined-flag mask");
    if(s->defined[i])require(model.eval(s->flags[i],true).is_true()==bool(flags.value&(1u<<i)),"final flag oracle");
  }
  if(keyed && relative && mode==64)
  {
    require(s->accesses.size()==5,"bytecode, push, RMW read/write, pop access order");
    require(!s->accesses[0].write && s->accesses[1].write && !s->accesses[2].write
            && s->accesses[3].write && !s->accesses[4].write,"read/write ordering");
    require(number(model,s->accesses[1].address)==sp-8 && s->accesses[1].bits==64
            && s->accesses[3].bits==32,"stack widths and address");
    for(unsigned i=0;i<8;++i)
      require(number(model,z3::select(s->memory,ctx.bv_val(sp-8+i,mode)))==((key_after>>(i*8))&255),"retained stack byte");
  }
}
}
void native_oracle(const char *path)
{
  std::ifstream input(path);require(bool(input),"native oracle report readable");
  size_t cases=0;
  while(input.peek()!=std::char_traits<char>::eof())
  {
    std::string line;std::getline(input,line);if(line.empty())continue;
    std::istringstream fields(line);uint64_t x[14]{};
    for(auto &value:x)require(bool(fields>>std::hex>>value),"complete native capture row");
    std::string extra;require(!(fields>>extra),"no extra native capture fields");
    const bool relative=(x[0]&2)!=0,back=(x[0]&1)!=0;const unsigned bits=relative?32:8;
    require(x[0]<4,"native scenario range");
    z3::context ctx;auto s=summarize(ctx,vm_test::candidate(64,back,relative,true));
    require(bool(s),"native oracle summary available");z3::solver solver(ctx);
    for(const auto &role:s->roles)
    {
      const uint64_t value=role=="vip"?x[3]:role=="key"?x[2]:role=="base"?x[4]:role=="sp"?x[5]:0;
      solver.add(ctx.bv_const(("input_"+role).c_str(),64)==ctx.bv_val(value,64));
    }
    auto memory=z3::const_array(ctx.bv_sort(64),ctx.bv_val(0,8));
    const uint64_t data=x[3]-(back?bits/8:0);
    for(unsigned i=0;i<bits/8;++i)memory=z3::store(memory,ctx.bv_val(data+i,64),ctx.bv_val((x[1]>>(8*i))&255,8));
    if(!relative)for(unsigned i=0;i<8;++i)
      memory=z3::store(memory,ctx.bv_val(x[4]+x[7]*8+i,64),ctx.bv_val((x[13]>>(8*i))&255,8));
    solver.add(ctx.constant("input_memory",memory.get_sort())==memory);
    require(solver.check()==z3::sat,"native inputs admitted");auto m=solver.get_model();
    require(number(m,s->registers[6])==x[6],"native VIP");
    require(number(m,s->registers[0])==x[7],"native decoded value");
    require(number(m,s->registers[3])==x[8],"native key");
    require(number(m,s->registers[7])==x[9],"native dispatch base");
    require(number(m,s->registers[4])==x[10],"native SP");
    require(number(m,s->next_pc)==x[13],"executed native dispatch reaches capture");
    const unsigned flag_bit[]={0,2,4,6,7,11};
    for(unsigned i=0;i<6;++i)if(s->defined[i])
      require(m.eval(s->flags[i],true).is_true()==bool(x[11]&(uint64_t{1}<<flag_bit[i])),"native defined arithmetic flag");
    if(relative)for(unsigned i=0;i<8;++i)
      require(number(m,z3::select(s->memory,ctx.bv_val(x[5]-8+i,64)))==((x[12]>>(8*i))&255),"native retained stack byte");
    ++cases;
  }
  require(cases==416,"native corner and seeded case count");
  std::cout<<"Native VM local-effect cases="<<cases<<'\n';
}
int main(int argc,char **argv)
{
  for(unsigned mode:{32u,64u})for(bool back:{false,true})for(bool relative:{false,true})for(bool keyed:{false,true})
  {
    z3::context ctx;
    const auto a=vm_test::candidate(mode,back,relative,keyed);
    const auto b=vm_test::candidate(mode,back,relative,keyed,5,2,1,mode==64?11:6);
    auto x=summarize(ctx,a),y=summarize(ctx,b);require(bool(x)&&bool(y),"permuted summaries built");
    require(compare(*x,*y).result==Equivalence::equivalent,"role-permuted full effects UNSAT");
    y->flags[3]=!y->flags[3];require(compare(*x,*y).result==Equivalence::different,"flag corruption SAT");
    y=summarize(ctx,b);y->accesses[0].address=y->accesses[0].address+ctx.bv_val(1,mode);
    require(compare(*x,*y).result==Equivalence::different,"access-address corruption SAT");
    y=summarize(ctx,b);y->defined[2]=!y->defined[2];
    require(compare(*x,*y).result==Equivalence::incompatible,"undefined flags are not borrowed");
    if(keyed)
    {
      auto changed=b;changed.support[4].src.value++;
      y=summarize(ctx,changed);require(bool(y),"different transform admitted");
      require(compare(*x,*y).result==Equivalence::different,"changed decode SAT");
      const auto exhausted=compare(*x,*y,1,1);
      require(exhausted.result==Equivalence::unknown && !exhausted.reason.empty(),"exhausted proof retains UNKNOWN and cannot reuse");
      changed=b;changed.support.insert(changed.support.begin()+4,{0,4,Op::bit_xor,vm_test::reg(b.value,b.read_bits),vm_test::imm(0),false});
      for(size_t i=0;i<changed.support.size();++i)changed.support[i].address=0x8000+i*4;
      y=summarize(ctx,changed);
      require(bool(y)&&normalized_shape(y->candidate)!=normalized_shape(x->candidate),"different syntax retained");
      require(compare(*x,*y).result==Equivalence::equivalent,"nonidentical syntax effect equivalence UNSAT");
    }
    for(uint32_t encoded:{0u,1u,127u,128u,255u,0x7fffffffu,0x80000000u,0xffffffffu})
      concrete(mode,back,relative,keyed,encoded,UINT64_C(0xa5a5a5a59999ffff),false);
  }
  for(bool back:{false,true})for(uint32_t value:{0u,0x80000000u,0xffffffffu})
    concrete(64,back,true,true,value,UINT64_C(0xfedcba9812345678),true);
  for(Op op:{Op::increment,Op::decrement,Op::negate,Op::bit_not,Op::byte_swap,Op::add,Op::sub,Op::bit_xor})
    for(uint32_t value:{0u,0x80000000u,0xffffffffu})
      concrete(64,false,true,true,value,UINT64_C(0xfedcba9812345678),false,op,11);
  for(Op op:{Op::rotate_left,Op::rotate_right})for(unsigned count:{0u,1u,8u,31u,32u,255u})
    for(bool relative:{false,true})concrete(64,false,relative,true,0x81234567u,UINT64_C(0xfedcba9812345678),false,op,count);
  z3::context ctx;
  auto c=vm_test::candidate(64,false,true,true);c.vip=-1;c.key=-1;
  auto s=summarize(ctx,c);require(bool(s)&&s->candidate.vip==6&&s->candidate.key==3,"untrusted role fields re-derived");
  c.support[2].op=Op::unsupported;require(!summarize(ctx,c),"unsupported effect rejects whole summary");
  std::vector<Candidate> candidates;
  for(unsigned i=0;i<17;++i)
  {
    auto next=vm_test::candidate(64,false,false,true);
    for(auto &instruction:next.support)instruction.address+=i*0x100;
    candidates.push_back(*recognize(next.support,64));
  }
  auto view=project_summaries(candidates,-1,bad_address);
  require(view.bindings.size()==16 && view.omitted==1,"summary retention quota");
  require(view.references.size()==1 && view.queries==15,"shared reference requires every UNSAT comparison");
  for(size_t i=1;i<view.bindings.size();++i)
    require(view.bindings[i].at("status")=="reused after UNSAT" && view.bindings[i].at("summary_id")=="1","actual reference reuse");
  for(size_t i=0;i<candidates.size();++i)candidates[i].support[4].src.value=i;
  view=project_summaries(candidates,-1,bad_address);
  require(view.queries==32 && view.references.size()==16,"comparison budget never implies reuse");
  for(const auto &row:view.references)
  {size_t bytes=0;for(const auto &field:row)bytes+=field.first.size()+field.second.size();require(bytes<=32768,"summary text payload cap");}
  if(argc==2)native_oracle(argv[1]);
  std::cout<<"VM semantics checks="<<checks<<'\n';
}
