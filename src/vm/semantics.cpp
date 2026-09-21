#include "semantics.hpp"
#include "../common/solver_evidence.hpp"
#include <algorithm>
#include <stdexcept>

namespace chernobog::vm {
namespace {
z3::expr bv(z3::context &ctx, uint64_t value, unsigned bits) { return ctx.bv_val(value,bits); }
z3::expr resize(const z3::expr &value, unsigned bits, bool sign=false)
{
  const auto old=value.get_sort().bv_size();
  return old==bits ? value : old>bits ? value.extract(bits-1,0)
      : sign ? z3::sext(value,bits-old) : z3::zext(value,bits-old);
}
std::vector<std::string> roles(const Candidate &c)
{
  std::vector<std::string> result(c.address_bits==64 ? 16 : 8);
  result[c.vip]="vip"; result[c.value]="value"; result[4]="sp";
  if(c.key>=0)result[c.key]="key";
  if(c.dispatch_base>=0)result[c.dispatch_base]="base";
  unsigned other=0;
  for(auto &name:result)if(name.empty())name="preserved_"+std::to_string(other++);
  return result;
}
class Evaluator
{
  Summary &out;
  z3::context &ctx;
  unsigned mode;
  uint64_t site = bad_address;
  z3::expr address(const Operand &o)
  {
    auto value=bv(ctx,o.value,mode);
    if(o.base>=0)value=value+out.registers.at(size_t(o.base));
    if(o.index>=0)value=value+out.registers.at(size_t(o.index))*bv(ctx,o.scale,mode);
    return value;
  }
  z3::expr read_memory(const z3::expr &at, unsigned bits)
  {
    auto value=z3::select(out.memory,at);
    for(unsigned offset=1;offset<bits/8;++offset)
      value=z3::concat(z3::select(out.memory,at+bv(ctx,offset,mode)),value);
    out.accesses.push_back({false,bits,at,value,site}); return value;
  }
  void write_memory(const z3::expr &at, const z3::expr &value)
  {
    const auto bits=value.get_sort().bv_size();
    out.accesses.push_back({true,bits,at,value,site});
    for(unsigned offset=0;offset<bits/8;++offset)
      out.memory=z3::store(out.memory,at+bv(ctx,offset,mode),value.extract(offset*8+7,offset*8));
  }
  z3::expr read(const Operand &o, unsigned bits)
  {
    if(o.kind==Kind::reg)return resize(out.registers.at(size_t(o.reg)),bits);
    if(o.kind==Kind::immediate)return bv(ctx,o.value,bits);
    if(o.kind==Kind::memory)return resize(read_memory(address(o),o.bits),bits);
    throw std::runtime_error("missing operand");
  }
  void write(const Operand &o, const z3::expr &input)
  {
    const auto value=resize(input,o.bits);
    if(o.kind==Kind::memory) { write_memory(address(o),value); return; }
    if(o.kind!=Kind::reg)throw std::runtime_error("invalid destination");
    auto &destination=out.registers.at(size_t(o.reg));
    if(o.bits==mode || (mode==64 && o.bits==32))destination=resize(value,mode);
    else destination=z3::concat(destination.extract(mode-1,o.bits),value);
  }
  void arithmetic_flags(const z3::expr &a, const z3::expr &b, const z3::expr &result,
                        bool subtract, bool logical, bool preserve_carry)
  {
    const auto bits=result.get_sort().bv_size();
    auto bit=[&](const z3::expr &v,unsigned index){return v.extract(index,index)==bv(ctx,1,1);};
    if(!preserve_carry)
    { out.flags[0]=logical?ctx.bool_val(false):subtract?z3::ult(a,b):z3::ult(result,a);out.defined[0]=true; }
    auto parity=bit(result,0);
    for(unsigned i=1;i<8;++i)parity=parity!=bit(result,i);
    out.flags[1]=!parity;out.defined[1]=true;
    out.flags[2]=bit(a^b^result,4);out.defined[2]=!logical;
    out.flags[3]=result==bv(ctx,0,bits);out.defined[3]=true;
    out.flags[4]=bit(result,bits-1);out.defined[4]=true;
    out.flags[5]=logical?ctx.bool_val(false):bit((subtract?(a^b):~(a^b))&(a^result),bits-1);
    out.defined[5]=true;
  }
public:
  explicit Evaluator(Summary &s):out(s),ctx(s.memory.ctx()),mode(s.candidate.address_bits){}
  void step(const Instruction &i)
  {
    site=i.address;
    if(i.op==Op::load) { write(i.dst,read(i.src,i.src.bits)); return; }
    if(i.op==Op::sign_extend) { write(i.dst,resize(read(i.src,i.src.bits),i.dst.bits,true));return; }
    if(i.op==Op::push)
    {
      const auto value=read(i.dst,mode);
      out.registers[4]=out.registers[4]-bv(ctx,mode/8,mode);
      write_memory(out.registers[4],value);return;
    }
    if(i.op==Op::pop)
    {
      const auto value=read_memory(out.registers[4],mode);write(i.dst,value);
      out.registers[4]=out.registers[4]+bv(ctx,mode/8,mode);return;
    }
    if(i.op==Op::jump) { out.next_pc=read(i.dst,mode);return; }
    const auto bits=i.dst.bits;
    auto a=read(i.dst,bits), b=bv(ctx,0,bits), result=a;
    if(i.op==Op::bit_not) result=~a;
    else if(i.op==Op::byte_swap)
    {
      result=a.extract(7,0);
      for(unsigned offset=1;offset<bits/8;++offset)result=z3::concat(result,a.extract(offset*8+7,offset*8));
    }
    else if(i.op==Op::rotate_left || i.op==Op::rotate_right)
    {
      const unsigned count=unsigned(i.src.value & (bits==64?63:31));
      result=i.op==Op::rotate_left?a.rotate_left(count):a.rotate_right(count);
      // No admitted sequence reads flags here. Its required key-feedback or
      // final base ADD overwrites the final observable arithmetic flags.
      out.defined.fill(false);
    }
    else
    {
      const bool logical=i.op==Op::bit_xor;
      const bool subtract=i.op==Op::sub || i.op==Op::decrement || i.op==Op::negate;
      const bool preserve=i.op==Op::increment || i.op==Op::decrement;
      if(i.op==Op::negate) { b=a; a=bv(ctx,0,bits); }
      else if(preserve)b=bv(ctx,1,bits);
      else b=read(i.src,bits);
      if(i.op!=Op::add && i.op!=Op::sub && !logical && !preserve && i.op!=Op::negate)
        throw std::runtime_error("unsupported arithmetic");
      result=logical?a^b:subtract?a-b:a+b;
      arithmetic_flags(a,b,result,subtract,logical,preserve);
    }
    write(i.dst,result);
  }
};
} // namespace

Summary::Summary(z3::context &ctx, Candidate c):candidate(std::move(c)),roles(vm::roles(candidate)),
  memory(ctx.constant("input_memory",ctx.array_sort(ctx.bv_sort(candidate.address_bits),ctx.bv_sort(8)))),
  next_pc(ctx.bv_val(0,candidate.address_bits))
{
  for(const auto &role:roles)registers.push_back(ctx.bv_const(("input_"+role).c_str(),candidate.address_bits));
  for(unsigned i=0;i<6;++i)flags.push_back(ctx.bool_const(("input_flag_"+std::to_string(i)).c_str()));
}

std::unique_ptr<Summary> summarize(z3::context &ctx, const Candidate &candidate)
{
  try
  {
    const auto c=recognize(candidate.support,candidate.address_bits);
    if(!c)return {};
    // The x86-32 byte register vocabulary has only AL/CL/DL/BL. This
    // restriction matters for portable callers, even though IDA rejects high aliases.
    if(c->address_bits==32 && c->read_bits==8 && c->key>=0 && (c->value>3 || c->key>3))return {};
    auto result=std::make_unique<Summary>(ctx,*c);
    Evaluator evaluator(*result);
    for(const auto &i:c->support)evaluator.step(i);
    // Every admitted scaffold must finish with defined CF/PF/ZF/SF/OF.
    for(unsigned i:{0u,1u,3u,4u,5u})if(!result->defined[i])return {};
    return result;
  }
  catch(const z3::exception &) { return {}; }
  catch(const std::exception &) { return {}; }
}

Comparison compare(const Summary &a, const Summary &b, unsigned timeout, unsigned resource)
{
  if(&a.memory.ctx()!=&b.memory.ctx() || a.candidate.address_bits!=b.candidate.address_bits
      || (a.candidate.key>=0)!=(b.candidate.key>=0)
      || (a.candidate.dispatch_base>=0)!=(b.candidate.dispatch_base>=0))return {Equivalence::incompatible,"input role contract differs"};
  if(a.accesses.size()!=b.accesses.size() || a.defined!=b.defined)
    return {Equivalence::incompatible,"ordered access or defined-flag contract differs"};
  try
  {
    auto &ctx=a.memory.ctx();auto mismatch=a.next_pc!=b.next_pc || a.memory!=b.memory;
    for(size_t i=0;i<a.roles.size();++i)
    {
      const auto it=std::find(b.roles.begin(),b.roles.end(),a.roles[i]);
      if(it==b.roles.end())return {Equivalence::incompatible,"register role map differs"};
      mismatch=mismatch || a.registers[i]!=b.registers[size_t(it-b.roles.begin())];
    }
    for(unsigned i=0;i<6;++i)if(a.defined[i])mismatch=mismatch || a.flags[i]!=b.flags[i];
    for(size_t i=0;i<a.accesses.size();++i)
    {
      const auto &x=a.accesses[i],&y=b.accesses[i];
      if(x.write!=y.write || x.bits!=y.bits)return {Equivalence::incompatible,"memory access contract differs"};
      mismatch=mismatch || x.address!=y.address || x.value!=y.value;
    }
    z3::solver solver(ctx);z3::params params(ctx);
    params.set("timeout",std::max(1u,timeout));params.set("rlimit",std::max(1u,resource));solver.set(params);
    solver.add(mismatch);
    const auto settings="timeout_ms="+std::to_string(std::max(1u,timeout))+";rlimit="+std::to_string(std::max(1u,resource));
    const auto result=solver_evidence::check(solver,"VM local summary effect mismatch",settings.c_str());
    if(result==z3::unsat)return {Equivalence::equivalent,"UNSAT: full modeled outputs and ordered accesses agree under role mapping"};
    if(result==z3::sat)return {Equivalence::different,"SAT: modeled effect counterexample exists"};
    return {Equivalence::unknown,solver.reason_unknown()};
  }
  catch(const z3::exception &) { return {Equivalence::unknown,"solver exception"}; }
}
} // namespace chernobog::vm
