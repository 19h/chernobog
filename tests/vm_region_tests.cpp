#include "vm/region.hpp"
#include <cstdlib>
#include <iostream>
using namespace chernobog::vm;
namespace {
size_t checks = 0;
void require(bool good, const char *name)
{ ++checks; if (!good) { std::cerr << name << '\n'; std::exit(1); } }
Operand r(int reg, unsigned bits) { Operand o; o.kind=Kind::reg; o.reg=reg; o.bits=bits; return o; }
Operand imm(uint64_t value) { Operand o; o.kind=Kind::immediate; o.value=value; return o; }
Operand mem(int base, unsigned bits, unsigned mode, int index=-1, unsigned scale=1)
{ Operand o; o.kind=Kind::memory; o.base=base; o.bits=bits; o.address_bits=mode; o.index=index; o.scale=scale; return o; }
void append(std::vector<Instruction> &v, Op op, Operand a, Operand b={})
{ v.push_back({0x1000 + v.size()*4, 4, op, a, b, false}); }
std::vector<Instruction> make(unsigned mode, bool backwards, bool relative, bool keyed, int vip, int value, int key, int base)
{
  std::vector<Instruction> v; const unsigned bits=relative?32:8;
  if (backwards) append(v,Op::sub,r(vip,mode),imm(bits/8));
  append(v,Op::load,r(value,32),mem(vip,bits,mode));
  if (!backwards) append(v,Op::add,r(vip,mode),imm(bits/8));
  if (keyed)
  {
    append(v,Op::bit_xor,r(value,bits),r(key,bits));
    append(v,Op::rotate_left,r(value,bits),imm(3));
    append(v,Op::add,r(value,bits),imm(7));
    if (mode==64 && relative)
    {
      append(v,Op::push,r(key,64)); append(v,Op::bit_xor,mem(4,32,64),r(value,32)); append(v,Op::pop,r(key,64));
    }
    else append(v,Op::bit_xor,r(key,bits),r(value,bits));
  }
  if (relative)
  {
    if (mode==64) append(v,Op::sign_extend,r(value,64),r(value,32));
    append(v,Op::add,r(base,mode),r(value,mode)); append(v,Op::jump,r(base,mode));
  }
  else append(v,Op::jump,mem(mode==64?base:-1,mode,mode,value,mode/8));
  return v;
}
}
int main()
{
  // All mode/direction/dispatch/key combinations, independent role assignments.
  for (unsigned mode : {32u,64u}) for (bool back : {false,true})
    for (bool relative : {false,true}) for (bool keyed : {false,true})
    {
      const auto a=make(mode,back,relative,keyed,6,0,3,7);
      const auto b=make(mode,back,relative,keyed,5,2,1,mode==64?11:6);
      const auto x=recognize(a,mode), y=recognize(b,mode);
      require(bool(x)&&bool(y),"role permutation admitted");
      require(normalized_shape(*x)==normalized_shape(*y),"role normalization stable");
      require(x->read_bits==(relative?32u:8u) && x->vip==6 && x->key==(keyed?3:-1),"roles and widths");
      require(x->direction==(back?Direction::backward:Direction::forward),"direction");
      auto clone=a; for(auto &i:clone) i.address+=0x10000;
      require(normalized_shape(*recognize(clone,mode))==normalized_shape(*x),"clone relocation");
      for(size_t index=1;index<a.size();++index)
      { auto bad=a; bad[index].alternate_entry=true; require(!recognize(bad,mode),"external entry rejected"); }
      auto bad=a; bad[back?0:1].src.value+=1; require(!recognize(bad,mode),"wrong stride rejected");
      bad=a; bad[back?1:0].src.address_bits=16; require(!recognize(bad,mode),"wrong address width rejected");
      bad=a; bad[back?1:0].src.index=2; require(!recognize(bad,mode),"indexed bytecode read rejected");
      bad=a; bad[back?1:0].src.value=1; require(!recognize(bad,mode),"displaced bytecode read rejected");
      bad=a; bad[1].address++; require(!recognize(bad,mode),"hole rejected");
      bad=a; bad.back().dst.bits=16; require(!recognize(bad,mode),"wrong dispatch width rejected");
      bad=a; bad[0].size=16; require(!recognize(bad,mode),"oversize instruction rejected");
      bad=a; bad[0].address=UINT64_MAX-1; require(!recognize(bad,mode),"address wrap rejected");
      require(!recognize(a,16),"unsupported mode rejected");
      if (keyed)
      {
        bad=a; bad[2].src.reg=6; require(!recognize(bad,mode),"VIP/key alias rejected");
        bad=a; bad[3].dst.reg=6; require(!recognize(bad,mode),"intervening VIP clobber rejected");
        bad=a; bad[3].src.value++;
        require(normalized_shape(*recognize(bad,mode))!=normalized_shape(*x),"constants preserved in shape");
      }
    }
  auto code=make(64,false,true,true,6,0,3,7);
  code[6].dst.bits=64; require(!recognize(code,64),"full stack update differs from low-dword idiom");
  code=make(64,false,true,false,6,0,3,7); code[2].op=Op::load;
  require(!recognize(code,64),"missing sign extension rejected");
  code.resize(129); require(!recognize(code,64),"window quota");
  code=make(64,false,true,true,6,0,3,7);
  for (Op operation : {Op::increment,Op::decrement,Op::negate,Op::bit_not,Op::byte_swap})
  {
    auto unary=code; unary[3].op=operation; unary[3].src={};
    require(bool(recognize(unary,64)),"source unary cryptor vocabulary");
  }
  // The source generator permits 101 value transforms; cover that maximum
  // without relaxing the independent hard window bound.
  auto long_decode=code;
  long_decode.insert(long_decode.begin()+4,99,code[3]);
  for(size_t i=0;i<long_decode.size();++i)long_decode[i].address=0x1000+i*4;
  require(bool(recognize(long_decode,64)),"101-transform source budget");
  LogicalState a{1,0x1000,2,3,0x2000,4,0x3000,0x4000};
  require(same_logical_state(a,a,true),"complete state identity");
  auto b=a; b.vip=0x2001; require(!same_logical_state(a,b,true),"same handler different VIP");
  b=a; b.key=5; require(!same_logical_state(a,b,true),"same handler different decoder key");
  b=a; b.memory_epoch++; require(!same_logical_state(a,b,true),"memory epoch");
  b=a; b.context++; require(!same_logical_state(a,b,true),"call context");
  b=a; b.publication++; require(!same_logical_state(a,b,true),"region publication");
  b=a; b.virtual_stack.reset(); require(!same_logical_state(a,b,true),"unknown stack not equal");
  b=a; b.key.reset(); require(!same_logical_state(a,b,true),"unknown key not equal");
  require(same_logical_state(a,b,false),"stateless decoder does not require key");
  a.vip.reset(); require(!same_logical_state(a,a,false),"unknown VIP cannot merge with itself");
  std::cout << "VM region checks=" << checks << '\n';
}
