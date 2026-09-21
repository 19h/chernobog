#pragma once
#include "vm/region.hpp"
#include <stdexcept>
namespace vm_test {
using namespace chernobog::vm;
inline Operand reg(int index,unsigned bits){Operand o;o.kind=Kind::reg;o.reg=index;o.bits=bits;return o;}
inline Operand imm(uint64_t v){Operand o;o.kind=Kind::immediate;o.value=v;return o;}
inline Operand mem(int base,unsigned bits,unsigned mode,int index=-1,unsigned scale=1)
{Operand o;o.kind=Kind::memory;o.base=base;o.bits=bits;o.address_bits=mode;o.index=index;o.scale=scale;return o;}
inline Candidate candidate(unsigned mode,bool backward,bool relative,bool keyed,
                           int vip=6,int value=0,int key=3,int base=7)
{
  std::vector<Instruction> code;
  auto add=[&](Op op,Operand a,Operand b=Operand{}){code.push_back({0x1000+code.size()*4,4,op,a,b,false});};
  const unsigned bits=relative?32:8;
  if(backward)add(Op::sub,reg(vip,mode),imm(bits/8));
  add(Op::load,reg(value,32),mem(vip,bits,mode));
  if(!backward)add(Op::add,reg(vip,mode),imm(bits/8));
  if(keyed)
  {
    add(Op::bit_xor,reg(value,bits),reg(key,bits));
    add(Op::rotate_left,reg(value,bits),imm(3));
    add(Op::add,reg(value,bits),imm(7));
    if(mode==64 && relative)
    {add(Op::push,reg(key,64));add(Op::bit_xor,mem(4,32,64),reg(value,32));add(Op::pop,reg(key,64));}
    else add(Op::bit_xor,reg(key,bits),reg(value,bits));
  }
  if(relative)
  {
    if(mode==64)add(Op::sign_extend,reg(value,64),reg(value,32));
    add(Op::add,reg(base,mode),reg(value,mode));add(Op::jump,reg(base,mode));
  }
  else add(Op::jump,mem(mode==64?base:-1,mode,mode,value,mode/8));
  auto result=recognize(code,mode);
  if(!result)throw std::runtime_error("test candidate rejected");
  return *result;
}
}
