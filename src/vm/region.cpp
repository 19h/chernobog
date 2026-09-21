#include "region.hpp"
#include <sstream>

namespace chernobog::vm {
namespace {
bool reg(const Operand &o, int r, unsigned bits)
{ return o.kind == Kind::reg && o.reg == r && o.bits == bits; }
bool valid_reg(int r, unsigned mode) { return r >= 0 && r < (mode == 64 ? 16 : 8) && r != 4; }
bool arithmetic(Op op) { return op == Op::add || op == Op::sub || op == Op::bit_xor; }
bool memory(const Operand &o, int base, unsigned bits, unsigned mode)
{ return o.kind == Kind::memory && o.base == base && o.index == -1 && o.value == 0
    && o.bits == bits && o.address_bits == mode; }
bool advance(const Instruction &i, int vip, unsigned bits, unsigned mode, Op op)
{ return i.op == op && reg(i.dst, vip, mode) && i.src.kind == Kind::immediate && i.src.value == bits / 8; }
} // namespace

std::optional<Candidate> recognize(const std::vector<Instruction> &code, unsigned mode)
{
  if ((mode != 32 && mode != 64) || code.size() < 3 || code.size() > 128) return {};
  for (size_t i = 0; i < code.size(); ++i)
    if (code[i].address == bad_address || !code[i].size || code[i].size > 15
        || code[i].address > UINT64_MAX - code[i].size
        || (i && (code[i].alternate_entry || code[i-1].address + code[i-1].size != code[i].address))) return {};
  const bool backwards = code[0].op == Op::sub;
  const auto &load = code[backwards ? 1 : 0];
  if (load.op != Op::load || load.dst.kind != Kind::reg || load.src.kind != Kind::memory
      || (load.src.bits != 8 && load.src.bits != 32)
      || load.dst.bits != 32 || !valid_reg(load.dst.reg, mode)
      || !valid_reg(load.src.base, mode) || load.dst.reg == load.src.base
      || !memory(load.src, load.src.base, load.src.bits, mode)) return {};
  if (!advance(code[backwards ? 0 : 1], load.src.base, load.src.bits, mode,
               backwards ? Op::sub : Op::add)) return {};
  Candidate c;
  c.start = code.front().address; c.end = code.back().address + code.back().size;
  c.read = load.address; c.dispatch = code.back().address;
  c.address_bits = mode; c.read_bits = load.src.bits;
  c.direction = backwards ? Direction::backward : Direction::forward;
  c.vip = load.src.base; c.value = load.dst.reg;
  size_t cursor = 2;
  // Stateful source-emitted decode: value OP key, bounded immediate/unary
  // transforms, then key OP value (including the x64 low-dword stack idiom).
  if (cursor < code.size() && arithmetic(code[cursor].op)
      && reg(code[cursor].dst, c.value, c.read_bits)
      && code[cursor].src.kind == Kind::reg)
  {
    const auto &mix = code[cursor++]; c.key = mix.src.reg;
    if (!valid_reg(c.key, mode) || c.key == c.vip || c.key == c.value || mix.src.bits != c.read_bits) return {};
    while (cursor < code.size())
    {
      const auto &i = code[cursor];
      if (!reg(i.dst, c.value, c.read_bits)) break;
      const bool immediate = (arithmetic(i.op) || i.op == Op::rotate_left || i.op == Op::rotate_right)
          && i.src.kind == Kind::immediate;
      const bool unary = (i.op == Op::negate || i.op == Op::bit_not || i.op == Op::increment || i.op == Op::decrement
                         || (i.op == Op::byte_swap && c.read_bits == 32)) && i.src.kind == Kind::none;
      if (!immediate && !unary) break;
      ++cursor;
    }
    if (cursor == code.size()) return {};
    if (mode == 64 && c.read_bits == 32)
    {
      if (cursor + 2 >= code.size()) return {};
      const auto &push = code[cursor], &update = code[cursor+1], &pop = code[cursor+2];
      if (push.op != Op::push || !reg(push.dst, c.key, 64) || update.op != mix.op
          || !memory(update.dst, 4, 32, 64) || !reg(update.src, c.value, 32)
          || pop.op != Op::pop || !reg(pop.dst, c.key, 64)) return {};
      c.stack_key_update = true; cursor += 3;
    }
    else
    {
      const auto &update = code[cursor++];
      if (update.op != mix.op || !reg(update.dst, c.key, c.read_bits)
          || !reg(update.src, c.value, c.read_bits)) return {};
    }
  }
  if (c.read_bits == 8)
  {
    if (cursor + 1 != code.size()) return {};
    const auto &jump = code[cursor]; const auto &target = jump.dst;
    if (jump.op != Op::jump || target.kind != Kind::memory || target.bits != mode
        || target.address_bits != mode || target.index != c.value || target.scale != mode/8) return {};
    if (mode == 64 && (!valid_reg(target.base, mode) || target.base == c.vip
        || target.base == c.value || target.base == c.key || target.value != 0)) return {};
    if (mode == 32 && target.base != -1) return {};
    c.dispatch_kind = Dispatch::indexed_table; c.dispatch_base = target.base;
    c.table_displacement = target.value;
  }
  else
  {
    if (mode == 64)
    {
      if (cursor >= code.size() || code[cursor].op != Op::sign_extend
          || !reg(code[cursor].dst, c.value, 64) || !reg(code[cursor].src, c.value, 32)) return {};
      ++cursor;
    }
    if (cursor + 2 != code.size()) return {};
    const auto &add = code[cursor], &jump = code[cursor+1];
    if (add.op != Op::add || add.dst.kind != Kind::reg || !valid_reg(add.dst.reg, mode)
        || add.dst.reg == c.vip || add.dst.reg == c.value || add.dst.reg == c.key
        || add.dst.bits != mode || !reg(add.src, c.value, mode)
        || jump.op != Op::jump || !reg(jump.dst, add.dst.reg, mode)) return {};
    c.dispatch_kind = Dispatch::relative_register; c.dispatch_base = add.dst.reg;
  }
  c.support = code; return c;
}

bool same_logical_state(const LogicalState &a, const LogicalState &b, bool stateful)
{
  return a.publication != 0 && a.publication == b.publication && a.native != bad_address
      && a.native == b.native && a.context != 0 && a.context == b.context
      && a.memory_epoch != 0 && a.memory_epoch == b.memory_epoch
      && a.vip && a.vip == b.vip && a.virtual_stack && a.virtual_stack == b.virtual_stack
      && a.dispatch_base && a.dispatch_base == b.dispatch_base
      && (!stateful || (a.key && a.key == b.key));
}

std::string normalized_shape(const Candidate &c)
{
  std::ostringstream out; out << c.address_bits << ':' << c.read_bits << ':' << int(c.direction) << ':' << int(c.dispatch_kind);
  const auto role = [&](int r) { return r == -1 ? -1 : r == c.vip ? 0 : r == c.value ? 1
      : r == c.key ? 2 : r == c.dispatch_base ? 3 : r == 4 ? 4 : 5 + r; };
  for (const auto &i : c.support)
  {
    out << ';' << int(i.op);
    for (const auto &o : {i.dst, i.src}) out << ',' << int(o.kind) << '/' << role(o.reg)
      << '/' << role(o.base) << '/' << role(o.index) << '/' << o.bits << '/' << o.address_bits
      << '/' << o.scale << '/' << o.value;
  }
  return out.str();
}
} // namespace chernobog::vm
