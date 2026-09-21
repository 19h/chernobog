#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// VM recognition is separate from function execution and from vm_mba. These
// descriptors do not authorize following an indirect edge or merging code.
namespace chernobog::vm {
constexpr uint64_t bad_address = UINT64_MAX;
enum class Kind { none, reg, immediate, memory };
struct Operand
{
  Kind kind = Kind::none;
  int reg = -1, base = -1, index = -1;
  unsigned bits = 0, address_bits = 0, scale = 1;
  uint64_t value = 0; // immediate or modular address displacement
};
enum class Op { unsupported, load, sign_extend, add, sub, bit_xor,
                rotate_left, rotate_right, negate, bit_not, byte_swap,
                push, pop, jump, nop, increment, decrement };
struct Instruction
{
  uint64_t address = bad_address;
  unsigned size = 0;
  Op op = Op::unsupported;
  Operand dst, src;
  bool alternate_entry = false;
};
enum class Direction { forward, backward };
enum class Dispatch { indexed_table, relative_register };
struct Candidate
{
  uint64_t start = bad_address, end = bad_address, read = bad_address, dispatch = bad_address;
  unsigned address_bits = 0, read_bits = 0;
  Direction direction = Direction::forward;
  Dispatch dispatch_kind = Dispatch::indexed_table;
  int vip = -1, value = -1, key = -1, dispatch_base = -1;
  bool stack_key_update = false;
  uint64_t table_displacement = 0;
  std::vector<Instruction> support;
};

// Strict contiguous local candidate, at most 128 instructions. No naming
// convention, fixed register assignment, target enumeration or VM identity.
std::optional<Candidate> recognize(const std::vector<Instruction> &, unsigned address_bits);

// Unknown state is never merged merely because its native handler matches.
// Values belong to one admitted region publication and memory/context epoch.
struct LogicalState
{
  uint64_t publication = 0, native = bad_address, context = 0, memory_epoch = 0;
  std::optional<uint64_t> vip, key, virtual_stack, dispatch_base;
};
bool same_logical_state(const LogicalState &, const LogicalState &, bool stateful_key);

// Descriptive role-normalized syntax only. Equality is NOT semantic proof and
// never authorizes summary reuse; constants, widths and ordering are retained.
std::string normalized_shape(const Candidate &);
} // namespace chernobog::vm
