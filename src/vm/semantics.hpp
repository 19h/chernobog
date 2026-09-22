#pragma once
#include "region.hpp"
#include <z3++.h>
#include <array>
#include <memory>

namespace chernobog::vm {
// Normal-completion semantics in flat little-endian modular-address memory.
// All accesses succeed; exceptions, concurrency, devices and segment bases are
// outside this contract. Near returns additionally require CET shadow stacks
// disabled. The summary never authorizes suppressing an access.
struct Access
{
  bool write;
  unsigned bits;
  z3::expr address, value;
  uint64_t site = bad_address; // provenance only; excluded from role equivalence
};
struct Summary
{
  Candidate candidate;
  std::vector<std::string> roles;
  std::vector<z3::expr> registers;
  z3::expr memory, next_pc;
  std::vector<Access> accesses;
  std::vector<z3::expr> flags; // CF, PF, AF, ZF, SF, OF
  std::array<bool,6> defined{{true,true,true,true,true,true}};
  Summary(z3::context &, Candidate);
};
// Re-recognizes support and ignores caller-supplied role claims. Invalid
// architecture/operands or unsupported effects return null, never a partial proof.
std::unique_ptr<Summary> summarize(z3::context &, const Candidate &);
enum class Equivalence { equivalent, different, unknown, incompatible };
struct Comparison
{
  Equivalence result = Equivalence::incompatible;
  std::string reason;
};
Comparison compare(const Summary &, const Summary &, unsigned timeout_ms=100,
                   unsigned resource_limit=200000);
} // namespace chernobog::vm
