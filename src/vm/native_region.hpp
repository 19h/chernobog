#pragma once
#include "region.hpp"
#include "../hybrid/program_model.hpp"
#include "../hybrid/rax_loader.hpp"
#include <cstddef>
#include <functional>

namespace chernobog::vm {
// An immutable allowlist for bounded native execution, separate from IDA
// function ownership and from a proven VM/handler identity. Calls execute their
// native instructions; no callee-return summary or ABI equivalence is assumed.
struct NativeHead
{
  uint64_t address = bad_address;
  std::vector<uint8_t> bytes;
  int32_t flow = RAX_FLOW_UNKNOWN;
};
struct NativeFrontier
{
  uint64_t site = bad_address;
  std::string reason;
};
using NativeDecoder=std::function<bool(uint64_t,const uint8_t *,size_t,rax_decoded &)>;
struct NativeExtension;
class NativeRegion
{
public:
  bool available() const { return at(entry_)!=nullptr; }
  uint64_t entry() const { return entry_; }
  uint64_t identity() const { return identity_; }
  uint64_t image_hash() const { return image_hash_; }
  uint64_t generation() const { return generation_; }
  unsigned address_bits() const { return arch_==hybrid::HybridArch::X86_64?64:arch_==hybrid::HybridArch::X86_32?32:0; }
  bool truncated() const { return truncated_; }
  const std::vector<NativeHead> &heads() const { return heads_; }
  const std::vector<NativeFrontier> &frontiers() const { return frontiers_; }
  const NativeHead *at(uint64_t) const;
  bool matches(const hybrid::ProgramImage &) const;
private:
  friend NativeRegion plan_native_region(const hybrid::ProgramImage &,
      const hybrid::RaxApi *,uint64_t,size_t,const NativeDecoder &);
  friend NativeExtension extend_native_region(const NativeRegion &,const hybrid::ProgramImage &,
      const hybrid::RaxApi *,uint64_t,uint64_t,size_t,const NativeDecoder &);
  uint64_t entry_=bad_address,identity_=0,image_hash_=0,generation_=0;
  hybrid::HybridArch arch_=hybrid::HybridArch::UNSUPPORTED;
  bool truncated_=false;
  std::vector<NativeHead> heads_;
  std::vector<NativeFrontier> frontiers_;
};
// Decode syntactic alternatives from one entry, including direct callees and
// possible continuations. Indirect destinations are not enumerated. Stop before
// traps, external/mixed-mode/unloaded/nonexecutecutable spans or overlapping
// instruction interpretations. Hard limit 4096 heads, no database access.
NativeRegion plan_native_region(const hybrid::ProgramImage &,
    const hybrid::RaxApi *,uint64_t entry,size_t maximum_heads=4096,const NativeDecoder &decoder={});
struct NativeExtension
{
  NativeRegion region;
  bool admitted=false;
  size_t added_heads=0;
  std::string reason;
};
// Add one explicitly observed indirect/return destination to a copied plan.
// The caller supplies the observation; this validates native byte admission,
// not target uniqueness, logical VM ownership, or semantic equivalence.
NativeExtension extend_native_region(const NativeRegion &,const hybrid::ProgramImage &,
    const hybrid::RaxApi *,uint64_t source,uint64_t target,size_t maximum_heads=4096,
    const NativeDecoder &decoder={});
} // namespace chernobog::vm
