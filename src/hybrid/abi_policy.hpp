/*
 * abi_policy.hpp -- deterministic, IDA-free ABI and input-seeding policy.
 *
 * This is the single production description used by the IDA call-site input
 * collector and the rax driver. It deliberately exposes a pure placement plan
 * so every supported ABI can be tested without either IDA or an emulator.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <rax.h>

#include "emu_input.hpp"
#include "program_model.hpp"

namespace chernobog::hybrid {

enum class HybridAbi : uint8_t
{
  UNKNOWN = 0,
  X86_32,
  X86_64_SYSV,
  X86_64_WIN64,
  AAPCS32,
  AAPCS64,
  RISCV64,
  CORTEX_M,
  HEXAGON,
};

struct HybridAbiLayout
{
  HybridAbi abi = HybridAbi::UNKNOWN;
  const char *name = "unknown";
  uint8_t pointer_size = 0;
  bool return_address_on_stack = false;
  uint32_t stack_argument_offset = 0; // home/shadow bytes before arg N+1
  std::vector<int> argument_registers; // positional integer carriers (rax ids)
  std::vector<const char *> ida_argument_registers; // same order, IDA names

  bool supported() const { return abi != HybridAbi::UNKNOWN; }
};

// Select an ABI from the portable architecture plus the only platform-specific
// distinction hybrid currently needs. X86_16 deliberately remains unsupported.
HybridAbi hybrid_abi_for_arch(HybridArch arch, bool windows_x64 = false);
const HybridAbiLayout &hybrid_abi_layout(HybridAbi abi);
const char *hybrid_abi_name(HybridAbi abi);

enum class HybridSeedValueKind : uint8_t
{
  ZERO = 0,
  ONE,
  U16_MAX,
  I16_MAX,
  I16_MIN,
  IMAGE_POINTER,
  STACK_POINTER,
  MIXED,
};

struct HybridSeedValue
{
  uint64_t value = 0;
  HybridSeedValueKind kind = HybridSeedValueKind::ZERO;
};

// Produce exactly `count` deterministic values. Every eight consecutive
// argument positions cover zero/one/integer boundaries, image/stack pointers,
// and a mixed scalar (rotated by seed). STACK_POINTER is emitted only when the
// supplied stack range is non-empty, non-overflowing, and the value is mapped.
std::vector<HybridSeedValue> hybrid_seed_argument_corpus(
    uint64_t seed, size_t count, uint64_t image_lo,
    uint64_t stack_base, uint64_t stack_size);

struct HybridAbiRegisterWrite
{
  int reg = -1;
  uint64_t value = 0;
};

struct HybridAbiStackWrite
{
  uint64_t address = 0;
  std::array<uint8_t, 8> bytes{};
  uint8_t size = 0;
};

enum class HybridAbiPlanError : uint8_t
{
  NONE = 0,
  UNSUPPORTED_ABI,
  INVALID_REGISTER,
  STACK_OFFSET_MISMATCH,
  ADDRESS_OVERFLOW,
  STACK_OUT_OF_RANGE,
};

struct HybridAbiInputPlan
{
  HybridAbiPlanError error = HybridAbiPlanError::NONE;
  std::vector<HybridAbiRegisterWrite> registers;
  std::vector<HybridAbiStackWrite> stack;

  bool valid() const { return error == HybridAbiPlanError::NONE; }
};

// Translate positional/explicit input into ordered rax register writes and
// target-endian stack writes. Later explicit writes intentionally follow (and
// therefore override) earlier positional writes, matching engine semantics.
HybridAbiInputPlan hybrid_plan_abi_input(const HybridAbiLayout &layout,
                                   const EmuInput &input,
                                   uint64_t entry_sp,
                                   uint64_t stack_base,
                                   uint64_t stack_size,
                                   bool big_endian);

} // namespace chernobog::hybrid
