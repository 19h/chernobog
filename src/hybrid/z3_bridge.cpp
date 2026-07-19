#include "z3_bridge.hpp"

#include <pro.h>
#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>
#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <deque>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>

namespace chernobog::hybrid {
namespace {

struct DeobfuscationProjection
{
  std::shared_ptr<const TargetEvidence> source;
  std::vector<RuntimeStringCandidate> runtime_strings;
  std::vector<FunctionChunkIdentity> function_identity;
  std::map<uint64_t, uint8_t> authorized_function_bytes;
  bool sealing_open = true;
};

struct Registry
{
  std::mutex mutex;
  std::map<int64_t, std::shared_ptr<const TargetEvidence>> evidence;
  std::map<int64_t, std::shared_ptr<const DeobfuscationProjection>>
      deobfuscation_projections;
  std::map<int64_t, std::deque<Z3ModelReplayRequest>> replays;
};

Registry &registry()
{
  static Registry value;
  return value;
}

std::shared_ptr<const TargetEvidence> registry_evidence(int64_t database_id)
{
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto found = state.evidence.find(database_id);
  return found == state.evidence.end() ? nullptr : found->second;
}

HybridEntryMode current_entry_mode(HybridArch architecture, ea_t address)
{
  if ( architecture != HybridArch::ARM32 )
    return HybridEntryMode::DEFAULT;
  const int t_register = str2reg("T");
  if ( t_register < 0 )
    return HybridEntryMode::UNKNOWN;
  const sel_t state = get_sreg(address, t_register);
  if ( state == BADSEL )
    return HybridEntryMode::UNKNOWN;
  return state == 0 ? HybridEntryMode::ARM : HybridEntryMode::THUMB;
}

void set_reason(std::string *reason, const std::string &value)
{
  if ( reason != nullptr )
    *reason = value;
}

std::string address_string(uint64_t address)
{
  std::ostringstream out;
  out << "0x" << std::uppercase << std::hex << address;
  return out.str();
}

template <typename Identity>
bool byte_identity_matches(const Identity &expected, const char *kind,
                           size_t index, std::string *reason)
{
  if ( expected.bytes.empty() )
  {
    set_reason(reason, std::string(kind) + " identity "
        + std::to_string(index) + " is empty");
    return false;
  }
  std::vector<uint8_t> bytes(expected.bytes.size(), 0);
  std::vector<uint8_t> mask((expected.bytes.size() + 7) / 8, 0);
  if ( get_bytes(bytes.data(), ssize_t(bytes.size()), ea_t(expected.start),
                 GMB_READALL, mask.data()) < 0 )
  {
    set_reason(reason, std::string("get_bytes failed for ") + kind + " "
        + std::to_string(index) + " at " + address_string(expected.start));
    return false;
  }

  const IdentityComparison comparison = hybrid_compare_identity_bytes(
      expected.bytes, expected.loaded_mask, bytes, mask);
  if ( comparison.matches() )
    return true;

  std::ostringstream out;
  out << kind << " " << index << " at "
      << address_string(expected.start + comparison.offset) << ": ";
  switch ( comparison.mismatch )
  {
    case IdentityMismatchKind::BYTE_VECTOR_SIZE:
      out << "byte-vector size changed (expected=" << comparison.expected_size
          << ", actual=" << comparison.actual_size << ")";
      break;
    case IdentityMismatchKind::MASK_VECTOR_SIZE:
      out << "loaded-mask size invalid (expected=" << comparison.expected_size
          << ", actual=" << comparison.actual_size << ")";
      break;
    case IdentityMismatchKind::LOADED_STATE:
      out << "loaded state changed (expected=" << unsigned(comparison.expected_byte)
          << ", actual=" << unsigned(comparison.actual_byte) << ")";
      break;
    case IdentityMismatchKind::BYTE_VALUE:
      out << "byte changed (expected=0x" << std::hex << std::uppercase
          << unsigned(comparison.expected_byte) << ", actual=0x"
          << unsigned(comparison.actual_byte) << ")";
      break;
    case IdentityMismatchKind::NONE:
      break;
  }
  set_reason(reason, out.str());
  return false;
}

bool current_function_shape_matches(
    const TargetEvidence &evidence,
    const std::vector<FunctionChunkIdentity> &expected_identity,
    std::vector<range_t> *current_chunks,
    std::string *reason = nullptr)
{
  func_t *function = get_func(ea_t(evidence.scope.function_start));
  if ( function == nullptr || uint64_t(function->start_ea) != evidence.scope.function_start )
  {
    set_reason(reason, "selected function no longer exists at "
        + address_string(evidence.scope.function_start));
    return false;
  }
  if ( current_entry_mode(evidence.architecture, function->start_ea)
    != evidence.entry_mode )
  {
    set_reason(reason, "entry execution mode changed at "
        + address_string(evidence.scope.function_start));
    return false;
  }
  qstring current_name;
  HybridFunctionProfile current_profile;
  if ( get_func_name(&current_name, function->start_ea) > 0 )
    current_profile = hybrid_function_profile_from_name(current_name.c_str());
  if ( current_profile.flavor == HybridFunctionFlavor::NATIVE )
  {
    tinfo_t type;
    func_type_data_t details;
    if ( get_tinfo(&type, function->start_ea)
      && type.get_func_details(&details, GTD_CALC_ARGLOCS) )
    {
      current_profile.explicit_arguments = details.size();
      current_profile.explicit_arguments_known = true;
    }
  }
  const HybridFunctionProfile &expected_profile = evidence.function_profile;
  if ( current_profile.flavor != expected_profile.flavor
    || current_profile.name != expected_profile.name
    || current_profile.objc_selector != expected_profile.objc_selector
    || current_profile.explicit_arguments != expected_profile.explicit_arguments
    || current_profile.explicit_arguments_known
       != expected_profile.explicit_arguments_known )
  {
    set_reason(reason, "function name/type-derived entry profile changed at "
        + address_string(evidence.scope.function_start));
    return false;
  }

  std::vector<range_t> chunks;
  func_tail_iterator_t iterator(function);
  for ( bool ok = iterator.main(); ok; ok = iterator.next() )
    chunks.push_back(iterator.chunk());
  if ( chunks.size() != expected_identity.size() )
  {
    set_reason(reason, "function chunk count changed (expected="
        + std::to_string(expected_identity.size()) + ", actual="
        + std::to_string(chunks.size()) + ")");
    return false;
  }

  for ( size_t index = 0; index < chunks.size(); ++index )
  {
    const range_t &current = chunks[index];
    const FunctionChunkIdentity &expected = expected_identity[index];
    if ( current.end_ea <= current.start_ea
      || uint64_t(current.start_ea) != expected.start
      || uint64_t(current.end_ea - current.start_ea) != expected.bytes.size() )
    {
      set_reason(reason, "function chunk topology changed at index "
          + std::to_string(index));
      return false;
    }
  }
  if ( current_chunks != nullptr )
    *current_chunks = std::move(chunks);
  return true;
}

bool current_function_identity_matches(
    const TargetEvidence &evidence,
    const std::vector<FunctionChunkIdentity> &expected_identity,
    std::string *reason = nullptr)
{
  if ( !current_function_shape_matches(
          evidence, expected_identity, nullptr, reason) )
  {
    return false;
  }
  for ( size_t index = 0; index < expected_identity.size(); ++index )
    if ( !byte_identity_matches(
            expected_identity[index], "function chunk", index, reason) )
      return false;
  return true;
}

bool current_function_identity_matches(const TargetEvidence &evidence,
                                       std::string *reason = nullptr)
{
  return current_function_identity_matches(
      evidence, evidence.function_identity, reason);
}

bool capture_current_function_identity(
    const TargetEvidence &source,
    std::vector<FunctionChunkIdentity> *captured,
    std::string *reason = nullptr)
{
  if ( captured == nullptr )
  {
    set_reason(reason, "missing function-identity destination");
    return false;
  }
  std::vector<range_t> chunks;
  if ( !current_function_shape_matches(
          source, source.function_identity, &chunks, reason) )
  {
    return false;
  }

  std::vector<FunctionChunkIdentity> result;
  result.reserve(chunks.size());
  for ( size_t index = 0; index < chunks.size(); ++index )
  {
    const range_t &chunk = chunks[index];
    const size_t size = size_t(chunk.end_ea - chunk.start_ea);
    FunctionChunkIdentity identity;
    identity.start = uint64_t(chunk.start_ea);
    identity.bytes.assign(size, 0);
    identity.loaded_mask.assign((size + 7) / 8, 0);
    if ( get_bytes(identity.bytes.data(), ssize_t(size), chunk.start_ea,
                   GMB_READALL, identity.loaded_mask.data()) < 0 )
    {
      set_reason(reason, "get_bytes failed while sealing function chunk "
          + std::to_string(index) + " at "
          + address_string(identity.start));
      return false;
    }
    result.push_back(std::move(identity));
  }
  *captured = std::move(result);
  return true;
}

bool current_identity_matches(const TargetEvidence &evidence,
                              std::string *reason = nullptr)
{
  if ( !current_function_identity_matches(evidence, reason) )
    return false;
  for ( size_t index = 0; index < evidence.context_identity.size(); ++index )
    if ( !byte_identity_matches(evidence.context_identity[index],
                                "consumed context", index, reason) )
      return false;
  return true;
}

std::string native_register_name(HybridArch architecture, int reg)
{
  static const char *x86_64[] = {
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
  static const char *x86_32[] = {
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
  switch ( architecture )
  {
    case HybridArch::X86_64:
      if ( reg >= RAX_X86_GPR64(0) && reg <= RAX_X86_GPR64(15) )
        return x86_64[reg - RAX_X86_GPR64(0)];
      break;
    case HybridArch::X86_32:
      if ( reg >= RAX_X86_GPR32(0) && reg <= RAX_X86_GPR32(7) )
        return x86_32[reg - RAX_X86_GPR32(0)];
      break;
    case HybridArch::ARM64:
      if ( reg >= RAX_ARM64_X(0) && reg <= RAX_ARM64_X(30) )
        return "X" + std::to_string(reg - RAX_ARM64_X(0));
      if ( reg == RAX_ARM64_REG_SP ) return "SP";
      break;
    case HybridArch::ARM32:
      if ( reg >= RAX_ARM_R(0) && reg <= RAX_ARM_R(12) )
        return "R" + std::to_string(reg - RAX_ARM_R(0));
      if ( reg == RAX_ARM_REG_SP ) return "SP";
      if ( reg == RAX_ARM_REG_LR ) return "LR";
      break;
    case HybridArch::CORTEX_M:
      if ( reg >= RAX_CM_R(0) && reg <= RAX_CM_R(12) )
        return "R" + std::to_string(reg - RAX_CM_R(0));
      if ( reg == RAX_REG_SP ) return "SP";
      if ( reg == RAX_CM_REG_LR ) return "LR";
      break;
    case HybridArch::RISCV64:
      if ( reg >= RAX_RISCV_X(0) && reg <= RAX_RISCV_X(31) )
        return "X" + std::to_string(reg - RAX_RISCV_X(0));
      break;
    case HybridArch::HEXAGON:
      if ( reg >= RAX_HEX_R(0) && reg <= RAX_HEX_R(31) )
        return "R" + std::to_string(reg - RAX_HEX_R(0));
      break;
    default:
      break;
  }
  return {};
}

} // namespace

bool hybrid_publish_evidence(
    int64_t database_id, std::shared_ptr<const TargetEvidence> evidence)
{
  bool valid = true;
  std::string rejection_reason;
  if ( evidence && database_id != int64_t(get_dbctx_id()) )
  {
    valid = false;
    rejection_reason = "database context changed";
  }
  else if ( evidence )
  {
    valid = current_identity_matches(*evidence, &rejection_reason);
  }
  if ( evidence && !valid )
    msg("[chernobog][rax] Evidence freshness rejection: %s\n",
        rejection_reason.c_str());
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  state.deobfuscation_projections.erase(database_id);
  if ( evidence && valid )
    state.evidence[database_id] = std::move(evidence);
  else
    state.evidence.erase(database_id);
  return valid;
}

void hybrid_clear_evidence(int64_t database_id)
{
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  state.evidence.erase(database_id);
  state.deobfuscation_projections.erase(database_id);
  state.replays.erase(database_id);
}

bool hybrid_current_evidence_is_fresh(uint64_t function_start)
{
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(int64_t(get_dbctx_id()));
  return evidence && evidence->scope.function_start == function_start
      && current_identity_matches(*evidence);
}

bool hybrid_begin_deobfuscation_projection(uint64_t function_start)
{
  const int64_t database_id = int64_t(get_dbctx_id());
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(database_id);
  if ( !evidence || evidence->scope.function_start != function_start
    || !current_identity_matches(*evidence) )
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.deobfuscation_projections.erase(database_id);
    return false;
  }

  auto projection = std::make_shared<DeobfuscationProjection>();
  projection->source = evidence;
  projection->runtime_strings = hybrid_consensus_runtime_strings(*evidence);
  projection->function_identity = evidence->function_identity;

  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto current = state.evidence.find(database_id);
  if ( current == state.evidence.end() || current->second != evidence )
    return false;
  state.deobfuscation_projections[database_id] = std::move(projection);
  return true;
}

void hybrid_abandon_deobfuscation_projection(uint64_t function_start)
{
  const int64_t database_id = int64_t(get_dbctx_id());
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto found = state.deobfuscation_projections.find(database_id);
  if ( found != state.deobfuscation_projections.end() && found->second
    && found->second->source
    && found->second->source->scope.function_start == function_start )
  {
    state.deobfuscation_projections.erase(found);
  }
}

bool hybrid_authorize_deobfuscation_patch(
    uint64_t function_start, uint64_t address, size_t size)
{
  if ( size == 0 || size > 4096
    || address > UINT64_MAX - uint64_t(size) )
  {
    return false;
  }

  const int64_t database_id = int64_t(get_dbctx_id());
  std::shared_ptr<const DeobfuscationProjection> projection;
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto found = state.deobfuscation_projections.find(database_id);
    if ( found == state.deobfuscation_projections.end() )
      return false;
    projection = found->second;
  }
  if ( !projection || !projection->sealing_open || !projection->source
    || projection->source->scope.function_start != function_start )
  {
    return false;
  }

  const FunctionChunkIdentity *containing_chunk = nullptr;
  for ( const FunctionChunkIdentity &chunk : projection->function_identity )
  {
    if ( address >= chunk.start
      && address - chunk.start <= chunk.bytes.size()
      && size <= chunk.bytes.size() - size_t(address - chunk.start) )
    {
      containing_chunk = &chunk;
      break;
    }
  }
  if ( containing_chunk == nullptr )
    return false;

  std::vector<uint8_t> bytes(size, 0);
  std::vector<uint8_t> mask((size + 7) / 8, 0);
  if ( get_bytes(bytes.data(), ssize_t(size), ea_t(address), GMB_READALL,
                 mask.data()) < 0 )
  {
    return false;
  }
  for ( size_t offset = 0; offset < size; ++offset )
    if ( (mask[offset / 8] & uint8_t(1u << (offset & 7))) == 0 )
      return false;

  auto updated = std::make_shared<DeobfuscationProjection>(*projection);
  for ( size_t offset = 0; offset < size; ++offset )
  {
    const uint64_t byte_address = address + uint64_t(offset);
    const auto existing = updated->authorized_function_bytes.find(byte_address);
    if ( existing != updated->authorized_function_bytes.end()
      && existing->second != bytes[offset] )
    {
      return false;
    }
    updated->authorized_function_bytes[byte_address] = bytes[offset];
  }

  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto found = state.deobfuscation_projections.find(database_id);
  if ( found == state.deobfuscation_projections.end()
    || found->second != projection )
  {
    return false;
  }
  found->second = std::move(updated);
  return true;
}

bool hybrid_seal_deobfuscation_projection(uint64_t function_start)
{
  const int64_t database_id = int64_t(get_dbctx_id());
  std::shared_ptr<const DeobfuscationProjection> projection;
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto found = state.deobfuscation_projections.find(database_id);
    if ( found == state.deobfuscation_projections.end() )
      return false;
    projection = found->second;
  }
  if ( !projection || !projection->sealing_open || !projection->source
    || projection->source->scope.function_start != function_start )
  {
    return false;
  }

  std::vector<FunctionChunkIdentity> sealed_identity;
  std::string rejection_reason;
  if ( !capture_current_function_identity(
          *projection->source, &sealed_identity, &rejection_reason) )
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto found = state.deobfuscation_projections.find(database_id);
    if ( found != state.deobfuscation_projections.end()
      && found->second == projection )
    {
      state.deobfuscation_projections.erase(found);
    }
    msg("[chernobog][rax] Runtime plaintext projection invalidated at %a: %s\n",
        ea_t(function_start), rejection_reason.c_str());
    return false;
  }

  size_t changed_bytes = 0;
  std::string unauthorized_reason;
  if ( sealed_identity.size() == projection->function_identity.size() )
  {
    for ( size_t chunk = 0; chunk < sealed_identity.size(); ++chunk )
    {
      const FunctionChunkIdentity &before = projection->function_identity[chunk];
      const FunctionChunkIdentity &after = sealed_identity[chunk];
      const size_t count = std::min(before.bytes.size(), after.bytes.size());
      for ( size_t offset = 0; offset < count; ++offset )
      {
        const bool before_loaded = offset / 8 < before.loaded_mask.size()
            && (before.loaded_mask[offset / 8]
                & uint8_t(1u << (offset & 7))) != 0;
        const bool after_loaded = offset / 8 < after.loaded_mask.size()
            && (after.loaded_mask[offset / 8]
                & uint8_t(1u << (offset & 7))) != 0;
        const uint64_t byte_address = after.start + uint64_t(offset);
        if ( before_loaded != after_loaded )
        {
          unauthorized_reason = "loaded state changed at "
              + address_string(byte_address);
          break;
        }
        if ( before_loaded && before.bytes[offset] != after.bytes[offset] )
        {
          const auto authorized =
              projection->authorized_function_bytes.find(byte_address);
          if ( authorized == projection->authorized_function_bytes.end()
            || authorized->second != after.bytes[offset] )
          {
            unauthorized_reason = "unregistered function-byte change at "
                + address_string(byte_address);
            break;
          }
          ++changed_bytes;
        }
      }
      if ( !unauthorized_reason.empty() )
        break;
    }
  }
  if ( !unauthorized_reason.empty() )
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto found = state.deobfuscation_projections.find(database_id);
    if ( found != state.deobfuscation_projections.end()
      && found->second == projection )
    {
      state.deobfuscation_projections.erase(found);
    }
    msg("[chernobog][rax] Runtime plaintext projection invalidated at %a: %s\n",
        ea_t(function_start), unauthorized_reason.c_str());
    return false;
  }

  auto sealed = std::make_shared<DeobfuscationProjection>(*projection);
  sealed->function_identity = std::move(sealed_identity);
  sealed->authorized_function_bytes.clear();
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto found = state.deobfuscation_projections.find(database_id);
    if ( found == state.deobfuscation_projections.end()
      || found->second != projection )
    {
      return false;
    }
    found->second = std::move(sealed);
  }
  if ( changed_bytes != 0 && !projection->runtime_strings.empty() )
  {
    msg("[chernobog][rax] Retained %zu runtime plaintexts across %zu trusted function-byte changes at %a\n",
        projection->runtime_strings.size(), changed_bytes,
        ea_t(function_start));
  }
  return true;
}

bool hybrid_finish_deobfuscation_projection(uint64_t function_start)
{
  // Capture any final trusted mutations before making the display identity
  // immutable. A later decompilation or analyst edit cannot reopen this lease;
  // only a new exact-fresh ensure_explored() prerequisite can do that.
  if ( !hybrid_seal_deobfuscation_projection(function_start) )
    return false;

  const int64_t database_id = int64_t(get_dbctx_id());
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto found = state.deobfuscation_projections.find(database_id);
  if ( found == state.deobfuscation_projections.end() || !found->second
    || !found->second->source
    || found->second->source->scope.function_start != function_start )
  {
    return false;
  }
  auto finished =
      std::make_shared<DeobfuscationProjection>(*found->second);
  finished->sealing_open = false;
  found->second = std::move(finished);
  return true;
}

std::vector<RuntimeStringCandidate> hybrid_current_runtime_strings(
    uint64_t function_start)
{
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(int64_t(get_dbctx_id()));
  if ( !evidence || evidence->scope.function_start != function_start
    || !current_identity_matches(*evidence) )
  {
    return {};
  }
  return hybrid_consensus_runtime_strings(*evidence);
}

std::vector<RuntimeStringCandidate>
hybrid_current_runtime_strings_for_decompilation(uint64_t function_start)
{
  std::shared_ptr<const TargetEvidence> evidence;
  std::shared_ptr<const DeobfuscationProjection> projection;
  {
    Registry &state = registry();
    std::lock_guard<std::mutex> lock(state.mutex);
    const int64_t database_id = int64_t(get_dbctx_id());
    const auto evidence_found = state.evidence.find(database_id);
    if ( evidence_found != state.evidence.end() )
      evidence = evidence_found->second;
    const auto projection_found =
        state.deobfuscation_projections.find(database_id);
    if ( projection_found != state.deobfuscation_projections.end() )
      projection = projection_found->second;
  }
  if ( evidence && evidence->scope.function_start == function_start
    && current_function_identity_matches(*evidence) )
  {
    return hybrid_consensus_runtime_strings(*evidence);
  }
  if ( !projection || projection->source != evidence
    || !projection->source
    || projection->source->scope.function_start != function_start
    || !current_function_identity_matches(
          *projection->source, projection->function_identity) )
  {
    return {};
  }
  return projection->runtime_strings;
}

HybridBranchCheck hybrid_check_current_branch_claim(
    uint64_t function_start, uint64_t branch_instruction,
    bool expected_taken)
{
  HybridBranchCheck result;
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(int64_t(get_dbctx_id()));
  if ( !evidence || evidence->scope.function_start != function_start )
    return result;
  result.evidence_available = true;
  result.generation = evidence->scope.generation;
  result.snapshot_current = current_identity_matches(*evidence);
  if ( result.snapshot_current )
    result.claim = evidence->check_branch_claim(
        branch_instruction, expected_taken);
  return result;
}

std::vector<Z3ConcretePredicateInput> hybrid_collect_current_z3_inputs(
    uint64_t function_start, uint64_t branch_instruction)
{
  std::vector<Z3ConcretePredicateInput> result;
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(int64_t(get_dbctx_id()));
  if ( !evidence || evidence->scope.function_start != function_start
    || !current_identity_matches(*evidence) || get_hexdsp() == nullptr )
    return result;
  for ( const StatePoint &state : evidence->events.states )
  {
    if ( state.kind != StatePoint::Kind::PredicateInput
      || state.source != branch_instruction )
      continue;
    Z3ConcretePredicateInput input;
    input.run_id = state.run_id;
    input.seed = state.seed;
    for ( const RegisterValue &value : state.regs )
    {
      const std::string name = native_register_name(
          evidence->architecture, value.reg);
      if ( name.empty() )
        continue;
      const int ida_register = str2reg(name.c_str());
      if ( ida_register < 0 )
        continue;
      const mreg_t micro_register = reg2mreg(ida_register);
      if ( micro_register == mr_none )
        continue;
      input.registers.push_back(Z3ConcreteRegisterInput{
          int(micro_register), value.width, value.value, name });
    }
    std::sort(input.registers.begin(), input.registers.end(),
              [](const Z3ConcreteRegisterInput &left,
                 const Z3ConcreteRegisterInput &right)
    {
      return std::tie(left.micro_register, left.width, left.native_register)
           < std::tie(right.micro_register, right.width, right.native_register);
    });
    if ( !input.registers.empty() )
      result.push_back(std::move(input));
  }
  return result;
}

std::vector<HybridObservedTargetCandidate>
hybrid_current_indirect_target_candidates(
    uint64_t function_start, uint64_t instruction)
{
  std::vector<HybridObservedTargetCandidate> result;
  const std::shared_ptr<const TargetEvidence> evidence =
      registry_evidence(int64_t(get_dbctx_id()));
  if ( !evidence || evidence->scope.function_start != function_start
    || !current_identity_matches(*evidence) )
    return result;
  std::map<std::pair<uint64_t, ExecEdge::Kind>, std::set<uint32_t>> grouped;
  std::map<std::pair<uint64_t, ExecEdge::Kind>, size_t> counts;
  for ( const IndirectTargetObservation &observation : evidence->indirect_targets )
  {
    if ( observation.instruction != instruction )
      continue;
    const auto key = std::make_pair(observation.target, observation.kind);
    ++counts[key];
    grouped[key].insert(observation.provenance.run_id);
  }
  for ( const auto &entry : grouped )
  {
    HybridObservedTargetCandidate candidate;
    candidate.target = entry.first.first;
    candidate.kind = entry.first.second;
    candidate.observations = counts[entry.first];
    candidate.runs.assign(entry.second.begin(), entry.second.end());
    result.push_back(std::move(candidate));
  }
  return result;
}

bool hybrid_queue_z3_model_replay(
    int64_t database_id, Z3ModelReplayRequest request)
{
  if ( request.arguments.size() > 32 )
    return false;
  if ( request.label.size() > 256 )
    request.label.resize(256);
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  std::deque<Z3ModelReplayRequest> &queue = state.replays[database_id];
  if ( queue.size() >= 16 )
    return false;
  queue.push_back(std::move(request));
  return true;
}

std::vector<Z3ModelReplayRequest> hybrid_take_z3_model_replays(
    int64_t database_id, uint64_t function_start)
{
  std::vector<Z3ModelReplayRequest> result;
  Registry &state = registry();
  std::lock_guard<std::mutex> lock(state.mutex);
  auto found = state.replays.find(database_id);
  if ( found == state.replays.end() )
    return result;
  std::deque<Z3ModelReplayRequest> retained;
  while ( !found->second.empty() )
  {
    Z3ModelReplayRequest request = std::move(found->second.front());
    found->second.pop_front();
    if ( request.function_start == function_start )
      result.push_back(std::move(request));
    else
      retained.push_back(std::move(request));
  }
  found->second = std::move(retained);
  if ( found->second.empty() )
    state.replays.erase(found);
  return result;
}

} // namespace chernobog::hybrid
