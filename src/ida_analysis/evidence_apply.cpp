#include "evidence_apply.hpp"

#include "analysis_config.hpp"
#include "../hybrid/decoder_core.hpp"
#include "../hybrid/evidence.hpp"

#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <auto.hpp>
#include <kernwin.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace chernobog::ida_analysis {
namespace {

using chernobog::hybrid::BranchDisposition;
using chernobog::hybrid::DataAcc;
using chernobog::hybrid::DataScope;
using chernobog::hybrid::DecoderDirectTarget;
using chernobog::hybrid::DecoderTargetKind;
using chernobog::hybrid::ExecEdge;
using chernobog::hybrid::HybridArch;
using chernobog::hybrid::RuntimeStringCandidate;
using chernobog::hybrid::StaticInstructionEvidence;
using chernobog::hybrid::TargetEvidence;

constexpr const char *kCommentPrefix = "[chernobog][rax-analysis] ";
using RunKey = std::pair<uint32_t, uint64_t>;

bool target_is_executable(ea_t target)
{
  const segment_t *segment = getseg(target);
  return target != BADADDR && is_mapped(target) && segment != nullptr
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0)
      && !is_tail(get_flags(target));
}

bool nonexecutable_data(ea_t address)
{
  const segment_t *segment = getseg(address);
  return segment != nullptr
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) == 0);
}

bool cref_exists(ea_t from, ea_t to)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_CODE);
        ok; ok = xref.next_from() )
  {
    if ( xref.to == to )
      return true;
  }
  return false;
}

bool dref_exists(ea_t from, ea_t to)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_DATA);
        ok; ok = xref.next_from() )
  {
    if ( xref.to == to )
      return true;
  }
  return false;
}

bool append_analysis_comment(ea_t address, const std::string &text)
{
  qstring tagged = kCommentPrefix;
  tagged.append(text.c_str());
  qstring current;
  get_cmt(&current, address, true);
  if ( current.find(tagged.c_str()) != qstring::npos )
    return false;
  if ( !current.empty() )
    current.append("\n");
  current.append(tagged);
  return set_cmt(address, current.c_str(), true);
}

qstring address_label(ea_t address)
{
  qstring name = get_name(address);
  if ( !name.empty() )
    return name;
  name.sprnt("%a", address);
  return name;
}

bool source_is_instruction(ea_t source)
{
  const flags64_t flags = get_flags(source);
  return is_code(flags) && is_head(flags);
}

bool has_protected_metadata(flags64_t flags)
{
  return has_any_name(flags) || has_cmt(flags) || has_extra_cmts(flags);
}

bool ensure_code_target(ea_t target, bool call, const EvidenceApplyConfig &config,
                        EvidenceApplyStats &stats)
{
  if ( !target_is_executable(target) )
    return false;
  const flags64_t flags = get_flags(target);
  if ( is_code(flags) && is_head(flags) )
    return true;
  if ( !is_unknown(flags) || !config.make_code )
    return false;
  insn_t decoded;
  if ( decode_insn(&decoded, target) <= 0 || create_insn(target) <= 0 )
    return false;
  if ( call )
    auto_make_proc(target);
  else
    auto_make_code(target);
  plan_ea(target);
  ++stats.code_items;
  return true;
}

bool add_code_reference(ea_t from, ea_t to, bool call,
                        const EvidenceApplyConfig &config,
                        EvidenceApplyStats &stats, bool dynamic)
{
  if ( !config.code_references || !source_is_instruction(from)
    || !ensure_code_target(to, call, config, stats) || cref_exists(from, to) )
  {
    return false;
  }
  const cref_t type = call ? fl_CN : fl_JN;
  if ( !add_cref(from, to, cref_t(int(type) | XREF_USER)) )
    return false;
  if ( dynamic )
    ++stats.dynamic_crefs;
  else
    ++stats.static_crefs;
  return true;
}

bool range_is_undefined_data(ea_t address, size_t size)
{
  const segment_t *segment = getseg(address);
  if ( size == 0 || !nonexecutable_data(address) || segment == nullptr
    || address >= segment->end_ea
    || size > size_t(segment->end_ea - address) )
    return false;
  for ( size_t offset = 0; offset < size; ++offset )
  {
    const ea_t current = address + ea_t(offset);
    const flags64_t flags = get_flags(current);
    if ( getseg(current) != segment || !is_mapped(current)
      || !is_unknown(flags) || has_protected_metadata(flags) )
    {
      return false;
    }
  }
  return true;
}

bool create_scalar(ea_t address, uint32_t size)
{
  switch ( size )
  {
    case 1: return create_byte(address, 1);
    case 2: return create_word(address, 2);
    case 4: return create_dword(address, 4);
    case 8: return create_qword(address, 8);
    case 16: return create_oword(address, 16);
    default: return false;
  }
}

bool create_pointer_offset(ea_t address, uint32_t size)
{
  if ( !create_scalar(address, size) )
    return false;
  if ( op_plain_offset(address, 0, 0) )
    return true;
  del_items(address, DELIT_SIMPLE, size);
  return false;
}

size_t exact_ascii_string_length(ea_t address, size_t maximum = 4096)
{
  const segment_t *segment = getseg(address);
  if ( segment == nullptr || !nonexecutable_data(address)
    || address >= segment->end_ea )
  {
    return 0;
  }
  maximum = std::min(maximum, size_t(segment->end_ea - address));
  size_t length = 0;
  for ( ; length < maximum; ++length )
  {
    const ea_t current = address + ea_t(length);
    const flags64_t flags = get_flags(current);
    if ( getseg(current) != segment || !is_mapped(current)
      || !is_loaded(current)
      || !is_unknown(flags) || has_protected_metadata(flags) )
    {
      return 0;
    }
    const uint8_t byte = get_byte(current);
    if ( byte == 0 )
      return length >= 4 ? length + 1 : 0;
    if ( byte < 0x20 || byte > 0x7E )
      return 0;
  }
  return 0;
}

bool create_ascii_string(ea_t address)
{
  if ( !nonexecutable_data(address) )
    return false;
  const size_t size = exact_ascii_string_length(address);
  return size != 0 && create_strlit(address, size, STRTYPE_C);
}

bool idb_matches_string(ea_t address, const std::string &value)
{
  if ( value.empty() || !range_is_undefined_data(address, value.size() + 1) )
    return false;
  for ( size_t index = 0; index < value.size(); ++index )
  {
    if ( !is_loaded(address + ea_t(index))
      || get_byte(address + ea_t(index)) != uint8_t(value[index]) )
      return false;
  }
  return is_loaded(address + ea_t(value.size()))
      && get_byte(address + ea_t(value.size())) == 0;
}

void apply_static_targets(const TargetEvidence &evidence,
                          const EvidenceApplyConfig &config,
                          EvidenceApplyStats &stats)
{
  for ( const StaticInstructionEvidence &item :
        evidence.static_analysis.instructions )
  {
    if ( !item.ida_projection_present || item.address != item.ida_head
      || item.rax.status != chernobog::hybrid::DecoderDecodeStatus::Valid )
    {
      continue;
    }
    const DecoderDirectTarget target =
        chernobog::hybrid::hybrid_decoder_direct_target(item.rax.instruction);
    if ( !target.valid )
      continue;
    const bool call = target.kind == DecoderTargetKind::Call;
    if ( target.kind != DecoderTargetKind::Call
      && target.kind != DecoderTargetKind::Jump )
    {
      continue;
    }
    add_code_reference(ea_t(item.address), ea_t(target.address), call,
                       config, stats, false);
  }
}

struct EdgeKey
{
  uint64_t from = 0;
  uint64_t to = 0;
  bool call = false;

  bool operator<(const EdgeKey &other) const
  {
    return std::tie(from, to, call)
         < std::tie(other.from, other.to, other.call);
  }
};

std::map<EdgeKey, std::set<RunKey>> corroborated_edges(
    const TargetEvidence &evidence)
{
  std::map<EdgeKey, std::set<RunKey>> result;
  for ( const auto &observation : evidence.indirect_targets )
  {
    if ( observation.kind != ExecEdge::Kind::Call
      && observation.kind != ExecEdge::Kind::Jump )
    {
      continue;
    }
    EdgeKey key;
    key.from = observation.instruction;
    key.to = observation.target;
    key.call = observation.kind == ExecEdge::Kind::Call;
    result[key].insert({ observation.provenance.run_id,
                         observation.provenance.seed });
  }
  return result;
}

void recover_function(ea_t target, const EvidenceApplyConfig &config,
                      EvidenceApplyStats &stats)
{
  if ( !config.function_recovery || !target_is_executable(target) )
    return;
  func_t *owner = get_func(target);
  if ( owner != nullptr )
    return; // never split an existing function
  if ( !source_is_instruction(target) )
    return;
  if ( add_func(target) )
    ++stats.functions;
}

void apply_dynamic_targets(const TargetEvidence &evidence,
                           const EvidenceApplyConfig &config,
                           EvidenceApplyStats &stats)
{
  for ( const auto &entry : corroborated_edges(evidence) )
  {
    if ( entry.second.size() < config.minimum_dynamic_runs )
      continue;
    const EdgeKey &edge = entry.first;
    const bool added = add_code_reference(
        ea_t(edge.from), ea_t(edge.to), edge.call, config, stats, true);
    if ( edge.call )
      recover_function(ea_t(edge.to), config, stats);
    if ( config.comments && (added || cref_exists(ea_t(edge.from), ea_t(edge.to))) )
    {
      qstring text;
      text.sprnt("corroborated %s target %s (%zu runs)",
                 edge.call ? "call" : "jump",
                 address_label(ea_t(edge.to)).c_str(), entry.second.size());
      if ( append_analysis_comment(ea_t(edge.from), text.c_str()) )
        ++stats.comments;
    }
  }
}

struct DataKey
{
  uint64_t from = 0;
  uint64_t address = 0;
  uint64_t value = 0;
  uint32_t size = 0;
  int kind = 0;

  bool operator<(const DataKey &other) const
  {
    return std::tie(from, address, value, size, kind)
         < std::tie(other.from, other.address, other.value,
                    other.size, other.kind);
  }
};

struct DrefKey
{
  uint64_t from = 0;
  uint64_t address = 0;
  int kind = 0;

  bool operator<(const DrefKey &other) const
  {
    return std::tie(from, address, kind)
         < std::tie(other.from, other.address, other.kind);
  }
};

void apply_data_evidence(const TargetEvidence &evidence,
                         const EvidenceApplyConfig &config,
                         EvidenceApplyStats &stats)
{
  std::map<DataKey, std::set<RunKey>> observations;
  std::map<DrefKey, std::set<RunKey>> reference_observations;
  for ( const DataAcc &access : evidence.events.data )
  {
    if ( access.scope != DataScope::IMAGE )
      continue;
    const RunKey run{ access.run_id, access.seed };
    observations[{ access.from, access.addr, access.value,
                   access.size, access.kind }]
        .insert(run);
    reference_observations[{ access.from, access.addr, access.kind }]
        .insert(run);
  }

  const uint32_t pointer_size = inf_is_64bit() ? 8u : 4u;
  if ( config.data_references )
  {
    for ( const auto &entry : reference_observations )
    {
      if ( entry.second.size() < config.minimum_dynamic_runs )
        continue;
      const ea_t from = ea_t(entry.first.from);
      const ea_t address = ea_t(entry.first.address);
      if ( !source_is_instruction(from) || !is_mapped(address)
        || is_code(get_flags(address)) || dref_exists(from, address) )
      {
        continue;
      }
      const dref_t type = entry.first.kind == RAX_MEM_WRITE ? dr_W : dr_R;
      if ( add_dref(from, address, dref_t(int(type) | XREF_USER)) )
        ++stats.drefs;
    }
  }

  std::set<ea_t> classified_data;
  for ( const auto &entry : observations )
  {
    if ( entry.second.size() < config.minimum_dynamic_runs )
      continue;
    const DataKey &key = entry.first;
    const ea_t from = ea_t(key.from);
    const ea_t address = ea_t(key.address);
    if ( !source_is_instruction(from) || !is_mapped(address)
      || is_code(get_flags(address)) )
    {
      continue;
    }
    if ( classified_data.count(address) != 0
      || !range_is_undefined_data(address, key.size) )
    {
      continue;
    }

    bool classified = false;
    if ( config.pointer_offsets && key.kind == RAX_MEM_READ
      && key.size == pointer_size && is_loaded(address)
      && is_mapped(ea_t(key.value)) )
    {
      const ea_t stored = pointer_size == 8
                        ? ea_t(get_qword(address)) : ea_t(get_dword(address));
      if ( stored == ea_t(key.value) && stored != address
        && is_mapped(stored)
        && create_pointer_offset(address, pointer_size) )
      {
        ++stats.pointer_offsets;
        classified = true;
        if ( config.comments )
        {
          qstring text;
          text.sprnt("pointer slot %s -> %s (%zu runs)",
                     address_label(address).c_str(),
                     address_label(stored).c_str(), entry.second.size());
          if ( append_analysis_comment(from, text.c_str()) )
            ++stats.comments;
        }
      }
    }
    if ( !classified && config.strings && create_ascii_string(address) )
    {
      ++stats.strings;
      classified = true;
    }
    if ( !classified && config.data_types && create_scalar(address, key.size) )
    {
      ++stats.typed_globals;
      classified = true;
    }
    if ( classified )
      classified_data.insert(address);
  }
}

void apply_consensus_runtime_strings(const TargetEvidence &evidence,
                                     const EvidenceApplyConfig &config,
                                     EvidenceApplyStats &stats)
{
  if ( !config.strings )
    return;
  for ( const RuntimeStringCandidate &candidate :
        chernobog::hybrid::hybrid_consensus_runtime_strings(evidence) )
  {
    const ea_t address = ea_t(candidate.address);
    if ( idb_matches_string(address, candidate.value)
      && create_strlit(address, candidate.value.size() + 1, STRTYPE_C) )
    {
      ++stats.strings;
    }
  }
}

void apply_stack_purge(const TargetEvidence &evidence,
                       const EvidenceApplyConfig &config,
                       EvidenceApplyStats &stats)
{
  if ( !config.stack_purge || evidence.architecture != HybridArch::X86_32 )
    return;
  size_t completed = 0;
  bool delta_known = false;
  int64_t common_delta = 0;
  for ( const auto &run : evidence.runs )
  {
    if ( !run.ran )
      continue;
    ++completed;
    if ( !run.outcome.returned || !run.outcome.sp_valid )
      return;
    if ( !delta_known )
    {
      common_delta = run.outcome.sp_delta;
      delta_known = true;
    }
    else if ( common_delta != run.outcome.sp_delta )
    {
      return;
    }
  }
  if ( completed < config.minimum_dynamic_runs )
    return;
  const int64_t purge = common_delta - 4;
  if ( purge <= 0 || purge > 512 || (purge % 4) != 0 )
    return;
  func_t *function = get_func(ea_t(evidence.scope.function_start));
  if ( function == nullptr
    || function->start_ea != ea_t(evidence.scope.function_start)
    || (function->flags & FUNC_PURGED_OK) != 0 || function->argsize != 0 )
  {
    return;
  }
  if ( set_purged(function->start_ea, int(purge), false) )
    ++stats.purges;
}

void apply_no_return(const TargetEvidence &evidence,
                     const EvidenceApplyConfig &config,
                     EvidenceApplyStats &stats)
{
  if ( !config.no_return_comments && !config.set_no_return )
    return;
  size_t completed = 0;
  bool definitive = false;
  for ( const auto &run : evidence.runs )
  {
    if ( !run.ran )
      continue;
    ++completed;
    if ( run.outcome.returned || !run.outcome.conclusive()
      || run.outcome.permission_violation || run.outcome.escaped_image
      || run.outcome.environment_model_failure )
    {
      return;
    }
    definitive = definitive || run.outcome.definitive_terminal();
  }
  if ( completed < config.minimum_noret_runs || !definitive )
    return;
  func_t *function = get_func(ea_t(evidence.scope.function_start));
  if ( function == nullptr
    || function->start_ea != ea_t(evidence.scope.function_start)
    || !function->does_return() )
  {
    return;
  }
  bool changed = false;
  if ( config.no_return_comments )
  {
    qstring text;
    text.sprnt("no returning outcome in %zu conclusive runs", completed);
    if ( append_analysis_comment(function->start_ea, text.c_str()) )
    {
      ++stats.comments;
      changed = true;
    }
  }
  if ( config.set_no_return )
  {
    const uint32_t old_flags = function->flags;
    function->flags |= FUNC_NORET;
    if ( update_func(function) )
    {
      reanalyze_function_ea(function->start_ea);
      changed = true;
    }
    else
    {
      function->flags = old_flags;
    }
  }
  if ( changed )
    ++stats.noret_annotations;
}

void apply_argument_registers(const TargetEvidence &evidence,
                              const EvidenceApplyConfig &config,
                              EvidenceApplyStats &stats)
{
  if ( !config.argument_registers || !config.comments )
    return;
  static const char *x64_sysv[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
  static const char *x64_win[] = { "rcx", "rdx", "r8", "r9" };
  static const char *a64[] = { "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7" };
  static const char *a32[] = { "R0", "R1", "R2", "R3" };
  static const char *rv64[] = { "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7" };
  static const char *hexagon[] = { "R0", "R1", "R2", "R3", "R4", "R5" };
  const char *const *names = nullptr;
  size_t name_count = 0;
  size_t width = 8;
  bool memory_base_is_explicit = false;
  switch ( evidence.architecture )
  {
    case HybridArch::X86_64:
      if ( inf_get_filetype() == f_PE )
      {
        names = x64_win;
        name_count = qnumber(x64_win);
      }
      else
      {
        names = x64_sysv;
        name_count = qnumber(x64_sysv);
      }
      break;
    case HybridArch::ARM64:
      names = a64;
      name_count = qnumber(a64);
      memory_base_is_explicit = true;
      break;
    case HybridArch::ARM32:
    case HybridArch::CORTEX_M:
      names = a32;
      name_count = qnumber(a32);
      width = 4;
      memory_base_is_explicit = true;
      break;
    case HybridArch::RISCV64:
      names = rv64;
      name_count = qnumber(rv64);
      break;
    case HybridArch::HEXAGON:
      names = hexagon;
      name_count = qnumber(hexagon);
      width = 4;
      break;
    default:
      return;
  }

  std::vector<int> arguments;
  for ( size_t index = 0; index < name_count; ++index )
  {
    const int reg = str2reg(names[index]);
    if ( reg >= 0 )
      arguments.push_back(reg);
  }
  if ( arguments.empty() )
    return;
  const auto is_argument = [&](int reg)
  {
    return std::find(arguments.begin(), arguments.end(), reg)
        != arguments.end();
  };

  const ea_t entry = ea_t(evidence.scope.function_start);
  const func_t *function = get_func(entry);
  if ( function == nullptr || function->start_ea != entry )
    return;
  std::set<int> written;
  std::vector<int> found;
  std::set<ea_t> visited;
  ea_t address = entry;
  for ( size_t step = 0; step < 64 && address != BADADDR
        && get_func(address) == function; ++step )
  {
    if ( !visited.insert(address).second )
      break;
    insn_t instruction;
    if ( decode_insn(&instruction, address) <= 0 )
      break;
    const uint32_t features = instruction.get_canon_feature(PH);
    for ( int index = 0; index < UA_MAXOP; ++index )
    {
      const op_t &operand = instruction.ops[index];
      if ( operand.type == o_void )
        break;
      if ( operand.type == o_reg )
      {
        const int reg = operand.reg;
        if ( has_cf_use(features, index) && written.count(reg) == 0
          && is_argument(reg)
          && std::find(found.begin(), found.end(), reg) == found.end() )
        {
          found.push_back(reg);
        }
        if ( has_cf_chg(features, index) )
          written.insert(reg);
      }
      else if ( memory_base_is_explicit
             && (operand.type == o_phrase || operand.type == o_displ) )
      {
        const int reg = operand.reg;
        if ( written.count(reg) == 0 && is_argument(reg)
          && std::find(found.begin(), found.end(), reg) == found.end() )
        {
          found.push_back(reg);
        }
      }
    }
    if ( is_call_insn(instruction) )
      break;
    ea_t next = address + instruction.size;
    if ( (features & CF_STOP) != 0 && !is_ret_insn(instruction) )
    {
      ea_t sole = BADADDR;
      size_t successors = 0;
      xrefblk_t xref;
      for ( bool ok = xref.first_from(address, XREF_CODE | XREF_NOFLOW);
            ok; ok = xref.next_from() )
      {
        if ( get_func(xref.to) == function )
        {
          sole = xref.to;
          ++successors;
        }
      }
      if ( successors != 1 )
        break;
      next = sole;
    }
    address = next;
  }
  if ( found.empty() )
    return;
  qstring text = "read-before-write argument registers: ";
  for ( size_t index = 0; index < found.size(); ++index )
  {
    qstring name;
    get_reg_name(&name, found[index], width);
    if ( index != 0 )
      text.append(", ");
    text.append(name);
  }
  if ( append_analysis_comment(entry, text.c_str()) )
  {
    ++stats.comments;
    ++stats.argument_annotations;
  }
}

void apply_opaque_observations(const TargetEvidence &evidence,
                               const EvidenceApplyConfig &config,
                               EvidenceApplyStats &stats)
{
  if ( !config.opaque_comments || !config.comments )
    return;
  struct Sides
  {
    std::set<RunKey> taken;
    std::set<RunKey> fallthrough;
    bool incomplete = false;
  };
  std::map<uint64_t, Sides> sites;
  for ( const auto &branch : evidence.branches )
  {
    Sides &site = sites[branch.instruction];
    if ( !branch.consumed_context_complete )
      site.incomplete = true;
    if ( branch.disposition == BranchDisposition::TAKEN )
      site.taken.insert({ branch.provenance.run_id, branch.provenance.seed });
    else if ( branch.disposition == BranchDisposition::FALLTHROUGH )
      site.fallthrough.insert(
          { branch.provenance.run_id, branch.provenance.seed });
    else
      site.incomplete = true;
  }
  for ( const auto &entry : sites )
  {
    const Sides &site = entry.second;
    if ( site.incomplete || site.taken.empty() == site.fallthrough.empty() )
      continue;
    const size_t runs = site.taken.empty()
                      ? site.fallthrough.size() : site.taken.size();
    if ( runs < config.minimum_dynamic_runs )
      continue;
    qstring text;
    text.sprnt("only %s successor observed across %zu context-complete runs",
               site.taken.empty() ? "fall-through" : "taken", runs);
    if ( append_analysis_comment(ea_t(entry.first), text.c_str()) )
    {
      ++stats.comments;
      ++stats.opaque_annotations;
    }
  }
}

void apply_switches(const TargetEvidence &evidence,
                    const EvidenceApplyConfig &config,
                    EvidenceApplyStats &stats)
{
  if ( !config.switch_recovery )
    return;
  std::map<ea_t, std::vector<ea_t>> groups;
  for ( const auto &entry : corroborated_edges(evidence) )
  {
    if ( entry.first.call
      || entry.second.size() < config.minimum_dynamic_runs )
    {
      continue;
    }
    std::vector<ea_t> &targets = groups[ea_t(entry.first.from)];
    const ea_t target = ea_t(entry.first.to);
    if ( target_is_executable(target)
      && std::find(targets.begin(), targets.end(), target) == targets.end() )
    {
      targets.push_back(target);
    }
  }
  for ( auto &entry : groups )
  {
    const ea_t jump = entry.first;
    std::vector<ea_t> &targets = entry.second;
    if ( targets.size() < 2 )
      continue;
    insn_t instruction;
    if ( decode_insn(&instruction, jump) <= 0
      || !is_indirect_jump_insn(instruction) )
    {
      continue;
    }
    switch_info_t existing;
    if ( get_switch_info(&existing, jump) > 0 )
      continue;
    switch_info_t info;
    info.flags |= SWI_USER | SWI_CUSTOM;
    info.ncases = uint16_t(std::min<size_t>(targets.size(), 0xFFFF));
    info.jumps = jump;
    info.lowcase = 0;
    info.defjump = BADADDR;
    info.startea = jump;
    set_switch_info(jump, info);
    if ( !create_switch_table(jump, info) )
    {
      del_switch_info(jump);
      continue;
    }
    for ( ea_t target : targets )
      add_code_reference(jump, target, false, config, stats, true);
    create_switch_xrefs(jump, info);
    if ( config.comments )
    {
      qstring text;
      text.sprnt("custom switch with %zu corroborated targets; target set may be incomplete",
                 targets.size());
      if ( append_analysis_comment(jump, text.c_str()) )
        ++stats.comments;
    }
    ++stats.switches;
  }
}

} // namespace

EvidenceApplyStats apply_evidence_to_ida(const TargetEvidence &evidence)
{
  EvidenceApplyStats stats;
  const EvidenceApplyConfig config = load_evidence_apply_config();
  if ( !config.enabled )
    return stats;

  apply_static_targets(evidence, config, stats);
  apply_dynamic_targets(evidence, config, stats);
  apply_data_evidence(evidence, config, stats);
  apply_consensus_runtime_strings(evidence, config, stats);
  apply_stack_purge(evidence, config, stats);
  apply_no_return(evidence, config, stats);
  apply_argument_registers(evidence, config, stats);
  apply_opaque_observations(evidence, config, stats);
  apply_switches(evidence, config, stats);

  if ( stats.total() != 0 )
  {
    msg("[chernobog][rax-analysis] applied to %a: static-crefs=%zu "
        "dynamic-crefs=%zu drefs=%zu code=%zu pointers=%zu typed=%zu "
        "strings=%zu functions=%zu purges=%zu annotations=%zu switches=%zu\n",
        ea_t(evidence.scope.function_start), stats.static_crefs,
        stats.dynamic_crefs, stats.drefs, stats.code_items,
        stats.pointer_offsets, stats.typed_globals, stats.strings,
        stats.functions, stats.purges,
        stats.noret_annotations + stats.argument_annotations
          + stats.opaque_annotations,
        stats.switches);
  }
  return stats;
}

} // namespace chernobog::ida_analysis
