/*
 * emu_driver.cpp — the rax emulation core.
 *
 * Strategy: mirror the analyzed image into guest memory once, then emulate each
 * function from its entry with a plausible stack whose top holds a sentinel
 * return address. A whole-range code hook records selected-function PCs and
 * transfer targets (so indirect calls/jumps and jump-table targets surface),
 * while stopping before an unmodeled out-of-function target executes. A memory
 * hook records data reads/writes (computed data references). An invalid hook
 * absorbs faults so a bad path stops cleanly instead of crashing or hanging;
 * an instruction-count and wall-clock cap bound every run.
 *
 * Per-run isolation uses rax context snapshots: the clean image+stack+registers
 * are captured once, and restored before each run so one function's stores can't
 * poison another's reads.
 */
#include "emu_driver.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <tuple>

namespace chernobog::hybrid {

namespace {

constexpr uint64_t kPage      = 0x1000;
constexpr uint64_t kStackSize = 0x100000;           // 1 MiB scratch stack
constexpr uint64_t kMaxCtx    = 512ull * 1024 * 1024; // cap snapshot buffer size

inline uint64_t page_down(uint64_t x) { return x & ~(kPage - 1); }

bool checked_add(uint64_t left, uint64_t right, uint64_t *out)
{
  if ( out == nullptr || left > std::numeric_limits<uint64_t>::max() - right )
    return false;
  *out = left + right;
  return true;
}

bool exit_value_is_attempted_steps(int reason)
{
  switch ( reason )
  {
    case RAX_STOP_COUNT:
    case RAX_STOP_UNTIL:
    case RAX_STOP_TIMEOUT:
    case RAX_STOP_STOPPED:
    case RAX_STOP_HLT:
    case RAX_STOP_EXCEPTION:
    case RAX_STOP_SHUTDOWN:
    case RAX_STOP_DEBUG:
    case RAX_STOP_ERROR:
      return true;
    default:
      return false;
  }
}

bool stop_preserves_observed_context(int reason)
{
  switch ( reason )
  {
    // These stops do not imply an unobserved architectural/environment action.
    // Count/timeout observations remain bounded prefixes whose consumed bytes
    // can still be complete for a concrete counterexample.
    case RAX_STOP_COUNT:
    case RAX_STOP_UNTIL:
    case RAX_STOP_TIMEOUT:
    case RAX_STOP_STOPPED:
    case RAX_STOP_HLT:
    case RAX_STOP_SHUTDOWN:
      return true;
    default:
      return false;
  }
}

bool input_overrides_argument(const EmuInput *input, size_t index,
                              const std::vector<int> &argument_registers)
{
  if ( input == nullptr )
    return false;
  const size_t offset = input->positional_argument_offset;
  if ( index >= offset && index - offset < input->args.size() )
    return true;
  if ( std::any_of(input->arg_overrides.begin(), input->arg_overrides.end(),
                   [&](const EmuInput::ArgOverride &override_value)
                   { return override_value.index == index; }) )
    return true;
  if ( index >= argument_registers.size() )
    return false;
  return std::any_of(
      input->register_overrides.begin(), input->register_overrides.end(),
      [&](const EmuInput::RegisterOverride &override_value)
      { return override_value.reg == argument_registers[index]; });
}

bool contains_range(uint64_t lo, uint64_t hi, uint64_t address, uint64_t size)
{
  uint64_t end = 0;
  return size != 0 && hi >= lo && address >= lo && checked_add(address, size, &end)
      && end <= hi;
}

bool image_contains_range(const ProgramImage *image, uint64_t address,
                          uint64_t size)
{
  if ( image == nullptr || size == 0 )
    return false;
  uint64_t end = 0;
  if ( !checked_add(address, size, &end) )
    return false;
  uint64_t cursor = address;
  while ( cursor < end )
  {
    const SegImage *segment = image->segment_at(cursor);
    if ( segment == nullptr )
      return false;
    cursor = std::min(end, segment->end);
  }
  return true;
}

// The stable context handed to every hook via the rax `user` pointer.
struct HookCtx
{
  EmuEvents *out = nullptr;
  const RaxApi *api = nullptr;
  const std::vector<int> *capture_regs = nullptr;
  const std::vector<EmuCallSummary> *summaries = nullptr;
  const ProgramImage *image = nullptr;
  uint64_t   lo = 0, hi = 0;      // image bounds; targets outside are ignored
  uint64_t   flo = 0, fhi = 0;    // current function bounds; only in-function sources are trusted
  const FuncRange *func = nullptr; // complete chunk topology when available
  uint64_t   stack_lo = 0, stack_hi = 0;
  uint64_t   heap_lo = 0, heap_cursor = 0, heap_hi = 0;
  uint64_t   prev_pc = 0, last_pc = 0;
  uint64_t   summary_source = 0;
  uint32_t   prev_size = 0;
  uint32_t   prev_decode_mode = 0;
  uint32_t   run_id = 0;
  uint64_t   seed = 0;
  uint64_t   sequence = 0;
  int        sp_reg = -1, lr_reg = -1, pc_reg = -1, ret_reg = -1;
  const std::vector<int> *arg_regs = nullptr;
  bool       is64 = false, big_endian = false;
  uint32_t   stack_argument_offset = 0;
  int        rax_arch = 0;
  uint32_t   rax_mode = 0;
  uint8_t    register_width = 8;
  bool       strict_permissions = false;
  bool       record_memory = false;
  bool       permission_violation = false;
  bool       cancellation_requested = false;
  bool       execution_truncated = false;
  bool       dependency_truncated = false;
  bool       terminated_process = false;
  bool       escaped_image = false;
  uint64_t   escape_source = 0;
  bool       function_boundary = false;
  uint64_t   function_boundary_source = 0;
  uint64_t   function_boundary_target = 0;
  ExecEdge::Kind function_boundary_kind = ExecEdge::Kind::Unknown;
  bool       unmodeled_external = false;
  uint64_t   external_target = 0;
  std::string external_name;
  bool       environment_model_failure = false;
  bool       summary_resume = false;
  uint32_t   summarized_calls = 0;
  bool       has_prev = false;
  bool       record_pcs = false; // populate out->exec_pcs (opaque-predicate analysis)
  size_t     edge_cap = 0, execution_cap = 0, data_cap = 0, state_cap = 0;
  size_t     dependency_cap = 0;
  bool     (*cancelled)(const void *) = nullptr;
  const void *cancellation_user = nullptr;
};

bool hook_in_function(const HookCtx *c, uint64_t ea)
{
  return c->func != nullptr ? c->func->contains(ea) : (ea >= c->flo && ea < c->fhi);
}

bool image_access_allowed(const HookCtx *c, uint64_t address, uint32_t size,
                          HybridSegPerm required)
{
  if ( c->image == nullptr || size == 0 )
    return true;
  uint64_t end = 0;
  if ( !checked_add(address, size, &end) )
    return false;
  // Stack, synthetic heap, and wholly external ranges do not belong to the IDA
  // image permission model. A range that intersects the image bounds must be
  // covered completely by mapped segments; gaps and boundary crossings fail.
  if ( end <= c->lo || address >= c->hi )
    return true;
  uint64_t cursor = address;
  while ( cursor < end )
  {
    const SegImage *segment = c->image->segment_at(cursor);
    if ( segment == nullptr )
      return false;
    if ( segment->perm != 0 && !segment->has_perm(required) )
      return false;
    cursor = std::min(end, segment->end);
  }
  return true;
}

bool summary_access_allowed(HookCtx *c, rax_engine *engine,
                            uint64_t address, uint64_t size,
                            HybridSegPerm required)
{
  if ( size > std::numeric_limits<uint32_t>::max()
    || (c->strict_permissions
     && !image_access_allowed(c, address, uint32_t(size), required)) )
  {
    c->permission_violation = true;
    c->api->emu_stop(engine);
    return false;
  }
  return true;
}

void restore_snapshot_bytes(HookCtx *c, rax_engine *engine,
                            uint64_t address, uint32_t size)
{
  if ( c->api == nullptr || c->image == nullptr || size == 0
    || size > (1u << 20) )
    return;
  std::vector<uint8_t> bytes(size, 0);
  for ( uint32_t index = 0; index < size; ++index )
  {
    uint64_t current = 0;
    if ( !checked_add(address, index, &current) )
      return;
    const SegImage *segment = c->image->segment_at(current);
    if ( segment == nullptr )
      return;
    const uint64_t raw_offset = current - segment->start;
    if ( raw_offset >= segment->bytes.size() )
      continue;
    const size_t offset = size_t(raw_offset);
    if ( offset / 8 < segment->mask.size()
      && (segment->mask[offset / 8] & uint8_t(1u << (offset & 7))) != 0 )
      bytes[index] = segment->bytes[offset];
  }
  c->api->mem_write(engine, address, bytes.data(), bytes.size());
}

const EmuCallSummary *find_summary(const HookCtx *c, uint64_t address)
{
  if ( c->summaries == nullptr )
    return nullptr;
  auto it = std::lower_bound(c->summaries->begin(), c->summaries->end(), address,
    [](const EmuCallSummary &s, uint64_t a) { return s.address < a; });
  return it != c->summaries->end() && it->address == address ? &*it : nullptr;
}

bool read_scalar(HookCtx *c, rax_engine *engine, uint64_t address,
                 size_t size, uint64_t *out)
{
  if ( c->api == nullptr || c->api->mem_read == nullptr || size == 0 || size > 8 )
    return false;
  if ( !summary_access_allowed(c, engine, address, size, HybridSegPerm::READ) )
    return false;
  uint8_t bytes[8] = { 0 };
  if ( c->api->mem_read(engine, address, bytes, size) != RAX_OK )
    return false;
  uint64_t value = 0;
  for ( size_t i = 0; i < size; ++i )
  {
    const size_t shift_index = c->big_endian ? (size - 1 - i) : i;
    value |= uint64_t(bytes[i]) << (8 * shift_index);
  }
  *out = value;
  return true;
}

bool summary_arg(HookCtx *c, rax_engine *engine, size_t index, uint64_t *out)
{
  if ( c->arg_regs != nullptr && index < c->arg_regs->size() )
    return c->api->reg_read_u64(engine, (*c->arg_regs)[index], out) == RAX_OK;
  if ( c->sp_reg < 0 )
    return false;
  uint64_t sp = 0;
  if ( c->api->reg_read_u64(engine, c->sp_reg, &sp) != RAX_OK )
    return false;
  const size_t ptr = c->is64 ? 8 : 4;
  size_t stack_index = index;
  if ( c->arg_regs != nullptr )
    stack_index -= c->arg_regs->size();
  const uint64_t return_slot = c->lr_reg < 0 ? ptr : 0;
  const uint64_t home = c->stack_argument_offset;
  if ( stack_index > std::numeric_limits<uint64_t>::max() / ptr )
    return false;
  uint64_t address = 0;
  return checked_add(sp, return_slot, &address)
      && checked_add(address, home, &address)
      && checked_add(address, uint64_t(stack_index) * ptr, &address)
      && read_scalar(c, engine, address, ptr, out);
}

DataScope access_scope(const HookCtx *c, uint64_t address, uint32_t size,
                       bool *recordable)
{
  if ( image_contains_range(c->image, address, size) )
  {
    *recordable = true;
    return DataScope::IMAGE;
  }
  if ( contains_range(c->heap_lo, c->heap_hi, address, size) )
  {
    *recordable = true;
    return DataScope::HEAP;
  }
  if ( contains_range(c->stack_lo, c->stack_hi, address, size) )
  {
    *recordable = true;
    return DataScope::STACK;
  }
  *recordable = false;
  return DataScope::OTHER;
}

void record_summary_access(HookCtx *c, int kind, uint64_t address,
                           uint64_t value, uint32_t size)
{
  if ( c->out == nullptr )
    return;
  bool recordable = false;
  const DataScope scope = access_scope(c, address, size, &recordable);
  if ( !recordable || !hook_in_function(c, c->summary_source) )
    return;
  if ( kind == RAX_MEM_READ && scope == DataScope::IMAGE )
  {
    if ( c->out->consumed_image_reads.size() >= c->dependency_cap )
      c->dependency_truncated = true;
    else
      c->out->consumed_image_reads.push_back(ConsumedImageRange{
          address, size, c->run_id, c->seed });
  }
  if ( c->out->data.size() >= c->data_cap )
    return;
  DataAcc a;
  a.from = c->summary_source;
  a.addr = address;
  a.value = value;
  a.size = size;
  a.kind = kind;
  a.scope = scope;
  a.sequence = c->sequence++;
  a.run_id = c->run_id;
  a.seed = c->seed;
  c->out->data.push_back(a);
}

uint64_t scalar_from_memory(const HookCtx *c, const uint8_t *bytes, size_t size)
{
  const size_t n = std::min<size_t>(size, 8);
  uint64_t value = 0;
  for ( size_t i = 0; i < n; ++i )
  {
    const size_t shift_index = c->big_endian ? (n - 1 - i) : i;
    value |= uint64_t(bytes[i]) << (8 * shift_index);
  }
  return value;
}

bool read_c_string(HookCtx *c, rax_engine *engine, uint64_t address,
                   std::vector<uint8_t> &out, size_t limit = 65536)
{
  out.clear();
  if ( c->api->mem_read == nullptr )
    return false;
  for ( size_t i = 0; i < limit; ++i )
  {
    uint64_t current = 0;
    if ( !checked_add(address, uint64_t(i), &current) )
      return false;
    uint8_t ch = 0;
    if ( !summary_access_allowed(
          c, engine, current, 1, HybridSegPerm::READ) )
      return false;
    if ( c->api->mem_read(engine, current, &ch, 1) != RAX_OK )
      return false;
    out.push_back(ch);
    if ( ch == 0 )
      return true;
  }
  return false;
}

bool summary_return(HookCtx *c, rax_engine *engine, uint64_t value)
{
  if ( c->ret_reg >= 0 )
    if ( c->api->reg_write_u64(engine, c->ret_reg, value) != RAX_OK )
      return false;
  uint64_t target = 0;
  if ( c->lr_reg >= 0 )
  {
    if ( c->api->reg_read_u64(engine, c->lr_reg, &target) != RAX_OK )
      return false;
  }
  else
  {
    uint64_t sp = 0;
    const size_t ptr = c->is64 ? 8 : 4;
    if ( c->sp_reg < 0 || c->api->reg_read_u64(engine, c->sp_reg, &sp) != RAX_OK
      || !read_scalar(c, engine, sp, ptr, &target) )
      return false;
    uint64_t next_sp = 0;
    if ( !checked_add(sp, ptr, &next_sp)
      || c->api->reg_write_u64(engine, c->sp_reg, next_sp) != RAX_OK )
      return false;
  }
  if ( c->pc_reg < 0 || c->api->reg_write_u64(engine, c->pc_reg, target) != RAX_OK )
    return false;
  // Request a clean boundary. EmuDriver resumes from the rewritten PC so the
  // destination receives its own code hook and the until/count/time budgets
  // remain under host control; executing it in this same step would skip hooks.
  c->summary_resume = true;
  c->api->emu_stop(engine);
  return true;
}

bool apply_summary(HookCtx *c, rax_engine *engine, const EmuCallSummary &summary)
{
  constexpr uint64_t kMaxModelBytes = 1ull << 20;
  uint64_t a0 = 0, a1 = 0, a2 = 0, result = 0;
  auto args = [&](size_t count) -> bool
  {
    return (count < 1 || summary_arg(c, engine, 0, &a0))
        && (count < 2 || summary_arg(c, engine, 1, &a1))
        && (count < 3 || summary_arg(c, engine, 2, &a2));
  };
  std::vector<uint8_t> bytes;
  switch ( summary.kind )
  {
    case EmuSummaryKind::UNMODELED:
      return false;
    case EmuSummaryKind::TERMINATE:
      c->terminated_process = true;
      ++c->summarized_calls;
      c->api->emu_stop(engine);
      return true;
    case EmuSummaryKind::STRLEN:
      if ( !args(1) || !read_c_string(c, engine, a0, bytes) )
        return false;
      result = bytes.size() - 1;
      record_summary_access(c, RAX_MEM_READ, a0,
                            scalar_from_memory(c, bytes.data(), bytes.size()),
                            uint32_t(bytes.size()));
      break;
    case EmuSummaryKind::STRCMP:
    {
      std::vector<uint8_t> rhs;
      if ( !args(2) || !read_c_string(c, engine, a0, bytes)
        || !read_c_string(c, engine, a1, rhs) )
        return false;
      const size_t n = std::min(bytes.size(), rhs.size());
      int cmp = std::memcmp(bytes.data(), rhs.data(), n);
      if ( cmp == 0 ) cmp = bytes.size() < rhs.size() ? -1 : bytes.size() > rhs.size() ? 1 : 0;
      result = uint64_t(int64_t(cmp));
      record_summary_access(c, RAX_MEM_READ, a0,
                            scalar_from_memory(c, bytes.data(), bytes.size()),
                            uint32_t(bytes.size()));
      record_summary_access(c, RAX_MEM_READ, a1,
                            scalar_from_memory(c, rhs.data(), rhs.size()),
                            uint32_t(rhs.size()));
      break;
    }
    case EmuSummaryKind::MEMCPY:
    case EmuSummaryKind::MEMMOVE:
    {
      if ( !args(3) )
        return false;
      if ( a2 > kMaxModelBytes )
        return false;
      const size_t n = size_t(a2);
      bytes.resize(n);
      if ( n != 0 )
      {
        if ( !summary_access_allowed(c, engine, a1, n, HybridSegPerm::READ)
          || !summary_access_allowed(c, engine, a0, n, HybridSegPerm::WRITE)
          || c->api->mem_read == nullptr
          || c->api->mem_read(engine, a1, bytes.data(), n) != RAX_OK
          || c->api->mem_write(engine, a0, bytes.data(), n) != RAX_OK )
          return false;
        const uint64_t value = scalar_from_memory(c, bytes.data(), n);
        record_summary_access(c, RAX_MEM_READ, a1, value, uint32_t(n));
        record_summary_access(c, RAX_MEM_WRITE, a0, value, uint32_t(n));
      }
      result = a0;
      break;
    }
    case EmuSummaryKind::MEMSET:
    {
      if ( !args(3) )
        return false;
      if ( a2 > kMaxModelBytes )
        return false;
      const size_t n = size_t(a2);
      bytes.assign(n, uint8_t(a1));
      if ( n != 0 )
      {
        if ( !summary_access_allowed(c, engine, a0, n, HybridSegPerm::WRITE)
          || c->api->mem_write(engine, a0, bytes.data(), n) != RAX_OK )
          return false;
        record_summary_access(c, RAX_MEM_WRITE, a0,
                              scalar_from_memory(c, bytes.data(), n), uint32_t(n));
      }
      result = a0;
      break;
    }
    case EmuSummaryKind::STRCPY:
      if ( !args(2) || !read_c_string(c, engine, a1, bytes)
        || !summary_access_allowed(
             c, engine, a0, bytes.size(), HybridSegPerm::WRITE)
        || c->api->mem_write(engine, a0, bytes.data(), bytes.size()) != RAX_OK )
        return false;
      record_summary_access(c, RAX_MEM_READ, a1,
                            scalar_from_memory(c, bytes.data(), bytes.size()),
                            uint32_t(bytes.size()));
      record_summary_access(c, RAX_MEM_WRITE, a0,
                            scalar_from_memory(c, bytes.data(), bytes.size()),
                            uint32_t(bytes.size()));
      result = a0;
      break;
    case EmuSummaryKind::STRNCPY:
    {
      if ( !args(3) )
        return false;
      if ( a2 > kMaxModelBytes )
        return false;
      const size_t n = size_t(a2);
      bytes.assign(n, 0);
      if ( n != 0 && !summary_access_allowed(
            c, engine, a0, n, HybridSegPerm::WRITE) )
        return false;
      size_t read_count = 0;
      bool terminated = false;
      for ( size_t i = 0; i < n && !terminated; ++i )
      {
        uint64_t source = 0;
        if ( !checked_add(a1, uint64_t(i), &source) || c->api->mem_read == nullptr
          || !summary_access_allowed(
               c, engine, source, 1, HybridSegPerm::READ)
          || c->api->mem_read(engine, source, &bytes[i], 1) != RAX_OK )
          return false;
        ++read_count;
        terminated = bytes[i] == 0;
      }
      if ( n != 0 && c->api->mem_write(engine, a0, bytes.data(), n) != RAX_OK )
        return false;
      if ( read_count != 0 )
        record_summary_access(c, RAX_MEM_READ, a1,
                              scalar_from_memory(c, bytes.data(), read_count),
                              uint32_t(read_count));
      if ( n != 0 )
        record_summary_access(c, RAX_MEM_WRITE, a0,
                              scalar_from_memory(c, bytes.data(), n), uint32_t(n));
      result = a0;
      break;
    }
    case EmuSummaryKind::ALLOCATE:
    case EmuSummaryKind::CALLOCATE:
    {
      if ( !args(summary.kind == EmuSummaryKind::CALLOCATE ? 2 : 1) )
        return false;
      uint64_t n = a0;
      if ( summary.kind == EmuSummaryKind::CALLOCATE )
      {
        if ( a0 != 0 && a1 > std::numeric_limits<uint64_t>::max() / a0 )
          n = 0;
        else
          n = a0 * a1;
      }
      // An oversized/overflowing request is conservatively modeled as an
      // allocation failure instead of fabricating a smaller valid object.
      if ( n > kMaxModelBytes )
        n = 0;
      const uint64_t aligned = (n + 15) & ~15ull;
      if ( n != 0 && c->heap_cursor <= c->heap_hi && aligned <= c->heap_hi - c->heap_cursor )
      {
        result = c->heap_cursor;
        if ( summary.kind == EmuSummaryKind::CALLOCATE )
        {
          bytes.assign(size_t(n), 0);
          if ( !summary_access_allowed(
                 c, engine, result, bytes.size(), HybridSegPerm::WRITE)
            || c->api->mem_write(engine, result, bytes.data(), bytes.size()) != RAX_OK )
            return false;
          record_summary_access(c, RAX_MEM_WRITE, result, 0, uint32_t(n));
        }
        c->heap_cursor += aligned;
      }
      break;
    }
    case EmuSummaryKind::DEALLOCATE:
      if ( !args(1) )
        return false;
      result = 0;
      break;
    case EmuSummaryKind::RETURN_ARG0:
      if ( !args(1) )
        return false;
      result = a0;
      break;
    case EmuSummaryKind::RETURN_ZERO:
      result = 0;
      break;
    case EmuSummaryKind::STORE_POINTER_ARG1:
    {
      if ( !args(2) )
        return false;
      const size_t width = c->is64 ? 8 : 4;
      uint8_t stored[8] = {};
      for ( size_t index = 0; index < width; ++index )
      {
        const size_t shift = c->big_endian ? width - 1 - index : index;
        stored[index] = uint8_t(a1 >> (shift * 8));
      }
      if ( !summary_access_allowed(c, engine, a0, width, HybridSegPerm::WRITE)
        || c->api->mem_write(engine, a0, stored, width) != RAX_OK )
        return false;
      record_summary_access(c, RAX_MEM_WRITE, a0, a1, uint32_t(width));
      result = 0;
      break;
    }
    case EmuSummaryKind::ALLOCATE_OBJECT:
    {
      constexpr uint64_t object_size = 256;
      const uint64_t aligned = (object_size + 15) & ~15ull;
      if ( c->heap_cursor <= c->heap_hi && aligned <= c->heap_hi - c->heap_cursor )
      {
        result = c->heap_cursor;
        bytes.assign(size_t(object_size), 0);
        if ( c->api->mem_write(engine, result, bytes.data(), bytes.size()) != RAX_OK )
          return false;
        record_summary_access(c, RAX_MEM_WRITE, result, 0, uint32_t(object_size));
        c->heap_cursor += aligned;
      }
      break;
    }
    case EmuSummaryKind::RANDOM_U32:
    case EmuSummaryKind::RANDOM_UNIFORM:
    {
      if ( summary.kind == EmuSummaryKind::RANDOM_UNIFORM && !args(1) )
        return false;
      uint64_t mixed = c->seed ^ summary.address
                     ^ (uint64_t(c->summarized_calls + 1) * UINT64_C(0x9E3779B97F4A7C15));
      mixed ^= mixed >> 30;
      mixed *= UINT64_C(0xBF58476D1CE4E5B9);
      mixed ^= mixed >> 27;
      mixed *= UINT64_C(0x94D049BB133111EB);
      mixed ^= mixed >> 31;
      const uint32_t random = uint32_t(mixed);
      const uint32_t bound = uint32_t(a0);
      result = summary.kind == EmuSummaryKind::RANDOM_UNIFORM
             ? uint64_t(bound < 2 ? 0 : random % bound)
             : uint64_t(random);
      break;
    }
  }
  if ( !summary_return(c, engine, result) )
    return false;
  ++c->summarized_calls;
  return true;
}

bool decode_at(const HookCtx *c, uint64_t pc, uint32_t mode, uint32_t *size,
               ExecEdge::Kind *kind, int32_t *flow = nullptr)
{
  if ( size != nullptr )
    *size = 0;
  if ( kind != nullptr )
    *kind = ExecEdge::Kind::Unknown;
  if ( flow != nullptr )
    *flow = RAX_FLOW_UNKNOWN;
  if ( c->api == nullptr || c->api->decode == nullptr || c->image == nullptr )
    return false;
  for ( const SegImage &segment : c->image->segs )
  {
    if ( pc < segment.start || pc >= segment.end )
      continue;
    const uint64_t raw_offset = pc - segment.start;
    if ( raw_offset >= segment.bytes.size() )
      return false;
    const size_t offset = size_t(raw_offset);
    const size_t available = std::min<size_t>(15, segment.bytes.size() - offset);
    size_t loaded = 0;
    while ( loaded < available )
    {
      const size_t bit = offset + loaded;
      if ( bit / 8 >= segment.mask.size()
        || (segment.mask[bit / 8] & uint8_t(1u << (bit & 7))) == 0 )
        break;
      ++loaded;
    }
    if ( loaded == 0 )
      return false;
    rax_decoded decoded{};
    if ( c->api->decode(c->rax_arch, mode, pc,
                        segment.bytes.data() + offset, loaded, &decoded) != RAX_OK
      || decoded.valid == 0 || decoded.size == 0 )
      return false;
    if ( size != nullptr )
      *size = decoded.size;
    if ( kind != nullptr )
    {
      switch ( decoded.flow )
      {
        case RAX_FLOW_CALL:
        case RAX_FLOW_INDIRECT_CALL: *kind = ExecEdge::Kind::Call; break;
        case RAX_FLOW_BRANCH:
        case RAX_FLOW_COND_BRANCH:
        case RAX_FLOW_INDIRECT_JUMP: *kind = ExecEdge::Kind::Jump; break;
        case RAX_FLOW_RETURN: *kind = ExecEdge::Kind::Return; break;
        default: break;
      }
    }
    if ( flow != nullptr )
      *flow = decoded.flow;
    return true;
  }
  return false;
}

uint32_t decode_mode_at_hook(const HookCtx *c, rax_engine *engine)
{
  uint32_t mode = c->rax_mode;
  if ( c->rax_arch != RAX_ARCH_ARM || c->api == nullptr )
    return mode;
  uint64_t cpsr = 0;
  if ( c->api->reg_read_u64(engine, RAX_ARM_REG_CPSR, &cpsr) != RAX_OK )
    return mode;
  mode &= ~(RAX_MODE_ARM | RAX_MODE_THUMB);
  mode |= (cpsr & (UINT64_C(1) << 5)) != 0
        ? RAX_MODE_THUMB : RAX_MODE_ARM;
  return mode;
}

void code_tr(rax_engine *engine, uint64_t addr, uint32_t size, void *user)
{
  HookCtx *c = static_cast<HookCtx *>(user);
  if ( c->cancelled != nullptr && c->cancelled(c->cancellation_user) )
  {
    c->cancellation_requested = true;
    c->api->emu_stop(engine);
    return;
  }
  const uint32_t current_decode_mode = decode_mode_at_hook(c, engine);
  uint32_t decoded_current_size = 0;
  decode_at(c, addr, current_decode_mode, &decoded_current_size, nullptr);
  const uint32_t effective_size = size != 0 ? size : decoded_current_size;
  const SegImage *current_segment = c->image != nullptr
                                  ? c->image->segment_at(addr) : nullptr;
  if ( current_segment == nullptr )
  {
    // This driver emulates an application function, not an operating system.
    // Reaching an exception vector, unmapped callee, or fabricated executable
    // address is a first-fault boundary; never let full-system exception
    // delivery consume the remaining instruction budget.
    c->escaped_image = true;
    c->escape_source = c->has_prev ? c->prev_pc : addr;
    c->api->emu_stop(engine);
    return;
  }
  if ( c->strict_permissions
    && !image_access_allowed(c, addr, effective_size == 0 ? 1 : effective_size,
                             HybridSegPerm::EXEC) )
  {
    c->permission_violation = true;
    c->api->emu_stop(engine);
    return;
  }
  const uint64_t event_sequence = c->sequence++;
  bool summary_transfer = false;
  ExecEdge::Kind transfer_kind = ExecEdge::Kind::Unknown;
  if ( c->has_prev )
  {
    uint32_t decoded_size = 0;
    decode_at(c, c->prev_pc, c->prev_decode_mode, &decoded_size, &transfer_kind);
    const uint64_t instruction_size = c->prev_size != 0 ? c->prev_size : decoded_size;
    uint64_t fallthrough = 0;
    const bool fallthrough_valid = instruction_size != 0
                                && checked_add(c->prev_pc, instruction_size, &fallthrough);
    summary_transfer = (!fallthrough_valid || addr != fallthrough)
                    && hook_in_function(c, c->prev_pc)
                    && addr >= c->lo && addr < c->hi;
    // Record a taken branch only when its SOURCE is inside the function being
    // emulated and its TARGET is inside the image. An out-of-function target is
    // retained as boundary evidence below, then stopped before it executes.
    if ( summary_transfer
      && c->out->edges.size() < c->edge_cap )
    {
      c->out->edges.push_back(ExecEdge{ c->prev_pc, addr, c->run_id,
                                        c->seed, transfer_kind, event_sequence });
      if ( c->api != nullptr && c->capture_regs != nullptr
        && c->out->states.size() < c->state_cap )
      {
        StatePoint p;
        p.kind = StatePoint::Kind::TransferTarget;
        p.source = c->prev_pc;
        p.pc = addr;
        p.sequence = event_sequence;
        p.run_id = c->run_id;
        p.seed = c->seed;
        p.regs.reserve(c->capture_regs->size());
        for ( int reg : *c->capture_regs )
        {
          uint64_t value = 0;
          if ( c->api->reg_read_u64(engine, reg, &value) == RAX_OK )
            p.regs.push_back(RegisterValue{ reg, value, c->register_width });
        }
        c->out->states.push_back(std::move(p));
      }
    }
  }
  c->summary_source = c->has_prev ? c->prev_pc : addr;
  const EmuCallSummary *summary = summary_transfer
                               && transfer_kind == ExecEdge::Kind::Call
                               ? find_summary(c, addr) : nullptr;
  if ( summary != nullptr && summary->kind != EmuSummaryKind::UNMODELED )
  {
    if ( !apply_summary(c, engine, *summary) )
    {
      c->environment_model_failure = true;
      c->external_target = addr;
      c->external_name = summary->name;
      c->api->emu_stop(engine);
    }
    c->prev_pc = addr;
    c->prev_size = effective_size;
    c->prev_decode_mode = current_decode_mode;
    c->has_prev = true;
    c->last_pc = addr;
    return;
  }
  if ( current_segment->kind == HybridSegmentKind::EXTERNAL )
  {
    if ( summary == nullptr || summary->kind == EmuSummaryKind::UNMODELED )
    {
      c->unmodeled_external = true;
      c->external_target = addr;
      if ( summary != nullptr )
        c->external_name = summary->name;
      c->api->emu_stop(engine);
    }
    c->prev_pc = addr;
    c->prev_size = effective_size;
    c->prev_decode_mode = current_decode_mode;
    c->has_prev = true;
    c->last_pc = addr;
    return;
  }
  if ( !hook_in_function(c, addr) )
  {
    // The selected FuncRange is the execution boundary. Preserve the observed
    // transfer itself (recorded above), but never execute an unmodeled callee,
    // tail target, or fallthrough beyond IDA's current function topology.
    c->function_boundary = true;
    c->function_boundary_source = c->has_prev ? c->prev_pc : addr;
    c->function_boundary_target = addr;
    c->function_boundary_kind = transfer_kind;
    c->api->emu_stop(engine);
    return;
  }
  if ( addr >= c->lo && addr < c->hi )
  {
    if ( c->out->execution.size() < c->execution_cap )
      c->out->execution.push_back(ExecPoint{ addr, effective_size, event_sequence,
                                             c->run_id, c->seed });
    else
      c->execution_truncated = true;
  }
  int32_t current_flow = RAX_FLOW_UNKNOWN;
  if ( hook_in_function(c, addr)
    && c->api != nullptr && c->capture_regs != nullptr
    && c->out->states.size() < c->state_cap
    && decode_at(c, addr, current_decode_mode, nullptr, nullptr, &current_flow)
    && current_flow == RAX_FLOW_COND_BRANCH )
  {
    StatePoint point;
    point.kind = StatePoint::Kind::PredicateInput;
    point.source = addr;
    point.pc = addr;
    point.sequence = event_sequence;
    point.run_id = c->run_id;
    point.seed = c->seed;
    point.regs.reserve(c->capture_regs->size());
    for ( int reg : *c->capture_regs )
    {
      uint64_t value = 0;
      if ( c->api->reg_read_u64(engine, reg, &value) == RAX_OK )
        point.regs.push_back(RegisterValue{ reg, value, c->register_width });
    }
    c->out->states.push_back(std::move(point));
  }
  if ( c->record_pcs && hook_in_function(c, addr) && c->out->exec_pcs.size() < c->edge_cap )
    c->out->exec_pcs.insert(addr);
  c->prev_pc = addr;
  c->prev_size = effective_size;
  c->prev_decode_mode = current_decode_mode;
  c->has_prev = true;
  c->last_pc = addr;
}

void mem_tr(rax_engine *engine, int kind, uint64_t addr, uint32_t size,
            uint64_t value, void *user)
{
  HookCtx *c = static_cast<HookCtx *>(user);
  if ( kind == RAX_MEM_FETCH )
    return; // instruction fetch is control flow, not a data reference
  const HybridSegPerm required = kind == RAX_MEM_WRITE ? HybridSegPerm::WRITE
                                                    : HybridSegPerm::READ;
  if ( c->strict_permissions
    && !image_access_allowed(c, addr, size, required) )
  {
    // Memory hooks are post-retirement in rax. Roll a forbidden image write
    // back to the immutable snapshot before stopping, so even the ephemeral
    // guest state obeys the policy and no forbidden evidence is published.
    if ( kind == RAX_MEM_WRITE )
      restore_snapshot_bytes(c, engine, addr, size);
    c->permission_violation = true;
    c->api->emu_stop(engine);
    return;
  }
  if ( !c->record_memory )
    return;
  // Attribute to the executing instruction (last_pc, set by the code hook at
  // instruction entry; rax dispatches an access at the boundary of the
  // instruction that made it, before the next instruction's code hook). Only
  // trust accesses whose source is inside the function being emulated.
  bool recordable = false;
  const DataScope scope = access_scope(c, addr, size, &recordable);
  if ( kind == RAX_MEM_READ && recordable && scope == DataScope::IMAGE )
  {
    if ( c->out->consumed_image_reads.size() >= c->dependency_cap )
      c->dependency_truncated = true;
    else
      c->out->consumed_image_reads.push_back(ConsumedImageRange{
          addr, size, c->run_id, c->seed });
  }
  if ( recordable
    && hook_in_function(c, c->last_pc)
    && c->out->data.size() < c->data_cap )
  {
    DataAcc a;
    a.from = c->last_pc;
    a.addr = addr;
    a.value = value;
    a.size = size;
    a.kind = kind;
    a.scope = scope;
    a.sequence = c->sequence++;
    a.run_id = c->run_id;
    a.seed = c->seed;
    c->out->data.push_back(a);
  }
}

int inv_tr(rax_engine *, uint64_t, void *)
{
  return 0; // do not handle the fault: stop the run cleanly
}

// Fill the rax arch/mode and the register ids for a supported HybridArch.
// Returns false for architectures hybrid does not drive.
bool arch_params(HybridArch a, bool big_endian, HybridEntryMode entry_mode,
                 int &rax_arch, uint32_t &mode,
                 int &sp_reg, int &fp_reg, int &lr_reg,
                 int &pc_reg, int &ret_reg, bool &is64)
{
  sp_reg = fp_reg = lr_reg = pc_reg = ret_reg = -1;
  switch ( a )
  {
    // X86_16 (segmented real mode) is intentionally not driven: linear IDA
    // addresses don't map to seg:off state and the stack model differs. It
    // falls through to `return false`, so current-function execution is a
    // clean no-op there.
    case HybridArch::X86_32:
      rax_arch = RAX_ARCH_X86; mode = RAX_MODE_32;
      sp_reg = RAX_X86_REG_ESP; fp_reg = RAX_X86_REG_EBP;
      pc_reg = RAX_X86_REG_EIP; ret_reg = RAX_X86_REG_EAX; is64 = false; return true;
    case HybridArch::X86_64:
      rax_arch = RAX_ARCH_X86; mode = RAX_MODE_64;
      sp_reg = RAX_X86_REG_RSP; fp_reg = RAX_X86_REG_RBP;
      pc_reg = RAX_X86_REG_RIP; ret_reg = RAX_X86_REG_RAX; is64 = true; return true;
    case HybridArch::ARM64:
      rax_arch = RAX_ARCH_ARM64;
      mode = big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN;
      sp_reg = RAX_ARM64_REG_SP; lr_reg = RAX_ARM64_X(30);
      pc_reg = RAX_ARM64_REG_PC; ret_reg = RAX_ARM64_X(0); is64 = true; return true;
    case HybridArch::ARM32:
      if ( entry_mode != HybridEntryMode::ARM
        && entry_mode != HybridEntryMode::THUMB )
        return false;
      rax_arch = RAX_ARCH_ARM;
      mode = (entry_mode == HybridEntryMode::THUMB
                ? RAX_MODE_THUMB : RAX_MODE_ARM)
           | (big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN);
      sp_reg = RAX_ARM_REG_SP; lr_reg = RAX_REG_LR;
      pc_reg = RAX_ARM_REG_PC; ret_reg = RAX_ARM_R(0); is64 = false; return true;
    case HybridArch::RISCV64:
      rax_arch = RAX_ARCH_RISCV64;
      mode = big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN;
      sp_reg = RAX_RISCV_X(2); fp_reg = RAX_RISCV_X(8); lr_reg = RAX_RISCV_X(1);
      pc_reg = RAX_RISCV_REG_PC; ret_reg = RAX_RISCV_X(10); is64 = true; return true;
    case HybridArch::CORTEX_M:
      rax_arch = RAX_ARCH_CORTEXM;
      mode = RAX_MODE_THUMB | (big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN);
      sp_reg = RAX_REG_SP; lr_reg = RAX_CM_REG_LR;
      pc_reg = RAX_CM_REG_PC; ret_reg = RAX_CM_R(0); is64 = false; return true;
    case HybridArch::HEXAGON:
      rax_arch = RAX_ARCH_HEXAGON;
      mode = big_endian ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN;
      sp_reg = RAX_HEX_R(29); fp_reg = RAX_HEX_R(30); lr_reg = RAX_HEX_R(31);
      pc_reg = RAX_HEX_REG_PC; ret_reg = RAX_HEX_R(0); is64 = false; return true;
    default:
      return false;
  }
}

} // namespace

const char *hybrid_rax_stop_reason_name(int reason)
{
  switch ( reason )
  {
    case RAX_STOP_NONE: return "none";
    case RAX_STOP_COUNT: return "instruction-budget";
    case RAX_STOP_UNTIL: return "return-sentinel";
    case RAX_STOP_TIMEOUT: return "timeout";
    case RAX_STOP_STOPPED: return "host-stop";
    case RAX_STOP_HLT: return "halt";
    case RAX_STOP_IO_IN: return "io-read";
    case RAX_STOP_IO_OUT: return "io-write";
    case RAX_STOP_MMIO_READ: return "mmio-read";
    case RAX_STOP_MMIO_WRITE: return "mmio-write";
    case RAX_STOP_EXCEPTION: return "exception";
    case RAX_STOP_INTERRUPT: return "interrupt";
    case RAX_STOP_SHUTDOWN: return "shutdown";
    case RAX_STOP_DEBUG: return "debug";
    case RAX_STOP_ERROR: return "engine-error";
    default: return "unknown";
  }
}

const char *hybrid_rax_status_name(int status)
{
  switch ( status )
  {
    case RAX_OK: return "success";
    case RAX_ERR_NOMEM: return "out-of-memory";
    case RAX_ERR_ARG: return "invalid-argument";
    case RAX_ERR_HANDLE: return "invalid-handle";
    case RAX_ERR_ARCH: return "unsupported-architecture";
    case RAX_ERR_BACKEND: return "backend-unavailable";
    case RAX_ERR_MODE: return "invalid-mode";
    case RAX_ERR_MAP: return "unmapped-access";
    case RAX_ERR_PERM: return "permission-error";
    case RAX_ERR_BOUNDS: return "bounds-error";
    case RAX_ERR_REG: return "register-error";
    case RAX_ERR_STATE: return "invalid-state";
    case RAX_ERR_FAULT: return "guest-fault";
    case RAX_ERR_IO: return "host-io-error";
    case RAX_ERR_FORMAT: return "format-error";
    case RAX_ERR_HOOK: return "hook-error";
    case RAX_ERR_UNSUPPORTED: return "unsupported-operation";
    case RAX_ERR_INTERNAL: return "internal-error";
    default: return "unknown";
  }
}

const char *hybrid_emu_outcome_name(const EmuOutcome &outcome)
{
  if ( outcome.returned ) return "returned";
  if ( outcome.cancelled ) return "cancelled";
  if ( outcome.unmodeled_external ) return "unmodeled-external";
  if ( outcome.environment_model_failure ) return "environment-model-failure";
  if ( outcome.function_boundary ) return "function-boundary";
  if ( outcome.escaped_image ) return "escaped-image-or-exception";
  if ( outcome.permission_violation ) return "permission-violation";
  if ( outcome.terminated_process ) return "modeled-process-termination";
  return hybrid_rax_stop_reason_name(outcome.stop_reason);
}

void EmuEvents::merge_from(const EmuEvents &other)
{
  if ( this == &other )
  {
    const EmuEvents copy(other);
    merge_from(copy);
    return;
  }
  edges.insert(edges.end(), other.edges.begin(), other.edges.end());
  execution.insert(execution.end(), other.execution.begin(), other.execution.end());
  data.insert(data.end(), other.data.begin(), other.data.end());
  states.insert(states.end(), other.states.begin(), other.states.end());
  final_writes.insert(final_writes.end(), other.final_writes.begin(), other.final_writes.end());
  consumed_image_reads.insert(consumed_image_reads.end(),
                              other.consumed_image_reads.begin(),
                              other.consumed_image_reads.end());
  exec_pcs.insert(other.exec_pcs.begin(), other.exec_pcs.end());
}

void EmuEvents::normalize()
{
  std::sort(edges.begin(), edges.end(), [](const ExecEdge &a, const ExecEdge &b)
  {
    return std::tie(a.run_id, a.seed, a.sequence, a.from, a.to, a.kind)
         < std::tie(b.run_id, b.seed, b.sequence, b.from, b.to, b.kind);
  });
  edges.erase(std::unique(edges.begin(), edges.end(), [](const ExecEdge &a, const ExecEdge &b)
  {
    return a.run_id == b.run_id && a.seed == b.seed && a.sequence == b.sequence
        && a.from == b.from && a.to == b.to && a.kind == b.kind;
  }), edges.end());

  std::sort(execution.begin(), execution.end(), [](const ExecPoint &a,
                                                    const ExecPoint &b)
  {
    return std::tie(a.run_id, a.seed, a.sequence, a.pc, a.size)
         < std::tie(b.run_id, b.seed, b.sequence, b.pc, b.size);
  });
  execution.erase(std::unique(execution.begin(), execution.end(),
    [](const ExecPoint &a, const ExecPoint &b)
    {
      return a.run_id == b.run_id && a.seed == b.seed
          && a.sequence == b.sequence && a.pc == b.pc && a.size == b.size;
    }), execution.end());

  std::sort(consumed_image_reads.begin(), consumed_image_reads.end(),
    [](const ConsumedImageRange &a, const ConsumedImageRange &b)
  {
    return std::tie(a.run_id, a.seed, a.addr, a.size)
         < std::tie(b.run_id, b.seed, b.addr, b.size);
  });
  consumed_image_reads.erase(std::unique(
    consumed_image_reads.begin(), consumed_image_reads.end(),
    [](const ConsumedImageRange &a, const ConsumedImageRange &b)
    {
      return a.run_id == b.run_id && a.seed == b.seed
          && a.addr == b.addr && a.size == b.size;
    }), consumed_image_reads.end());

  // Memory accesses are ordered evidence.  Preserve repeated accesses but put
  // merged runs into a deterministic run/sequence order.
  std::sort(data.begin(), data.end(), [](const DataAcc &a, const DataAcc &b)
  {
    return std::tie(a.run_id, a.seed, a.sequence, a.from, a.addr, a.kind,
                    a.size, a.value, a.scope)
         < std::tie(b.run_id, b.seed, b.sequence, b.from, b.addr, b.kind,
                    b.size, b.value, b.scope);
  });
  data.erase(std::unique(data.begin(), data.end(), [](const DataAcc &a, const DataAcc &b)
  {
    return a.run_id == b.run_id && a.seed == b.seed && a.sequence == b.sequence
        && a.from == b.from && a.addr == b.addr && a.kind == b.kind
        && a.size == b.size && a.value == b.value && a.scope == b.scope;
  }), data.end());

  for ( StatePoint &state : states )
  {
    std::sort(state.regs.begin(), state.regs.end(), [](const RegisterValue &a,
                                                       const RegisterValue &b)
    {
      return std::tie(a.reg, a.width, a.value) < std::tie(b.reg, b.width, b.value);
    });
    state.regs.erase(std::unique(state.regs.begin(), state.regs.end(),
      [](const RegisterValue &a, const RegisterValue &b)
      { return a.reg == b.reg && a.width == b.width && a.value == b.value; }),
      state.regs.end());
  }

  auto regs_less = [](const std::vector<RegisterValue> &a,
                      const std::vector<RegisterValue> &b)
  {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(),
      [](const RegisterValue &x, const RegisterValue &y)
      { return std::tie(x.reg, x.value, x.width) < std::tie(y.reg, y.value, y.width); });
  };
  std::sort(states.begin(), states.end(), [&](const StatePoint &a, const StatePoint &b)
  {
    const auto ak = std::tie(a.run_id, a.source, a.pc, a.seed,
                             a.sequence, a.kind);
    const auto bk = std::tie(b.run_id, b.source, b.pc, b.seed,
                             b.sequence, b.kind);
    if ( ak != bk )
      return ak < bk;
    return regs_less(a.regs, b.regs);
  });
  states.erase(std::unique(states.begin(), states.end(), [](const StatePoint &a, const StatePoint &b)
  {
    if ( a.run_id != b.run_id || a.source != b.source || a.pc != b.pc
      || a.seed != b.seed || a.sequence != b.sequence || a.kind != b.kind
      || a.regs.size() != b.regs.size() )
      return false;
    for ( size_t i = 0; i < a.regs.size(); ++i )
      if ( a.regs[i].reg != b.regs[i].reg || a.regs[i].value != b.regs[i].value
        || a.regs[i].width != b.regs[i].width )
        return false;
    return true;
  }), states.end());

  std::sort(final_writes.begin(), final_writes.end(), [](const MemoryBytes &a, const MemoryBytes &b)
  {
    return std::tie(a.run_id, a.seed, a.addr, a.scope, a.bytes)
         < std::tie(b.run_id, b.seed, b.addr, b.scope, b.bytes);
  });
  final_writes.erase(std::unique(final_writes.begin(), final_writes.end(),
    [](const MemoryBytes &a, const MemoryBytes &b)
    {
      return a.run_id == b.run_id && a.addr == b.addr && a.seed == b.seed
          && a.scope == b.scope && a.bytes == b.bytes;
    }), final_writes.end());
}

EmuDriver::EmuDriver(const RaxApi *api, const ProgramImage &img, bool strict_perms,
                     bool windows_x64, const std::vector<EmuCallSummary> &summaries)
  : api_(api), img_(img), strict_perms_(strict_perms), windows_x64_(windows_x64),
    summaries_(summaries)
{
  if ( api_ == nullptr )
    return;
  int rax_arch = 0, sp = -1, fp = -1, lr = -1, pc = -1, ret = -1;
  uint32_t mode = 0;
  bool is64 = false;
  const HybridEntryMode entry_mode = img_.entries.size() == 1
                                   ? img_.entries.front().entry_mode
                                   : HybridEntryMode::UNKNOWN;
  if ( !arch_params(img_.arch, img_.big_endian, entry_mode, rax_arch, mode,
                    sp, fp, lr, pc, ret, is64) )
    return;
  sp_reg_ = sp; fp_reg_ = fp; lr_reg_ = lr; pc_reg_ = pc; ret_reg_ = ret;
  rax_arch_ = rax_arch;
  rax_mode_ = mode;
  abi_ = hybrid_abi_for_arch(img_.arch, windows_x64_);
  const HybridAbiLayout &abi_layout = hybrid_abi_layout(abi_);
  if ( !abi_layout.supported() )
    return;
  std::sort(summaries_.begin(), summaries_.end(), [](const EmuCallSummary &a,
                                                     const EmuCallSummary &b)
  {
    if ( a.address != b.address )
      return a.address < b.address;
    const bool a_modeled = a.kind != EmuSummaryKind::UNMODELED;
    const bool b_modeled = b.kind != EmuSummaryKind::UNMODELED;
    if ( a_modeled != b_modeled )
      return a_modeled; // retain an available model for duplicate target xrefs
    return std::tie(a.kind, a.name) < std::tie(b.kind, b.name);
  });
  summaries_.erase(std::unique(summaries_.begin(), summaries_.end(),
    [](const EmuCallSummary &a, const EmuCallSummary &b)
    { return a.address == b.address; }), summaries_.end());

  // Integer argument registers are selected by the same IDA-free ABI policy
  // used by call-site input collection and stack placement.
  arg_regs_ = abi_layout.argument_registers;
  capture_regs_ = arg_regs_;
  auto add_capture = [&](int reg)
  {
    if ( reg >= 0 && std::find(capture_regs_.begin(), capture_regs_.end(), reg) == capture_regs_.end() )
      capture_regs_.push_back(reg);
  };
  add_capture(sp_reg_);
  add_capture(fp_reg_);
  add_capture(lr_reg_);
  add_capture(pc_reg_);
  add_capture(ret_reg_);
  // Predicate-state sampling is intentionally limited to architectural scalar
  // registers. This is enough to export concrete Z3 inputs at native branch
  // boundaries without copying vector state on every instruction.
  switch ( img_.arch )
  {
    case HybridArch::X86_64:
      for ( int index = 0; index < 16; ++index ) add_capture(RAX_X86_GPR64(index));
      add_capture(RAX_X86_REG_RFLAGS);
      break;
    case HybridArch::X86_32:
      for ( int index = 0; index < 8; ++index ) add_capture(RAX_X86_GPR32(index));
      add_capture(RAX_X86_REG_EFLAGS);
      break;
    case HybridArch::ARM64:
      for ( int index = 0; index <= 30; ++index ) add_capture(RAX_ARM64_X(index));
      add_capture(RAX_ARM64_REG_PSTATE);
      break;
    case HybridArch::ARM32:
      for ( int index = 0; index <= 12; ++index ) add_capture(RAX_ARM_R(index));
      add_capture(RAX_ARM_REG_CPSR);
      break;
    case HybridArch::CORTEX_M:
      for ( int index = 0; index <= 12; ++index ) add_capture(RAX_CM_R(index));
      add_capture(RAX_CM_REG_XPSR);
      break;
    case HybridArch::RISCV64:
      for ( int index = 0; index < 32; ++index ) add_capture(RAX_RISCV_X(index));
      break;
    case HybridArch::HEXAGON:
      for ( int index = 0; index < 32; ++index ) add_capture(RAX_HEX_R(index));
      break;
    default:
      break;
  }

  // Choose a scratch stack region that does not intersect the image. This region
  // doubles as the engine's initial (default) mapping, so it never collides with
  // the image maps below.
  static const uint64_t cand64[] = { 0x00007ffd00000000ull, 0x0000600000000000ull, 0x0000000120000000ull };
  static const uint64_t cand32[] = { 0x70000000ull, 0x50000000ull, 0x10000000ull };
  const uint64_t *cands = is64 ? cand64 : cand32;
  const size_t ncand = is64 ? 3 : 3;
  stack_size_ = kStackSize;
  bool chosen = false;
  for ( size_t i = 0; i < ncand; ++i )
  {
    const uint64_t b = cands[i];
    const uint64_t e = b + stack_size_;
    const bool intersects = img_.hi > img_.lo && b < img_.hi && img_.lo < e;
    if ( !intersects )
    {
      stack_base_ = b;
      chosen = true;
      break;
    }
  }
  if ( !chosen )
    return; // no scratch-stack region clear of the image; leave the engine closed (no-op)
  sentinel_ = stack_base_ + kPage;

  rax_engine_config cfg;
  std::memset(&cfg, 0, sizeof(cfg));
  cfg.size      = sizeof(cfg);
  cfg.arch      = rax_arch;
  cfg.mode      = mode;
  cfg.backend   = RAX_BACKEND_EMULATOR;
  cfg.mem_base  = stack_base_;
  cfg.mem_size  = stack_size_;
  cfg.mem_perms = RAX_PROT_ALL;
  cfg.flags     = 0;

  if ( api_->engine_open_config(&cfg, &engine_) != RAX_OK || engine_ == nullptr )
  {
    engine_ = nullptr;
    return;
  }

  stepping_ = api_->engine_supports_stepping(engine_) != 0;

  if ( !map_image() )
  {
    api_->engine_close(engine_);
    engine_ = nullptr;
    return;
  }
  if ( !map_stack() )
  {
    api_->engine_close(engine_);
    engine_ = nullptr;
    return;
  }

  // Probe whether the backend records per-access memory. If not,
  // drefs are simply skipped; crefs still work wherever code hooks fire.
  uint32_t probe_id = 0;
  if ( api_->hook_add_mem(engine_, RAX_HOOK_MEM_READ, 1, 0, mem_tr, nullptr, &probe_id) == RAX_OK )
  {
    mem_hooks_ok_ = true;
    api_->hook_del(engine_, probe_id);
  }

  save_baseline();
}

EmuDriver::~EmuDriver()
{
  if ( engine_ != nullptr )
    api_->engine_close(engine_);
  engine_ = nullptr;
}

bool EmuDriver::map_image()
{
  // Build page permissions first. IDA and rax use different permission bit
  // layouts; pages shared by adjacent segments receive the union. In permissive
  // compatibility mode every page remains RWX, but the evidence records which
  // mode produced a run at the caller level.
  std::map<uint64_t, uint32_t> pages;
  for ( const SegImage &s : img_.segs )
  {
    if ( s.end <= s.start )
      continue;
    uint32_t prot = RAX_PROT_NONE;
    if ( !strict_perms_ || s.perm == 0 )
      prot = RAX_PROT_ALL;
    else
    {
      if ( (s.perm & 4u) != 0 ) prot |= RAX_PROT_READ;  // SEGPERM_READ
      if ( (s.perm & 2u) != 0 ) prot |= RAX_PROT_WRITE; // SEGPERM_WRITE
      if ( (s.perm & 1u) != 0 ) prot |= RAX_PROT_EXEC;  // SEGPERM_EXEC
    }
    uint64_t rounded_end = s.end;
    if ( (s.end & (kPage - 1)) != 0 )
    {
      uint64_t rounded = 0;
      if ( !checked_add(s.end, kPage - 1, &rounded) )
        return false;
      rounded_end = page_down(rounded);
    }
    for ( uint64_t p = page_down(s.start); p < rounded_end; )
    {
      pages[p] |= prot;
      if ( rounded_end - p <= kPage )
        break;
      p += kPage;
    }
  }

  struct IV { uint64_t base, end; uint32_t prot; };
  std::vector<IV> merged;
  for ( const auto &kv : pages )
  {
    const uint64_t base = kv.first;
    const uint32_t prot = kv.second == RAX_PROT_NONE ? RAX_PROT_READ : kv.second;
    if ( !merged.empty() && base == merged.back().end && prot == merged.back().prot )
    {
      merged.back().end += kPage;
    }
    else
    {
      uint64_t end = 0;
      if ( !checked_add(base, kPage, &end) )
        return false;
      merged.push_back(IV{ base, end, prot });
    }
  }

  for ( const IV &iv : merged )
  {
    const uint64_t len = iv.end - iv.base;
    int st = api_->mem_map(engine_, iv.base, len, iv.prot);
    if ( st != RAX_OK )
    {
      // Possibly already mapped. The selected scratch range is guaranteed not
      // to overlap the image, so protecting this exact interval is safe.
      if ( api_->mem_protect(engine_, iv.base, len, iv.prot) != RAX_OK )
        return false;
    }
  }

  return load_image_bytes();
}

bool EmuDriver::load_image_bytes()
{
  // Write each segment's initialized bytes; leave holes (.bss) as zero-fill.
  // Used once at map time; per-run restoration is done via the context snapshot
  // (see restore_state / save_baseline), which resets memory AND registers.
  for ( const SegImage &s : img_.segs )
  {
    const size_t len = s.bytes.size();
    if ( s.end < s.start || uint64_t(len) > s.end - s.start
      || (len != 0 && s.mask.size() < (len + 7) / 8) )
      return false;
    size_t i = 0;
    while ( i < len )
    {
      while ( i < len && (s.mask[i / 8] & (1u << (i & 7))) == 0 )
        ++i; // skip an uninitialized run
      if ( i >= len )
        break;
      size_t j = i;
      while ( j < len && (s.mask[j / 8] & (1u << (j & 7))) != 0 )
        ++j;
      uint64_t address = 0;
      if ( !checked_add(s.start, uint64_t(i), &address)
        || api_->mem_write(engine_, address, s.bytes.data() + i, j - i) != RAX_OK )
        return false;
      i = j;
    }
  }
  return true;
}

bool EmuDriver::map_stack()
{
  // The stack is the engine's default region (mem_base/mem_size at open); just
  // make sure it is data-accessible. The sentinel is an `until` address and is
  // never fetched, so an executable stack is unnecessary in strict mode.
  const uint32_t prot = strict_perms_ ? (RAX_PROT_READ | RAX_PROT_WRITE) : RAX_PROT_ALL;
  return api_->mem_protect(engine_, stack_base_, stack_size_, prot) == RAX_OK;
}

void EmuDriver::save_baseline()
{
  baseline_ok_ = false;
  baseline_.clear();
  if ( api_->context_save == nullptr )
    return;
  size_t len = 0;
  if ( api_->context_save(engine_, nullptr, 0, &len) != RAX_OK || len == 0 || len > kMaxCtx )
    return;
  try
  {
    baseline_.resize(len);
  }
  catch ( ... ) // bad_alloc on a very large image: no baseline => no discovery
  {
    baseline_.clear();
    return;
  }
  if ( api_->context_save(engine_, baseline_.data(), baseline_.size(), &len) != RAX_OK )
  {
    baseline_.clear();
    return;
  }
  baseline_.resize(len);
  baseline_ok_ = true;
}

bool EmuDriver::seed_arg_regs(uint64_t seed, const FuncRange *function)
{
  for ( int reg : arg_regs_ )
    if ( api_->reg_write_u64(engine_, reg, 0) != RAX_OK )
      return false;

  const HybridFunctionProfile *profile = function != nullptr
                                       ? &function->profile : nullptr;
  const size_t implicit = profile != nullptr ? profile->implicit_arguments() : 0;
  const size_t available = implicit < arg_regs_.size()
                         ? arg_regs_.size() - implicit : 0;
  const size_t explicit_count = profile != nullptr
                             && profile->explicit_arguments_known
      ? std::min(profile->explicit_arguments, available) : available;
  const std::vector<HybridSeedValue> corpus = seed == 0
      ? std::vector<HybridSeedValue>{}
      : hybrid_seed_argument_corpus(
            seed, explicit_count, img_.lo, stack_base_, stack_size_);
  for ( size_t index = 0; index < corpus.size(); ++index )
  {
    if ( api_->reg_write_u64(engine_, arg_regs_[implicit + index],
                             corpus[index].value) != RAX_OK )
      return false;
  }

  if ( profile != nullptr && implicit == 2 && arg_regs_.size() >= 2 )
  {
    // Objective-C methods receive valid mapped placeholders for the hidden
    // receiver/class and selector arguments. They are deliberately isolated
    // from the summary allocator's cursor and are overridden by any proven
    // call-site or solver input applied below.
    uint64_t self = 0, selector = 0;
    if ( !checked_add(stack_base_, 0x10000, &self)
      || !checked_add(self, 0x200, &selector) )
      return false;
    const std::vector<uint8_t> object(256, 0);
    if ( api_->mem_write(engine_, self, object.data(), object.size()) != RAX_OK )
      return false;
    std::string selector_text = profile->objc_selector;
    selector_text.push_back('\0');
    if ( api_->mem_write(engine_, selector, selector_text.data(),
                         selector_text.size()) != RAX_OK
      || api_->reg_write_u64(engine_, arg_regs_[0], self) != RAX_OK
      || api_->reg_write_u64(engine_, arg_regs_[1], selector) != RAX_OK )
      return false;
  }
  return true;
}

bool EmuDriver::apply_input(const EmuInput &input, uint64_t sp)
{
  const HybridAbiInputPlan plan = hybrid_plan_abi_input(
      hybrid_abi_layout(abi_), input, sp, stack_base_, stack_size_, img_.big_endian);
  if ( !plan.valid() )
    return false;
  for ( const HybridAbiRegisterWrite &write : plan.registers )
    if ( api_->reg_write_u64(engine_, write.reg, write.value) != RAX_OK )
      return false;
  for ( const HybridAbiStackWrite &write : plan.stack )
    if ( api_->mem_write(engine_, write.address, write.bytes.data(), write.size) != RAX_OK )
      return false;
  return true;
}

void EmuDriver::capture_final_writes(EmuEvents &out, const HybridConfig &cfg,
                                     uint32_t run_id, uint64_t seed, size_t data_begin)
{
  if ( api_->mem_read == nullptr || cfg.max_runtime_bytes == 0 || data_begin >= out.data.size() )
    return;

  struct Range { uint64_t lo, hi; DataScope scope; };
  std::vector<Range> ranges;
  for ( size_t i = data_begin; i < out.data.size(); ++i )
  {
    const DataAcc &a = out.data[i];
    if ( a.kind != RAX_MEM_WRITE || a.size == 0 || a.run_id != run_id )
      continue;
    const uint64_t hi = a.addr > std::numeric_limits<uint64_t>::max() - a.size
                      ? std::numeric_limits<uint64_t>::max() : a.addr + a.size;
    if ( hi <= a.addr )
      continue;
    ranges.push_back(Range{ a.addr, hi, a.scope });
  }
  std::sort(ranges.begin(), ranges.end(), [](const Range &a, const Range &b)
  {
    return std::tie(a.scope, a.lo, a.hi) < std::tie(b.scope, b.lo, b.hi);
  });

  std::vector<Range> merged;
  for ( const Range &r : ranges )
  {
    if ( !merged.empty() && r.scope == merged.back().scope && r.lo <= merged.back().hi )
      merged.back().hi = std::max(merged.back().hi, r.hi);
    else
      merged.push_back(r);
  }

  uint64_t remaining = cfg.max_runtime_bytes;
  for ( const Range &r : merged )
  {
    if ( remaining == 0 )
      break;
    const uint64_t raw_len = r.hi - r.lo;
    const size_t len = size_t(std::min<uint64_t>(raw_len, remaining));
    if ( len == 0 )
      continue;
    MemoryBytes b;
    b.addr = r.lo;
    b.bytes.resize(len);
    b.scope = r.scope;
    b.run_id = run_id;
    b.seed = seed;
    if ( api_->mem_read(engine_, b.addr, b.bytes.data(), b.bytes.size()) != RAX_OK )
      continue;
    remaining -= b.bytes.size();
    out.final_writes.push_back(std::move(b));
  }
}

bool EmuDriver::restore_state()
{
  // Restore the clean baseline (memory + registers) before each run so per-run
  // isolation holds: one function's stores and leftover register values can't
  // leak into the next. A captured baseline is REQUIRED for discovery (see
  // can_discover), so this always restores.
  return api_->context_restore(engine_, baseline_.data(), baseline_.size()) == RAX_OK;
}

bool EmuDriver::emulate_from(uint64_t entry, uint64_t func_end, const HybridConfig &cfg, EmuEvents &out,
                             EmuOutcome *outcome, bool record_pcs, uint64_t seed,
                             uint32_t run_id, const EmuInput *input,
                             bool (*cancelled)(const void *),
                             const void *cancellation_user)
{
  if ( !can_discover() )
    return false;

  if ( outcome != nullptr )
    *outcome = EmuOutcome{};
  const uint64_t effective_seed = input != nullptr ? input->seed : seed;
  const uint32_t effective_run = input != nullptr ? input->run_id : run_id;
  const size_t data_begin = out.data.size();
  const FuncRange *function = img_.function_at(entry);

  if ( !restore_state() )
    return false;

  const bool is64 = img_.arch == HybridArch::X86_64 || img_.arch == HybridArch::ARM64
                 || img_.arch == HybridArch::RISCV64;
  const uint64_t align = is64 ? 0xFull : 0x3ull;
  uint64_t sp = (stack_base_ + stack_size_ - 0x400) & ~align;
  if ( img_.arch == HybridArch::X86_64 )
    sp |= 0x8; // x86-64 ABI: rsp%16 == 8 at entry (after the call pushed retaddr)
  const uint64_t sp_entry = sp;

  if ( sp_reg_ >= 0 )
    if ( api_->reg_write_u64(engine_, sp_reg_, sp) != RAX_OK )
      return false;
  if ( fp_reg_ >= 0 )
    if ( api_->reg_write_u64(engine_, fp_reg_, sp) != RAX_OK )
      return false;

  if ( lr_reg_ >= 0 )
  {
    // Link-register architectures (ARM): the return address lives in LR.
    const bool thumb_return = img_.arch == HybridArch::CORTEX_M
                           || (img_.arch == HybridArch::ARM32
                            && function != nullptr
                            && function->entry_mode == HybridEntryMode::THUMB);
    const uint64_t return_address = thumb_return ? sentinel_ | 1u : sentinel_;
    if ( api_->reg_write_u64(engine_, lr_reg_, return_address) != RAX_OK )
      return false;
  }
  else
  {
    // Stack-return architectures (x86): place the sentinel at [sp].
    const size_t ptr = is64 ? 8 : 4;
    uint8_t buf[8] = { 0 };
    uint64_t s = sentinel_;
    for ( size_t k = 0; k < ptr; ++k )
      buf[k] = (uint8_t)((s >> (8 * k)) & 0xFF);
    if ( api_->mem_write(engine_, sp, buf, ptr) != RAX_OK )
      return false;
  }

  if ( !seed_arg_regs(effective_seed, function) )
    return false;

  if ( input != nullptr )
  {
    if ( !apply_input(*input, sp) )
      return false;
  }
  const bool synthetic_entry_context = function != nullptr
      && function->profile.implicit_arguments() == 2
      && !(input_overrides_argument(input, 0, arg_regs_)
        && input_overrides_argument(input, 1, arg_regs_));

  HookCtx ctx;
  ctx.out = &out;
  ctx.api = api_;
  ctx.capture_regs = &capture_regs_;
  ctx.summaries = &summaries_;
  ctx.image = &img_;
  ctx.lo = img_.lo;
  ctx.hi = img_.hi;
  ctx.flo = entry;
  ctx.fhi = func_end > entry ? func_end : img_.hi;
  ctx.func = function != nullptr && function->start == entry ? function : nullptr;
  ctx.stack_lo = stack_base_;
  ctx.stack_hi = stack_base_ + stack_size_;
  ctx.heap_lo = stack_base_ + 0x10000;
  ctx.heap_cursor = ctx.heap_lo + 0x1000; // reserve Objective-C entry artifacts
  ctx.heap_hi = stack_base_ + stack_size_ / 2;
  ctx.sp_reg = sp_reg_;
  ctx.lr_reg = lr_reg_;
  ctx.pc_reg = pc_reg_;
  ctx.ret_reg = ret_reg_;
  ctx.arg_regs = &arg_regs_;
  ctx.is64 = is64;
  ctx.register_width = is64 ? 8 : 4;
  ctx.big_endian = img_.big_endian;
  ctx.strict_permissions = strict_perms_;
  ctx.record_memory = cfg.want_drefs || cfg.want_runtime_strings
                   || cfg.want_smc_evidence;
  ctx.stack_argument_offset = hybrid_abi_layout(abi_).stack_argument_offset;
  ctx.rax_arch = rax_arch_;
  ctx.rax_mode = rax_mode_;
  ctx.run_id = effective_run;
  ctx.seed = effective_seed;
  ctx.record_pcs = record_pcs;
  ctx.cancelled = cancelled;
  ctx.cancellation_user = cancellation_user;
  const auto per_run_cap = [](size_t existing, uint64_t allowance)
  {
    const size_t increment = allowance > std::numeric_limits<size_t>::max()
                           ? std::numeric_limits<size_t>::max()
                           : static_cast<size_t>(allowance);
    return increment > std::numeric_limits<size_t>::max() - existing
         ? std::numeric_limits<size_t>::max() : existing + increment;
  };
  ctx.edge_cap = per_run_cap(out.edges.size(), cfg.max_insns);
  ctx.execution_cap = per_run_cap(out.execution.size(), cfg.max_insns);
  ctx.data_cap = per_run_cap(out.data.size(), cfg.max_insns);
  ctx.dependency_cap = per_run_cap(out.consumed_image_reads.size(),
                                   cfg.max_insns);
  ctx.state_cap = per_run_cap(out.states.size(),
                              std::min<uint64_t>(cfg.max_insns, 65536));

  uint32_t code_id = 0, mem_id = 0, inv_id = 0;
  bool code_ok = api_->hook_add_code(engine_, 1, 0, code_tr, &ctx, &code_id) == RAX_OK;
  bool mem_ok = false;
  if ( (ctx.record_memory || strict_perms_) && mem_hooks_ok_ )
  {
    mem_ok = api_->hook_add_mem(engine_,
                                RAX_HOOK_MEM_READ | RAX_HOOK_MEM_WRITE,
                                1, 0, mem_tr, &ctx, &mem_id) == RAX_OK;
  }
  bool inv_ok = api_->hook_add_invalid(engine_, inv_tr, &ctx, &inv_id) == RAX_OK;

  const uint64_t icount_start = api_->emu_icount(engine_);
  uint64_t attempted_steps = 0;
  bool attempted_steps_valid = code_ok;
  if ( code_ok )
  {
    const uint64_t timeout_total = cfg.timeout_ms > std::numeric_limits<uint64_t>::max() / 1000
                                 ? std::numeric_limits<uint64_t>::max()
                                 : cfg.timeout_ms * 1000ull;
    const auto wall_start = std::chrono::steady_clock::now();
    uint64_t begin = entry;
    for ( unsigned resumptions = 0; resumptions <= 256; ++resumptions )
    {
      const uint64_t used = api_->emu_icount(engine_) - icount_start;
      if ( used >= cfg.max_insns )
        break;
      const uint64_t elapsed = uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - wall_start).count());
      if ( elapsed >= timeout_total )
        break;
      ctx.summary_resume = false;
      const int status = api_->emu_start(engine_, begin, sentinel_,
                                         timeout_total - elapsed, cfg.max_insns - used);
      rax_exit slice_exit;
      std::memset(&slice_exit, 0, sizeof(slice_exit));
      if ( api_->emu_last_exit(engine_, &slice_exit) == RAX_OK )
      {
        if ( exit_value_is_attempted_steps(slice_exit.reason) )
        {
          const uint64_t remaining = std::numeric_limits<uint64_t>::max()
                                   - attempted_steps;
          attempted_steps += std::min<uint64_t>(remaining, slice_exit.value);
        }
        else
        {
          attempted_steps_valid = false;
        }
      }
      else
        attempted_steps_valid = false;
      if ( status != RAX_OK || !ctx.summary_resume )
        break;
      if ( pc_reg_ < 0 || api_->reg_read_u64(engine_, pc_reg_, &begin) != RAX_OK )
        break;
    }
  }

  // Summarize the run for the function-level analyses (purge / no-return).
  if ( code_ok && outcome != nullptr )
  {
    outcome->instruction_count = api_->emu_icount(engine_) - icount_start;
    outcome->attempted_steps = attempted_steps;
    outcome->attempted_steps_valid = attempted_steps_valid;
    rax_exit ex;
    std::memset(&ex, 0, sizeof(ex));
    if ( api_->emu_last_exit(engine_, &ex) == RAX_OK )
    {
      outcome->stop_valid = true;
      outcome->stop_reason = ex.reason;
      outcome->stop_status = ex.status;
      outcome->stop_pc = ex.address;
      outcome->returned = ex.reason == RAX_STOP_UNTIL; // reached the sentinel
      if ( ex.reason == RAX_STOP_ERROR && api_->engine_errmsg != nullptr )
      {
        char detail[512] = {};
        if ( api_->engine_errmsg(engine_, detail, sizeof(detail)) > 0 )
        {
          outcome->engine_error = detail;
          std::replace(outcome->engine_error.begin(), outcome->engine_error.end(),
                       '\n', ' ');
          std::replace(outcome->engine_error.begin(), outcome->engine_error.end(),
                       '\r', ' ');
        }
      }
    }
    outcome->terminated_process = ctx.terminated_process;
    outcome->permission_violation = ctx.permission_violation;
    outcome->cancelled = ctx.cancellation_requested;
    outcome->escaped_image = ctx.escaped_image;
    outcome->escape_source = ctx.escape_source;
    outcome->function_boundary = ctx.function_boundary;
    outcome->function_boundary_source = ctx.function_boundary_source;
    outcome->function_boundary_target = ctx.function_boundary_target;
    outcome->function_boundary_kind = ctx.function_boundary_kind;
    outcome->unmodeled_external = ctx.unmodeled_external;
    outcome->external_target = ctx.external_target;
    outcome->external_name = ctx.external_name;
    outcome->environment_model_failure = ctx.environment_model_failure;
    outcome->external_model_used = ctx.summarized_calls != 0;
    outcome->synthetic_entry_context = synthetic_entry_context;
    outcome->memory_observation_requested = ctx.record_memory;
    outcome->memory_observation_available = ctx.record_memory && mem_ok;
    outcome->consumed_context_complete = ctx.record_memory && mem_ok
                                       && outcome->stop_valid
                                       && stop_preserves_observed_context(
                                              outcome->stop_reason)
                                       && !ctx.execution_truncated
                                       && !ctx.dependency_truncated
                                       && !ctx.permission_violation
                                       && !ctx.cancellation_requested
                                       && !ctx.escaped_image
                                       && !ctx.function_boundary
                                       && !ctx.unmodeled_external
                                       && !ctx.environment_model_failure
                                       && ctx.summarized_calls == 0
                                       && !synthetic_entry_context;
    outcome->summarized_calls = ctx.summarized_calls;
    if ( outcome->returned && sp_reg_ >= 0 )
    {
      uint64_t sp_final = 0;
      if ( api_->reg_read_u64(engine_, sp_reg_, &sp_final) == RAX_OK )
      {
        if ( sp_final >= sp_entry && sp_final - sp_entry <= uint64_t(std::numeric_limits<int64_t>::max()) )
        {
          outcome->sp_delta = int64_t(sp_final - sp_entry);
          outcome->sp_valid = true;
        }
        else if ( sp_entry > sp_final && sp_entry - sp_final <= uint64_t(std::numeric_limits<int64_t>::max()) )
        {
          outcome->sp_delta = -int64_t(sp_entry - sp_final);
          outcome->sp_valid = true;
        }
      }
    }
  }

  if ( code_ok ) api_->hook_del(engine_, code_id);
  if ( mem_ok )  api_->hook_del(engine_, mem_id);
  if ( inv_ok )  api_->hook_del(engine_, inv_id);

  if ( code_ok )
    capture_final_writes(out, cfg, effective_run, effective_seed, data_begin);

  return code_ok;
}

} // namespace chernobog::hybrid
