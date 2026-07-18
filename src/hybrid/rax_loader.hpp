/*
 * rax_loader.hpp — internal address table for the linked RAX emulation engine.
 *
 * rax-capi is compiled into hybrid as a Rust staticlib.  Consumers retain one
 * function-pointer boundary, but the table is populated from direct rax_*
 * addresses instead of deployment-time symbol lookup.  This makes a missing
 * or incomplete C ABI a link error and leaves no companion shared library.
 *
 * CHERNOBOG_RAX_DISABLE=1 intentionally returns an unavailable result so the
 * independent IDA-native and deobfuscation providers remain isolatable.
 */
#pragma once

#include <rax.h> // linked rax_* declarations, typedefs, and ABI constants

namespace chernobog::hybrid {

// The subset of the rax C ABI that hybrid drives. Listed once as (field, symbol)
// pairs so the struct fields and linked addresses cannot drift.
#define CHERNOBOG_RAX_API_FUNCS(X)                                     \
  /* version + diagnostics (used for the ABI gate) */        \
  X(version,                  rax_version)                   \
  X(version_string,           rax_version_string)            \
  X(strerror,                 rax_strerror)                  \
  /* engine lifecycle */                                     \
  X(engine_open_config,       rax_engine_open_config)        \
  X(engine_close,             rax_engine_close)              \
  X(engine_supports_stepping, rax_engine_supports_stepping)  \
  X(engine_errmsg,            rax_engine_errmsg)             \
  /* memory */                                               \
  X(mem_map,                  rax_mem_map)                   \
  X(mem_protect,              rax_mem_protect)               \
  X(mem_write,                rax_mem_write)                 \
  /* registers */                                            \
  X(reg_write_u64,            rax_reg_write_u64)             \
  X(reg_read_u64,             rax_reg_read_u64)              \
  /* execution control */                                    \
  X(emu_start,                rax_emu_start)                 \
  X(emu_stop,                 rax_emu_stop)                  \
  X(emu_last_exit,            rax_emu_last_exit)             \
  X(emu_icount,               rax_emu_icount)                \
  /* hooks */                                                \
  X(hook_add_code,            rax_hook_add_code)             \
  X(hook_add_mem,             rax_hook_add_mem)              \
  X(hook_add_invalid,         rax_hook_add_invalid)          \
  X(hook_del,                 rax_hook_del)                  \
  /* snapshots (per-run isolation) */                        \
  X(context_save,             rax_context_save)              \
  X(context_restore,          rax_context_restore)

// Capability additions remain separate so consumers and injected test tables
// can degrade independently.  The production linked table populates all of
// them from the rax 1.3 static ABI.
#define CHERNOBOG_RAX_API_OPTIONAL_FUNCS(X)                            \
  /* lifecycle/introspection */                              \
  X(engine_reset,             rax_engine_reset)              \
  X(engine_arch,              rax_engine_arch)               \
  X(engine_mode,              rax_engine_mode)               \
  /* complete memory inspection */                           \
  X(mem_unmap,               rax_mem_unmap)                  \
  X(mem_read,                rax_mem_read)                   \
  X(mem_write_virt,          rax_mem_write_virt)             \
  X(mem_read_virt,           rax_mem_read_virt)              \
  X(mem_translate,           rax_mem_translate)              \
  X(mem_regions,             rax_mem_regions)                \
  /* complete register access */                             \
  X(reg_size,                rax_reg_size)                   \
  X(reg_read,                rax_reg_read)                   \
  X(reg_write,               rax_reg_write)                  \
  /* granular execution */                                   \
  X(emu_step,                rax_emu_step)                   \
  X(interrupt,               rax_interrupt)                  \
  X(nmi,                     rax_nmi)                        \
  X(can_interrupt,           rax_can_interrupt)              \
  /* richer hooks for environment models and coverage */     \
  X(hook_add_block,          rax_hook_add_block)             \
  X(hook_add_intr,           rax_hook_add_intr)              \
  X(hook_add_io_in,          rax_hook_add_io_in)             \
  X(hook_add_io_out,         rax_hook_add_io_out)            \
  X(hook_add_mmio_read,      rax_hook_add_mmio_read)         \
  X(hook_add_mmio_write,     rax_hook_add_mmio_write)

// Linked rax_* entry points. Every field is valid iff rax_load() != nullptr.
struct RaxApi
{
#define X(field, sym) decltype(&sym) field = nullptr;
  CHERNOBOG_RAX_API_FUNCS(X)
  CHERNOBOG_RAX_API_OPTIONAL_FUNCS(X)
#undef X

  // Introduced in rax API 1.2.  Consumers still probe the field so cloned test
  // tables and future capability policies can disable it independently.
  decltype(&rax_decode) decode = nullptr;

  // Introduced in rax API 1.3: stateless SMIR instruction-effect analysis.
  // The result is entirely caller-owned fixed-layout data; no Rust pointer
  // crosses this boundary.
  decltype(&rax_analyze) analyze = nullptr;
};

// Bind the linked table exactly once for the process (thread-safe), caching the
// outcome. Returns nullptr only for an ABI mismatch or CHERNOBOG_RAX_DISABLE=1.
// Safe to call from any thread; in practice invoked once on the main thread.
const RaxApi *rax_load();

// Convenience: true iff linked rax is enabled and ABI-compatible.
inline bool rax_available() { return rax_load() != nullptr; }

// True iff the linked table exposes the static decoder.
inline bool rax_can_decode()
{
  const RaxApi *a = rax_load();
  return a != nullptr && a->decode != nullptr;
}

// True iff the linked table exposes the versioned stateless analyzer.
inline bool rax_can_analyze()
{
  const RaxApi *a = rax_load();
  return a != nullptr && a->analyze != nullptr;
}

// Precise reason emulation is unavailable (empty when available).
const char *rax_unavailable_reason();

} // namespace chernobog::hybrid
