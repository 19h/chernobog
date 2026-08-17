/*
 * IDC orchestration surface for Chernobog.
 *
 * Every capability the plugin exposes through hotkeys, popup actions, or
 * environment variables is also reachable from IDA's IDC interpreter through
 * `chernobog_*` functions. The functions themselves live in the interpreter's
 * process-wide table; each call resolves the per-database Host below from
 * IDA's current database context, so a script never reaches into another IDB.
 */
#pragma once

#include <cstddef>
#include <cstdint>

struct hikari_cfg_stats_t;
struct native_opaque_stats_t;

namespace chernobog::hybrid { class Session; }
namespace chernobog::ida_analysis {
class EarlyHexRaysAnalysis;
class NativeAnalysisEngine;
}

namespace chernobog::idc {

// Implemented by the per-database plugmod. The IDC layer borrows every
// returned pointer for the duration of one call and owns none of them.
class Host
{
public:
  virtual ~Host() = default;

  virtual int64_t database_context() const = 0;

  // Lifecycle. ensure_activated() is idempotent and returns true once the
  // Hex-Rays callback and components are installed for this database.
  virtual bool ensure_activated() = 0;
  virtual bool hexrays_ready() const = 0;
  virtual bool components_ready() const = 0;
  virtual void clear_state() = 0;

  // Automatic emulation/deobfuscation on decompilation. The setter overrides
  // the cached CHERNOBOG_AUTO decision for the remainder of the process.
  virtual bool auto_mode() const = 0;
  virtual void set_auto_mode(bool enabled) = 0;
  virtual bool transformations_disabled() const = 0;

  virtual hybrid::Session *rax_session() = 0;
  virtual ida_analysis::NativeAnalysisEngine *native_analysis_engine() = 0;
  virtual ida_analysis::EarlyHexRaysAnalysis *early_hexrays_analysis() = 0;

  // Explicit re-runs of the two one-shot pre-Hex-Rays database passes. Both
  // ignore the per-database "already attempted" latch and refresh it, so a
  // script can drive them without the automatic path repeating the work.
  virtual bool run_hikari_cfg(hikari_cfg_stats_t *out) = 0;
  virtual bool run_native_opaque(native_opaque_stats_t *out) = 0;
};

// Bind `host` to its database context, registering the interpreter functions
// on first use. Returns false when the complete function table could not be
// registered, leaving the host unbound.
bool install(Host *host);

// Remove the binding; the last removal also deletes the interpreter
// functions. Safe to call for a host that was never installed.
void uninstall(Host *host);

// Number of chernobog_* functions the interpreter currently exposes.
size_t function_count();

} // namespace chernobog::idc
