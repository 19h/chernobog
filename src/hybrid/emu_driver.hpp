/*
 * emu_driver.hpp — drive rax to emulate the analyzed image and record the
 * control-flow edges and data accesses IDA's static pass could not resolve.
 *
 * This module is PURE rax: it includes no IDA headers and never touches the
 * database, so it is safe to run off the main thread against a pre-copied
 * ProgramImage. It produces raw addresses; classification into crefs/drefs and
 * the add-only-if-missing diff live in ref_discovery (which is on the DB side).
 */
#pragma once

#include <cstdint>
#include <unordered_set>
#include <vector>

#include "rax_loader.hpp"
#include "abi_policy.hpp"
#include "program_model.hpp"
#include "hybrid_config.hpp"

struct rax_engine; // opaque

namespace chernobog::hybrid {

// A taken control transfer prev->to observed during emulation (to != the static
// fall-through of prev). `from` is the transferring instruction.
struct ExecEdge
{
  uint64_t from = 0;
  uint64_t to   = 0;
  uint32_t run_id = 0;
  uint64_t seed = 0;
  enum class Kind : uint8_t
  {
    Unknown = 0,
    Call,
    Jump,
    Return,
  } kind = Kind::Unknown;
  // Total event order within one run.  The edge receives the sequence of the
  // destination code hook, after any source-instruction memory accesses.
  uint64_t sequence = 0;
};

// A bounded, ordered execution observation.  Unlike exec_pcs, this preserves
// per-run provenance, repetitions, and temporal order relative to DataAcc.
struct ExecPoint
{
  uint64_t pc = 0;
  uint32_t size = 0;
  uint64_t sequence = 0;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

enum class DataScope : uint8_t
{
  IMAGE = 0,
  STACK,
  HEAP,
  OTHER,
};

enum class EmuSummaryKind : uint8_t
{
  MEMCPY = 1,
  MEMMOVE,
  MEMSET,
  STRCPY,
  STRNCPY,
  STRLEN,
  STRCMP,
  ALLOCATE,
  CALLOCATE,
  DEALLOCATE,
  TERMINATE,
};

struct EmuCallSummary
{
  uint64_t address = 0;
  EmuSummaryKind kind = EmuSummaryKind::MEMCPY;
};

// A data memory access observed during emulation, attributed to the executing
// instruction `from`. `kind` is RAX_MEM_READ / RAX_MEM_WRITE. `value` is the
// datum read/written (low 8 bytes, little-endian) — a loaded value that is
// itself an in-image address reveals a pointer (vtable slot, function pointer).
struct DataAcc
{
  uint64_t from = 0;
  uint64_t addr = 0;
  uint64_t value = 0;
  uint32_t size = 0;
  int      kind = 0;
  DataScope scope = DataScope::IMAGE;
  uint64_t sequence = 0; // total order within one run
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

struct RegisterValue
{
  int reg = -1;          // rax register id
  uint64_t value = 0;
  uint8_t width = 8;
};

// Register state observed immediately after a non-fallthrough transfer (i.e.
// at the target's code hook).  It is deliberately architecture-neutral and is
// primarily used for call arguments, dispatcher states and reproducibility.
struct StatePoint
{
  enum class Kind : uint8_t
  {
    TransferTarget = 0,
    PredicateInput,
  } kind = Kind::TransferTarget;
  uint64_t source = 0;
  uint64_t pc = 0;
  uint64_t sequence = 0;
  std::vector<RegisterValue> regs;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

// Final bytes for a range written during the run.  This complements the
// per-access low-64-bit hook value and permits exact reconstruction of runtime
// strings, decrypted buffers and generated code.
struct MemoryBytes
{
  uint64_t addr = 0;
  std::vector<uint8_t> bytes;
  DataScope scope = DataScope::IMAGE;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

// Immutable-image bytes consumed as data by a run. This is deliberately
// separate from DataAcc: the latter remains current-function evidence, whereas
// dependency capture must also include reads performed by reached callees so a
// later branch counterexample cannot survive a relevant database patch.
struct ConsumedImageRange
{
  uint64_t addr = 0;
  uint32_t size = 0;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

struct EmuEvents
{
  std::vector<ExecEdge> edges;
  std::vector<ExecPoint> execution;
  std::vector<DataAcc>  data;
  std::vector<StatePoint> states;
  std::vector<MemoryBytes> final_writes;
  std::vector<ConsumedImageRange> consumed_image_reads;
  // Distinct instruction addresses executed this run (populated only when the
  // caller asks for it — see EmuDriver::emulate_from `record_pcs`). Used for
  // opaque-predicate / dead-branch analysis (which successors were reachable).
  std::unordered_set<uint64_t> exec_pcs;

  // Preserve per-run provenance while collecting all positive evidence. Exact
  // duplicates within the same run are removed by normalize(); observations
  // from different runs remain distinct for corroboration/conflict analysis.
  void merge_from(const EmuEvents &other);
  void normalize();
};

// Post-run summary of a single emulation, for the function-level analyses.
struct EmuOutcome
{
  int      stop_reason = 0;    // RAX_STOP_* from rax_emu_last_exit
  uint64_t stop_pc = 0;        // PC at stop
  bool     stop_valid = false;  // last-exit metadata was available
  uint64_t instruction_count = 0;
  bool     returned = false;   // reached the sentinel return address (function returned)
  bool     sp_valid = false;   // sp_delta is meaningful (returned + SP readable)
  int64_t  sp_delta = 0;       // final SP - entry SP (net stack change on return)
  bool     terminated_process = false; // modeled exit/abort/termination routine
  bool     permission_violation = false; // strict segment policy stopped the run
  bool     cancelled = false; // cooperative worker-generation cancellation
  // True only when code and image-data dependencies were observed without a
  // backend-capability gap or trace truncation. Universal-claim vetoes require
  // this; ordinary exploratory observations do not.
  bool     consumed_context_complete = false;
  uint32_t summarized_calls = 0;

  bool definitive_terminal() const
  {
    return terminated_process || stop_reason == RAX_STOP_HLT || stop_reason == RAX_STOP_SHUTDOWN;
  }
  bool conclusive() const { return returned || definitive_terminal(); }
};

class EmuDriver
{
public:
  EmuDriver(const RaxApi *api, const ProgramImage &img, bool strict_perms = true,
            bool windows_x64 = false,
            const std::vector<EmuCallSummary> &summaries = {});
  ~EmuDriver();

  EmuDriver(const EmuDriver &) = delete;
  EmuDriver &operator=(const EmuDriver &) = delete;

  // True iff the engine opened and the image mapped: emulation is possible.
  bool ok() const { return engine_ != nullptr; }
  // True iff discovery can run: the engine opened, the backend supports
  // single-stepping (required for code hooks, hence edge discovery), AND a clean
  // baseline was captured (required for correct per-run isolation). When false,
  // emulate_from() is a no-op.
  bool can_discover() const { return ok() && stepping_ && baseline_ok_; }

  // Emulate one function (its entry .. func_end) under the caps in `cfg`,
  // appending discovered edges/data to `out`. Only edges/accesses whose source
  // instruction lies within [entry, func_end) are recorded, so callee bodies
  // executed under this function's fabricated state do not contribute noise —
  // each function is mined from its own entry. Bounded by instruction count and
  // wall-clock timeout; faults are contained. Returns true if emulation ran.
  bool emulate_from(uint64_t entry, uint64_t func_end, const HybridConfig &cfg, EmuEvents &out,
                    EmuOutcome *outcome = nullptr, bool record_pcs = false, uint64_t seed = 0,
                    uint32_t run_id = 0, const EmuInput *input = nullptr,
                    bool (*cancelled)(const void *) = nullptr,
                    const void *cancellation_user = nullptr);

private:
  bool map_image();
  bool map_stack();
  bool load_image_bytes();
  void save_baseline();
  bool restore_state();
  bool seed_arg_regs(uint64_t seed); // deterministic fallback variation
  bool apply_input(const EmuInput &input, uint64_t sp);
  void capture_final_writes(EmuEvents &out, const HybridConfig &cfg,
                            uint32_t run_id, uint64_t seed, size_t data_begin);

  const RaxApi     *api_ = nullptr;
  const ProgramImage &img_;
  rax_engine       *engine_ = nullptr;
  bool              stepping_ = false;
  bool              mem_hooks_ok_ = false;
  bool              strict_perms_ = true;
  bool              windows_x64_ = false;
  HybridAbi             abi_ = HybridAbi::UNKNOWN;

  // Per-arch execution parameters resolved in the constructor.
  int      sp_reg_ = -1;   // stack-pointer register id
  int      fp_reg_ = -1;   // frame-pointer register id (-1 if none)
  int      lr_reg_ = -1;   // link register id (-1 => return address is on stack)
  int      pc_reg_ = -1;
  int      ret_reg_ = -1;
  int      rax_arch_ = 0;
  uint32_t rax_mode_ = 0;
  std::vector<int> arg_regs_; // integer argument registers (for multi-run seeding)
  std::vector<int> capture_regs_; // compact architectural state sampled at transfers
  uint64_t stack_base_ = 0;
  uint64_t stack_size_ = 0;
  uint64_t sentinel_ = 0;  // "returned out of the function" stop address
  std::vector<EmuCallSummary> summaries_;

  std::vector<uint8_t> baseline_; // rax context snapshot (image+regs) for reuse
  bool baseline_ok_ = false;
};

} // namespace chernobog::hybrid
