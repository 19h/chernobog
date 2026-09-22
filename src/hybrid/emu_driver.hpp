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
#include <string>
#include <unordered_set>
#include <vector>

#include "rax_loader.hpp"
#include "abi_policy.hpp"
#include "program_model.hpp"
#include "hybrid_config.hpp"
#include "temporal_memory.hpp"
#include "../vm/native_region.hpp"

struct rax_engine; // opaque

namespace chernobog::hybrid
{

// A taken control transfer prev->to observed during emulation (to != the static
// fall-through of prev). `from` is the transferring instruction.
struct ExecEdge
{
    uint64_t from = 0;
    uint64_t to = 0;
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

enum class EmuSummaryKind : uint8_t
{
    UNMODELED = 0,
    MEMCPY,
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
    RETURN_ARG0,
    RETURN_ZERO,
    STORE_POINTER_ARG1,
    ALLOCATE_OBJECT,
    RANDOM_U32,
    RANDOM_UNIFORM,
    MEMCHR,
    STRNLEN,
};

struct EmuCallSummary
{
    uint64_t address = 0;
    EmuSummaryKind kind = EmuSummaryKind::UNMODELED;
    std::string name;
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
    int kind = 0;
    DataScope scope = DataScope::IMAGE;
    uint64_t sequence = 0; // total order within one run
    uint32_t run_id = 0;
    uint64_t seed = 0;
};

struct RegisterValue
{
    int reg = -1; // rax register id
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
        RegionEntry,
        NativeInstructionEntry,
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
// dependency capture must also include image reads performed by bounded call
// summaries so a later branch counterexample cannot survive a relevant patch.
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
    std::vector<DataAcc> data;
    std::vector<StatePoint> states;
    std::vector<MemoryBytes> final_writes;
    std::vector<ConsumedImageRange> consumed_image_reads;
    std::vector<AllocationLifetime> allocations;
    std::vector<UseSnapshot> uses;
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
    struct NativeAdmission
    {
        uint64_t source = 0, target = 0, sequence = 0, before_identity = 0, after_identity = 0;
        size_t added_heads = 0;
        bool admitted = false;
        std::string reason;
    };
    bool native_walk = false;
    bool native_state_capture_requested = false, native_state_capture_complete = false;
    std::string native_walk_stop;
    std::vector<NativeAdmission> native_admissions;
    struct NativeObjectState
    {
        uint32_t argument = 0, offset = 0;
        uint64_t address = 0;
        std::vector<uint8_t> initial, final;
        bool readable = false;
    };
    std::vector<NativeObjectState> native_objects;
    std::vector<RegisterValue> native_final_registers;
    bool native_final_registers_complete = false;
    // Separate native-region observations never establish function-level facts.
    bool native_region = false, region_boundary = false, region_code_changed = false;
    uint64_t region_identity = 0, region_boundary_source = 0, region_boundary_target = 0;
    uint64_t entry_sp = 0;
    int stop_reason = 0;      // RAX_STOP_* from rax_emu_last_exit
    int stop_status = 0;      // rax_status when stop_reason == RAX_STOP_ERROR
    uint64_t stop_pc = 0;     // PC at stop
    bool stop_valid = false;  // last-exit metadata was available
    std::string engine_error; // backend diagnostic for RAX_STOP_ERROR
    uint64_t instruction_count = 0;
    uint64_t attempted_steps = 0;
    bool attempted_steps_valid = false;
    bool returned = false;             // reached the sentinel return address (function returned)
    bool sp_valid = false;             // sp_delta is meaningful (returned + SP readable)
    int64_t sp_delta = 0;              // final SP - entry SP (net stack change on return)
    bool terminated_process = false;   // modeled exit/abort/termination routine
    bool permission_violation = false; // strict segment policy stopped the run
    bool cancelled = false;            // cooperative worker-generation cancellation
    bool escaped_image = false;        // execution reached code outside the snapshotted image
    uint64_t escape_source = 0;
    // First transfer from the selected function into an unmodeled in-image
    // callee/tail target. The target instruction is not executed.
    bool function_boundary = false;
    uint64_t function_boundary_source = 0;
    uint64_t function_boundary_target = 0;
    ExecEdge::Kind function_boundary_kind = ExecEdge::Kind::Unknown;
    bool unmodeled_external = false;
    uint64_t external_target = 0;
    std::string external_name;
    bool environment_model_failure = false;
    // Explicit region environment contract, separate from function completeness.
    bool native_temporal_requested = false, native_temporal_complete = false;
    // Complete temporal ledger before a sentinel or pre-instruction region stop.
    // This does not assert that the selected execution returned or can continue.
    bool native_temporal_prefix_complete = false;
    uint64_t native_temporal_prefix_end = 0; // exclusive event sequence bound
    bool external_model_used = false;
    bool synthetic_entry_context = false;
    // `requested` records configuration intent; `available` records whether a
    // backend hook was successfully installed for this run.  A zero memory-event
    // count is interpretable only when available is true.
    bool memory_observation_requested = false;
    bool memory_observation_available = false;
    // Complete ordered data-event prefix for directly executed instructions.
    // Distinct from dependency completeness. Values wider than 8 bytes remain
    // partial, and this does not assert execution beyond a function-boundary stop.
    bool data_trace_complete = false;
    bool data_trace_truncated = false;
    bool data_trace_filtered = false;
    // True only when code and image-data dependencies were observed without a
    // backend-capability gap or trace truncation. Universal-claim vetoes require
    // this; ordinary exploratory observations do not.
    bool consumed_context_complete = false;
    // Bounded use evidence may depend on explicit call models. This flag does
    // not grant the model-free universal-claim contract above.
    bool temporal_observation_available = false;
    bool temporal_capture_complete = false;
    bool temporal_capture_truncated = false;
    uint32_t summarized_calls = 0;

    bool definitive_terminal() const
    {
        return !native_region && (terminated_process || stop_reason == RAX_STOP_HLT ||
                                  stop_reason == RAX_STOP_SHUTDOWN);
    }
    bool conclusive() const { return !native_region && (returned || definitive_terminal()); }
};

inline const char *hybrid_rax_stop_reason_name(int reason)
{
    switch (reason)
    {
    case RAX_STOP_NONE:
        return "none";
    case RAX_STOP_COUNT:
        return "instruction-budget";
    case RAX_STOP_UNTIL:
        return "return-sentinel";
    case RAX_STOP_TIMEOUT:
        return "timeout";
    case RAX_STOP_STOPPED:
        return "host-stop";
    case RAX_STOP_HLT:
        return "halt";
    case RAX_STOP_IO_IN:
        return "io-read";
    case RAX_STOP_IO_OUT:
        return "io-write";
    case RAX_STOP_MMIO_READ:
        return "mmio-read";
    case RAX_STOP_MMIO_WRITE:
        return "mmio-write";
    case RAX_STOP_EXCEPTION:
        return "exception";
    case RAX_STOP_INTERRUPT:
        return "interrupt";
    case RAX_STOP_SHUTDOWN:
        return "shutdown";
    case RAX_STOP_DEBUG:
        return "debug";
    case RAX_STOP_ERROR:
        return "engine-error";
    default:
        return "unknown";
    }
}
const char *hybrid_rax_status_name(int status);
inline const char *hybrid_emu_outcome_name(const EmuOutcome &outcome)
{
    if (outcome.region_code_changed)
        return "region-code-changed";
    if (outcome.region_boundary)
        return "native-region-boundary";
    if (outcome.native_region && outcome.returned)
        return "region-return-sentinel";
    if (outcome.returned)
        return "returned";
    if (outcome.cancelled)
        return "cancelled";
    if (outcome.unmodeled_external)
        return "unmodeled-external";
    if (outcome.environment_model_failure)
        return "environment-model-failure";
    if (outcome.function_boundary)
        return "function-boundary";
    if (outcome.escaped_image)
        return "escaped-image-or-exception";
    if (outcome.permission_violation)
        return "permission-violation";
    if (outcome.terminated_process)
        return "modeled-process-termination";
    return hybrid_rax_stop_reason_name(outcome.stop_reason);
}

class EmuDriver
{
  public:
    EmuDriver(const RaxApi *api, const ProgramImage &img, bool strict_perms = true,
              bool windows_x64 = false, const std::vector<EmuCallSummary> &summaries = {});
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

    // Emulate one function (all of its FuncRange chunks) under the caps in `cfg`,
    // appending discovered edges/data to `out`. Known calls may be handled by a
    // bounded summary. An unmodeled transfer outside the function is recorded at
    // its source/target boundary and stopped before the target instruction; no
    // callee body is recursively executed. Bounded by instruction count and
    // wall-clock timeout; faults are contained. Returns true if emulation ran.
    bool emulate_from(uint64_t entry, uint64_t func_end, const HybridConfig &cfg, EmuEvents &out,
                      EmuOutcome *outcome = nullptr, bool record_pcs = false, uint64_t seed = 0,
                      uint32_t run_id = 0, const EmuInput *input = nullptr,
                      bool (*cancelled)(const void *) = nullptr,
                      const void *cancellation_user = nullptr);

    // Explicit, separately identified native-region capture. The immutable plan
    // may span IDA functions; exact runtime instruction bytes gate execution.
    // No environment summaries or function-level conclusions. Requires an empty
    // event sink; caps at 65536 instructions and 1000 ms even for larger config.
    bool emulate_region(const vm::NativeRegion &, const HybridConfig &, EmuEvents &, EmuOutcome &,
                        const EmuInput *input = nullptr);

    // Opt-in observed-native continuation with one shared execution/time budget.
    // Extends the caller's plan between emulator slices, retaining machine state.
    // At most 64 extensions; no ordinary function or logical VM admission.
    bool emulate_region_walk(vm::NativeRegion &, const HybridConfig &, EmuEvents &, EmuOutcome &,
                             const vm::NativeDecoder &, size_t maximum_extensions = 64,
                             const EmuInput *input = nullptr,
                             bool sample_native_instructions = false);

    // Explicitly uses constructor-supplied call models and captures temporal
    // events. Ordinary temporal_capture_complete/conclusive remain false.
    // Caller objects are rejected: their scratch range overlaps modeled heap.
    bool emulate_region_temporal(vm::NativeRegion &, const HybridConfig &, EmuEvents &,
                                 EmuOutcome &, const vm::NativeDecoder &,
                                 const EmuInput *input = nullptr);

  private:
    bool emulate_region_impl(const vm::NativeRegion &, const HybridConfig &, EmuEvents &,
                             EmuOutcome &, const EmuInput *, vm::NativeRegion *,
                             const vm::NativeDecoder *, size_t,
                             bool sample_native_instructions = false, bool native_temporal = false);
    bool emulate_scope(uint64_t entry, uint64_t func_end, const HybridConfig &, EmuEvents &,
                       EmuOutcome *, bool record_pcs, uint64_t seed, uint32_t run_id,
                       const EmuInput *, bool (*cancelled)(const void *),
                       const void *cancellation_user, const vm::NativeRegion *,
                       vm::NativeRegion *expanding = nullptr,
                       const vm::NativeDecoder *decoder = nullptr, size_t maximum_extensions = 0,
                       bool sample_native_instructions = false, bool native_temporal = false);
    bool map_image();
    bool map_stack();
    bool load_image_bytes();
    void save_baseline();
    bool restore_state();
    bool seed_arg_regs(uint64_t seed, const FuncRange *function);
    bool apply_input(const EmuInput &input, uint64_t sp);
    void capture_final_writes(EmuEvents &out, const HybridConfig &cfg, uint32_t run_id,
                              uint64_t seed, size_t data_begin);

    const RaxApi *api_ = nullptr;
    const ProgramImage &img_;
    rax_engine *engine_ = nullptr;
    bool stepping_ = false;
    bool mem_hooks_ok_ = false;
    bool strict_perms_ = true;
    bool windows_x64_ = false;
    HybridAbi abi_ = HybridAbi::UNKNOWN;

    // Per-arch execution parameters resolved in the constructor.
    int sp_reg_ = -1; // stack-pointer register id
    int fp_reg_ = -1; // frame-pointer register id (-1 if none)
    int lr_reg_ = -1; // link register id (-1 => return address is on stack)
    int pc_reg_ = -1;
    int ret_reg_ = -1;
    int rax_arch_ = 0;
    uint32_t rax_mode_ = 0;
    std::vector<int> arg_regs_;     // integer argument registers (for multi-run seeding)
    std::vector<int> capture_regs_; // compact architectural state sampled at transfers
    uint64_t stack_base_ = 0;
    uint64_t stack_size_ = 0;
    uint64_t sentinel_ = 0; // "returned out of the function" stop address
    std::vector<EmuCallSummary> summaries_;

    std::vector<uint8_t> baseline_; // rax context snapshot (image+regs) for reuse
    bool baseline_ok_ = false;
    uint64_t baseline_image_hash_ = 0;
};

} // namespace chernobog::hybrid
