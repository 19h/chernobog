#pragma once
#include "model.hpp"
#include "byte_memory.hpp"
#include "pool_model.hpp"
#include "stack_model.hpp"
#include <rax.h>
#include <limits>
#include <map>
#include <memory>
#include <vector>

namespace chernobog::warbird
{
constexpr uint32_t no_record = std::numeric_limits<uint32_t>::max();
enum class EffectOrigin
{
    Native,
    Setup,
    Dispatcher,
    External
};
enum class EffectKind
{
    Read,
    Write,
    Havoc,
    Alignment
};
enum class FlowKind
{
    Next,
    Branch,
    Call,
    Return,
    ExternalCall
};
struct MemoryEffect
{
    uint32_t previous;
    EffectOrigin origin;
    EffectKind kind;
    uint64_t site;
    unsigned bits;
    z3::expr address, value, bytes;
};
struct NativeInstruction
{
    uint64_t site;
    rax_smir_instruction instruction;
    std::vector<rax_smir_op> operations;
    std::vector<uint8_t> bytes;
};
struct FlowEdge
{
    uint64_t key, source, target;
    FlowKind kind;
    z3::expr domain;
};
struct RecoveryState
{
    uint64_t key, site;
    uint32_t effects;
    bool table_unchanged, imports_unchanged, dispatch_unchanged;
    std::vector<z3::expr> registers, vectors, flags;
    ByteMemory memory;
    StackState stack;
    PoolState pool;
    z3::expr domain;
};
struct HandlerRelation
{
    uint32_t input, output;
    z3::expr next_key, domain;
};
// Published only after the worker finishes. The arena is declared first so it
// outlives every retained expression, including COW memory and pool records.
// Consumers serialize all access to an artifact; Z3 contexts are not reentrant.
struct Recovery
{
    const std::shared_ptr<z3::context> arena;
    Lease lease;
    Recovery(std::shared_ptr<z3::context>, const Lease &);
    Recovery(const Recovery &) = default;
    Recovery(Recovery &&) = delete;
    Recovery &operator=(const Recovery &) = delete;
    Recovery &operator=(Recovery &&) = delete;
    bool capture_complete = true;
    bool exploration_complete = false;
    size_t estimated_bytes = 0;
    std::string omission;
    std::map<uint64_t, NativeInstruction> instructions;
    std::vector<MemoryEffect> effects;
    std::vector<FlowEdge> flow;
    std::vector<RecoveryState> states;
    std::vector<HandlerRelation> relations;
    // Structural validation only; never semantic or pseudocode admission.
    bool valid() const;
    std::vector<uint32_t> ordered_effects(const HandlerRelation &) const;
};
class RecoveryRecorder
{
    std::shared_ptr<Recovery> data_;
    size_t limit_;
    bool reserve(size_t);
    void expression(const z3::expr &, unsigned bits, bool boolean = false) const;

  public:
    RecoveryRecorder(std::shared_ptr<z3::context>, const Lease &, size_t bytes);
    uint32_t state(uint64_t key, uint64_t site, uint32_t effects, bool table_unchanged,
                   bool imports_unchanged, bool dispatch_unchanged,
                   const std::vector<z3::expr> &registers, const std::vector<z3::expr> &vectors,
                   const std::vector<z3::expr> &flags, const ByteMemory &, const StackState &,
                   const PoolState &, const z3::expr &domain);
    uint32_t effect(uint32_t previous, EffectOrigin, EffectKind, uint64_t site, unsigned bits,
                    const z3::expr &address, const z3::expr &value, const z3::expr &bytes);
    void instruction(uint64_t, const rax_smir_instruction &, const std::vector<rax_smir_op> &,
                     const uint8_t *bytes);
    void flow(uint64_t key, uint64_t source, uint64_t target, FlowKind, const z3::expr &domain);
    void relation(uint32_t input, uint32_t output, const z3::expr &key, const z3::expr &domain);
    std::shared_ptr<const Recovery> finish(bool exploration_complete);
};
}
