#pragma once
#include "../deobf_types.h"
#include <vector>
#include <memory>

//--------------------------------------------------------------------------
// Peephole Optimizers
//
// Collection of small, targeted optimizations that run on individual
// instructions. Each optimizer handles a specific pattern.
//
// Optimizers included:
//   - ConstantCallFold: Fold helper calls with constant args (rotate, etc.)
//   - ReadOnlyDataFold: Fold loads from read-only memory
//   - LocalConstProp: Propagate constants through local variables
//   - DeadCodeElim: Remove dead stores and unused computations
//
// Ported from d810-ng's peephole optimization passes
//--------------------------------------------------------------------------

namespace chernobog {
namespace peephole {

//--------------------------------------------------------------------------
// Base class for peephole optimizers
//--------------------------------------------------------------------------
class PeepholeOptimizer {
public:
    virtual ~PeepholeOptimizer() = default;

    // Optimizer name for logging
    virtual const char* name() const = 0;

    // Try to optimize the instruction
    // Returns 1 if optimized, 0 otherwise
    virtual int optimize(mblock_t* blk, minsn_t* ins) = 0;

    // Statistics
    size_t hit_count() const { return hit_count_; }
    void reset_stats() { hit_count_ = 0; }

protected:
    size_t hit_count_ = 0;
};

//--------------------------------------------------------------------------
// Fold helper function calls with constant arguments
// e.g., __ROL4__(x, 0) -> x, __ROR4__(const, n) -> result
//--------------------------------------------------------------------------
class ConstantCallFoldOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "ConstantCallFold"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;

private:
    // Check if function is a rotate helper
    static bool is_rotate_helper(ea_t func_ea, int* bits, bool* is_left);

    // Evaluate rotate with constants
    static uint64_t eval_rotate(uint64_t val, int shift, int bits, bool left);
};

//--------------------------------------------------------------------------
// Fold loads from read-only memory (constants, vtables, etc.)
//--------------------------------------------------------------------------
class ReadOnlyDataFoldOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "ReadOnlyDataFold"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;

private:
    // Check if address is in read-only segment
    static bool is_readonly_addr(ea_t addr);

    // Read value from read-only memory
    static bool read_const_value(ea_t addr, int size, uint64_t* out);
};

//--------------------------------------------------------------------------
// Propagate constants through stack variables
//--------------------------------------------------------------------------
class LocalConstPropOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "LocalConstProp"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;

private:
    // Track constant values stored to stack
    std::map<sval_t, uint64_t> stack_constants_;
};

//--------------------------------------------------------------------------
// Simplify shifts by zero
//--------------------------------------------------------------------------
class ShiftByZeroOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "ShiftByZero"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Fold double negation: ~~x -> x, -(-x) -> x
//--------------------------------------------------------------------------
class DoubleNegationOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "DoubleNegation"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Fold multiplication/division by powers of 2
//--------------------------------------------------------------------------
class PowerOfTwoOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "PowerOfTwo"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;

private:
    static bool is_power_of_2(uint64_t val, int* shift);
};

//--------------------------------------------------------------------------
// Simplify comparison with self: x == x -> true, x != x -> false
//--------------------------------------------------------------------------
class SelfCompareOptimizer : public PeepholeOptimizer {
public:
    const char* name() const override { return "SelfCompare"; }
    int optimize(mblock_t* blk, minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Peephole Handler - runs all optimizers
//--------------------------------------------------------------------------
class peephole_handler_t {
public:
    // Initialize optimizers
    static void initialize();

    // Detect if peephole patterns are present (always returns true)
    static bool detect(mbl_array_t* mba);

    // Run all peephole optimizations
    static int run(mbl_array_t* mba, deobf_ctx_t* ctx);

    // Instruction-level optimization
    static int simplify_insn(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx);

    // Statistics
    static void dump_statistics();
    static void reset_statistics();

private:
    static std::vector<std::unique_ptr<PeepholeOptimizer>> optimizers_;
    static bool initialized_;
};

} // namespace peephole
} // namespace chernobog
