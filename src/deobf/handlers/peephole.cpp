#include "peephole.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"

namespace chernobog {
namespace peephole {

//--------------------------------------------------------------------------
// Static member initialization
//--------------------------------------------------------------------------
std::vector<std::unique_ptr<PeepholeOptimizer>> peephole_handler_t::optimizers_;
bool peephole_handler_t::initialized_ = false;

//--------------------------------------------------------------------------
// ReadOnlyDataFoldOptimizer implementation
//--------------------------------------------------------------------------

bool ReadOnlyDataFoldOptimizer::is_readonly_addr(ea_t addr)
{
    segment_t* seg = getseg(addr);
    if ( !seg ) 
        return false;

    // Check segment permissions
    if ( seg->perm & SEGPERM_WRITE ) 
        return false;

    // Check if it's in a code or const data segment
    return (seg->type == SEG_CODE || seg->type == SEG_DATA);
}

bool ReadOnlyDataFoldOptimizer::read_const_value(ea_t addr, int size, uint64_t* out)
{
    if ( !out || !is_readonly_addr(addr) || size <= 0 || size > 8 )
        return false;

    auto value = chernobog::ida_memory::read_integer(addr, size);
    if ( !value )
        return false;
    *out = *value;
    return true;
}

int ReadOnlyDataFoldOptimizer::optimize(mblock_t* blk, minsn_t* ins)
{
    if ( !ins || ins->opcode != m_ldx ) 
        return 0;

    // Check for load from constant address
    // ldx ds.2, #addr.8, dest
    if ( ins->r.t != mop_n || !ins->r.nnn )
        return 0;

    const ea_t addr = static_cast<ea_t>(ins->r.nnn->value);

    if ( addr == BADADDR ) 
        return 0;

    uint64_t value;
    if ( !read_const_value(addr, ins->d.size, &value) ) 
        return 0;

    ins->opcode = m_mov;
    ins->l.make_number(value, ins->d.size);
    ins->r.erase();
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// LocalConstPropOptimizer implementation
//--------------------------------------------------------------------------

int LocalConstPropOptimizer::optimize(mblock_t* blk, minsn_t* ins)
{
    // Track exact direct stores to stack. Any overlapping prior fact is stale,
    // including a wider load fact at the same base offset.
    if ( (ins->opcode == m_stx || ins->opcode == m_mov) &&
         ins->d.t == mop_S && ins->d.s ) {
        const sval_t offset = ins->d.s->off;
        const int size = ins->l.size;
        if ( !chernobog::bitvector::valid_byte_width(size) ) {
            stack_constants_.clear();
            return 0;
        }

        const auto overlaps = [offset, size](const auto& entry) {
            const sval_t previous_offset = entry.first.first;
            const int previous_size = entry.first.second;
            if ( !chernobog::bitvector::valid_byte_width(previous_size) )
                return true;
            if ( offset <= previous_offset )
                return static_cast<uint64_t>(previous_offset) -
                       static_cast<uint64_t>(offset) < static_cast<uint64_t>(size);
            return static_cast<uint64_t>(offset) -
                   static_cast<uint64_t>(previous_offset) <
                   static_cast<uint64_t>(previous_size);
        };
        for ( auto it = stack_constants_.begin(); it != stack_constants_.end(); )
            it = overlaps(*it) ? stack_constants_.erase(it) : std::next(it);

        if ( ins->l.t == mop_n && ins->l.nnn )
            stack_constants_[{offset, size}] =
                chernobog::bitvector::truncate(ins->l.nnn->value, size);
        return 0;
    }

    // Propagate to loads from stack
    if ( ins->opcode == m_ldx && ins->r.t == mop_S && ins->r.s ) {
        auto p = stack_constants_.find({ins->r.s->off, ins->d.size});
        if ( p != stack_constants_.end() ) {
            ins->opcode = m_mov;
            ins->l.make_number(p->second, ins->d.size);
            ins->r.erase();
            hit_count_++;
            return 1;
        }
    }

    // Unknown stores and calls may alias tracked stack locations.
    if ( ins->opcode == m_stx || is_mcode_call(ins->opcode) )
        stack_constants_.clear();

    return 0;
}

//--------------------------------------------------------------------------
// ShiftByZeroOptimizer implementation
//--------------------------------------------------------------------------

int ShiftByZeroOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if ( !ins ) 
        return 0;

    // Check for shift operations
    if ( ins->opcode != m_shl && ins->opcode != m_shr && ins->opcode != m_sar ) 
        return 0;

    // Check if shift amount is 0
    if ( ins->r.t != mop_n || !ins->r.nnn )
        return 0;

    if ( ins->r.nnn->value != 0 ) 
        return 0;

    if ( !chernobog::bitvector::valid_byte_width(ins->l.size)
      || ins->d.size != ins->l.size )
        return 0;

    // x << 0 = x, x >> 0 = x
    ins->opcode = m_mov;
    ins->r.erase();
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// DoubleNegationOptimizer implementation
//--------------------------------------------------------------------------

int DoubleNegationOptimizer::optimize(mblock_t* blk, minsn_t* ins)
{
    if ( !ins ) 
        return 0;

    // Check for bnot or neg
    if ( ins->opcode != m_bnot && ins->opcode != m_neg ) 
        return 0;

    // Check if operand is result of same operation
    if ( ins->l.t != mop_d || !ins->l.d ) 
        return 0;

    if ( ins->l.d->opcode != ins->opcode ) 
        return 0;

    if ( ins->l.size <= 0 || ins->l.size != ins->d.size ||
         ins->l.d->l.size != ins->l.size )
        return 0;

    // Preserve the nested source before assigning over the owning mop_d.
    mop_t replacement = ins->l.d->l;

    // ~~x = x or -(-x) = x
    ins->opcode = m_mov;
    ins->l = replacement;
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// PowerOfTwoOptimizer implementation
//--------------------------------------------------------------------------

bool PowerOfTwoOptimizer::is_power_of_2(uint64_t val, int* shift) {
    if ( val == 0 ) 
        return false;

    if ( (val & (val - 1)) != 0 ) 
        return false;

    *shift = 0;
    while ( (val & 1) == 0 ) {
        val >>= 1;
        (*shift)++;
    }
    return true;
}

int PowerOfTwoOptimizer::optimize(mblock_t* blk, minsn_t* ins)
{
    if ( !ins ) 
        return 0;

    // x * (power of 2) -> x << shift
    if ( ins->opcode == m_mul ) {
        if ( !chernobog::bitvector::valid_byte_width(ins->d.size)
          || ins->l.size != ins->d.size || ins->r.size != ins->d.size )
            return 0;

        const bool constant_on_left = ins->l.t == mop_n && ins->l.nnn;
        const mop_t& constant = constant_on_left ? ins->l : ins->r;
        if ( constant.t != mop_n || !constant.nnn )
            return 0;

        int shift;
        const uint64_t value = chernobog::bitvector::truncate(
            constant.nnn->value, constant.size);
        if ( !is_power_of_2(value, &shift) )
            return 0;

        if ( constant_on_left ) {
            mop_t multiplicand = ins->r;
            ins->l = multiplicand;
        }

        if ( shift == 0 ) {
            // x * 1 = x
            ins->opcode = m_mov;
            ins->r.erase();
        } else {
            ins->opcode = m_shl;
            ins->r.make_number(shift, 1);
        }
        hit_count_++;
        return 1;
    }

    // x / (power of 2) -> x >> shift (for unsigned)
    if ( ins->opcode == m_udiv ) {
        if ( !chernobog::bitvector::valid_byte_width(ins->d.size)
          || ins->l.size != ins->d.size || ins->r.size != ins->d.size )
            return 0;
        if ( ins->r.t != mop_n || !ins->r.nnn )
            return 0;

        int shift;
        const uint64_t divisor = chernobog::bitvector::truncate(
            ins->r.nnn->value, ins->r.size);
        if ( !is_power_of_2(divisor, &shift) )
            return 0;

        if ( shift == 0 ) {
            // x / 1 = x
            ins->opcode = m_mov;
            ins->r.erase();
        } else {
            ins->opcode = m_shr;
            ins->r.make_number(shift, 1);
        }
        hit_count_++;
        return 1;
    }

    return 0;
}

//--------------------------------------------------------------------------
// SelfCompareOptimizer implementation
//--------------------------------------------------------------------------

int SelfCompareOptimizer::optimize(mblock_t* blk, minsn_t* ins)
{
    if ( !ins ) 
        return 0;

    // Check for comparison operations
    mcode_t op = ins->opcode;
    if ( op != m_setz && op != m_setnz && op != m_setl && op != m_setge &&
        op != m_setb && op != m_setae && op != m_setle && op != m_setg &&
        op != m_setbe && op != m_seta)
        return 0;

    if ( ins->is_fpinsn() )
        return 0;

    // Check if comparing something with itself
    if ( ins->l.size <= 0 || ins->l.size != ins->r.size ||
         !ins->l.equal_mops(ins->r, EQ_IGNSIZE) )
        return 0;

    // x == x -> 1
    // x != x -> 0
    // x < x -> 0
    // x >= x -> 1
    // etc.
    int result = 0;
    switch ( op ) {
        case m_setz:   // ==
        case m_setge:  // >= (signed)
        case m_setae:  // >= (unsigned)
        case m_setle:  // <= (signed)
        case m_setbe:  // <= (unsigned)
            result = 1;
            break;
        case m_setnz:  // !=
        case m_setl:   // < (signed)
        case m_setb:   // < (unsigned)
        case m_setg:   // > (signed)
        case m_seta:   // > (unsigned)
            result = 0;
            break;
        default:
            return 0;
    }

    ins->opcode = m_mov;
    ins->l.make_number(result, ins->d.size);
    ins->r.erase();
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// Handler implementation
//--------------------------------------------------------------------------

void peephole_handler_t::initialize()
{
    if ( initialized_ ) 
        return;

    optimizers_.clear();
    // Calls carry mcallinfo_t in D, not an ordinary result operand. Replacing
    // a helper call with m_mov requires call-use rewriting and is therefore
    // intentionally excluded from this instruction-local pass.
    optimizers_.push_back(std::make_unique<ReadOnlyDataFoldOptimizer>());
    optimizers_.push_back(std::make_unique<ShiftByZeroOptimizer>());
    optimizers_.push_back(std::make_unique<DoubleNegationOptimizer>());
    optimizers_.push_back(std::make_unique<PowerOfTwoOptimizer>());
    optimizers_.push_back(std::make_unique<SelfCompareOptimizer>());
    // LocalConstProp needs block-level state, handle separately

    initialized_ = true;
    msg("[chernobog] Peephole optimizers initialized (%zu optimizers)\n",
        optimizers_.size());
}

bool peephole_handler_t::detect(mbl_array_t* mba)
{
    // Peephole optimizations are always applicable
    return mba != nullptr;
}

int peephole_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    if ( !initialized_ ) 
        initialize();

    int total_changes = 0;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t* blk = mba->get_mblock(i);
        if ( !blk) continue;

        // Block-level optimizer for const propagation
        LocalConstPropOptimizer const_prop;

        for ( minsn_t* ins = blk->head; ins; ins = ins->next ) {
            // Run all optimizers
            for ( auto& opt : optimizers_ ) {
                int changes = opt->optimize(blk, ins);
                total_changes += changes;
            }

            // Run const propagation
            total_changes += const_prop.optimize(blk, ins);
        }
    }

    if ( total_changes > 0 ) {
        ctx->expressions_simplified += total_changes;
        deobf::log_verbose("[Peephole] Applied %d optimizations\n", total_changes);
    }

    return total_changes;
}

int peephole_handler_t::simplify_insn(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx) {
    if ( !initialized_ ) 
        initialize();

    int total_changes = 0;

    for ( auto& opt : optimizers_ ) {
        int changes = opt->optimize(blk, ins);
        total_changes += changes;
    }

    if ( total_changes > 0 && ctx ) {
        ctx->expressions_simplified += total_changes;
    }

    return total_changes;
}

void peephole_handler_t::dump_statistics()
{
    msg("[chernobog] Peephole Optimizer Statistics:\n");
    for ( auto& opt : optimizers_ ) {
        msg("  %s: %zu hits\n", opt->name(), opt->hit_count());
    }
}

void peephole_handler_t::reset_statistics()
{
    for ( auto& opt : optimizers_ ) {
        opt->reset_stats();
    }
}

} // namespace peephole
} // namespace chernobog
