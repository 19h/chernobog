#include "peephole.h"

namespace chernobog {
namespace peephole {

//--------------------------------------------------------------------------
// Static member initialization
//--------------------------------------------------------------------------
std::vector<std::unique_ptr<PeepholeOptimizer>> peephole_handler_t::optimizers_;
bool peephole_handler_t::initialized_ = false;

//--------------------------------------------------------------------------
// ConstantCallFoldOptimizer implementation
//--------------------------------------------------------------------------

bool ConstantCallFoldOptimizer::is_rotate_helper(ea_t func_ea, int* bits, bool* is_left) {
    qstring func_name;
    if (!get_func_name(&func_name, func_ea))
        return false;

    // Check for IDA's rotate helper functions
    // __ROL1__, __ROL2__, __ROL4__, __ROL8__
    // __ROR1__, __ROR2__, __ROR4__, __ROR8__
    if (func_name.find("__ROL") == 0 || func_name.find("__ROR") == 0) {
        *is_left = (func_name[3] == 'L');

        if (func_name.find("1__") != qstring::npos) {
            *bits = 8;
        } else if (func_name.find("2__") != qstring::npos) {
            *bits = 16;
        } else if (func_name.find("4__") != qstring::npos) {
            *bits = 32;
        } else if (func_name.find("8__") != qstring::npos) {
            *bits = 64;
        } else {
            return false;
        }
        return true;
    }

    return false;
}

uint64_t ConstantCallFoldOptimizer::eval_rotate(uint64_t val, int shift, int bits, bool left) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    val &= mask;
    shift %= bits;

    if (shift == 0)
        return val;

    if (left) {
        return ((val << shift) | (val >> (bits - shift))) & mask;
    } else {
        return ((val >> shift) | (val << (bits - shift))) & mask;
    }
}

int ConstantCallFoldOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins || ins->opcode != m_call)
        return 0;

    // Get call target
    if (ins->l.t != mop_v && ins->l.t != mop_a)
        return 0;

    ea_t func_ea = (ins->l.t == mop_v) ? ins->l.g : ins->l.a->g;

    int bits;
    bool is_left;
    if (!is_rotate_helper(func_ea, &bits, &is_left))
        return 0;

    // Check for call arguments
    mcallinfo_t* ci = ins->d.f;
    if (!ci || ci->args.size() < 2)
        return 0;

    // Check if both arguments are constants
    mcallarg_t& arg0 = ci->args[0];
    mcallarg_t& arg1 = ci->args[1];

    if (arg0.t != mop_n || arg1.t != mop_n)
        return 0;

    uint64_t val = arg0.nnn->value;
    int shift = static_cast<int>(arg1.nnn->value);

    // Rotate by 0 - just return the value
    if (shift == 0) {
        ins->opcode = m_mov;
        ins->l.make_number(val, ins->d.size);
        ins->r.erase();
        hit_count_++;
        return 1;
    }

    // Compute result
    uint64_t result = eval_rotate(val, shift, bits, is_left);

    ins->opcode = m_mov;
    ins->l.make_number(result, ins->d.size);
    ins->r.erase();
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// ReadOnlyDataFoldOptimizer implementation
//--------------------------------------------------------------------------

bool ReadOnlyDataFoldOptimizer::is_readonly_addr(ea_t addr) {
    segment_t* seg = getseg(addr);
    if (!seg)
        return false;

    // Check segment permissions
    if (seg->perm & SEGPERM_WRITE)
        return false;

    // Check if it's in a code or const data segment
    return (seg->type == SEG_CODE || seg->type == SEG_DATA);
}

bool ReadOnlyDataFoldOptimizer::read_const_value(ea_t addr, int size, uint64_t* out) {
    if (!is_readonly_addr(addr))
        return false;

    // Read bytes from database
    switch (size) {
        case 1:
            *out = get_byte(addr);
            return true;
        case 2:
            *out = get_word(addr);
            return true;
        case 4:
            *out = get_dword(addr);
            return true;
        case 8:
            *out = get_qword(addr);
            return true;
        default:
            return false;
    }
}

int ReadOnlyDataFoldOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins || ins->opcode != m_ldx)
        return 0;

    // Check for load from constant address
    // ldx ds.2, #addr.8, dest
    if (ins->l.t != mop_n && ins->r.t != mop_n)
        return 0;

    ea_t addr = BADADDR;
    if (ins->r.t == mop_n) {
        addr = static_cast<ea_t>(ins->r.nnn->value);
    } else if (ins->l.t == mop_n) {
        // Segment operand - need to combine with offset
        return 0;  // Complex case, skip for now
    }

    if (addr == BADADDR)
        return 0;

    uint64_t value;
    if (!read_const_value(addr, ins->d.size, &value))
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

int LocalConstPropOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    // Track stores to stack
    if (ins->opcode == m_stx && ins->d.t == mop_S) {
        if (ins->l.t == mop_n) {
            stack_constants_[ins->d.s->off] = ins->l.nnn->value;
        } else {
            // Non-constant store invalidates the slot
            stack_constants_.erase(ins->d.s->off);
        }
        return 0;
    }

    // Propagate to loads from stack
    if (ins->opcode == m_ldx && ins->l.t == mop_S) {
        auto it = stack_constants_.find(ins->l.s->off);
        if (it != stack_constants_.end()) {
            ins->opcode = m_mov;
            ins->l.make_number(it->second, ins->d.size);
            ins->r.erase();
            hit_count_++;
            return 1;
        }
    }

    return 0;
}

//--------------------------------------------------------------------------
// ShiftByZeroOptimizer implementation
//--------------------------------------------------------------------------

int ShiftByZeroOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins)
        return 0;

    // Check for shift operations
    if (ins->opcode != m_shl && ins->opcode != m_shr && ins->opcode != m_sar)
        return 0;

    // Check if shift amount is 0
    if (ins->r.t != mop_n)
        return 0;

    if (ins->r.nnn->value != 0)
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

int DoubleNegationOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins)
        return 0;

    // Check for bnot or neg
    if (ins->opcode != m_bnot && ins->opcode != m_neg)
        return 0;

    // Check if operand is result of same operation
    if (ins->l.t != mop_d || !ins->l.d)
        return 0;

    if (ins->l.d->opcode != ins->opcode)
        return 0;

    // ~~x = x or -(-x) = x
    ins->opcode = m_mov;
    ins->l = ins->l.d->l;
    hit_count_++;
    return 1;
}

//--------------------------------------------------------------------------
// PowerOfTwoOptimizer implementation
//--------------------------------------------------------------------------

bool PowerOfTwoOptimizer::is_power_of_2(uint64_t val, int* shift) {
    if (val == 0)
        return false;

    if ((val & (val - 1)) != 0)
        return false;

    *shift = 0;
    while ((val & 1) == 0) {
        val >>= 1;
        (*shift)++;
    }
    return true;
}

int PowerOfTwoOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins)
        return 0;

    // x * (power of 2) -> x << shift
    if (ins->opcode == m_mul) {
        if (ins->r.t != mop_n)
            return 0;

        int shift;
        if (!is_power_of_2(ins->r.nnn->value, &shift))
            return 0;

        if (shift == 0) {
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
    if (ins->opcode == m_udiv) {
        if (ins->r.t != mop_n)
            return 0;

        int shift;
        if (!is_power_of_2(ins->r.nnn->value, &shift))
            return 0;

        if (shift == 0) {
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

int SelfCompareOptimizer::optimize(mblock_t* blk, minsn_t* ins) {
    if (!ins)
        return 0;

    // Check for comparison operations
    mcode_t op = ins->opcode;
    if (op != m_setz && op != m_setnz && op != m_setl && op != m_setge &&
        op != m_setb && op != m_setae && op != m_setle && op != m_setg &&
        op != m_setbe && op != m_seta)
        return 0;

    // Get comparison operands from inner instruction
    if (ins->l.t != mop_d || !ins->l.d)
        return 0;

    minsn_t* cmp = ins->l.d;

    // Check if comparing something with itself
    if (!cmp->l.equal_mops(cmp->r, EQ_IGNSIZE))
        return 0;

    // x == x -> 1
    // x != x -> 0
    // x < x -> 0
    // x >= x -> 1
    // etc.
    int result = 0;
    switch (op) {
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

void peephole_handler_t::initialize() {
    if (initialized_)
        return;

    optimizers_.clear();
    optimizers_.push_back(std::make_unique<ConstantCallFoldOptimizer>());
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

bool peephole_handler_t::detect(mbl_array_t* mba) {
    // Peephole optimizations are always applicable
    return mba != nullptr;
}

int peephole_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx) {
    if (!mba || !ctx)
        return 0;

    if (!initialized_)
        initialize();

    int total_changes = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk) continue;

        // Block-level optimizer for const propagation
        LocalConstPropOptimizer const_prop;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            // Run all optimizers
            for (auto& opt : optimizers_) {
                int changes = opt->optimize(blk, ins);
                total_changes += changes;
            }

            // Run const propagation
            total_changes += const_prop.optimize(blk, ins);
        }
    }

    if (total_changes > 0) {
        ctx->expressions_simplified += total_changes;
        deobf::log_verbose("[Peephole] Applied %d optimizations\n", total_changes);
    }

    return total_changes;
}

int peephole_handler_t::simplify_insn(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx) {
    if (!initialized_)
        initialize();

    int total_changes = 0;

    for (auto& opt : optimizers_) {
        int changes = opt->optimize(blk, ins);
        total_changes += changes;
    }

    if (total_changes > 0 && ctx) {
        ctx->expressions_simplified += total_changes;
    }

    return total_changes;
}

void peephole_handler_t::dump_statistics() {
    msg("[chernobog] Peephole Optimizer Statistics:\n");
    for (auto& opt : optimizers_) {
        msg("  %s: %zu hits\n", opt->name(), opt->hit_count());
    }
}

void peephole_handler_t::reset_statistics() {
    for (auto& opt : optimizers_) {
        opt->reset_stats();
    }
}

} // namespace peephole
} // namespace chernobog
