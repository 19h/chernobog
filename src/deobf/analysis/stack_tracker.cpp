#include "stack_tracker.h"

// Static members
std::map<sval_t, stack_tracker_t::stack_slot_t> stack_tracker_t::s_slots;
mbl_array_t *stack_tracker_t::s_mba = nullptr;

//--------------------------------------------------------------------------
// Initialize for a function
//--------------------------------------------------------------------------
void stack_tracker_t::init(mbl_array_t *mba) {
    clear();
    s_mba = mba;
}

void stack_tracker_t::clear() {
    s_slots.clear();
    s_mba = nullptr;
}

//--------------------------------------------------------------------------
// Track writes
//--------------------------------------------------------------------------
void stack_tracker_t::track_write(sval_t offset, uint64_t value, int size) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = false;
    slot.is_string = false;
    slot.value = value;
    slot.size = size;
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

void stack_tracker_t::track_write(sval_t offset, ea_t addr) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = true;
    slot.is_string = false;
    slot.address = addr;
    slot.value = addr;
    slot.size = sizeof(ea_t);
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

void stack_tracker_t::track_write_string(sval_t offset, const char *str) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = false;
    slot.is_string = true;
    slot.string_val = str;
    slot.size = sizeof(ea_t);  // Pointer size
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

//--------------------------------------------------------------------------
// Read from stack
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::read_value(sval_t offset, int size) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.has_value) {
        return it->second.value;
    }
    return std::nullopt;
}

std::optional<ea_t> stack_tracker_t::read_address(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.has_value) {
        if (it->second.is_address) {
            return it->second.address;
        }
        return (ea_t)it->second.value;
    }
    return std::nullopt;
}

std::optional<std::string> stack_tracker_t::read_string(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.is_string) {
        return it->second.string_val;
    }
    return std::nullopt;
}

bool stack_tracker_t::is_known(sval_t offset) {
    auto it = s_slots.find(offset);
    return it != s_slots.end() && it->second.has_value;
}

//--------------------------------------------------------------------------
// Resolve indirect call through stack
//--------------------------------------------------------------------------
ea_t stack_tracker_t::resolve_stack_call(minsn_t *call_insn, mbl_array_t *mba) {
    if (!call_insn)
        return BADADDR;

    // Check if the call target is through a stack slot
    // Pattern: icall/call where target is loaded from stack

    // For icall, the target is in l operand
    if (call_insn->opcode == m_icall) {
        // Check if target comes from stack
        if (call_insn->l.t == mop_S) {
            sval_t offset = call_insn->l.s ? call_insn->l.s->off : 0;
            auto addr = read_address(offset);
            if (addr.has_value()) {
                return *addr;
            }
        }

        // Target might be in a register loaded from stack
        if (call_insn->l.t == mop_r) {
            // Need to trace back the register
            // This is complex - would need dataflow analysis
        }
    }

    // For call with indirect target
    if (call_insn->opcode == m_call) {
        if (call_insn->l.t == mop_d && call_insn->l.d) {
            // Nested instruction - might be load from stack
            minsn_t *inner = call_insn->l.d;
            if (inner->opcode == m_ldx || inner->opcode == m_mov) {
                sval_t offset;
                if (is_stack_ref(inner->l, &offset)) {
                    auto addr = read_address(offset);
                    if (addr.has_value()) {
                        return *addr;
                    }
                }
            }
        }
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Analyze a block
//--------------------------------------------------------------------------
void stack_tracker_t::analyze_block(mblock_t *blk) {
    if (!blk)
        return;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Look for stores to stack
        if (ins->opcode == m_mov || ins->opcode == m_stx) {
            sval_t offset;
            if (is_stack_ref(ins->d, &offset)) {
                // Destination is stack slot

                // Get the source value
                if (ins->l.t == mop_n) {
                    // Immediate value
                    track_write(offset, ins->l.nnn->value, ins->l.size);
                }
                else if (ins->l.t == mop_v) {
                    // Global address
                    track_write(offset, ins->l.g);

                    // Check if it's a string
                    qstring str;
                    size_t len = get_max_strlit_length(ins->l.g, STRTYPE_C);
                    if (len > 0 && len < 256) {
                        str.resize(len);
                        if (get_strlit_contents(&str, ins->l.g, len, STRTYPE_C) > 0) {
                            track_write_string(offset, str.c_str());
                        }
                    }

                    // Check if it's a function
                    func_t *fn = get_func(ins->l.g);
                    if (fn) {
                        track_write(offset, ins->l.g);
                    }
                }
                else if (ins->l.t == mop_a && ins->l.a) {
                    // Address expression
                    if (ins->l.a->t == mop_v) {
                        track_write(offset, ins->l.a->g);
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Analyze entire function
//--------------------------------------------------------------------------
void stack_tracker_t::analyze_function(mbl_array_t *mba) {
    if (!mba)
        return;

    init(mba);

    // Analyze in execution order (simplified - just linear)
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        analyze_block(blk);
    }
}

//--------------------------------------------------------------------------
// Get slot info for annotation
//--------------------------------------------------------------------------
std::optional<stack_tracker_t::slot_info_t> stack_tracker_t::get_slot_info(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it == s_slots.end() || !it->second.has_value) {
        return std::nullopt;
    }

    slot_info_t info;
    info.offset = offset;

    if (it->second.is_string) {
        info.type = slot_info_t::STRING;
        info.string_val = it->second.string_val;
    } else if (it->second.is_address) {
        info.type = slot_info_t::ADDRESS;
        info.address = it->second.address;
    } else {
        info.type = slot_info_t::VALUE;
        info.value = it->second.value;
    }

    return info;
}

//--------------------------------------------------------------------------
// Extract value from mop
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::get_mop_value(const mop_t &op) {
    if (op.t == mop_n) {
        return op.nnn->value;
    }
    if (op.t == mop_v) {
        return op.g;
    }
    return std::nullopt;
}

//--------------------------------------------------------------------------
// Check if mop is a stack reference
//--------------------------------------------------------------------------
bool stack_tracker_t::is_stack_ref(const mop_t &op, sval_t *out_offset) {
    if (op.t == mop_S) {
        if (out_offset && op.s) {
            *out_offset = op.s->off;
        }
        return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Trace register value back through block
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::trace_register_value(mblock_t *blk, int reg, minsn_t *before) {
    if (!blk)
        return std::nullopt;

    // Search backwards from 'before' for a write to the register
    for (minsn_t *ins = before ? before->prev : blk->tail; ins; ins = ins->prev) {
        if (ins->opcode == m_mov && ins->d.t == mop_r && ins->d.r == reg) {
            // Found a write to the register
            return get_mop_value(ins->l);
        }
        if (ins->opcode == m_ldx && ins->d.t == mop_r && ins->d.r == reg) {
            // Load from memory to register
            // Check if loading from stack
            sval_t offset;
            if (is_stack_ref(ins->l, &offset)) {
                return read_value(offset, ins->d.size);
            }
        }
    }

    return std::nullopt;
}
