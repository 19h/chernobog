#include "savedregs.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool savedregs_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    int savedregs_refs = 0;
    int indirect_calls = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Count savedregs references
            sval_t offset;
            if (is_savedregs_ref(ins->l, &offset) ||
                is_savedregs_ref(ins->r, &offset) ||
                is_savedregs_ref(ins->d, &offset)) {
                savedregs_refs++;
            }

            // Count indirect calls through savedregs
            if (ins->opcode == m_icall || ins->opcode == m_call) {
                if (ins->l.t == mop_d && ins->l.d) {
                    // Check if call target is loaded from savedregs
                    minsn_t *inner = ins->l.d;
                    if (inner->opcode == m_ldx || inner->opcode == m_mov) {
                        if (is_savedregs_ref(inner->l, &offset)) {
                            indirect_calls++;
                        }
                    }
                }
            }
        }
    }

    // If we have both savedregs references and indirect calls, likely obfuscated
    return savedregs_refs >= 5 && indirect_calls >= 1;
}

//--------------------------------------------------------------------------
// Check if operand is a savedregs reference
//--------------------------------------------------------------------------
bool savedregs_handler_t::is_savedregs_ref(const mop_t &op, sval_t *out_offset) {
    // Pattern: &savedregs - N  or  *(&savedregs - N)
    // In microcode: mop_S with negative offset from frame

    if (op.t == mop_S && op.s) {
        // Stack variable reference
        // Savedregs typically have negative offsets from frame base
        if (op.s->off < 0) {
            if (out_offset)
                *out_offset = op.s->off;
            return true;
        }
    }

    // Also check for address expressions
    if (op.t == mop_a && op.a) {
        if (op.a->t == mop_S && op.a->s) {
            if (op.a->s->off < 0) {
                if (out_offset)
                    *out_offset = op.a->s->off;
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Classify a value by its address
//--------------------------------------------------------------------------
savedregs_handler_t::slot_type_t
savedregs_handler_t::classify_value(ea_t addr) {
    if (addr == BADADDR)
        return SLOT_UNKNOWN;

    // Check if it's a function
    func_t *fn = get_func(addr);
    if (fn) {
        return SLOT_FUNC_PTR;
    }

    // Check if address points to code (might be a function start)
    flags64_t flags = get_flags(addr);
    if (is_code(flags)) {
        return SLOT_FUNC_PTR;
    }

    // Check if it's a string
    size_t len = get_max_strlit_length(addr, STRTYPE_C);
    if (len > 0 && len < 1024) {
        // Check if it looks like an ObjC selector
        qstring str;
        str.resize(len);
        if (get_strlit_contents(&str, addr, len, STRTYPE_C) > 0) {
            // ObjC selectors often contain colons
            if (str.find(':') != qstring::npos) {
                return SLOT_SELECTOR;
            }
            return SLOT_STRING;
        }
    }

    return SLOT_VALUE;
}

//--------------------------------------------------------------------------
// Check if address is an objc_msgSend variant
//--------------------------------------------------------------------------
bool savedregs_handler_t::is_objc_msgsend(ea_t addr) {
    if (addr == BADADDR)
        return false;

    qstring name;
    if (get_name(&name, addr) > 0) {
        // Check various objc_msgSend variants
        if (name.find("objc_msgSend") != qstring::npos)
            return true;
        if (name.find("_objc_msgSend") != qstring::npos)
            return true;
        // Also check for mangled names
        if (name.find("msgSend") != qstring::npos)
            return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Analyze all savedregs writes in function
//--------------------------------------------------------------------------
void savedregs_handler_t::analyze_savedregs_writes(
    mbl_array_t *mba,
    std::map<sval_t, slot_info_ext_t> &slots)
{
    if (!mba)
        return;

    slots.clear();

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for writes to savedregs slots
            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                sval_t offset;
                if (!is_savedregs_ref(ins->d, &offset))
                    continue;

                slot_info_ext_t info;
                info.offset = offset;
                info.type = SLOT_UNKNOWN;
                info.func_addr = BADADDR;
                info.value = 0;
                info.is_objc_msgsend = false;

                // Analyze source operand
                if (ins->l.t == mop_n) {
                    // Immediate value
                    info.type = SLOT_VALUE;
                    info.value = ins->l.nnn->value;
                }
                else if (ins->l.t == mop_v) {
                    // Global address
                    ea_t addr = ins->l.g;
                    info.type = classify_value(addr);

                    if (info.type == SLOT_FUNC_PTR) {
                        info.func_addr = addr;
                        info.is_objc_msgsend = is_objc_msgsend(addr);
                    }
                    else if (info.type == SLOT_STRING || info.type == SLOT_SELECTOR) {
                        size_t len = get_max_strlit_length(addr, STRTYPE_C);
                        if (len > 0 && len < 1024) {
                            info.string_val.resize(len);
                            get_strlit_contents(&info.string_val, addr, len, STRTYPE_C);
                        }
                    }
                    else {
                        info.value = addr;
                    }
                }
                else if (ins->l.t == mop_a && ins->l.a) {
                    // Address expression &something
                    if (ins->l.a->t == mop_v) {
                        ea_t addr = ins->l.a->g;
                        info.type = classify_value(addr);

                        if (info.type == SLOT_FUNC_PTR) {
                            info.func_addr = addr;
                            info.is_objc_msgsend = is_objc_msgsend(addr);
                        }
                        else if (info.type == SLOT_STRING || info.type == SLOT_SELECTOR) {
                            size_t len = get_max_strlit_length(addr, STRTYPE_C);
                            if (len > 0 && len < 1024) {
                                info.string_val.resize(len);
                                get_strlit_contents(&info.string_val, addr, len, STRTYPE_C);
                            }
                        }
                    }
                }

                // Store the slot info
                slots[offset] = info;
            }
        }
    }
}

//--------------------------------------------------------------------------
// Resolve an indirect call through savedregs
//--------------------------------------------------------------------------
bool savedregs_handler_t::resolve_indirect_call(
    mblock_t *blk,
    minsn_t *call_insn,
    const std::map<sval_t, slot_info_ext_t> &slots,
    resolved_call_t *out)
{
    if (!blk || !call_insn || !out)
        return false;

    // Check if this is an indirect call
    if (call_insn->opcode != m_icall && call_insn->opcode != m_call)
        return false;

    // Get the call target
    sval_t target_offset = 0;
    bool found_target = false;

    // Check direct savedregs reference in call target
    if (is_savedregs_ref(call_insn->l, &target_offset)) {
        found_target = true;
    }
    // Check nested instruction (ldx/mov from savedregs)
    else if (call_insn->l.t == mop_d && call_insn->l.d) {
        minsn_t *inner = call_insn->l.d;
        if (inner->opcode == m_ldx || inner->opcode == m_mov) {
            if (is_savedregs_ref(inner->l, &target_offset)) {
                found_target = true;
            }
        }
    }

    if (!found_target)
        return false;

    // Look up the target in our slot map
    auto it = slots.find(target_offset);
    if (it == slots.end())
        return false;

    const slot_info_ext_t &slot = it->second;
    if (slot.type != SLOT_FUNC_PTR || slot.func_addr == BADADDR)
        return false;

    // Fill in resolved call info
    out->call_addr = call_insn->ea;
    out->target_func = slot.func_addr;
    out->is_objc = slot.is_objc_msgsend;

    // Get target function name
    get_name(&out->target_name, slot.func_addr);

    // Extract arguments from savedregs
    extract_call_args(call_insn, slots, out);

    return true;
}

//--------------------------------------------------------------------------
// Extract call arguments from savedregs
//--------------------------------------------------------------------------
bool savedregs_handler_t::extract_call_args(
    minsn_t *call_insn,
    const std::map<sval_t, slot_info_ext_t> &slots,
    resolved_call_t *out)
{
    if (!call_insn || !out)
        return false;

    out->args.clear();
    out->selector.clear();

    // For icall, arguments are in the r operand as mcallargs_t
    if (call_insn->opcode == m_icall) {
        if (call_insn->d.t == mop_f && call_insn->d.f) {
            mcallinfo_t *ci = call_insn->d.f;

            // Iterate through call arguments
            for (size_t i = 0; i < ci->args.size(); i++) {
                mcallarg_t &arg = ci->args[i];

                sval_t offset;
                if (is_savedregs_ref(arg, &offset)) {
                    auto it = slots.find(offset);
                    if (it != slots.end()) {
                        const slot_info_ext_t &slot = it->second;

                        if (slot.type == SLOT_STRING || slot.type == SLOT_SELECTOR) {
                            out->args.push_back(slot.string_val);

                            // For ObjC calls, the selector is typically arg 1 (after self)
                            if (out->is_objc && i == 1 && slot.type == SLOT_SELECTOR) {
                                out->selector = slot.string_val;
                            }
                        }
                    }
                }
            }
        }
    }

    return !out->args.empty() || !out->selector.empty();
}

//--------------------------------------------------------------------------
// Transform a call to use direct target
//--------------------------------------------------------------------------
bool savedregs_handler_t::transform_call(
    mblock_t *blk,
    minsn_t *call_insn,
    const resolved_call_t &resolved)
{
    if (!blk || !call_insn)
        return false;

    // For now, we just annotate rather than transform
    // Full transformation would require:
    // 1. Changing icall to call
    // 2. Setting direct target address
    // 3. Fixing up call arguments

    // This is complex because argument handling differs between
    // direct and indirect calls in microcode

    return false;
}

//--------------------------------------------------------------------------
// Format ObjC call for annotation
//--------------------------------------------------------------------------
qstring savedregs_handler_t::format_objc_call(const resolved_call_t &resolved) {
    qstring result;

    if (!resolved.selector.empty()) {
        // Format: [obj selector:arg1 param2:arg2 ...]
        // For now, just show the selector
        result.sprnt("[... %s]", resolved.selector.c_str());
    }
    else {
        result.sprnt("objc_msgSend(...)");
    }

    return result;
}

//--------------------------------------------------------------------------
// Annotate a resolved call
//--------------------------------------------------------------------------
void savedregs_handler_t::annotate_call(ea_t call_addr, const resolved_call_t &resolved) {
    if (call_addr == BADADDR)
        return;

    qstring comment;

    if (resolved.is_objc) {
        // ObjC-style annotation
        if (!resolved.selector.empty()) {
            comment.sprnt("DEOBF: ObjC call - [obj %s]", resolved.selector.c_str());
        }
        else {
            comment.sprnt("DEOBF: ObjC call - %s", resolved.target_name.c_str());
        }
    }
    else {
        // Regular function call
        comment.sprnt("DEOBF: Indirect call to %s (0x%llX)",
                     resolved.target_name.c_str(),
                     (unsigned long long)resolved.target_func);
    }

    // Add string arguments to comment
    for (size_t i = 0; i < resolved.args.size(); i++) {
        if (i == 0 && resolved.is_objc && resolved.args[i] == resolved.selector)
            continue;  // Skip selector, already shown

        qstring arg_comment;
        arg_comment.sprnt("\n  arg[%d]: \"%s\"", (int)i, resolved.args[i].c_str());
        comment += arg_comment;
    }

    // Set the comment
    set_cmt(call_addr, comment.c_str(), false);
}

//--------------------------------------------------------------------------
// Main processing
//--------------------------------------------------------------------------
int savedregs_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    int changes = 0;

    // Step 1: Analyze all savedregs writes
    std::map<sval_t, slot_info_ext_t> slots;
    analyze_savedregs_writes(mba, slots);

    if (slots.empty()) {
        deobf::log("[savedregs] No savedregs slots found\n");
        return 0;
    }

    deobf::log("[savedregs] Found %d savedregs slots\n", (int)slots.size());

    // Log interesting slots
    for (const auto &pair : slots) {
        const slot_info_ext_t &slot = pair.second;
        switch (slot.type) {
            case SLOT_FUNC_PTR:
                deobf::log("[savedregs]   offset %d: func %s (0x%llX)%s\n",
                          (int)slot.offset,
                          slot.string_val.empty() ? "unknown" : slot.string_val.c_str(),
                          (unsigned long long)slot.func_addr,
                          slot.is_objc_msgsend ? " [objc_msgSend]" : "");
                break;
            case SLOT_SELECTOR:
                deobf::log("[savedregs]   offset %d: selector \"%s\"\n",
                          (int)slot.offset, slot.string_val.c_str());
                break;
            case SLOT_STRING:
                deobf::log("[savedregs]   offset %d: string \"%s\"\n",
                          (int)slot.offset, slot.string_val.c_str());
                break;
            default:
                break;
        }
    }

    // Step 2: Find and resolve indirect calls through savedregs
    std::vector<resolved_call_t> resolved_calls;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_icall || ins->opcode == m_call) {
                resolved_call_t resolved;
                if (resolve_indirect_call(blk, ins, slots, &resolved)) {
                    resolved_calls.push_back(resolved);
                    changes++;
                }
            }
        }
    }

    deobf::log("[savedregs] Resolved %d indirect calls\n", (int)resolved_calls.size());

    // Step 3: Annotate resolved calls
    for (const auto &resolved : resolved_calls) {
        annotate_call(resolved.call_addr, resolved);

        if (resolved.is_objc) {
            deobf::log("[savedregs]   0x%llX: %s\n",
                      (unsigned long long)resolved.call_addr,
                      format_objc_call(resolved).c_str());
        }
        else {
            deobf::log("[savedregs]   0x%llX: call %s\n",
                      (unsigned long long)resolved.call_addr,
                      resolved.target_name.c_str());
        }
    }

    ctx->indirect_resolved += changes;
    return changes;
}

//--------------------------------------------------------------------------
// Per-instruction simplification
//--------------------------------------------------------------------------
int savedregs_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    // This is called during microcode optimization
    // We can't do much here since we need full function context
    // The main work is done in run()
    return 0;
}
