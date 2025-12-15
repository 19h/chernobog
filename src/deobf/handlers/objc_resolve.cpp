#include "objc_resolve.h"
#include "../analysis/stack_tracker.h"

//--------------------------------------------------------------------------
// Check if function is objc_msgSend variant (by address)
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::is_objc_msgsend(ea_t func_addr) {
    if (func_addr == BADADDR)
        return false;

    qstring name;
    if (get_name(&name, func_addr) > 0) {
        return is_objc_msgsend(name.c_str());
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if function is objc_msgSend variant (by name)
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::is_objc_msgsend(const char *name) {
    if (!name)
        return false;

    // Skip leading underscore if present
    if (name[0] == '_')
        name++;

    // Check various objc_msgSend patterns
    if (strncmp(name, "objc_msgSend", 12) == 0)
        return true;
    if (strncmp(name, "objc_msgLookup", 14) == 0)
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Classify objc_msgSend variant
//--------------------------------------------------------------------------
objc_resolve_handler_t::msgsend_variant_t
objc_resolve_handler_t::classify_msgsend(ea_t addr) {
    qstring name;
    if (get_name(&name, addr) <= 0)
        return MSGSEND_UNKNOWN;

    return classify_msgsend(name.c_str());
}

objc_resolve_handler_t::msgsend_variant_t
objc_resolve_handler_t::classify_msgsend(const char *name) {
    if (!name)
        return MSGSEND_UNKNOWN;

    // Skip leading underscore
    if (name[0] == '_')
        name++;

    if (strcmp(name, "objc_msgSend") == 0)
        return MSGSEND_NORMAL;
    if (strcmp(name, "objc_msgSendSuper") == 0)
        return MSGSEND_SUPER;
    if (strcmp(name, "objc_msgSendSuper2") == 0)
        return MSGSEND_SUPER2;
    if (strcmp(name, "objc_msgSend_stret") == 0)
        return MSGSEND_STRET;
    if (strcmp(name, "objc_msgSend_fpret") == 0)
        return MSGSEND_FPRET;
    if (strcmp(name, "objc_msgSend_fp2ret") == 0)
        return MSGSEND_FP2RET;

    // Check for prefixed versions
    if (strstr(name, "msgSendSuper2"))
        return MSGSEND_SUPER2;
    if (strstr(name, "msgSendSuper"))
        return MSGSEND_SUPER;
    if (strstr(name, "msgSend_stret"))
        return MSGSEND_STRET;
    if (strstr(name, "msgSend_fpret"))
        return MSGSEND_FPRET;
    if (strstr(name, "msgSend"))
        return MSGSEND_NORMAL;

    return MSGSEND_UNKNOWN;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    int msgsend_calls = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_call && ins->opcode != m_icall)
                continue;

            // Check direct call to objc_msgSend
            if (ins->l.t == mop_v && is_objc_msgsend(ins->l.g)) {
                msgsend_calls++;
            }
            // Check for address reference
            else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                if (is_objc_msgsend(ins->l.a->g)) {
                    msgsend_calls++;
                }
            }
            // Check indirect call (might be through stack)
            else if (ins->opcode == m_icall) {
                // We'll count these as potential candidates
                // The actual resolution happens in run()
            }
        }
    }

    return msgsend_calls > 0;
}

//--------------------------------------------------------------------------
// Find all objc_msgSend calls
//--------------------------------------------------------------------------
void objc_resolve_handler_t::find_msgsend_calls(
    mbl_array_t *mba,
    std::vector<std::pair<mblock_t*, minsn_t*>> &calls)
{
    calls.clear();

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_call && ins->opcode != m_icall)
                continue;

            bool is_msgsend = false;

            // Direct call
            if (ins->l.t == mop_v && is_objc_msgsend(ins->l.g)) {
                is_msgsend = true;
            }
            // Address reference
            else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                if (is_objc_msgsend(ins->l.a->g)) {
                    is_msgsend = true;
                }
            }
            // Indirect through stack - check if we can resolve it
            else if (ins->opcode == m_icall && ins->l.t == mop_S && ins->l.s) {
                auto addr = stack_tracker_t::read_address(ins->l.s->off);
                if (addr.has_value() && is_objc_msgsend(*addr)) {
                    is_msgsend = true;
                }
            }

            if (is_msgsend) {
                calls.push_back({blk, ins});
            }
        }
    }
}

//--------------------------------------------------------------------------
// Get selector string from operand
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::get_selector_string(
    mbl_array_t *mba,
    const mop_t &sel_op,
    qstring *out_selector)
{
    if (!out_selector)
        return false;

    out_selector->clear();

    // Direct global string reference
    if (sel_op.t == mop_v) {
        size_t len = get_max_strlit_length(sel_op.g, STRTYPE_C);
        if (len > 0 && len < 256) {
            out_selector->resize(len);
            if (get_strlit_contents(out_selector, sel_op.g, len, STRTYPE_C) > 0) {
                return true;
            }
        }

        // Might be a selector reference (__objc_selrefs)
        // Try reading pointer and then string
        ea_t sel_ptr = get_qword(sel_op.g);
        if (sel_ptr != 0 && sel_ptr != BADADDR) {
            len = get_max_strlit_length(sel_ptr, STRTYPE_C);
            if (len > 0 && len < 256) {
                out_selector->resize(len);
                if (get_strlit_contents(out_selector, sel_ptr, len, STRTYPE_C) > 0) {
                    return true;
                }
            }
        }
    }

    // Address expression
    if (sel_op.t == mop_a && sel_op.a && sel_op.a->t == mop_v) {
        size_t len = get_max_strlit_length(sel_op.a->g, STRTYPE_C);
        if (len > 0 && len < 256) {
            out_selector->resize(len);
            if (get_strlit_contents(out_selector, sel_op.a->g, len, STRTYPE_C) > 0) {
                return true;
            }
        }
    }

    // Stack reference
    if (sel_op.t == mop_S && sel_op.s) {
        auto str = stack_tracker_t::read_string(sel_op.s->off);
        if (str.has_value()) {
            *out_selector = str->c_str();
            return true;
        }

        // Try as address pointing to string
        auto addr = stack_tracker_t::read_address(sel_op.s->off);
        if (addr.has_value()) {
            size_t len = get_max_strlit_length(*addr, STRTYPE_C);
            if (len > 0 && len < 256) {
                out_selector->resize(len);
                if (get_strlit_contents(out_selector, *addr, len, STRTYPE_C) > 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Trace selector argument from call
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::trace_selector(
    mbl_array_t *mba,
    mblock_t *blk,
    minsn_t *call_insn,
    qstring *out_selector)
{
    if (!mba || !blk || !call_insn || !out_selector)
        return false;

    // For objc_msgSend, selector is arg 1 (0-indexed = second argument)
    // For msgSendSuper, it's also arg 1 (after super struct)

    // Get call arguments
    if (call_insn->d.t != mop_f || !call_insn->d.f)
        return false;

    mcallinfo_t *ci = call_insn->d.f;

    // Need at least 2 arguments (receiver, selector)
    if (ci->args.size() < 2)
        return false;

    // Get selector argument (index 1)
    const mcallarg_t &sel_arg = ci->args[1];

    return get_selector_string(mba, sel_arg, out_selector);
}

//--------------------------------------------------------------------------
// Get selector from sel_registerName call
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::get_selector_from_registration(
    mbl_array_t *mba,
    const mop_t &op,
    qstring *out)
{
    // This would trace back to find a sel_registerName("string") call
    // and extract the string argument
    // Complex implementation - would need dataflow analysis
    return false;
}

//--------------------------------------------------------------------------
// Trace receiver to find class name
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::trace_receiver_class(
    mbl_array_t *mba,
    mblock_t *blk,
    minsn_t *call_insn,
    qstring *out_class)
{
    if (!mba || !blk || !call_insn || !out_class)
        return false;

    if (call_insn->d.t != mop_f || !call_insn->d.f)
        return false;

    mcallinfo_t *ci = call_insn->d.f;
    if (ci->args.empty())
        return false;

    // Get receiver argument (index 0)
    const mcallarg_t &recv_arg = ci->args[0];

    return is_class_object(mba, recv_arg, out_class);
}

//--------------------------------------------------------------------------
// Check if operand is a class object reference
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::is_class_object(
    mbl_array_t *mba,
    const mop_t &receiver,
    qstring *out_class)
{
    if (!out_class)
        return false;

    // Check for direct class reference
    if (receiver.t == mop_v) {
        qstring name;
        if (get_name(&name, receiver.g) > 0) {
            // ObjC class references typically have patterns like:
            // _OBJC_CLASS_$_ClassName
            // classRef_ClassName
            const char *prefix = "_OBJC_CLASS_$_";
            size_t prefix_len = strlen(prefix);
            if (name.length() > prefix_len &&
                strncmp(name.c_str(), prefix, prefix_len) == 0) {
                *out_class = name.c_str() + prefix_len;
                return true;
            }

            // Check for classRef pattern
            if (name.find("classRef_") == 0) {
                *out_class = name.c_str() + 9;  // Skip "classRef_"
                return true;
            }
        }
    }

    // Check address expression
    if (receiver.t == mop_a && receiver.a && receiver.a->t == mop_v) {
        qstring name;
        if (get_name(&name, receiver.a->g) > 0) {
            const char *prefix = "_OBJC_CLASS_$_";
            size_t prefix_len = strlen(prefix);
            if (name.length() > prefix_len &&
                strncmp(name.c_str(), prefix, prefix_len) == 0) {
                *out_class = name.c_str() + prefix_len;
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Resolve a single objc_msgSend call
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::resolve_msgsend_call(
    mbl_array_t *mba,
    mblock_t *blk,
    minsn_t *call_insn,
    objc_call_info_t *out)
{
    if (!mba || !blk || !call_insn || !out)
        return false;

    // Initialize output
    out->call_addr = call_insn->ea;
    out->msgsend_addr = BADADDR;
    out->selector.clear();
    out->receiver_class.clear();
    out->is_class_method = false;
    out->is_super_call = false;
    out->is_stret = false;

    // Get msgSend address
    if (call_insn->l.t == mop_v) {
        out->msgsend_addr = call_insn->l.g;
    }
    else if (call_insn->l.t == mop_a && call_insn->l.a && call_insn->l.a->t == mop_v) {
        out->msgsend_addr = call_insn->l.a->g;
    }
    else if (call_insn->l.t == mop_S && call_insn->l.s) {
        auto addr = stack_tracker_t::read_address(call_insn->l.s->off);
        if (addr.has_value()) {
            out->msgsend_addr = *addr;
        }
    }

    if (out->msgsend_addr == BADADDR)
        return false;

    // Get variant info
    msgsend_variant_t variant = classify_msgsend(out->msgsend_addr);
    get_name(&out->msgsend_variant, out->msgsend_addr);

    out->is_super_call = (variant == MSGSEND_SUPER || variant == MSGSEND_SUPER2);
    out->is_stret = (variant == MSGSEND_STRET);

    // Trace selector
    if (!trace_selector(mba, blk, call_insn, &out->selector)) {
        return false;  // Must have selector to be useful
    }

    // Try to trace receiver class
    if (trace_receiver_class(mba, blk, call_insn, &out->receiver_class)) {
        out->is_class_method = true;  // If we found a class, it's likely a class method
    }

    return true;
}

//--------------------------------------------------------------------------
// Format method signature
//--------------------------------------------------------------------------
qstring objc_resolve_handler_t::format_method_signature(const objc_call_info_t &info) {
    qstring result;

    // Format: +/-[ClassName selector]
    char method_type = info.is_class_method ? '+' : '-';

    if (!info.receiver_class.empty()) {
        result.sprnt("%c[%s %s]", method_type,
                    info.receiver_class.c_str(),
                    info.selector.c_str());
    }
    else {
        result.sprnt("%c[? %s]", method_type, info.selector.c_str());
    }

    return result;
}

//--------------------------------------------------------------------------
// Annotate a resolved ObjC call
//--------------------------------------------------------------------------
void objc_resolve_handler_t::annotate_objc_call(ea_t call_addr, const objc_call_info_t &info) {
    if (call_addr == BADADDR)
        return;

    qstring comment;
    comment.sprnt("DEOBF: %s", format_method_signature(info).c_str());

    if (info.is_super_call) {
        comment += " (super)";
    }
    if (info.is_stret) {
        comment += " (stret)";
    }

    set_cmt(call_addr, comment.c_str(), false);
}

//--------------------------------------------------------------------------
// Main processing
//--------------------------------------------------------------------------
int objc_resolve_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    int changes = 0;

    // Find all objc_msgSend calls
    std::vector<std::pair<mblock_t*, minsn_t*>> msgsend_calls;
    find_msgsend_calls(mba, msgsend_calls);

    if (msgsend_calls.empty()) {
        return 0;
    }

    deobf::log("[objc_resolve] Found %d objc_msgSend calls\n", (int)msgsend_calls.size());

    // Resolve each call
    for (const auto &pair : msgsend_calls) {
        mblock_t *blk = pair.first;
        minsn_t *ins = pair.second;

        objc_call_info_t info;
        if (resolve_msgsend_call(mba, blk, ins, &info)) {
            annotate_objc_call(info.call_addr, info);

            deobf::log("[objc_resolve]   0x%llX: %s\n",
                      (unsigned long long)info.call_addr,
                      format_method_signature(info).c_str());

            changes++;
        }
    }

    deobf::log("[objc_resolve] Resolved %d ObjC method calls\n", changes);

    return changes;
}
