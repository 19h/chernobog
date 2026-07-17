#include "objc_resolve.h"
#include "../analysis/stack_tracker.h"
#include "../analysis/arch_utils.h"

namespace {

std::string normalize_objc_symbol(const char *raw_name)
{
    std::string name = raw_name ? raw_name : "";
    while ( !name.empty() && name.front() == '_' )
        name.erase(name.begin());
    if ( name.compare(0, 4, "imp_") == 0 )
        name.erase(0, 4);
    if ( name.compare(0, 2, "j_") == 0 )
        name.erase(0, 2);
    while ( !name.empty() && name.front() == '_' )
        name.erase(name.begin());
    return name;
}

int pointer_size()
{
    return arch::is_64bit() ? 8 : 4;
}

bool selector_at_address(ea_t address, qstring *out_selector)
{
    if ( address == BADADDR || !out_selector )
        return false;

    size_t length = get_max_strlit_length(address, STRTYPE_C);
    if ( length > 0 && length < 256 )
    {
        out_selector->resize(length);
        if ( get_strlit_contents(out_selector, address, length, STRTYPE_C) > 0 )
            return true;
    }

    const ea_t pointee = arch::read_ptr(address);
    if ( pointee == 0 || pointee == BADADDR )
        return false;
    length = get_max_strlit_length(pointee, STRTYPE_C);
    if ( length == 0 || length >= 256 )
        return false;
    out_selector->resize(length);
    return get_strlit_contents(out_selector, pointee, length, STRTYPE_C) > 0;
}

} // namespace

//--------------------------------------------------------------------------
// Check if function is objc_msgSend variant (by address)
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::is_objc_msgsend(ea_t func_addr)
{
    if ( func_addr == BADADDR ) 
        return false;

    qstring name;
    if ( get_name(&name, func_addr) > 0 ) {
        return is_objc_msgsend(name.c_str());
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if function is objc_msgSend variant (by name)
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::is_objc_msgsend(const char *name)
{
    if ( !name ) 
        return false;

    const std::string symbol = normalize_objc_symbol(name);
    return symbol == "objc_msgSend" || symbol == "objc_msgSendSuper" ||
           symbol == "objc_msgSendSuper2" ||
           symbol == "objc_msgSend_stret" ||
           symbol == "objc_msgSend_fpret" ||
           symbol == "objc_msgSend_fp2ret" ||
           symbol == "objc_msgSendSuper_stret" ||
           symbol == "objc_msgSendSuper2_stret" ||
           symbol == "objc_msgSend_fixup" ||
           symbol == "objc_msgLookup" ||
           symbol == "objc_msgLookupSuper" ||
           symbol.compare(0, sizeof("objc_msgSend$") - 1,
                          "objc_msgSend$") == 0;
}

//--------------------------------------------------------------------------
// Classify objc_msgSend variant
//--------------------------------------------------------------------------
objc_resolve_handler_t::msgsend_variant_t
objc_resolve_handler_t::classify_msgsend(ea_t addr) {
    qstring name;
    if ( get_name(&name, addr) <= 0 ) 
        return MSGSEND_UNKNOWN;

    return classify_msgsend(name.c_str());
}

objc_resolve_handler_t::msgsend_variant_t
objc_resolve_handler_t::classify_msgsend(const char *name) {
    if ( !name ) 
        return MSGSEND_UNKNOWN;

    const std::string symbol = normalize_objc_symbol(name);
    if ( symbol == "objc_msgSendSuper2_stret" )
        return MSGSEND_SUPER2_STRET;
    if ( symbol == "objc_msgSendSuper_stret" )
        return MSGSEND_SUPER_STRET;
    if ( symbol == "objc_msgSendSuper2" )
        return MSGSEND_SUPER2;
    if ( symbol == "objc_msgSendSuper" || symbol == "objc_msgLookupSuper" )
        return MSGSEND_SUPER;
    if ( symbol == "objc_msgSend_stret" )
        return MSGSEND_STRET;
    if ( symbol == "objc_msgSend_fpret" )
        return MSGSEND_FPRET;
    if ( symbol == "objc_msgSend_fp2ret" )
        return MSGSEND_FP2RET;
    if ( symbol == "objc_msgSend" || symbol == "objc_msgSend_fixup" ||
         symbol == "objc_msgLookup" ||
         symbol.compare(0, sizeof("objc_msgSend$") - 1,
                        "objc_msgSend$") == 0 )
        return MSGSEND_NORMAL;

    return MSGSEND_UNKNOWN;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool objc_resolve_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    int msgsend_calls = 0;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( ins->opcode != m_call && ins->opcode != m_icall ) 
                continue;

            const mop_t &target = ins->opcode == m_icall ? ins->r : ins->l;

            // Check direct call to objc_msgSend
            if ( target.t == mop_v && is_objc_msgsend(target.g) ) {
                msgsend_calls++;
            }
            // Check for address reference
            else if ( target.t == mop_a && target.a && target.a->t == mop_v ) {
                if ( is_objc_msgsend(target.a->g) ) {
                    msgsend_calls++;
                }
            }
            else if ( target.t == mop_S && target.s ) {
                auto address = stack_tracker_t::trace_address(
                    blk, ins, target.s->off, pointer_size());
                if ( address && is_objc_msgsend(*address) )
                    msgsend_calls++;
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

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( ins->opcode != m_call && ins->opcode != m_icall ) 
                continue;

            bool is_msgsend = false;
            const mop_t &target = ins->opcode == m_icall ? ins->r : ins->l;

            // Direct call
            if ( target.t == mop_v && is_objc_msgsend(target.g) ) {
                is_msgsend = true;
            }
            // Address reference
            else if ( target.t == mop_a && target.a && target.a->t == mop_v ) {
                if ( is_objc_msgsend(target.a->g) ) {
                    is_msgsend = true;
                }
            }
            // Indirect through stack - check if we can resolve it
            else if ( target.t == mop_S && target.s ) {
                auto addr = stack_tracker_t::trace_address(
                    blk, ins, target.s->off, pointer_size());
                if ( addr.has_value() && is_objc_msgsend(*addr) ) {
                    is_msgsend = true;
                }
            }

            if ( is_msgsend ) {
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
    if ( !out_selector ) 
        return false;

    out_selector->clear();

    // Direct global string reference
    if ( sel_op.t == mop_v ) {
        return selector_at_address(sel_op.g, out_selector);
    }

    // Address expression
    if ( sel_op.t == mop_a && sel_op.a && sel_op.a->t == mop_v ) {
        return selector_at_address(sel_op.a->g, out_selector);
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
    if ( !mba || !blk || !call_insn || !out_selector ) 
        return false;

    // For objc_msgSend, selector is arg 1 (0-indexed = second argument)
    // For msgSendSuper, it's also arg 1 (after super struct)

    // Get call arguments
    if ( call_insn->d.t != mop_f || !call_insn->d.f ) 
        return false;

    mcallinfo_t *ci = call_insn->d.f;

    // Need at least 2 arguments (receiver, selector)
    if ( ci->args.size() < 2 ) 
        return false;

    // Get selector argument (index 1)
    const mcallarg_t &sel_arg = ci->args[1];

    if ( sel_arg.t == mop_S && sel_arg.s )
    {
        auto address = stack_tracker_t::trace_address(
            blk, call_insn, sel_arg.s->off, pointer_size());
        return address && selector_at_address(*address, out_selector);
    }
    return get_selector_string(mba, sel_arg, out_selector);
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
    if ( !mba || !blk || !call_insn || !out_class ) 
        return false;

    if ( call_insn->d.t != mop_f || !call_insn->d.f ) 
        return false;

    mcallinfo_t *ci = call_insn->d.f;
    if ( ci->args.empty() ) 
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
    if ( !out_class ) 
        return false;

    // Check for direct class reference
    if ( receiver.t == mop_v ) {
        qstring name;
        if ( get_name(&name, receiver.g) > 0 ) {
            // ObjC class references typically have patterns like:
            // _OBJC_CLASS_$_ClassName
            // classRef_ClassName
            const char *prefix = "_OBJC_CLASS_$_";
            size_t prefix_len = strlen(prefix);
            if ( name.length() > prefix_len &&
                strncmp(name.c_str(), prefix, prefix_len) == 0)
                {
                *out_class = name.c_str() + prefix_len;
                return true;
            }

            // Check for classRef pattern
            if ( name.find("classRef_") == 0 ) {
                *out_class = name.c_str() + 9;  // Skip "classRef_"
                return true;
            }
        }
    }

    // Check address expression
    if ( receiver.t == mop_a && receiver.a && receiver.a->t == mop_v ) {
        qstring name;
        if ( get_name(&name, receiver.a->g) > 0 ) {
            const char *prefix = "_OBJC_CLASS_$_";
            size_t prefix_len = strlen(prefix);
            if ( name.length() > prefix_len &&
                strncmp(name.c_str(), prefix, prefix_len) == 0)
                {
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
    if ( !mba || !blk || !call_insn || !out ) 
        return false;

    // Initialize output
    out->call_addr = call_insn->ea;
    out->msgsend_addr = BADADDR;
    out->selector.clear();
    out->receiver_class.clear();
    out->is_class_method = false;
    out->is_super_call = false;
    out->is_stret = false;

    // m_call uses l; m_icall uses r as the offset half of its selector/offset
    // pair.
    const mop_t &target = call_insn->opcode == m_icall
                        ? call_insn->r : call_insn->l;
    if ( target.t == mop_v ) {
        out->msgsend_addr = target.g;
    }
    else if ( target.t == mop_a && target.a && target.a->t == mop_v ) {
        out->msgsend_addr = target.a->g;
    }
    else if ( target.t == mop_S && target.s ) {
        auto addr = stack_tracker_t::trace_address(
            blk, call_insn, target.s->off, pointer_size());
        if ( addr.has_value() ) {
            out->msgsend_addr = *addr;
        }
    }

    if ( out->msgsend_addr == BADADDR ) 
        return false;

    // Get variant info
    msgsend_variant_t variant = classify_msgsend(out->msgsend_addr);
    get_name(&out->msgsend_variant, out->msgsend_addr);

    out->is_super_call = variant == MSGSEND_SUPER ||
                         variant == MSGSEND_SUPER2 ||
                         variant == MSGSEND_SUPER_STRET ||
                         variant == MSGSEND_SUPER2_STRET;
    out->is_stret = variant == MSGSEND_STRET ||
                    variant == MSGSEND_SUPER_STRET ||
                    variant == MSGSEND_SUPER2_STRET;

    // Trace selector
    if ( !trace_selector(mba, blk, call_insn, &out->selector) ) {
        return false;  // Must have selector to be useful
    }

    // Try to trace receiver class
    if ( trace_receiver_class(mba, blk, call_insn, &out->receiver_class) ) {
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

    if ( !info.receiver_class.empty() ) {
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
void objc_resolve_handler_t::annotate_objc_call(ea_t call_addr, const objc_call_info_t &info)
{
    if ( call_addr == BADADDR ) 
        return;

    qstring comment;
    comment.sprnt("DEOBF: %s", format_method_signature(info).c_str());

    if ( info.is_super_call ) {
        comment += " (super)";
    }
    if ( info.is_stret ) {
        comment += " (stret)";
    }

    set_cmt(call_addr, comment.c_str(), false);
}

//--------------------------------------------------------------------------
// Main processing
//--------------------------------------------------------------------------
int objc_resolve_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    int changes = 0;

    // Find all objc_msgSend calls
    std::vector<std::pair<mblock_t*, minsn_t*>> msgsend_calls;
    find_msgsend_calls(mba, msgsend_calls);

    if ( msgsend_calls.empty() ) {
        return 0;
    }

    deobf::log("[objc_resolve] Found %d objc_msgSend calls\n", (int)msgsend_calls.size());

    // Resolve each call
    for ( const auto &pair : msgsend_calls ) {
        mblock_t *blk = pair.first;
        minsn_t *ins = pair.second;

        objc_call_info_t info;
        if ( resolve_msgsend_call(mba, blk, ins, &info) ) {
            annotate_objc_call(info.call_addr, info);

            deobf::log("[objc_resolve]   0x%llX: %s\n",
                      (unsigned long long)info.call_addr,
                      format_method_signature(info).c_str());

            changes++;
        }
    }

    deobf::log("[objc_resolve] Resolved %d ObjC method calls\n", changes);

    // ObjC signatures are annotations; the current microcode is unchanged.
    return 0;
}
