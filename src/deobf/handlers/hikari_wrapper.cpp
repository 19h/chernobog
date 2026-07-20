#include "hikari_wrapper.h"

namespace {

std::string normalize_import_name(const qstring &raw_name)
{
    std::string name = raw_name.c_str();
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

bool is_objc_dispatch_name(const qstring &raw_name)
{
    const std::string name = normalize_import_name(raw_name);
    static const std::set<std::string> dispatchers = {
        "objc_msgSend", "objc_msgSendSuper", "objc_msgSendSuper2",
        "objc_msgSend_stret", "objc_msgSend_fpret", "objc_msgSend_fp2ret",
        "objc_msgSendSuper_stret", "objc_msgSendSuper2_stret",
        "objc_msgSend_fixup"
    };
    return dispatchers.count(name) != 0 ||
           name.compare(0, sizeof("objc_msgSend$") - 1, "objc_msgSend$") == 0;
}

bool is_dynamic_loader_name(const qstring &raw_name)
{
    const std::string name = normalize_import_name(raw_name);
    return name == "dlsym" || name == "dlopen";
}

enum class wrapper_runtime_t : uint8_t
{
    none = 0,
    objc,
    dynamic_loader,
};

bool unique_direct_transfer_target(ea_t from, ea_t *target)
{
    if ( !target )
        return false;
    *target = BADADDR;
    xrefblk_t xref;
    for ( bool ok = xref.first_from(from, XREF_CODE);
          ok; ok = xref.next_from() ) {
        const int type = int(xref.type) & XREF_MASK;
        if ( type == fl_F )
            continue;
        if ( type != fl_CN && type != fl_CF )
            return false;
        if ( *target != BADADDR && *target != xref.to )
            return false;
        *target = xref.to;
    }
    return *target != BADADDR;
}

wrapper_runtime_t classify_strict_runtime_wrapper(
    ea_t function_ea,
    ea_t *runtime_target)
{
    if ( runtime_target )
        *runtime_target = BADADDR;
    const func_t *function = get_func(function_ea);
    if ( !function || function->start_ea != function_ea
      || function->tailqty != 0 || function->end_ea <= function->start_ea
      || function->end_ea - function->start_ea > 128 )
        return wrapper_runtime_t::none;

    wrapper_runtime_t kind = wrapper_runtime_t::none;
    ea_t selected_target = BADADDR;
    size_t instruction_count = 0;
    bool saw_return = false;
    ea_t address = function->start_ea;
    while ( address < function->end_ea ) {
        if ( ++instruction_count > 32
          || !is_head(get_flags(address)) || !is_code(get_flags(address)) )
            return wrapper_runtime_t::none;
        insn_t instruction;
        if ( decode_insn(&instruction, address) <= 0
          || instruction.size == 0
          || instruction.ea + instruction.size > function->end_ea )
            return wrapper_runtime_t::none;

        if ( is_call_insn(instruction) ) {
            if ( kind != wrapper_runtime_t::none )
                return wrapper_runtime_t::none;
            ea_t target = BADADDR;
            if ( !unique_direct_transfer_target(instruction.ea, &target) )
                return wrapper_runtime_t::none;
            qstring name;
            if ( get_func_name(&name, target) <= 0 )
                get_name(&name, target);
            if ( is_objc_dispatch_name(name) )
                kind = wrapper_runtime_t::objc;
            else if ( is_dynamic_loader_name(name) )
                kind = wrapper_runtime_t::dynamic_loader;
            else
                return wrapper_runtime_t::none;
            selected_target = target;
        } else if ( is_ret_insn(instruction) ) {
            if ( saw_return || kind == wrapper_runtime_t::none )
                return wrapper_runtime_t::none;
            saw_return = true;
            if ( instruction.ea + instruction.size != function->end_ea )
                return wrapper_runtime_t::none;
        } else if ( is_basic_block_end(instruction, false) ) {
            // A forwarding wrapper is one straight-line call/return body.
            // Conditional control flow and secondary tail transfers require a
            // separate path-complete semantic proof.
            return wrapper_runtime_t::none;
        }
        address += instruction.size;
    }
    if ( !saw_return || kind == wrapper_runtime_t::none )
        return wrapper_runtime_t::none;
    if ( runtime_target )
        *runtime_target = selected_target;
    return kind;
}

} // namespace

// Static member
std::map<ssize_t, std::map<ea_t, hikari_wrapper_handler_t::wrapper_info_t>>
    hikari_wrapper_handler_t::s_wrapper_cache;
std::map<ssize_t, std::set<ea_t>>
    hikari_wrapper_handler_t::s_non_wrapper_cache;

std::map<ea_t, hikari_wrapper_handler_t::wrapper_info_t> &
hikari_wrapper_handler_t::wrapper_cache()
{
    return s_wrapper_cache[get_dbctx_id()];
}

std::set<ea_t> &hikari_wrapper_handler_t::non_wrapper_cache()
{
    return s_non_wrapper_cache[get_dbctx_id()];
}

void hikari_wrapper_handler_t::clear_cache()
{
    const ssize_t database = get_dbctx_id();
    s_wrapper_cache.erase(database);
    s_non_wrapper_cache.erase(database);
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    // Look for calls to wrapper functions
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( ins->opcode == m_call ) {
                ea_t target = BADADDR;
                if ( ins->l.t == mop_v ) 
                    target = ins->l.g;

                wrapper_info_t wrapper;
                if ( target != BADADDR && get_wrapper_info(target, &wrapper) ) {
                    return true;
                }
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int hikari_wrapper_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[hikari_wrapper] Starting wrapper resolution\n");

    // Find calls to wrappers in this function
    auto calls = find_wrapper_calls(mba);
    deobf::log("[hikari_wrapper] Found %zu wrapper calls in function\n", calls.size());

    int changes = 0;

    for ( auto &call : calls ) {
        // Try to resolve the arguments
        if ( !resolve_call_args(&call) )
            continue;
        annotate_call_site(call);
        ++changes;

        deobf::log_verbose("[hikari_wrapper] Resolved call to %s -> %s\n",
                          call.wrapper.original_name.c_str(),
                          call.wrapper.resolved_name.c_str());
    }

    deobf::log("[hikari_wrapper] Resolved %d wrapper calls\n", changes);
    // This pass currently annotates call sites only.
    return 0;
}

//--------------------------------------------------------------------------
// Analyze a single wrapper
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::analyze_wrapper(ea_t func_ea, wrapper_info_t *out)
{
    if ( !out )
        return false;
    func_t *func = get_func(func_ea);
    if ( !func ) 
        return false;

    out->func_ea = func_ea;
    get_func_name(&out->original_name, func_ea);

    ea_t runtime_target = BADADDR;
    const wrapper_runtime_t runtime = classify_strict_runtime_wrapper(
        func_ea, &runtime_target);

    // Check for one straight-line objc_msgSend forwarding body.
    if ( runtime == wrapper_runtime_t::objc ) {
        out->is_objc = true;
        out->target_func = runtime_target;

        // Try to extract the selector from the code
        // This is complex - the selector might be passed as argument
        // or hardcoded in the wrapper

        // For now, use the wrapper number as identifier
        out->resolved_name = out->original_name;
        out->resolved_name.replace("HikariFunctionWrapper_", "ObjC_Wrapper_");

        return true;
    }

    // Check for dlsym pattern
    if ( runtime == wrapper_runtime_t::dynamic_loader ) {
        out->is_objc = false;
        out->target_func = runtime_target;
        if ( get_func_name(&out->resolved_name, runtime_target) <= 0 )
            get_name(&out->resolved_name, runtime_target);
        if ( out->resolved_name.empty() )
            out->resolved_name = "dynamic_loader";
        return true;
    }

    // A wrapper-like name alone does not resolve any semantics and produces a
    // tautological annotation. Admit only wrappers with a proven runtime API.
    return false;
}

bool hikari_wrapper_handler_t::get_wrapper_info(ea_t func_ea,
                                                wrapper_info_t *out)
{
    if ( func_ea == BADADDR || !out )
        return false;

    std::map<ea_t, wrapper_info_t> &wrappers = wrapper_cache();
    std::set<ea_t> &non_wrappers = non_wrapper_cache();
    const auto cached = wrappers.find(func_ea);
    if ( cached != wrappers.end() ) {
        *out = cached->second;
        return true;
    }
    if ( non_wrappers.count(func_ea) != 0 )
        return false;

    if ( !is_wrapper_by_name(func_ea) && !is_wrapper_by_pattern(func_ea) ) {
        non_wrappers.insert(func_ea);
        return false;
    }

    wrapper_info_t wrapper;
    if ( !analyze_wrapper(func_ea, &wrapper) ) {
        non_wrappers.insert(func_ea);
        return false;
    }
    wrappers.emplace(func_ea, wrapper);
    *out = wrapper;
    return true;
}

//--------------------------------------------------------------------------
// Check if function is a wrapper by name
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::is_wrapper_by_name(ea_t func_ea)
{
    qstring name;
    if ( get_func_name(&name, func_ea) <= 0 ) 
        return false;

    // Common Hikari wrapper patterns
    if ( name.find("HikariFunctionWrapper") != qstring::npos ) 
        return true;
    if ( name.find("HikariWrapper") != qstring::npos ) 
        return true;
    if ( name.find("FunctionWrapper_") != qstring::npos ) 
        return true;
    if ( name.find("_wrapper_") != qstring::npos ) 
        return true;

    // OLLVM patterns
    if ( name.find("ollvm_") != qstring::npos ) 
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Check if function is a wrapper by pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::is_wrapper_by_pattern(ea_t func_ea)
{
    func_t *func = get_func(func_ea);
    if ( !func ) 
        return false;

    return classify_strict_runtime_wrapper(func_ea, nullptr)
        != wrapper_runtime_t::none;
}

//--------------------------------------------------------------------------
// Find wrapper calls in function
//--------------------------------------------------------------------------
std::vector<hikari_wrapper_handler_t::call_site_t>
hikari_wrapper_handler_t::find_wrapper_calls(mbl_array_t *mba)
    {

    std::vector<call_site_t> result;
    if ( !mba )
        return result;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( ins->opcode == m_call ) {
                ea_t target = BADADDR;
                if ( ins->l.t == mop_v ) 
                    target = ins->l.g;

                wrapper_info_t wrapper;
                if ( target != BADADDR && get_wrapper_info(target, &wrapper) ) {
                    call_site_t call;
                    call.block_idx = i;
                    call.call_insn = ins;
                    call.wrapper = wrapper;
                    result.push_back(call);
                }
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Try to resolve call arguments
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::resolve_call_args(call_site_t *call)
{
    if ( !call || !call->call_insn
      || call->call_insn->d.t != mop_f || !call->call_insn->d.f )
        return false;

    // Only inspect operands that Hex-Rays identified as arguments of this
    // call. Backward scans can capture unrelated constants on another path.
    const mcallinfo_t *call_info = call->call_insn->d.f;
    for ( const mcallarg_t& argument : call_info->args ) {
        const mop_t *value = &argument;
        if ( value->t == mop_a && value->a )
            value = value->a;

        ea_t address = BADADDR;
        if ( value->t == mop_v )
            address = value->g;
        else if ( value->t == mop_n && value->nnn ) {
            const ea_t candidate = static_cast<ea_t>(value->nnn->value);
            if ( getseg(candidate) )
                address = candidate;
        }
        if ( address == BADADDR )
            continue;

        qstring name;
        if ( call->class_arg.empty() && get_name(&name, address) > 0
          && name.find("OBJC_CLASS_") != qstring::npos )
        {
            call->class_arg = name;
            call->class_arg.replace("OBJC_CLASS___", "");
            call->class_arg.replace("OBJC_CLASS_$_", "");
        }

        const size_t length = get_max_strlit_length(address, STRTYPE_C);
        if ( call->selector_arg.empty() && length > 0 && length < 256 ) {
            qstring content;
            if ( get_strlit_contents(&content, address, length, STRTYPE_C) > 0
              && (content.find(':') != qstring::npos || content.length() > 3) )
            {
                call->selector_arg = content;
            }
        }
    }

    return !call->class_arg.empty() || !call->selector_arg.empty();
}

//--------------------------------------------------------------------------
// Annotate call site
//--------------------------------------------------------------------------
void hikari_wrapper_handler_t::annotate_call_site(const call_site_t &call)
    {

    if ( !call.call_insn ) 
        return;

    qstring comment;

    if ( call.wrapper.is_objc ) {
        if ( !call.class_arg.empty() && !call.selector_arg.empty() ) {
            comment.sprnt("ObjC: [%s %s]",
                         call.class_arg.c_str(), call.selector_arg.c_str());
        } else if ( !call.class_arg.empty() ) {
            comment.sprnt("ObjC: %s method call", call.class_arg.c_str());
        } else if ( !call.selector_arg.empty() ) {
            comment.sprnt("ObjC selector: %s", call.selector_arg.c_str());
        }
    } else if ( !call.selector_arg.empty() ) {
        comment.sprnt("Dynamic lookup via %s: %s",
                     call.wrapper.resolved_name.c_str(),
                     call.selector_arg.c_str());
    }

    if ( !comment.empty() ) {
        set_cmt(call.call_insn->ea, comment.c_str(), false);
    }
}

//--------------------------------------------------------------------------
// Check for objc_msgSend pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::has_objc_msgsend(ea_t func_ea)
{
    return classify_strict_runtime_wrapper(func_ea, nullptr)
        == wrapper_runtime_t::objc;
}

//--------------------------------------------------------------------------
// Check for dlsym pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::has_dlsym_call(ea_t func_ea)
{
    return classify_strict_runtime_wrapper(func_ea, nullptr)
        == wrapper_runtime_t::dynamic_loader;
}
