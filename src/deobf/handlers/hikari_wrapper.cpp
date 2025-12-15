#include "hikari_wrapper.h"
#include "../analysis/pattern_match.h"

// Static member
std::map<ea_t, hikari_wrapper_handler_t::wrapper_info_t> hikari_wrapper_handler_t::s_wrapper_cache;

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Look for calls to wrapper functions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_call) {
                ea_t target = BADADDR;
                if (ins->l.t == mop_v)
                    target = ins->l.g;

                if (target != BADADDR && is_wrapper_by_name(target)) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool hikari_wrapper_handler_t::detect_in_binary() {
    // Scan for functions with wrapper-like names
    size_t count = get_func_qty();
    for (size_t i = 0; i < count; i++) {
        func_t *func = getn_func(i);
        if (func && is_wrapper_by_name(func->start_ea)) {
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int hikari_wrapper_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[hikari_wrapper] Starting wrapper resolution\n");

    // Find all wrappers in the binary (cached)
    auto wrappers = find_wrappers();
    deobf::log("[hikari_wrapper] Found %zu wrapper functions\n", wrappers.size());

    // Find calls to wrappers in this function
    auto calls = find_wrapper_calls(mba, wrappers);
    deobf::log("[hikari_wrapper] Found %zu wrapper calls in function\n", calls.size());

    int changes = 0;

    for (auto &call : calls) {
        // Try to resolve the arguments
        resolve_call_args(mba, &call);

        // Find the wrapper info
        for (const auto &wrapper : wrappers) {
            if (wrapper.func_ea == call.wrapper_func) {
                // Annotate the call site
                annotate_call_site(call, wrapper);
                changes++;

                deobf::log_verbose("[hikari_wrapper] Resolved call to %s -> %s\n",
                                  wrapper.original_name.c_str(),
                                  wrapper.resolved_name.c_str());
                break;
            }
        }
    }

    deobf::log("[hikari_wrapper] Resolved %d wrapper calls\n", changes);
    return changes;
}

//--------------------------------------------------------------------------
// Resolve all wrappers in the binary
//--------------------------------------------------------------------------
int hikari_wrapper_handler_t::resolve_all_wrappers() {
    auto wrappers = find_wrappers();

    int renamed = 0;
    for (const auto &wrapper : wrappers) {
        if (!wrapper.resolved_name.empty() &&
            wrapper.resolved_name != wrapper.original_name) {
            if (rename_wrapper(wrapper)) {
                renamed++;
            }
        }
    }

    msg("[hikari_wrapper] Renamed %d wrapper functions\n", renamed);
    return renamed;
}

//--------------------------------------------------------------------------
// Find all wrapper functions
//--------------------------------------------------------------------------
std::vector<hikari_wrapper_handler_t::wrapper_info_t>
hikari_wrapper_handler_t::find_wrappers() {

    std::vector<wrapper_info_t> result;

    size_t count = get_func_qty();
    for (size_t i = 0; i < count; i++) {
        func_t *func = getn_func(i);
        if (!func)
            continue;

        // Check cache first
        auto it = s_wrapper_cache.find(func->start_ea);
        if (it != s_wrapper_cache.end()) {
            result.push_back(it->second);
            continue;
        }

        // Check if this is a wrapper
        if (is_wrapper_by_name(func->start_ea) || is_wrapper_by_pattern(func->start_ea)) {
            wrapper_info_t info;
            if (analyze_wrapper(func->start_ea, &info)) {
                s_wrapper_cache[func->start_ea] = info;
                result.push_back(info);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze a single wrapper
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::analyze_wrapper(ea_t func_ea, wrapper_info_t *out) {
    func_t *func = get_func(func_ea);
    if (!func)
        return false;

    out->func_ea = func_ea;
    get_func_name(&out->original_name, func_ea);

    // Check for objc_msgSend pattern
    if (has_objc_msgsend(func_ea)) {
        out->is_objc = true;

        // Try to extract the selector from the code
        // This is complex - the selector might be passed as argument
        // or hardcoded in the wrapper

        // For now, use the wrapper number as identifier
        out->resolved_name = out->original_name;
        out->resolved_name.replace("HikariFunctionWrapper_", "ObjC_Wrapper_");

        return true;
    }

    // Check for dlsym pattern
    if (has_dlsym_call(func_ea)) {
        out->is_objc = false;
        out->resolved_name = out->original_name;
        out->resolved_name.replace("HikariFunctionWrapper_", "DynAPI_");
        return true;
    }

    // Generic wrapper - just mark it
    out->resolved_name = out->original_name;
    return true;
}

//--------------------------------------------------------------------------
// Check if function is a wrapper by name
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::is_wrapper_by_name(ea_t func_ea) {
    qstring name;
    if (get_func_name(&name, func_ea) <= 0)
        return false;

    // Common Hikari wrapper patterns
    if (name.find("HikariFunctionWrapper") != qstring::npos)
        return true;
    if (name.find("HikariWrapper") != qstring::npos)
        return true;
    if (name.find("FunctionWrapper_") != qstring::npos)
        return true;
    if (name.find("_wrapper_") != qstring::npos)
        return true;

    // OLLVM patterns
    if (name.find("ollvm_") != qstring::npos)
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Check if function is a wrapper by pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::is_wrapper_by_pattern(ea_t func_ea) {
    func_t *func = get_func(func_ea);
    if (!func)
        return false;

    // Wrappers are typically very short
    if (func->end_ea - func->start_ea > 128)
        return false;

    // Check for typical wrapper patterns:
    // 1. Few instructions
    // 2. Contains call to objc_msgSend/dlsym
    // 3. Forwards arguments

    int insn_count = 0;
    bool has_call = false;
    bool has_jmp = false;

    ea_t curr = func->start_ea;
    while (curr < func->end_ea && insn_count < 20) {
        insn_t insn;
        if (decode_insn(&insn, curr) == 0)
            break;

        insn_count++;

        if (is_call_insn(insn))
            has_call = true;

        // Check for tail call (jmp to function)
        // This is arch-specific, simplified here

        curr = insn.ea + insn.size;
    }

    // Very short function with a call - likely a wrapper
    return (insn_count <= 10 && has_call);
}

//--------------------------------------------------------------------------
// Find wrapper calls in function
//--------------------------------------------------------------------------
std::vector<hikari_wrapper_handler_t::call_site_t>
hikari_wrapper_handler_t::find_wrapper_calls(mbl_array_t *mba,
    const std::vector<wrapper_info_t> &wrappers) {

    std::vector<call_site_t> result;

    // Build a set of wrapper addresses for fast lookup
    std::set<ea_t> wrapper_addrs;
    for (const auto &w : wrappers) {
        wrapper_addrs.insert(w.func_ea);
    }

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_call) {
                ea_t target = BADADDR;
                if (ins->l.t == mop_v)
                    target = ins->l.g;

                if (target != BADADDR && wrapper_addrs.count(target)) {
                    call_site_t call;
                    call.block_idx = i;
                    call.call_insn = ins;
                    call.wrapper_func = target;
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
bool hikari_wrapper_handler_t::resolve_call_args(mbl_array_t *mba, call_site_t *call) {
    if (!mba || !call || !call->call_insn)
        return false;

    // Try to find the class and selector arguments
    // This requires analyzing the instructions before the call

    mblock_t *blk = mba->get_mblock(call->block_idx);
    if (!blk)
        return false;

    // Search backwards for argument setup
    // For Obj-C: first arg is class (or self), second is selector

    for (minsn_t *ins = call->call_insn->prev; ins; ins = ins->prev) {
        // Look for loads of class references
        if (ins->opcode == m_mov || ins->opcode == m_ldx) {
            if (ins->l.t == mop_v) {
                // Global reference - might be a class
                ea_t ref = ins->l.g;
                qstring name;
                if (get_name(&name, ref) > 0) {
                    if (name.find("OBJC_CLASS_") != qstring::npos) {
                        call->class_arg = name;
                        call->class_arg.replace("OBJC_CLASS___", "");
                        call->class_arg.replace("OBJC_CLASS_$_", "");
                    }
                }
            }
        }

        // Look for string references (selectors)
        if (ins->l.t == mop_v) {
            ea_t str_addr = ins->l.g;
            qstring str_content;
            // Try to read the string
            size_t len = get_max_strlit_length(str_addr, STRTYPE_C);
            if (len > 0 && len < 256) {
                str_content.resize(len);
                if (get_strlit_contents(&str_content, str_addr, len, STRTYPE_C) > 0) {
                    // Check if it looks like a selector
                    if (str_content.find(':') != qstring::npos ||
                        str_content.length() > 3) {
                        call->selector_arg = str_content;
                    }
                }
            }
        }

        // Stop if we've gone too far back
        if (ins == blk->head)
            break;
    }

    return !call->class_arg.empty() || !call->selector_arg.empty();
}

//--------------------------------------------------------------------------
// Rename wrapper function
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::rename_wrapper(const wrapper_info_t &info) {
    if (info.resolved_name.empty() || info.resolved_name == info.original_name)
        return false;

    // Check if name already exists
    if (get_name_ea(BADADDR, info.resolved_name.c_str()) != BADADDR) {
        // Name exists - append a number
        qstring unique_name;
        for (int i = 1; i < 100; i++) {
            unique_name.sprnt("%s_%d", info.resolved_name.c_str(), i);
            if (get_name_ea(BADADDR, unique_name.c_str()) == BADADDR) {
                return set_name(info.func_ea, unique_name.c_str(), SN_NOWARN | SN_NOCHECK);
            }
        }
        return false;
    }

    return set_name(info.func_ea, info.resolved_name.c_str(), SN_NOWARN | SN_NOCHECK);
}

//--------------------------------------------------------------------------
// Annotate call site
//--------------------------------------------------------------------------
void hikari_wrapper_handler_t::annotate_call_site(const call_site_t &call,
    const wrapper_info_t &wrapper) {

    if (!call.call_insn)
        return;

    qstring comment;

    if (wrapper.is_objc && !call.class_arg.empty()) {
        if (!call.selector_arg.empty()) {
            comment.sprnt("ObjC: [%s %s]",
                         call.class_arg.c_str(), call.selector_arg.c_str());
        } else {
            comment.sprnt("ObjC: %s method call", call.class_arg.c_str());
        }
    } else if (!wrapper.resolved_name.empty()) {
        comment.sprnt("Wrapper -> %s", wrapper.resolved_name.c_str());
    }

    if (!comment.empty()) {
        set_cmt(call.call_insn->ea, comment.c_str(), false);
    }
}

//--------------------------------------------------------------------------
// Generate meaningful name
//--------------------------------------------------------------------------
qstring hikari_wrapper_handler_t::generate_name(const qstring &cls, const qstring &sel) {
    qstring name;

    if (!cls.empty() && !sel.empty()) {
        name = cls;
        name += "_";

        // Clean up selector: remove colons, make CamelCase
        for (size_t i = 0; i < sel.length(); i++) {
            char c = sel[i];
            if (c == ':') {
                // Skip colon, capitalize next char
                if (i + 1 < sel.length()) {
                    name += (char)toupper(sel[i + 1]);
                    i++;
                }
            } else {
                name += c;
            }
        }
    } else if (!cls.empty()) {
        name = cls;
        name += "_method";
    } else if (!sel.empty()) {
        name = "unknown_";
        name += sel;
    }

    return name;
}

//--------------------------------------------------------------------------
// Check for objc_msgSend pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::has_objc_msgsend(ea_t func_ea) {
    func_t *func = get_func(func_ea);
    if (!func)
        return false;

    // Look for calls to objc_msgSend variants
    ea_t curr = func->start_ea;
    while (curr < func->end_ea) {
        insn_t insn;
        if (decode_insn(&insn, curr) == 0)
            break;

        if (is_call_insn(insn)) {
            ea_t target = get_first_fcref_from(insn.ea);
            if (target != BADADDR) {
                qstring name;
                if (get_func_name(&name, target) > 0) {
                    if (name.find("objc_msgSend") != qstring::npos ||
                        name.find("_objc_msgSend") != qstring::npos) {
                        return true;
                    }
                }
            }
        }

        curr = insn.ea + insn.size;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check for dlsym pattern
//--------------------------------------------------------------------------
bool hikari_wrapper_handler_t::has_dlsym_call(ea_t func_ea) {
    func_t *func = get_func(func_ea);
    if (!func)
        return false;

    ea_t curr = func->start_ea;
    while (curr < func->end_ea) {
        insn_t insn;
        if (decode_insn(&insn, curr) == 0)
            break;

        if (is_call_insn(insn)) {
            ea_t target = get_first_fcref_from(insn.ea);
            if (target != BADADDR) {
                qstring name;
                if (get_func_name(&name, target) > 0) {
                    if (name.find("dlsym") != qstring::npos ||
                        name.find("dlopen") != qstring::npos) {
                        return true;
                    }
                }
            }
        }

        curr = insn.ea + insn.size;
    }

    return false;
}
