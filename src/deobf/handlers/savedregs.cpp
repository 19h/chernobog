#include "savedregs.h"
#include "../analysis/arch_utils.h"
#include "../analysis/stack_tracker.h"

namespace {

bool extract_stack_source(const mop_t& operand, sval_t *offset)
{
    if ( !offset )
        return false;
    if ( operand.t == mop_S && operand.s && operand.s->off < 0 )
    {
        *offset = operand.s->off;
        return true;
    }
    if ( operand.t == mop_a && operand.a
      && operand.a->t == mop_S && operand.a->s
      && operand.a->s->off < 0 )
    {
        *offset = operand.a->s->off;
        return true;
    }
    return false;
}

bool string_at_address(ea_t address, qstring *value)
{
    if ( address == BADADDR || !value )
        return false;

    size_t length = get_max_strlit_length(address, STRTYPE_C);
    if ( length > 0 && length < 1024 )
    {
        value->resize(length);
        if ( get_strlit_contents(value, address, length, STRTYPE_C) > 0 )
            return true;
    }

    const ea_t pointee = arch::read_ptr(address);
    if ( pointee == BADADDR || pointee == 0 )
        return false;
    length = get_max_strlit_length(pointee, STRTYPE_C);
    if ( length == 0 || length >= 1024 )
        return false;
    value->resize(length);
    return get_strlit_contents(value, pointee, length, STRTYPE_C) > 0;
}

bool direct_string_operand(const mop_t& operand, qstring *value)
{
    if ( operand.t == mop_v )
        return string_at_address(operand.g, value);
    if ( operand.t == mop_a && operand.a && operand.a->t == mop_v )
        return string_at_address(operand.a->g, value);
    return false;
}

} // namespace

bool savedregs_handler_t::is_savedregs_ref(const mop_t& operand,
                                           sval_t *offset)
{
    return extract_stack_source(operand, offset);
}

bool savedregs_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba )
        return false;

    int savedregs_references = 0;
    int indirect_calls = 0;
    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *block = mba->get_mblock(i);
        if ( !block )
            continue;
        for ( minsn_t *instruction = block->head;
              instruction;
              instruction = instruction->next )
        {
            sval_t offset = 0;
            if ( is_savedregs_ref(instruction->l, &offset)
              || is_savedregs_ref(instruction->r, &offset)
              || is_savedregs_ref(instruction->d, &offset) )
            {
                ++savedregs_references;
            }

            if ( instruction->opcode != m_call
              && instruction->opcode != m_icall )
                continue;
            const mop_t& target = instruction->opcode == m_icall
                ? instruction->r : instruction->l;
            bool through_savedregs = is_savedregs_ref(target, &offset);
            if ( !through_savedregs && target.t == mop_d && target.d )
            {
                const minsn_t *nested = target.d;
                if ( nested->opcode == m_ldx )
                    through_savedregs = is_savedregs_ref(nested->r, &offset);
                else if ( nested->opcode == m_mov )
                    through_savedregs = is_savedregs_ref(nested->l, &offset);
            }
            if ( through_savedregs )
                ++indirect_calls;
        }
    }
    return savedregs_references >= 5 && indirect_calls > 0;
}

bool savedregs_handler_t::is_objc_msgsend(ea_t address)
{
    qstring name;
    if ( address == BADADDR || get_name(&name, address) <= 0 )
        return false;
    const char *symbol = name.c_str();
    if ( symbol[0] == '_' )
        ++symbol;
    return strncmp(symbol, "objc_msgSend", 12) == 0
        || strncmp(symbol, "objc_msgLookup", 14) == 0;
}

void savedregs_handler_t::extract_call_args(mblock_t *block,
                                            minsn_t *call,
                                            resolved_call_t *out)
{
    if ( !block || !call || !out || call->d.t != mop_f || !call->d.f )
        return;

    const mcallinfo_t *info = call->d.f;
    out->args.resize(info->args.size());
    for ( size_t i = 0; i < info->args.size(); ++i )
    {
        const mcallarg_t& argument = info->args[i];
        qstring value;
        sval_t offset = 0;
        if ( is_savedregs_ref(argument, &offset) )
        {
            auto address = stack_tracker_t::trace_address(
                block, call, offset, arch::get_ptr_size());
            if ( !address || !string_at_address(*address, &value) )
                continue;
        }
        else if ( !direct_string_operand(argument, &value) )
        {
            continue;
        }

        out->args[i] = value;
        if ( out->is_objc && i == 1 )
            out->selector = value;
    }
}

bool savedregs_handler_t::resolve_indirect_call(mblock_t *block,
                                                minsn_t *call,
                                                resolved_call_t *out)
{
    if ( !block || !call || !out
      || (call->opcode != m_icall && call->opcode != m_call) )
    {
        return false;
    }

    const mop_t& target = call->opcode == m_icall ? call->r : call->l;
    sval_t offset = 0;
    bool found = is_savedregs_ref(target, &offset);
    if ( !found && target.t == mop_d && target.d )
    {
        const minsn_t *nested = target.d;
        if ( nested->opcode == m_ldx )
            found = is_savedregs_ref(nested->r, &offset);
        else if ( nested->opcode == m_mov )
            found = is_savedregs_ref(nested->l, &offset);
    }
    if ( !found )
        return false;

    auto address = stack_tracker_t::trace_address(
        block, call, offset, arch::get_ptr_size());
    if ( !address )
        return false;

    func_t *function = get_func(*address);
    const flags64_t flags = get_flags(*address);
    const bool function_start = function && function->start_ea == *address;
    const bool named_external = has_any_name(flags) && !is_code(flags);
    if ( !function_start && !named_external )
        return false;

    out->call_addr = call->ea;
    out->target_func = *address;
    out->is_objc = is_objc_msgsend(*address);
    get_name(&out->target_name, *address);
    extract_call_args(block, call, out);
    return true;
}

void savedregs_handler_t::annotate_call(const resolved_call_t& resolved)
{
    if ( resolved.call_addr == BADADDR )
        return;

    qstring comment;
    if ( resolved.is_objc )
    {
        if ( !resolved.selector.empty() )
            comment.sprnt("DEOBF: ObjC call - [obj %s]", resolved.selector.c_str());
        else
            comment.sprnt("DEOBF: ObjC call - %s", resolved.target_name.c_str());
    }
    else
    {
        comment.sprnt("DEOBF: Indirect call to %s (0x%llX)",
                      resolved.target_name.c_str(),
                      (unsigned long long)resolved.target_func);
    }

    for ( size_t i = 0; i < resolved.args.size(); ++i )
    {
        if ( resolved.args[i].empty()
          || (resolved.is_objc && i == 1
              && resolved.args[i] == resolved.selector) )
            continue;
        comment.cat_sprnt("\n  arg[%zu]: \"%s\"", i,
                          resolved.args[i].c_str());
    }
    set_cmt(resolved.call_addr, comment.c_str(), false);
}

int savedregs_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx )
        return 0;

    int resolved_count = 0;
    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *block = mba->get_mblock(i);
        if ( !block )
            continue;
        for ( minsn_t *instruction = block->head;
              instruction;
              instruction = instruction->next )
        {
            resolved_call_t resolved;
            if ( resolve_indirect_call(block, instruction, &resolved) )
            {
                annotate_call(resolved);
                ++resolved_count;
            }
        }
    }

    ctx->indirect_resolved += resolved_count;
    deobf::log_verbose("[savedregs] Resolved and annotated %d calls\n",
                       resolved_count);
    return 0;
}
