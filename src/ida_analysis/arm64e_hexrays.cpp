#include "arm64e_hexrays.hpp"

#include "../common/arm64e.h"
#include <bytes.hpp>
#include <idp.hpp>
#include <typeinf.hpp>

namespace chernobog::ida_analysis
{
namespace
{
thread_local bool generating_native = false;

mop_t read_register(unsigned number, bool stack)
{
    mop_t result;
    if (number == 31 && !stack)
        result.make_number(0, 8);
    else
    {
        qstring name;
        if (number == 31)
            name = "SP";
        else
            name.sprnt("X%u", number);
        result.make_reg(reg2mreg(str2reg(name.c_str())), 8);
    }
    return result;
}

bool emit_helper(codegen_t &codegen, const char *name, const mop_t &value, const mop_t *modifier,
                 mop_t &result, bool memory = false)
{
    tinfo_t type(BTF_UINT64);
    mcallargs_t arguments;
    mcallarg_t argument;
    argument = value;
    argument.type = type;
    arguments.push_back(argument);
    if (modifier)
    {
        argument = *modifier;
        argument.type = type;
        arguments.push_back(argument);
    }
    const mreg_t temporary = codegen.mba->alloc_kreg(8);
    if (temporary == mr_none)
        return false;
    result.make_reg(temporary, 8);
    std::unique_ptr<minsn_t> expression(
        codegen.mba->create_helper_call(codegen.insn.ea, name, &type, &arguments, &result));
    minsn_t *call = expression ? expression->find_call(true) : nullptr;
    if (!call || call->d.t != mop_f || !call->d.f)
        return false;
    // Do not turn authentication or a keyed value into an arithmetic no-op.
    // These are architectural intrinsics, with no ABI register clobbers.
    call->d.f->flags &= ~(FCI_PURE | FCI_NOSIDE);
    call->d.f->flags |= FCI_FINAL | FCI_SPLOK;
    call->d.f->spoiled.clear();
    call->d.f->visible_memory.clear();
    if (memory)
        call->d.f->visible_memory.set_all_values();
    call->set_mbarrier();
    codegen.mb->insert_into_block(expression.release(), codegen.mb->tail);
    return true;
}
} // namespace

bool matches_arm64e_primitive(const codegen_t &codegen)
{
    if (generating_native || PH.id != PLFM_ARM || !inf_is_64bit() || codegen.insn.size != 4)
        return false;
    const auto primitive = arm64e::decode(get_dword(codegen.insn.ea));
    if (!primitive)
        return false;
    // The conventional LR hints are already consumed by the native frame and
    // return generator. Data operations and X17 veneers need explicit values.
    if (primitive->implicit && primitive->destination == 30)
        return false;
    return primitive->kind == arm64e::Kind::sign || primitive->kind == arm64e::Kind::authenticate ||
           primitive->kind == arm64e::Kind::strip || primitive->kind == arm64e::Kind::generic ||
           primitive->kind == arm64e::Kind::load || primitive->kind == arm64e::Kind::branch ||
           primitive->kind == arm64e::Kind::call;
}

merror_t emit_arm64e_primitive(codegen_t &codegen)
{
    const auto primitive = arm64e::decode(get_dword(codegen.insn.ea));
    if (!primitive || !codegen.mba || !codegen.mb)
        return MERR_INSN;
    struct Emission
    {
        mblock_t *block;
        minsn_t *before;
        bool committed = false;
        ~Emission()
        {
            if (!committed)
                while ((before ? before->next : block->head) != nullptr)
                {
                    minsn_t *ins = before ? before->next : block->head;
                    block->remove_from_block(ins);
                    delete ins;
                }
        }
    } emission{codegen.mb, codegen.mb->tail};
    mop_t value = read_register(primitive->source, primitive->kind == arm64e::Kind::load);
    mop_t modifier;
    if (primitive->zero_modifier)
        modifier.make_number(0, 8);
    else
        modifier = read_register(primitive->modifier, true);
    mop_t result;
    if (primitive->kind == arm64e::Kind::branch || primitive->kind == arm64e::Kind::call)
    {
        if (!emit_helper(codegen, arm64e::helper(arm64e::Kind::branch, primitive->key), value,
                         &modifier, result))
            return MERR_INSN;
        minsn_t *before_native = codegen.mb->tail;
        struct NativeGeneration
        {
            NativeGeneration() { generating_native = true; }
            ~NativeGeneration() { generating_native = false; }
        } native_generation;
        const merror_t status = codegen.gen_micro();
        if (status != MERR_OK && status != MERR_BLOCK)
            return MERR_INSN;
        bool replaced = false;
        // Keep the native generator's selector, link-register effects and call
        // setup. Redirect only its IR operand; no architectural GPR changes.
        for (minsn_t *ins = before_native->next; ins; ins = ins->next)
        {
            if (ins->opcode == m_ijmp)
            {
                ins->d = result;
                replaced = true;
            }
            else if (minsn_t *call = ins->find_call(true); call && call->opcode == m_icall)
            {
                call->r = result;
                replaced = true;
            }
        }
        if (!replaced)
            return MERR_INSN;
        emission.committed = true;
        return status;
    }
    if (primitive->kind == arm64e::Kind::load)
    {
        mop_t authenticated;
        if (!emit_helper(codegen, arm64e::helper(arm64e::Kind::authenticate, primitive->key), value,
                         &modifier, authenticated))
            return MERR_INSN;
        const mreg_t temporary = codegen.mba->alloc_kreg(8);
        if (temporary == mr_none)
            return MERR_INSN;
        mop_t address;
        address.make_reg(temporary, 8);
        mop_t offset;
        offset.make_number(uint64_t(primitive->offset), 8);
        codegen.emit(m_add, &authenticated, &offset, &address);
        if (!emit_helper(codegen, "__arm64e_load64", address, nullptr, result, true))
            return MERR_INSN;
        // Writeback happens after a successful read. Overlap was rejected by
        // the decoder; SP uses its native full-width register identity.
        if (primitive->writeback)
        {
            mop_t base = read_register(primitive->source, true);
            codegen.emit(m_mov, &address, nullptr, &base);
        }
    }
    else if (!emit_helper(codegen, arm64e::helper(primitive->kind, primitive->key), value,
                          primitive->kind == arm64e::Kind::strip ? nullptr : &modifier, result))
        return MERR_INSN;
    if (primitive->destination != 31)
    {
        mop_t destination = read_register(primitive->destination, false);
        codegen.emit(m_mov, &result, nullptr, &destination);
    }
    emission.committed = true;
    return MERR_OK;
}
} // namespace chernobog::ida_analysis
