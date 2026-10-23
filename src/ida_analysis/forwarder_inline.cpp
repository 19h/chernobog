#include "forwarder_inline.hpp"

#include "../deobf/deobf_types.h"
#include "../common/warn_off.h"
#include <intel.hpp>
#include "../common/warn_on.h"

#include <set>
#include <utility>
#include <vector>

namespace chernobog::ida_analysis
{
namespace
{
bool reg(const op_t &operand, int expected)
{
    return operand.type == o_reg && operand.reg == expected && get_dtype_size(operand.dtype) == 8;
}

bool scratch(int value)
{
    // RAX/RDX may carry a return value. Nonvolatile registers must not be
    // restored from a different value merely to remove a call boundary.
    return value == R_cx || value == R_r8 || value == R_r9 || value == R_r10 || value == R_r11 ||
           (inf_get_filetype() != f_PE && (value == R_si || value == R_di));
}

bool stack_adjust(const insn_t &ins, uint16 opcode, uval_t amount)
{
    return ins.itype == opcode && reg(ins.Op1, R_sp) && ins.Op2.type == o_imm &&
           ins.Op2.value == amount;
}

bool near_call(const insn_t &ins) { return ins.itype == NN_call || ins.itype == NN_callni; }

bool forwarder(ea_t target)
{
    const bool windows_abi = inf_get_filetype() == f_PE;
    const func_t *function = get_func(target);
    if (!function || function->start_ea != target || get_func_tail_qty(target) != 0 ||
        function->end_ea <= target || function->end_ea - target > 64)
        return false;
    tinfo_t type;
    if (get_tinfo(&type, target))
    {
        func_type_data_t details;
        if (!type.get_func_details(&details) || is_user_cc(details.get_cc()))
            return false;
    }
    std::vector<insn_t> code;
    for (ea_t ea = target; ea < function->end_ea;)
    {
        insn_t ins;
        if (code.size() >= 8 || !is_code(get_flags(ea)) || !is_head(get_flags(ea)) ||
            decode_insn(&ins, ea) <= 0 || ins.size == 0 || ea + ins.size > function->end_ea)
            return false;
        code.push_back(ins);
        ea += ins.size;
    }
    if (code.size() < 4 || code.back().itype != NN_retn || code.back().Op1.type != o_void)
        return false;

    if (code.size() == 4 && near_call(code[1]))
    {
        // Hikari commonly allocates alignment space with push rax and
        // discards it with pop rcx. A pop into RAX is not a forwarding return.
        if (!windows_abi && code[0].itype == NN_push && reg(code[0].Op1, R_ax) &&
            code[2].itype == NN_pop && code[2].Op1.type == o_reg &&
            get_dtype_size(code[2].Op1.dtype) == 8 && scratch(code[2].Op1.reg))
            return true;
        if (code[0].Op2.type != o_imm)
            return false;
        const uval_t amount = code[0].Op2.value;
        return amount >= (windows_abi ? 40u : 8u) && amount <= 256 && amount % 16 == 8 &&
               stack_adjust(code[0], NN_sub, amount) && stack_adjust(code[2], NN_add, amount);
    }

    // Conventional frame-pointer adapters, optionally reserving local space.
    if (!reg(code[0].Op1, R_bp) || code[0].itype != NN_push || code[1].itype != NN_mov ||
        !reg(code[1].Op1, R_bp) || !reg(code[1].Op2, R_sp))
        return false;
    if (code.size() == 5)
        return !windows_abi && near_call(code[2]) && code[3].itype == NN_pop &&
               reg(code[3].Op1, R_bp);
    if (code.size() == 7)
    {
        if (code[2].Op2.type != o_imm)
            return false;
        const uval_t amount = code[2].Op2.value;
        return amount >= (windows_abi ? 32u : 0u) && amount <= 256 && amount % 16 == 0 &&
               stack_adjust(code[2], NN_sub, amount) && near_call(code[3]) &&
               stack_adjust(code[4], NN_add, amount) && code[5].itype == NN_pop &&
               reg(code[5].Op1, R_bp);
    }
    return false;
}

ea_t call_target(const minsn_t *ins)
{
    if (!ins || ins->opcode != m_call)
        return BADADDR;
    if (ins->l.t == mop_v)
        return ins->l.g;
    if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v)
        return ins->l.a->g;
    return BADADDR;
}
} // namespace

merror_t inline_forwarders(codegen_t *codegen, int decomp_flags)
{
    qstring enabled;
    if (qgetenv("CHERNOBOG_INLINE_FORWARDERS", &enabled) && enabled == "0")
        return MERR_OK;
    if (!codegen || !codegen->mba || PH.id != PLFM_386 || !inf_is_64bit())
        return MERR_OK;
    mba_t *mba = codegen->mba;
    if (mba->maturity > MMAT_GENERATED || mba->qty > 4096)
        return MERR_OK;
    static thread_local bool active = false;
    if (active)
        return MERR_OK;
    struct guard_t
    {
        bool &flag;
        explicit guard_t(bool &value) : flag(value) { flag = true; }
        ~guard_t() { flag = false; }
    } guard(active);

    std::set<std::pair<ea_t, ea_t>> attempted;
    unsigned count = 0;
    for (; count < 128 && mba->qty <= 4096 && !user_cancelled();)
    {
        bool changed = false;
        for (int index = 0; index < mba->qty; ++index)
        {
            const minsn_t *call = mba->get_mblock(index)->tail;
            const ea_t target = call_target(call);
            if (target == BADADDR || target == mba->entry_ea ||
                !attempted.emplace(call->ea, target).second || !forwarder(target))
                continue;
            const ea_t site = call->ea;
#if IDA_SDK_VERSION >= 940
            decomp_ranges_t ranges(target);
            const merror_t result = mba->inline_function(*codegen, index, ranges, decomp_flags, 0);
#else
            mba_ranges_t ranges(get_func(target));
            const merror_t result = mba->inline_func(*codegen, index, ranges, decomp_flags, 0);
#endif
            if (result != MERR_OK)
                return result;
            ++count;
            changed = true;
            deobf::log_verbose("[forwarder_inline] Inlined %a at %a\n", target, site);
            break; // The SDK may have renumbered every following block.
        }
        if (!changed)
            break;
    }
    if (count != 0)
        deobf::log("[forwarder_inline] Inlined %u native call/return adapters\n", count);
    return MERR_OK;
}
} // namespace chernobog::ida_analysis
