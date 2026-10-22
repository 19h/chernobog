#include "inline_abi.hpp"
#include "../deobf/deobf_types.h"
#include "../common/warn_off.h"
#include <intel.hpp>
#include <frame.hpp>
#include "../common/warn_on.h"

namespace chernobog::ida_analysis
{
namespace
{
bool saved_register(int reg)
{
    return reg == R_bp || reg == R_bx || (reg >= R_r12 && reg <= R_r15) ||
           (inf_get_filetype() == f_PE && (reg == R_si || reg == R_di));
}

// This adapter is for ordinary ABI calls with a conventional, balanced native
// save/restore sequence. Custom register contracts and incomplete ranges do
// not justify inserting an ABI preservation boundary.
std::vector<int> native_saves(const func_t *function, std::set<ea_t> &returns, std::set<ea_t> &pops)
{
    if (!function || (function->flags & FUNC_OUTLINE) == 0 ||
        get_func_tail_qty(function->start_ea) != 0 || function->end_ea <= function->start_ea ||
        function->end_ea - function->start_ea > 16384)
        return {};
    tinfo_t type;
    func_type_data_t details;
    if (!get_tinfo(&type, function->start_ea) || !type.get_func_details(&details) ||
        details.get_cc() == CM_CC_UNKNOWN || is_user_cc(details.get_cc()))
        return {};
    std::vector<insn_t> native;
    for (ea_t ea = function->start_ea; ea < function->end_ea;)
    {
        insn_t ins;
        const int size = decode_insn(&ins, ea);
        if (native.size() >= 1024 || size <= 0 || size > 15 || ea + ea_t(size) > function->end_ea)
            return {};
        native.push_back(ins);
        ea += ea_t(size);
    }
    if (native.size() < 5 || native[0].itype != NN_push || native[0].Op1.type != o_reg ||
        native[0].Op1.reg != R_bp || get_dtype_size(native[0].Op1.dtype) != 8 ||
        native[1].itype != NN_mov || native[1].Op1.type != o_reg || native[1].Op1.reg != R_bp ||
        native[1].Op2.type != o_reg || native[1].Op2.reg != R_sp ||
        get_dtype_size(native[1].Op1.dtype) != 8 || get_dtype_size(native[1].Op2.dtype) != 8)
        return {};
    std::vector<int> saved{R_bp};
    for (size_t i = 2; i < native.size() && native[i].itype == NN_push; ++i)
    {
        const op_t &reg = native[i].Op1;
        if (reg.type != o_reg || !saved_register(reg.reg))
            break;
        if (get_dtype_size(reg.dtype) != 8 ||
            std::find(saved.begin(), saved.end(), reg.reg) != saved.end())
            return {};
        saved.push_back(reg.reg);
    }
    for (size_t i = 0; i < native.size(); ++i)
    {
        const insn_t &ins = native[i];
        const uint32 features = ins.get_canon_feature(PH);
        if ((features & CF_CALL) == 0 &&
            ((features & CF_JUMP) != 0 || ins.itype == NN_jmp || ins.itype == NN_jmpni))
        {
            bool internal = false;
            for (const op_t &op : ins.ops)
                internal |= op.type == o_near && op.addr >= function->start_ea &&
                            op.addr < function->end_ea;
            if (!internal)
                return {};
        }
        for (unsigned operand = 0; operand < UA_MAXOP && ins.ops[operand].type != o_void; ++operand)
        {
            const op_t &op = ins.ops[operand];
            if (!has_cf_chg(features, operand) || (op.type != o_displ && op.type != o_phrase))
                continue;
            const int base = x86_base_reg(ins, op);
            if (base == R_sp)
                return {};
            if (base != R_bp)
                continue;
            const sval_t offset = sval_t(op.addr);
            const int bytes = get_dtype_size(op.dtype);
            const sval_t lowest = -sval_t((saved.size() - 1) * 8);
            if (x86_index_reg(ins, op) != R_none || bytes <= 0 ||
                (offset < 8 && offset >= lowest - bytes + 1))
                return {};
        }
        if (native[i].itype != NN_retn)
            continue;
        if (native[i].Op1.type != o_void || i < saved.size())
            return {};
        for (size_t j = 0; j < saved.size(); ++j)
        {
            const insn_t &pop = native[i - j - 1];
            if (pop.itype != NN_pop || pop.Op1.type != o_reg || pop.Op1.reg != saved[j] ||
                get_dtype_size(pop.Op1.dtype) != 8 ||
                get_spd(const_cast<func_t *>(function), pop.ea) != -sval_t((j + 1) * 8))
                return {};
            pops.insert(pop.ea);
        }
        returns.insert(native[i].ea);
    }
    for (const insn_t &ins : native)
    {
        if (ins.itype == NN_pop && ins.Op1.type == o_reg && saved_register(ins.Op1.reg) &&
            !pops.count(ins.ea))
            return {};
        const uint32 features = ins.get_canon_feature(PH);
        for (unsigned operand = 0; operand < UA_MAXOP && ins.ops[operand].type != o_void; ++operand)
            if (has_cf_chg(features, operand) && ins.ops[operand].type == o_reg &&
                ins.ops[operand].reg == R_bp && ins.ea != native[1].ea && !pops.count(ins.ea))
                return {};
    }
    return returns.empty() ? std::vector<int>{} : saved;
}
} // namespace

int preserve_inlined_abi(codegen_t *codegen, int source, int first, int last)
{
    if (!codegen || !codegen->mba || PH.id != PLFM_386 || !inf_is_64bit())
        return 0;
    mba_t *mba = codegen->mba;
    if (mba->maturity > MMAT_GENERATED || mba->qty > 1024 || source < 0 || source >= mba->qty ||
        first < 0 || last <= first || last > mba->qty || last - first > 128 ||
        (source >= first && source < last))
        return 0;
    mblock_t *caller = mba->get_mblock(source);
    if (!caller->tail || caller->tail->opcode != m_goto || caller->tail->l.t != mop_b ||
        caller->tail->l.b != first)
        return 0;
    const func_t *callee = get_func(mba->get_mblock(first)->start);
    if (!callee || callee->start_ea == mba->entry_ea ||
        callee->start_ea != mba->get_mblock(first)->start)
        return 0;
    std::set<ea_t> returns, pops;
    auto saved = native_saves(callee, returns, pops);
    // Keep native frame-pointer and stack relocation with the SDK. These
    // scalar snapshots cover only the ordinary nonvolatile general registers.
    saved.erase(std::remove(saved.begin(), saved.end(), R_bp), saved.end());
    if (saved.empty())
        return 0;
    std::vector<mblock_t *> exits;
    size_t inspected = 0;
    for (int index = first; index < last; ++index)
    {
        mblock_t *block = mba->get_mblock(index);
        for (const minsn_t *ins = block->head; ins; ins = ins->next)
        {
            if (++inspected > 8192)
                return 0;
            // A generator which already retained native restoration needs no
            // adapter. Do not duplicate an existing stack read or register write.
            if (pops.count(ins->ea) && ins->opcode != m_nop)
                return 0;
        }
        const minsn_t *tail = block->tail;
        if (!tail || tail->opcode != m_goto || tail->l.t != mop_b ||
            (tail->l.b >= first && tail->l.b < last))
            continue;
        if (tail->l.b < 0 || tail->l.b >= mba->qty || !returns.count(tail->ea) ||
            mba->get_mblock(tail->l.b)->start != caller->end)
            return 0;
        exits.push_back(block);
    }
    if (exits.size() != returns.size())
        return 0;
    std::vector<mreg_t> temporaries;
    for (size_t i = 0; i < saved.size(); ++i)
    {
        const mreg_t temporary = mba->alloc_kreg(8);
        if (temporary == mr_none)
            return 0;
        temporaries.push_back(temporary);
    }
    for (size_t i = 0; i < saved.size(); ++i)
    {
        const mreg_t reg = reg2mreg(saved[i]);
        auto *capture = new minsn_t(caller->tail->ea);
        capture->opcode = m_mov;
        capture->l.make_reg(reg, 8);
        capture->d.make_reg(temporaries[i], 8);
        caller->insert_into_block(capture, caller->tail->prev);
        for (mblock_t *exit : exits)
        {
            auto *restore = new minsn_t(exit->tail->ea);
            restore->opcode = m_mov;
            restore->l.make_reg(temporaries[i], 8);
            restore->d.make_reg(reg, 8);
            exit->insert_into_block(restore, exit->tail->prev);
        }
    }
    caller->mark_lists_dirty();
    for (mblock_t *exit : exits)
        exit->mark_lists_dirty();
    mba->mark_chains_dirty();
    deobf::log_verbose("[inline_abi] Retained %zu native callee saves at %a -> %a\n", saved.size(),
                       caller->tail->ea, callee->start_ea);
    return int(saved.size());
}
} // namespace chernobog::ida_analysis
