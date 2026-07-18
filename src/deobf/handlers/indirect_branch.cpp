#include "indirect_branch.h"

#include "../analysis/arch_utils.h"
#include "../analysis/opaque_eval.h"
#include "../../common/arm64_branch.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include "../../common/warn_on.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

#include <unordered_map>

namespace {

constexpr int MAX_TARGET_EVAL_DEPTH = 16;

bool aggressive_writable_pointer_mode_enabled()
{
    static int cached = -1;
    if ( cached == -1 )
    {
        qstring value;
        cached = qgetenv("CHERNOBOG_WRITABLE_CONST", &value)
              && !value.empty() && value[0] == '2' ? 1 : 0;
    }
    return cached == 1;
}

bool direct_branch_patch_mode_enabled()
{
    static int cached = -1;
    if ( cached == -1 )
    {
        qstring value;
        cached = qgetenv("CHERNOBOG_PATCH_BRANCHES", &value)
              && !value.empty() && value[0] == '1' ? 1 : 0;
    }
    return cached == 1;
}

bool patch_arm64_indirect_tail(ea_t branch_ea, ea_t target_ea)
{
    if ( !direct_branch_patch_mode_enabled() || !arch::is_arm64()
      || branch_ea == BADADDR || target_ea == BADADDR )
    {
        return false;
    }

    insn_t instruction;
    if ( decode_insn(&instruction, branch_ea) != 4
      || instruction.itype != ARM_br
      || instruction.Op1.type != o_reg )
    {
        return false;
    }

    const std::optional<uint32_t> encoding =
        chernobog::arm64_branch::encode_b(branch_ea, target_ea);
    if ( !encoding )
        return false;

    // patch_dword preserves the original IDB bytes for Edit/Patch program/
    // Revert. The input file on disk is not modified.
    if ( !patch_dword(branch_ea, *encoding)
      && static_cast<uint32_t>(get_dword(branch_ea)) != *encoding )
    {
        return false;
    }

    // A prior multi-target CFG annotation may have attached several exact
    // successors to the original BR. Once an opaque predicate proves one
    // target, retaining those stale crefs makes Hex-Rays treat the direct B as
    // an inconsistent multi-successor instruction.
    std::vector<ea_t> stale_targets;
    xrefblk_t xref;
    for ( bool ok = xref.first_from(branch_ea, XREF_FAR);
          ok;
          ok = xref.next_from() )
    {
        if ( xref.iscode && xref.to != target_ea )
            stale_targets.push_back(xref.to);
    }
    for ( ea_t stale_target : stale_targets )
        del_cref(branch_ea, stale_target, false);
    add_cref(branch_ea, target_ea, fl_JN);
    deobf::log(
        "[indirect_branch] Patched ARM64 BR at %a to reversible B %a "
        "(0x%08X)\n",
        branch_ea, target_ea, *encoding);
    return true;
}

std::optional<uint64_t> relocated_code_pointer(const mop_t &operand)
{
    if ( operand.t != mop_v || operand.g == BADADDR
      || operand.size != (inf_is_64bit() ? 8 : 4) )
    {
        return std::nullopt;
    }

    const segment_t *slot_segment = getseg(operand.g);
    if ( !slot_segment || (slot_segment->perm & SEGPERM_EXEC) != 0 )
        return std::nullopt;
    if ( (slot_segment->perm & SEGPERM_WRITE) != 0
      && !aggressive_writable_pointer_mode_enabled() )
    {
        return std::nullopt;
    }

    fixup_data_t fixup;
    if ( !get_fixup(&fixup, operand.g) || fixup.is_unused() )
        return std::nullopt;

    const std::optional<uint64_t> pointer =
        chernobog::ida_memory::read_integer(operand.g, operand.size);
    if ( !pointer )
        return std::nullopt;
    const segment_t *target_segment = getseg(static_cast<ea_t>(*pointer));
    if ( !target_segment || (target_segment->perm & SEGPERM_EXEC) == 0 )
        return std::nullopt;
    return *pointer;
}

std::optional<uint64_t> evaluate_target_operand(
    const mop_t &operand, const minsn_t *before, int depth);

std::optional<uint64_t> evaluate_target_instruction(
    const minsn_t *instruction, int depth)
{
    if ( !instruction || depth > MAX_TARGET_EVAL_DEPTH
      || instruction->is_fpinsn() )
    {
        return std::nullopt;
    }

    const int width = instruction->d.size > 0
        ? instruction->d.size
        : (inf_is_64bit() ? 8 : 4);
    switch ( instruction->opcode )
    {
        case m_mov:
        case m_xdu:
        case m_xds:
        case m_low:
            return evaluate_target_operand(
                instruction->l, instruction, depth + 1);

        case m_add:
        case m_sub:
        {
            const std::optional<uint64_t> left = evaluate_target_operand(
                instruction->l, instruction, depth + 1);
            const std::optional<uint64_t> right = evaluate_target_operand(
                instruction->r, instruction, depth + 1);
            if ( !left || !right )
                return std::nullopt;
            const uint64_t value = instruction->opcode == m_add
                ? *left + *right
                : *left - *right;
            return chernobog::bitvector::truncate(value, width);
        }

        default:
            return std::nullopt;
    }
}

std::optional<uint64_t> evaluate_target_operand(
    const mop_t &operand, const minsn_t *before, int depth)
{
    if ( depth > MAX_TARGET_EVAL_DEPTH )
        return std::nullopt;

    if ( operand.t == mop_n && operand.nnn )
        return chernobog::bitvector::truncate(
            operand.nnn->value, operand.size);
    if ( operand.t == mop_a && operand.a && operand.a->t == mop_v )
        return operand.a->g;
    if ( operand.t == mop_v )
    {
        // In a pointer-valued branch expression Hex-Rays uses a code-segment
        // mop_v as the loaded address, not as a request to read code bytes.
        const segment_t *segment = getseg(operand.g);
        if ( segment && (segment->perm & SEGPERM_EXEC) != 0 )
            return operand.g;
        return relocated_code_pointer(operand);
    }
    if ( operand.t == mop_d && operand.d )
        return evaluate_target_instruction(operand.d, depth + 1);
    if ( operand.t != mop_r || !before )
        return std::nullopt;

    // At late global optimization, the exact branch target is commonly held
    // in a register defined by pointer arithmetic in the same block. Do not
    // cross a block boundary or accept a width-changing redefinition.
    for ( const minsn_t *definition = before->prev;
          definition;
          definition = definition->prev )
    {
        if ( definition->d.t != mop_r || definition->d.r != operand.r )
            continue;
        if ( definition->d.size != operand.size )
            return std::nullopt;
        return evaluate_target_instruction(definition, depth + 1);
    }
    return std::nullopt;
}

//--------------------------------------------------------------------------
// Replace every old CFG successor and install the single direct successor.
//--------------------------------------------------------------------------
void replace_cfg_successors(mbl_array_t *mba, mblock_t *src, int target_idx)
{
    for ( int old_idx : src->succset ) {
        if ( old_idx < 0 || old_idx >= mba->qty || old_idx == target_idx )
            continue;

        mblock_t *old_dst = mba->get_mblock(old_idx);
        if ( !old_dst )
            continue;

        auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(),
                              src->serial);
        if ( pred != old_dst->predset.end() )
            old_dst->predset.erase(pred);
        old_dst->mark_lists_dirty();
    }

    src->succset.clear();
    src->succset.push_back(target_idx);

    mblock_t *dst = mba->get_mblock(target_idx);
    auto pred = std::find(dst->predset.begin(), dst->predset.end(), src->serial);
    if ( pred == dst->predset.end() )
        dst->predset.push_back(src->serial);

    src->mark_lists_dirty();
    dst->mark_lists_dirty();
}

//--------------------------------------------------------------------------
// Resolve the actual m_ijmp offset operand.  A target merely contained in a
// block is insufficient: m_goto transfers to the block start, so accepting an
// interior address would change program semantics.
//--------------------------------------------------------------------------
int resolve_ijmp(
    mbl_array_t *mba,
    mblock_t *src,
    deobf_ctx_t *ctx,
    const std::unordered_map<ea_t, int> &block_starts)
{
    minsn_t *ijmp = src->tail;
    if ( !ijmp || ijmp->opcode != m_ijmp || ijmp->d.empty() )
        return 0;

    // In a selector/offset instruction, a global operand is address-used: its
    // EA is the offset. In nested value expressions, mop_v instead denotes the
    // global's contents and is handled by the immutable evaluator.
    std::optional<uint64_t> value = evaluate_target_operand(ijmp->d, ijmp, 0);
    if ( !value )
    {
        value = ijmp->d.t == mop_v
            ? std::optional<uint64_t>(ijmp->d.g)
            : opaque_eval_t::evaluate_operand(ijmp->d);
    }
    if ( !value )
        return 0;

    const ea_t target_ea = static_cast<ea_t>(*value);
    const auto target = block_starts.find(target_ea);
    const int target_idx = target == block_starts.end() ? -1 : target->second;

    if ( target_idx < 0 ) {
        // An exact target outside the current MBA cannot become m_goto, but
        // canonicalizing the ijmp operand is still semantics-preserving and
        // exposes a tail target to ctree. Require an executable function entry
        // so an interior address cannot be mislabeled as an external call.
        const segment_t *segment = getseg(target_ea);
        const func_t *target_function = get_func(target_ea);
        if ( segment && (segment->perm & SEGPERM_EXEC) != 0
          && target_function && target_function->start_ea == target_ea )
        {
            const bool already_canonical =
                ijmp->d.t == mop_v && ijmp->d.g == target_ea;
            add_cref(ijmp->ea, target_ea, fl_JN);

            qstring target_name;
            if ( get_func_name(&target_name, target_ea) <= 0 )
                target_name.sprnt("sub_%a", target_ea);
            qstring comment;
            comment.sprnt("DEOBF: exact indirect tail target -> %s (%a)",
                          target_name.c_str(), target_ea);
            set_cmt(ijmp->ea, comment.c_str(), false);
            patch_arm64_indirect_tail(ijmp->ea, target_ea);

            if ( !already_canonical )
            {
                ijmp->d.make_gvar(target_ea);
                ijmp->d.size = inf_is_64bit() ? 8 : 4;
                src->mark_lists_dirty();
                mba->mark_chains_dirty();
                ++ctx->branches_simplified;
                deobf::log(
                    "[indirect_branch] Canonicalized external ijmp in block %d "
                    "to function %a\n",
                    src->serial, target_ea);
                return 1;
            }
            return 0;
        }

        deobf::log_verbose(
            "[indirect_branch] Exact target %a is not a unique microblock start\n",
            target_ea);
        return 0;
    }

    deobf::log("[indirect_branch] Converting block %d ijmp to goto block %d "
               "(target %a)\n",
               src->serial, target_idx, target_ea);

    ijmp->opcode = m_goto;
    ijmp->l.make_blkref(target_idx);
    ijmp->r.erase();
    ijmp->d.erase();

    replace_cfg_successors(mba, src, target_idx);
    src->type = BLT_1WAY;
    ++ctx->branches_simplified;
    return 1;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba )
        return false;

    for ( int i = 0; i < mba->qty; ++i ) {
        const mblock_t *blk = mba->get_mblock(i);
        if ( blk && blk->tail && blk->tail->opcode == m_ijmp )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Main pass
//--------------------------------------------------------------------------
int indirect_branch_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx )
        return 0;

    // Index exact microblock starts once. Resolution is therefore expected
    // O(B + J) for B blocks and J indirect jumps, with O(B) auxiliary space.
    std::unordered_map<ea_t, int> block_starts;
    block_starts.reserve(static_cast<size_t>(mba->qty));
    for ( int i = 0; i < mba->qty; ++i ) {
        const mblock_t *blk = mba->get_mblock(i);
        if ( blk ) {
            auto [entry, inserted] = block_starts.emplace(blk->start, i);
            if ( !inserted )
                entry->second = -1;
        }
    }

    int changes = 0;
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( blk && blk->tail && blk->tail->opcode == m_ijmp )
            changes += resolve_ijmp(mba, blk, ctx, block_starts);
    }

    deobf::log("[indirect_branch] Resolved %d exact indirect branches\n",
               changes);
    return changes;
}
