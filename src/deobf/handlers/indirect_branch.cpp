#include "indirect_branch.h"

#include "../analysis/arch_utils.h"
#include "../analysis/opaque_eval.h"
#include "../analysis/finite_targets.h"
#include "../../common/arm64_branch.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"
#include "../../hybrid/z3_bridge.hpp"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include "../../common/warn_on.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

#include <unordered_map>
#include <gdl.hpp>
#include <frame.hpp>

namespace
{

constexpr int MAX_TARGET_EVAL_DEPTH = 16;

struct projection_t
{
    ea_t site = BADADDR;
    std::vector<ea_t> targets;
    std::vector<range_t> fragments;
    std::vector<chernobog::finite_targets_t::dependency_t> dependencies;
    std::vector<ea_t> owned_edges;
    qstring previous_comment;
    qstring published_comment;
    sval_t inherited_spd = 0;
    sval_t frame_offset = 0;
    ea_t root = BADADDR;
    ea_t root_end = BADADDR;
    sval_t frame_size = 0;
    sval_t frame_delta = 0;
    ea_t source_owner = BADADDR;
    sval_t source_spd = 0;
};

using projection_key_t = std::pair<ssize_t, ea_t>;
std::map<projection_key_t, std::map<ea_t, projection_t>> projections;
std::set<projection_key_t> projection_restarts;

void revoke_projection(const projection_t &proof)
{
    for (ea_t target : proof.owned_edges)
        del_cref(proof.site, target, false);
    qstring current;
    get_cmt(&current, proof.site, false);
    if (current == proof.published_comment)
        set_cmt(proof.site, proof.previous_comment.c_str(), false);
}

bool fresh_projection(const projection_t &proof)
{
    const func_t *root = get_func(proof.root);
    if (!root || root->start_ea != proof.root || root->end_ea != proof.root_end ||
        root->frsize != proof.frame_size || root->fpd != proof.frame_delta)
        return false;
    func_t *source = get_func(proof.source_owner);
    if (!source || source->start_ea != proof.source_owner ||
        get_spd(source, proof.site) != proof.source_spd)
        return false;
    for (const auto &fragment : proof.fragments)
    {
        const func_t *owner = get_func(fragment.start_ea);
        if (!owner || owner->start_ea != fragment.start_ea || owner->end_ea != fragment.end_ea ||
            has_user_name(get_flags(fragment.start_ea)) || is_userti(fragment.start_ea))
            return false;
    }
    for (const auto &dependency : proof.dependencies)
    {
        const segment_t *segment = getseg(dependency.address);
        std::vector<uint8_t> bytes(dependency.bytes.size());
        if (!segment || segment->perm != dependency.permissions ||
            dependency.address + bytes.size() > segment->end_ea ||
            !chernobog::ida_memory::read_exact(bytes.data(), bytes.size(), dependency.address) ||
            bytes != dependency.bytes)
            return false;
    }
    return true;
}

bool capture_code(projection_t &proof, ea_t start, ea_t end)
{
    const segment_t *segment = getseg(start);
    if (!segment || end <= start || end - start > 16384 || end > segment->end_ea)
        return false;
    chernobog::finite_targets_t::dependency_t dependency{start, segment->perm,
                                                         std::vector<uint8_t>(size_t(end - start))};
    if (!chernobog::ida_memory::read_exact(dependency.bytes.data(), dependency.bytes.size(), start))
        return false;
    proof.dependencies.push_back(std::move(dependency));
    return true;
}

// A jump does not establish an independent call frame. Admit only small,
// automatically named fragments that consume the incoming frame before
// redefining it, and that have no call-site or user-prototype evidence.
std::optional<range_t> frame_fragment(ea_t root, ea_t target)
{
    const func_t *function = get_func(target);
    if (!function || function->start_ea != target || target == root || function->end_ea <= target ||
        function->end_ea - target > 4096 || (function->flags & (FUNC_LIB | FUNC_THUNK)) != 0 ||
        has_user_name(get_flags(target)) || is_userti(target) || get_func_tail_qty(target) != 0)
        return std::nullopt;
    xrefblk_t xref;
    for (bool ok = xref.first_to(target, XREF_FAR); ok; ok = xref.next_to())
    {
        if (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF))
            return std::nullopt;
    }
    const int fp = str2reg("X29");
    const int sp = str2reg("SP");
    ea_t ea = target;
    for (unsigned count = 0; count < 16 && ea < function->end_ea; ++count)
    {
        insn_t instruction;
        if (decode_insn(&instruction, ea) != 4 || is_call_insn(instruction))
            return std::nullopt;
        const uint32_t features = instruction.get_canon_feature(PH);
        for (unsigned index = 0; index < UA_MAXOP; ++index)
        {
            const op_t &op = instruction.ops[index];
            if (op.type == o_void)
                break;
            if ((op.type == o_phrase || op.type == o_displ) && (op.reg == fp || op.reg == sp))
                return range_t(target, function->end_ea);
            if (op.type == o_reg && (op.reg == fp || op.reg == sp) && has_cf_chg(features, index))
                return std::nullopt;
        }
        if (is_ret_insn(instruction) || is_indirect_jump_insn(instruction))
            return std::nullopt;
        ea += 4;
    }
    return std::nullopt;
}

bool record_projection(mbl_array_t *mba, ea_t site, const chernobog::finite_targets_t &finite,
                       const qstring &comment)
{
    if (!arch::is_arm64() || finite.targets.size() > 2)
        return false;
    projection_t proof;
    proof.site = site;
    proof.targets = finite.targets;
    proof.dependencies = finite.dependencies;
    proof.frame_offset = mba->frsize - mba->fpd;
    const func_t *root = get_func(mba->entry_ea);
    if (!root || !capture_code(proof, root->start_ea, root->end_ea))
        return false;
    proof.root = root->start_ea;
    proof.root_end = root->end_ea;
    proof.frame_size = root->frsize;
    proof.frame_delta = root->fpd;
    proof.frame_offset = root->frsize - root->fpd;
    func_t *source_owner = get_func(site);
    if (!source_owner)
        return false;
    proof.source_owner = source_owner->start_ea;
    proof.source_spd = get_spd(source_owner, site);
    if (source_owner != root && !capture_code(proof, source_owner->start_ea, source_owner->end_ea))
        return false;
    proof.inherited_spd = get_spd(source_owner, site);
    if (source_owner->start_ea != root->start_ea)
    {
        bool linked = false;
        const auto incoming = projections.find({get_dbctx_id(), mba->entry_ea});
        if (incoming != projections.end())
        {
            for (const auto &[incoming_site, parent] : incoming->second)
            {
                for (const auto &fragment : parent.fragments)
                {
                    if (fragment.contains(site))
                    {
                        proof.inherited_spd +=
                            parent.inherited_spd - get_spd(source_owner, fragment.start_ea);
                        linked = true;
                        break;
                    }
                }
                if (linked)
                    break;
            }
        }
        if (!linked)
            return false;
    }
    for (ea_t target : finite.targets)
    {
        const auto fragment = frame_fragment(mba->entry_ea, target);
        if (fragment && (root->flags & FUNC_FRAME) != 0 &&
            (finite.targets.size() == 1 || !finite.condition.empty()))
        {
            if (!capture_code(proof, fragment->start_ea, fragment->end_ea))
                return false;
            proof.fragments.push_back(*fragment);
        }
    }
    const projection_key_t key{get_dbctx_id(), mba->entry_ea};
    if (projections.size() >= 128 && projections.count(key) == 0)
        return false;
    auto &sites = projections[key];
    const auto old = sites.find(site);
    if (old != sites.end() && old->second.targets == proof.targets && fresh_projection(old->second))
        return false;
    if (sites.size() >= 32)
        return false;
    if (old != sites.end())
        revoke_projection(old->second);
    get_cmt(&proof.previous_comment, site, false);
    proof.published_comment = comment;
    for (ea_t target : finite.targets)
    {
        bool present = false;
        xrefblk_t xref;
        for (bool ok = xref.first_from(site, XREF_FAR); ok; ok = xref.next_from())
            present |= xref.iscode && xref.to == target;
        if (!present && add_cref(site, target, fl_JN))
            proof.owned_edges.push_back(target);
    }
    deobf::set_cmt_if_changed(site, comment.c_str(), false);
    const bool restart = !proof.fragments.empty();
    deobf::log_verbose(
        "[indirect_branch] Proved %zu targets at %a; projecting %zu frame fragments\n",
        proof.targets.size(), site, proof.fragments.size());
    sites[site] = std::move(proof);
    if (restart)
        projection_restarts.insert(key);
    return restart;
}

void rebuild_flowchart(qflow_chart_t *flowchart, const rangevec_t &ranges)
{
    const qstring title = flowchart->title;
    flowchart->create(title.c_str(), ranges, flowchart->flags);
}

#if IDA_SDK_VERSION >= 940
void rebuild_flowchart(qflow_chart_ea_t *flowchart, const rangevec_t &ranges)
{
    const qstring title = flowchart->title;
    flowchart->create(title.c_str(), ranges, flowchart->flags);
}
#endif

template <class Flowchart>
int extend_projection(Flowchart *flowchart, bitset_t *reachable, ea_t root, mba_t *mba)
{
    if (!flowchart)
        return 0;
    const auto found = projections.find({get_dbctx_id(), root});
    if (found == projections.end())
        return 0;
    int changes = 0;
    rangevec_t ranges;
    for (int index = 0; index < flowchart->nproper; ++index)
    {
        const auto &block = flowchart->blocks[index];
        if (block.end_ea > block.start_ea)
            ranges.push_back(range_t(block.start_ea, block.end_ea));
    }
    for (auto it = found->second.begin(); it != found->second.end();)
    {
        if (!fresh_projection(it->second))
        {
            revoke_projection(it->second);
            projection_restarts.insert({get_dbctx_id(), root});
            it = found->second.erase(it);
            continue;
        }
        for (const auto &fragment : it->second.fragments)
        {
            if (mba)
            {
                auto &extra_ranges = const_cast<decomp_ranges_t &>(mba->get_decomp_ranges()).ranges;
                if (std::none_of(extra_ranges.begin(), extra_ranges.end(), [&](const range_t &range)
                                 { return range.contains(fragment.start_ea); }))
                    extra_ranges.push_back(fragment);
            }
            bool present = false;
            for (const auto &range : ranges)
                present |= range.contains(fragment.start_ea);
            if (!present && ranges.size() < 512)
            {
                ranges.push_back(fragment);
                ++changes;
            }
        }
        ++it;
    }
    if (changes > 0)
    {
        rebuild_flowchart(flowchart, ranges);
        if (mba)
        {
            auto &decompilation = const_cast<decomp_ranges_t &>(mba->get_decomp_ranges());
            decompilation.func_ea = BADADDR;
            decompilation.ranges = ranges;
        }
    }
    // Appending can move block indices. Install edges only after all ranges
    // are present, and preserve any other native successors.
    for (const auto &[site, proof] : found->second)
    {
        int source = -1;
        for (int index = 0; index < flowchart->nproper; ++index)
            if (flowchart->blocks[index].contains(site))
                source = index;
        if (source < 0)
            continue;
        for (ea_t target : proof.targets)
        {
            for (int index = 0; index < flowchart->nproper; ++index)
            {
                if (flowchart->blocks[index].start_ea != target)
                    continue;
                auto &successors = flowchart->blocks[source].succ;
                auto &predecessors = flowchart->blocks[index].pred;
                if (std::find(successors.begin(), successors.end(), index) == successors.end())
                {
                    successors.push_back(index);
                    ++changes;
                }
                if (std::find(predecessors.begin(), predecessors.end(), source) ==
                    predecessors.end())
                    predecessors.push_back(source);
            }
        }
    }
    if (reachable)
    {
        bool again = true;
        while (again)
        {
            again = false;
            for (size_t index = 0; index < flowchart->blocks.size(); ++index)
            {
                if (!reachable->has(int(index)))
                    continue;
                for (int successor : flowchart->blocks[index].succ)
                {
                    if (!reachable->has(successor))
                    {
                        reachable->add(successor);
                        again = true;
                    }
                }
            }
        }
    }
    if (changes > 0)
    {
        for (size_t index = 0; index < flowchart->blocks.size(); ++index)
        {
            const auto &block = flowchart->blocks[index];
            deobf::log_verbose("[indirect_branch] Projected block %zu: %a..%a type=%d succ=%zu\n",
                               index, block.start_ea, block.end_ea,
                               int(flowchart->calc_block_type(index)), block.succ.size());
        }
    }
    return changes;
}

bool aggressive_writable_pointer_mode_enabled()
{
    static int cached = -1;
    if (cached == -1)
    {
        qstring value;
        cached = qgetenv("CHERNOBOG_WRITABLE_CONST", &value) && !value.empty() && value[0] == '2'
                     ? 1
                     : 0;
    }
    return cached == 1;
}

bool direct_branch_patch_mode_enabled()
{
    static int cached = -1;
    if (cached == -1)
    {
        qstring value;
        cached = qgetenv("CHERNOBOG_PATCH_BRANCHES", &value) && !value.empty() && value[0] == '1'
                     ? 1
                     : 0;
    }
    return cached == 1;
}

bool patch_arm64_indirect_tail(ea_t branch_ea, ea_t target_ea)
{
    if (!direct_branch_patch_mode_enabled() || !arch::is_arm64() || branch_ea == BADADDR ||
        target_ea == BADADDR)
    {
        return false;
    }

    insn_t instruction;
    if (decode_insn(&instruction, branch_ea) != 4 || instruction.itype != ARM_br ||
        instruction.Op1.type != o_reg)
    {
        return false;
    }
    const auto native_branch = chernobog::arm64_branch::decode_indirect(get_dword(branch_ea));
    if (!native_branch || native_branch->authenticated)
        return false; // A direct B would remove the authentication operation.

    const std::optional<uint32_t> encoding =
        chernobog::arm64_branch::encode_b(branch_ea, target_ea);
    if (!encoding)
        return false;

    // patch_dword preserves the original IDB bytes for Edit/Patch program/
    // Revert. The input file on disk is not modified.
    patch_dword(branch_ea, *encoding);
    if (static_cast<uint32_t>(get_dword(branch_ea)) != *encoding)
        return false;

    // A display projection can retain this exact Chernobog-owned patch, but
    // no other function-byte change in the decompiler window. Authorization
    // records the bytes after patch_dword has verified the final encoding.
    const func_t *owner = get_func(branch_ea);
    if (owner != nullptr)
    {
        (void)chernobog::hybrid::hybrid_authorize_deobfuscation_patch(
            uint64_t(owner->start_ea), uint64_t(branch_ea), sizeof(uint32_t));
    }

    // A prior multi-target CFG annotation may have attached several exact
    // successors to the original BR. Once an opaque predicate proves one
    // target, retaining those stale crefs makes Hex-Rays treat the direct B as
    // an inconsistent multi-successor instruction.
    std::vector<ea_t> stale_targets;
    xrefblk_t xref;
    for (bool ok = xref.first_from(branch_ea, XREF_FAR); ok; ok = xref.next_from())
    {
        if (xref.iscode && xref.to != target_ea)
            stale_targets.push_back(xref.to);
    }
    for (ea_t stale_target : stale_targets)
        del_cref(branch_ea, stale_target, false);
    add_cref(branch_ea, target_ea, fl_JN);
    deobf::log("[indirect_branch] Patched ARM64 BR at %a to reversible B %a "
               "(0x%08X)\n",
               branch_ea, target_ea, *encoding);
    return true;
}

std::optional<uint64_t> relocated_code_pointer(const mop_t &operand)
{
    if (operand.t != mop_v || operand.g == BADADDR || operand.size != (inf_is_64bit() ? 8 : 4))
    {
        return std::nullopt;
    }

    const segment_t *slot_segment = getseg(operand.g);
    if (!slot_segment || (slot_segment->perm & SEGPERM_EXEC) != 0)
        return std::nullopt;
    if ((slot_segment->perm & SEGPERM_WRITE) != 0 && !aggressive_writable_pointer_mode_enabled())
    {
        return std::nullopt;
    }

    fixup_data_t fixup;
    if (!get_fixup(&fixup, operand.g) || fixup.is_unused())
        return std::nullopt;

    const std::optional<uint64_t> pointer =
        chernobog::ida_memory::read_integer(operand.g, operand.size);
    if (!pointer)
        return std::nullopt;
    const segment_t *target_segment = getseg(static_cast<ea_t>(*pointer));
    if (!target_segment || (target_segment->perm & SEGPERM_EXEC) == 0)
        return std::nullopt;
    return *pointer;
}

std::optional<uint64_t> evaluate_target_operand(const mop_t &operand, const minsn_t *before,
                                                int depth);

std::optional<uint64_t> evaluate_target_instruction(const minsn_t *instruction, int depth)
{
    if (!instruction || depth > MAX_TARGET_EVAL_DEPTH || instruction->is_fpinsn())
    {
        return std::nullopt;
    }

    const int width = instruction->d.size > 0 ? instruction->d.size : (inf_is_64bit() ? 8 : 4);
    switch (instruction->opcode)
    {
    case m_mov:
    case m_xdu:
    case m_xds:
    case m_low:
        return evaluate_target_operand(instruction->l, instruction, depth + 1);

    case m_add:
    case m_sub:
    {
        const std::optional<uint64_t> left =
            evaluate_target_operand(instruction->l, instruction, depth + 1);
        const std::optional<uint64_t> right =
            evaluate_target_operand(instruction->r, instruction, depth + 1);
        if (!left || !right)
            return std::nullopt;
        const uint64_t value = instruction->opcode == m_add ? *left + *right : *left - *right;
        return chernobog::bitvector::truncate(value, width);
    }

    default:
        return std::nullopt;
    }
}

std::optional<uint64_t> evaluate_target_operand(const mop_t &operand, const minsn_t *before,
                                                int depth)
{
    if (depth > MAX_TARGET_EVAL_DEPTH)
        return std::nullopt;

    if (operand.t == mop_n && operand.nnn)
        return chernobog::bitvector::truncate(operand.nnn->value, operand.size);
    if (operand.t == mop_a && operand.a && operand.a->t == mop_v)
        return operand.a->g;
    if (operand.t == mop_v)
    {
        // In a pointer-valued branch expression Hex-Rays uses a code-segment
        // mop_v as the loaded address, not as a request to read code bytes.
        const segment_t *segment = getseg(operand.g);
        if (segment && (segment->perm & SEGPERM_EXEC) != 0)
            return operand.g;
        return relocated_code_pointer(operand);
    }
    if (operand.t == mop_d && operand.d)
        return evaluate_target_instruction(operand.d, depth + 1);
    if (operand.t != mop_r || !before)
        return std::nullopt;

    // At late global optimization, the exact branch target is commonly held
    // in a register defined by pointer arithmetic in the same block. Do not
    // cross a block boundary or accept a width-changing redefinition.
    for (const minsn_t *definition = before->prev; definition; definition = definition->prev)
    {
        if (definition->d.t != mop_r || definition->d.r != operand.r)
            continue;
        if (definition->d.size != operand.size)
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
    for (int old_idx : src->succset)
    {
        if (old_idx < 0 || old_idx >= mba->qty || old_idx == target_idx)
            continue;

        mblock_t *old_dst = mba->get_mblock(old_idx);
        if (!old_dst)
            continue;

        auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(), src->serial);
        if (pred != old_dst->predset.end())
            old_dst->predset.erase(pred);
        old_dst->mark_lists_dirty();
    }

    src->succset.clear();
    src->succset.push_back(target_idx);

    mblock_t *dst = mba->get_mblock(target_idx);
    auto pred = std::find(dst->predset.begin(), dst->predset.end(), src->serial);
    if (pred == dst->predset.end())
        dst->predset.push_back(src->serial);
    std::sort(dst->predset.begin(), dst->predset.end());

    src->mark_lists_dirty();
    dst->mark_lists_dirty();
}

int lower_conditional_targets(mbl_array_t *mba, mblock_t *src,
                              const chernobog::finite_targets_t &finite)
{
    if (finite.condition.empty() || finite.targets.size() != 2)
        return 0;
    mblock_t *destinations[2] = {nullptr, nullptr};
    for (int index = 0; index < mba->qty; ++index)
    {
        mblock_t *candidate = mba->get_mblock(index);
        for (unsigned outcome = 0; outcome < 2; ++outcome)
        {
            if (candidate->start == finite.targets_by_condition[outcome])
            {
                if (destinations[outcome])
                    return 0;
                destinations[outcome] = candidate;
            }
        }
    }
    if (!destinations[0] || !destinations[1])
        return 0;

    if (destinations[0]->serial == src->serial + 1)
    {
        minsn_t *branch = src->tail;
        branch->opcode = m_jcnd;
        branch->l = finite.condition;
        branch->r.erase();
        branch->d.make_blkref(destinations[1]->serial);
        replace_cfg_successors(mba, src, destinations[1]->serial);
        src->succset.push_back(destinations[0]->serial);
        std::sort(src->succset.begin(), src->succset.end());
        auto &predecessors = destinations[0]->predset;
        if (std::find(predecessors.begin(), predecessors.end(), src->serial) == predecessors.end())
            predecessors.push_back(src->serial);
        std::sort(predecessors.begin(), predecessors.end());
        src->type = BLT_2WAY;
        src->flags &= ~(MBL_NORET | MBL_TCAL);
        src->mark_lists_dirty();
        destinations[0]->mark_lists_dirty();
        mba->mark_chains_dirty();
        return 1;
    }

    if (destinations[1]->serial == src->serial + 1)
    {
        chernobog::finite_targets_t inverted = finite;
        minsn_t inverse(src->tail->ea);
        inverse.opcode = m_lnot;
        inverse.l = finite.condition;
        inverse.d.size = 1;
        inverted.condition.create_from_insn(&inverse);
        std::swap(inverted.targets_by_condition[0], inverted.targets_by_condition[1]);
        return lower_conditional_targets(mba, src, inverted);
    }
    // A switch already preserves this exact target set when neither edge is
    // the physical fallthrough. Retain it instead of renumbering unrelated
    // blocks and their branch/case operands inside a late optimizer callback.
    return 0;
}

//--------------------------------------------------------------------------
// Resolve the actual m_ijmp offset operand.  A target merely contained in a
// block is insufficient: m_goto transfers to the block start, so accepting an
// interior address would change program semantics.
//--------------------------------------------------------------------------
int resolve_ijmp(mbl_array_t *mba, mblock_t *src, deobf_ctx_t *ctx,
                 const std::unordered_map<ea_t, int> &block_starts)
{
    minsn_t *ijmp = src->tail;
    if (!ijmp || ijmp->opcode != m_ijmp || ijmp->d.empty())
        return 0;

    // In a selector/offset instruction, a global operand is address-used: its
    // EA is the offset. In nested value expressions, mop_v instead denotes the
    // global's contents and is handled by the immutable evaluator.
    std::optional<uint64_t> value = evaluate_target_operand(ijmp->d, ijmp, 0);
    if (!value)
    {
        value = ijmp->d.t == mop_v ? std::optional<uint64_t>(ijmp->d.g)
                                   : opaque_eval_t::evaluate_operand(ijmp->d);
    }
    if (!value)
    {
        const auto finite = chernobog::evaluate_finite_targets(ijmp->d, ijmp, src);
        if (finite)
        {
            qstring comment;
            if (finite->targets.size() == 2 && !finite->condition.empty())
            {
                comment.sprnt("DEOBF: conditional indirect targets: false=%a, true=%a",
                              finite->targets_by_condition[0], finite->targets_by_condition[1]);
            }
            else if (finite->targets.size() == 1)
                comment.sprnt("DEOBF: exact indirect target -> %a", finite->targets.front());
            record_projection(mba, ijmp->ea, *finite, comment);
            if (finite->targets.size() == 1)
                value = finite->targets.front();
            else
            {
                const int changed = lower_conditional_targets(mba, src, *finite);
                ctx->branches_simplified += changed;
                return changed;
            }
        }
    }
    if (!value)
    {
        const auto candidates = chernobog::hybrid::hybrid_current_indirect_target_candidates(
            uint64_t(mba->entry_ea), uint64_t(ijmp->ea));
        for (const auto &candidate : candidates)
        {
            deobf::log_verbose("[indirect_branch][rax] Observed candidate %a at %a "
                               "(%zu observations, %zu runs); retained indirect because "
                               "concrete coverage is non-exhaustive\n",
                               ea_t(candidate.target), ijmp->ea, candidate.observations,
                               candidate.runs.size());
        }
        return 0;
    }

    const ea_t target_ea = static_cast<ea_t>(*value);
    const auto target = block_starts.find(target_ea);
    const int target_idx = target == block_starts.end() ? -1 : target->second;

    if (target_idx < 0)
    {
        // An exact target outside the current MBA cannot become m_goto, but
        // canonicalizing the ijmp operand is still semantics-preserving and
        // exposes a tail target to ctree. Require an executable function entry
        // so an interior address cannot be mislabeled as an external call.
        const segment_t *segment = getseg(target_ea);
        const func_t *target_function = get_func(target_ea);
        if (segment && (segment->perm & SEGPERM_EXEC) != 0 && target_function &&
            target_function->start_ea == target_ea)
        {
            const bool already_canonical = ijmp->d.t == mop_v && ijmp->d.g == target_ea;
            add_cref(ijmp->ea, target_ea, fl_JN);

            qstring target_name;
            if (get_func_name(&target_name, target_ea) <= 0)
                target_name.sprnt("sub_%a", target_ea);
            qstring comment;
            comment.sprnt("DEOBF: exact indirect tail target -> %s (%a)", target_name.c_str(),
                          target_ea);
            set_cmt(ijmp->ea, comment.c_str(), false);
            patch_arm64_indirect_tail(ijmp->ea, target_ea);

            if (!already_canonical)
            {
                ijmp->d.make_gvar(target_ea);
                ijmp->d.size = inf_is_64bit() ? 8 : 4;
                src->mark_lists_dirty();
                mba->mark_chains_dirty();
                ++ctx->branches_simplified;
                deobf::log("[indirect_branch] Canonicalized external ijmp in block %d "
                           "to function %a\n",
                           src->serial, target_ea);
                return 1;
            }
            return 0;
        }

        deobf::log_verbose("[indirect_branch] Exact target %a is not a unique microblock start\n",
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
    if (!mba)
        return false;

    for (int i = 0; i < mba->qty; ++i)
    {
        const mblock_t *blk = mba->get_mblock(i);
        if (blk && blk->tail && blk->tail->opcode == m_ijmp)
            return true;
        if (blk && blk->tail && blk->tail->opcode == m_jtbl)
            return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Main pass
//--------------------------------------------------------------------------
int indirect_branch_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if (!mba || !ctx)
        return 0;

    // Index exact microblock starts once. Resolution is therefore expected
    // O(B + J) for B blocks and J indirect jumps, with O(B) auxiliary space.
    std::unordered_map<ea_t, int> block_starts;
    block_starts.reserve(static_cast<size_t>(mba->qty));
    for (int i = 0; i < mba->qty; ++i)
    {
        const mblock_t *blk = mba->get_mblock(i);
        if (blk)
        {
            auto [entry, inserted] = block_starts.emplace(blk->start, i);
            if (!inserted)
                entry->second = -1;
        }
    }

    int changes = 0;
    for (int i = 0; i < mba->qty; ++i)
    {
        mblock_t *blk = mba->get_mblock(i);
        if (blk && blk->tail && blk->tail->opcode == m_ijmp)
        {
            const int before = mba->qty;
            changes += resolve_ijmp(mba, blk, ctx, block_starts);
            if (mba->qty != before)
                break; // Block serials changed; rebuild the index next pass.
        }
        else if (blk && blk->tail && blk->tail->opcode == m_jtbl)
        {
            const minsn_t *table = blk->tail;
            if (table->r.t != mop_c || !table->r.c ||
                table->r.c->values.size() != table->r.c->targets.size())
                continue;
            const auto finite = chernobog::evaluate_finite_targets(blk->tail->l, blk->tail, blk);
            if (finite && !finite->condition.empty())
            {
                bool exact = true;
                for (ea_t target : finite->targets)
                {
                    bool matched = false;
                    for (size_t entry = 0; entry < table->r.c->values.size(); ++entry)
                    {
                        const auto &values = table->r.c->values[entry];
                        const int destination = table->r.c->targets[entry];
                        if (std::find(values.begin(), values.end(), target) != values.end() &&
                            destination >= 0 && destination < mba->qty &&
                            mba->get_mblock(destination)->start == target)
                            matched = true;
                    }
                    exact &= matched;
                }
                if (!exact)
                    continue;
                const int changed = lower_conditional_targets(mba, blk, *finite);
                ctx->branches_simplified += changed;
                changes += changed;
            }
        }
    }

    deobf::log("[indirect_branch] Resolved %d exact indirect branches\n", changes);
    return changes;
}

bool indirect_branch_handler_t::take_projection_restart(ea_t function)
{
    return projection_restarts.erase({get_dbctx_id(), function}) != 0;
}

std::optional<std::array<ea_t, 2>> indirect_branch_handler_t::proven_targets(ea_t function,
                                                                             ea_t site)
{
    const auto found = projections.find({get_dbctx_id(), function});
    if (found == projections.end())
        return std::nullopt;
    const auto proof = found->second.find(site);
    if (proof == found->second.end() || proof->second.targets.size() != 2 ||
        !fresh_projection(proof->second))
        return std::nullopt;
    return std::array<ea_t, 2>{proof->second.targets[0], proof->second.targets[1]};
}

void indirect_branch_handler_t::clear_projections()
{
    const ssize_t database = get_dbctx_id();
    for (auto it = projections.begin(); it != projections.end();)
        if (it->first.first == database)
        {
            for (const auto &[site, proof] : it->second)
                if (getseg(site))
                    revoke_projection(proof);
            it = projections.erase(it);
        }
        else
            ++it;
    for (auto it = projection_restarts.begin(); it != projection_restarts.end();)
        if (it->first == database)
            it = projection_restarts.erase(it);
        else
            ++it;
}

void indirect_branch_handler_t::adjust_fragment_stack(mba_t *mba, stkpnts_t *points)
{
    if (!mba || !points)
        return;
    const auto found = projections.find({get_dbctx_id(), mba->entry_ea});
    if (found == projections.end())
        return;
    std::map<ea_t, sval_t> projected;
    for (const auto &point : *points)
        projected.emplace(point.ea, point.spd);
    for (const auto &[site, proof] : found->second)
    {
        if (!fresh_projection(proof) || proof.fragments.empty())
            continue;
        for (const auto &fragment : proof.fragments)
        {
            func_t *owner = get_func(fragment.start_ea);
            if (!owner)
                continue;
            const sval_t origin = get_spd(owner, fragment.start_ea);
            for (ea_t ea = fragment.start_ea; ea < fragment.end_ea; ea += 4)
            {
                const sval_t value = proof.inherited_spd + get_spd(owner, ea) - origin;
                projected[ea] = value;
            }
        }
    }
    points->clear();
    for (const auto &[ea, spd] : projected)
        points->push_back(stkpnt_t{ea, spd});
}

bool indirect_branch_handler_t::is_projected_return(const codegen_t &codegen)
{
    if (!codegen.mba || !arch::is_arm64())
        return false;
    const uint32_t word = uint32_t(get_dword(codegen.insn.ea));
    if (word != 0xD65F03C0U && word != 0xD65F0BFFU && word != 0xD65F0FFFU)
        return false;
    const auto found = projections.find({get_dbctx_id(), codegen.mba->entry_ea});
    if (found == projections.end())
        return false;
    for (const auto &[site, proof] : found->second)
    {
        if (!fresh_projection(proof))
            continue;
        for (const auto &fragment : proof.fragments)
        {
            func_t *owner = get_func(fragment.start_ea);
            if (owner && fragment.contains(codegen.insn.ea) &&
                proof.inherited_spd + get_spd(owner, codegen.insn.ea) -
                        get_spd(owner, fragment.start_ea) ==
                    0)
                return true;
        }
    }
    return false;
}

int indirect_branch_handler_t::apply_generated_projections(mba_t *mba)
{
    if (!mba || mba->maturity > MMAT_GENERATED)
        return 0;
    const auto found = projections.find({get_dbctx_id(), mba->entry_ea});
    if (found == projections.end())
        return 0;
    int retained = 0;
    for (const auto &[site, proof] : found->second)
    {
        if (!fresh_projection(proof) || proof.fragments.empty())
            continue;
        for (int index = 0; index < mba->qty; ++index)
        {
            mblock_t *block = mba->get_mblock(index);
            if (!block->tail || block->tail->ea != site || block->tail->opcode != m_ijmp)
                continue;
            if (proof.targets.size() != 2)
                continue;
            std::array<mblock_t *, 2> destinations = {nullptr, nullptr};
            for (int destination = 0; destination < mba->qty; ++destination)
                for (unsigned outcome = 0; outcome < 2; ++outcome)
                    if (mba->get_mblock(destination)->start == proof.targets[outcome])
                        destinations[outcome] = mba->get_mblock(destination);
            if (!destinations[0] || !destinations[1])
                continue;
            // Function-mode generation elides the frame-pointer setup. The
            // extra ranges must see that same frame, rather than an unrelated
            // incoming X29 supplied by their standalone IDB prototypes.
            mop_t slot;
            slot.make_stkvar(mba, mba->tmpstk_size + proof.frame_offset);
            slot.size = NOSIZE;
            minsn_t *frame = new minsn_t(site);
            frame->opcode = m_mov;
            frame->l.t = mop_a;
            frame->l.a = new mop_addr_t(slot, NOSIZE, NOSIZE);
            frame->l.size = 8;
            frame->d.make_reg(reg2mreg(str2reg("X29")), 8);
            block->insert_into_block(frame, block->tail->prev);
            // Publish control edges before liveness can discard registers
            // consumed by the projected fragments. KEEP alone is insufficient.
            minsn_t *jump = block->tail;
            jump->l = jump->d;
            jump->d.erase();
            jump->r.erase();
            jump->r.t = mop_c;
            jump->r.c = new mcases_t;
            jump->r.size = NOSIZE;
            jump->r.c->resize(3);
            for (unsigned outcome = 0; outcome < 2; ++outcome)
            {
                jump->r.c->values[outcome].push_back(proof.targets[outcome]);
                jump->r.c->targets[outcome] = destinations[outcome]->serial;
            }
            // The exhaustive proof excludes the default; retaining one makes
            // the initial switch valid before normal CFG construction.
            jump->r.c->targets[2] = mba->qty - 1;
            jump->opcode = m_jtbl;
            block->flags &= ~(MBL_NORET | MBL_TCAL);
            block->mark_lists_dirty();
        }
        for (int index = 0; index < mba->qty; ++index)
        {
            mblock_t *block = mba->get_mblock(index);
            for (const auto &fragment : proof.fragments)
            {
                if (fragment.contains(block->start))
                {
                    block->flags |= MBL_KEEP;
                    ++retained;
                    break;
                }
            }
        }
    }
    deobf::log_verbose(
        "[indirect_branch] Retained %d projected blocks through initial optimization\n", retained);
    return retained;
}

int indirect_branch_handler_t::extend_flowchart(qflow_chart_t *flowchart, bitset_t *reachable,
                                                mba_t *mba)
{
    return flowchart && flowchart->pfn
               ? extend_projection(flowchart, reachable, flowchart->pfn->start_ea, mba)
               : 0;
}

#if IDA_SDK_VERSION >= 940
int indirect_branch_handler_t::extend_flowchart(qflow_chart_ea_t *flowchart, bitset_t *reachable,
                                                mba_t *mba)
{
    return flowchart ? extend_projection(flowchart, reachable, flowchart->func_ea, mba) : 0;
}
#endif
