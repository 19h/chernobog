#include "indirect_branch.h"

#include "../analysis/arch_utils.h"
#include "../analysis/finite_targets.h"
#include "../../common/arm64e.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"
#include "../../common/warn_off.h"
#include <intel.hpp>
#include "../../common/warn_on.h"

#include <unordered_map>
#include <gdl.hpp>
#include <frame.hpp>

namespace
{

bool native_jump(ea_t address)
{
    insn_t instruction;
    if (decode_insn(&instruction, address) <= 0)
        return false;
    if (arch::is_x86_64())
        return instruction.itype == NN_jmp || instruction.itype == NN_jmpni;
    return arch::is_arm64() && instruction.itype == ARM_br;
}

bool native_tail(const mblock_t *block)
{
    return block && block->tail &&
           ((block->tail->opcode == m_call && block->tail->l.t == mop_v) ||
            block->tail->opcode == m_icall) &&
           native_jump(block->tail->ea);
}

struct projection_t
{
    ea_t site = BADADDR;
    // A union of discovered destinations, not an exhaustive target proof for
    // the current CFG. Generation must retain the actual target and fallback.
    std::vector<ea_t> targets;
    std::vector<range_t> fragments;
    std::vector<range_t> root_ranges, source_ranges;
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

// Function ranges of the microcode arrays that a projection turned into
// snippets, restored once the decompilation is final.
struct projected_function_t
{
    ssize_t database = 0;
    decomp_ranges_t ranges;
};
std::map<const mba_t *, projected_function_t> projected_functions;

std::vector<range_t> function_ranges(const func_t *function)
{
    std::vector<range_t> ranges;
    func_tail_iterator_t iterator(const_cast<func_t *>(function));
    for (bool valid = iterator.main(); valid; valid = iterator.next())
    {
        if (ranges.size() >= 128)
            return {};
        const auto &chunk = iterator.chunk();
        ranges.emplace_back(chunk.start_ea, chunk.end_ea);
    }
    return ranges;
}

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
    // This validates a discovery hint's sources, not a target proof for the
    // current predecessor set. The native target still guards every case.
    const func_t *root = get_func(proof.root);
    if (!root || root->start_ea != proof.root || root->end_ea != proof.root_end ||
        root->frsize != proof.frame_size || root->fpd != proof.frame_delta ||
        function_ranges(root) != proof.root_ranges)
        return false;
    func_t *source = get_func(proof.source_owner);
    if (!source || source->start_ea != proof.source_owner ||
        get_spd(source, proof.site) != proof.source_spd ||
        (source != root && function_ranges(source) != proof.source_ranges))
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

bool capture_function(projection_t &proof, const func_t *function, std::vector<range_t> &ranges)
{
    ranges = function_ranges(function);
    if (ranges.empty())
        return false;
    size_t total = 0;
    for (const range_t &range : ranges)
    {
        if (range.end_ea <= range.start_ea || range.size() > 16384 - total ||
            !capture_code(proof, range.start_ea, range.end_ea))
            return false;
        total += size_t(range.size());
    }
    return true;
}

// A jump does not establish an independent call frame. Admit only small,
// automatically named fragments that consume the incoming frame before
// redefining it, and that have no call-site or user-prototype evidence.
std::optional<range_t> incoming_frame_prefix(ea_t target, ea_t end)
{
    const bool arm64 = arch::is_arm64();
    const int fp = str2reg(arm64 ? "X29" : "RBP");
    const int sp = str2reg(arm64 ? "SP" : "RSP");
    const int first_saved = str2reg("X19"), last_saved = str2reg("X28");
    const std::set<int> x86_saved = {R_bx, R_r12, R_r13, R_r14, R_r15};
    const auto saved = [&](int reg)
    { return arm64 ? reg >= first_saved && reg <= last_saved : x86_saved.count(reg) != 0; };
    std::set<int> defined;
    bool inherited_register = false;
    ea_t ea = target;
    for (unsigned count = 0; count < 32 && ea < end; ++count)
    {
        insn_t instruction;
        const int size = decode_insn(&instruction, ea);
        if (size <= 0 || size > (arm64 ? 16 : 15) || (arm64 && (size & 3) != 0) ||
            ea + ea_t(size) > end || is_call_insn(instruction))
            return std::nullopt;
        if (!arm64 && (instruction.itype == NN_push || instruction.itype == NN_enter))
            return std::nullopt;
        const auto primitive = arm64 ? chernobog::arm64e::decode(get_dword(ea)) : std::nullopt;
        if (primitive && primitive->kind == chernobog::arm64e::Kind::sign && primitive->implicit &&
            primitive->destination == 30)
            return std::nullopt;
        const uint32_t features = instruction.get_canon_feature(PH);
        // Check every operand before accepting a read: a paired store can
        // read X29 before its later operand allocates a new stack frame.
        for (unsigned index = 0; index < UA_MAXOP && instruction.ops[index].type != o_void; ++index)
        {
            const op_t &op = instruction.ops[index];
            const bool memory = op.type == o_phrase || op.type == o_displ;
            const int base = !memory ? -1 : arm64 ? op.reg : x86_base_reg(instruction, op);
            if ((op.type == o_displ && base == sp && sval_t(op.addr) < 0) ||
                (op.type == o_reg && (op.reg == fp || op.reg == sp) && has_cf_chg(features, index)))
                return std::nullopt;
        }
        for (unsigned index = 0; index < UA_MAXOP; ++index)
        {
            const op_t &op = instruction.ops[index];
            if (op.type == o_void)
                break;
            const bool memory = op.type == o_phrase || op.type == o_displ;
            const int base = !memory ? -1 : arm64 ? op.reg : x86_base_reg(instruction, op);
            const int index_reg = arm64 || !memory ? -1 : x86_index_reg(instruction, op);
            if ((op.type == o_phrase || op.type == o_displ) && (base == fp || base == sp))
                return range_t(target, end);
            if (op.type == o_reg && (op.reg == fp || op.reg == sp) && has_cf_use(features, index))
                return range_t(target, end);
            if (op.type == o_reg && has_cf_use(features, index) && saved(op.reg) &&
                !defined.count(op.reg))
                inherited_register = true;
            if (op.type == o_phrase || op.type == o_displ)
                inherited_register |= (saved(base) && !defined.count(base)) ||
                                      (saved(index_reg) && !defined.count(index_reg));
        }
        if (is_ret_insn(instruction))
            return std::nullopt;
        if ((features & (CF_JUMP | CF_STOP)) != 0 || is_indirect_jump_insn(instruction))
            return inherited_register ? std::optional<range_t>(range_t(target, end)) : std::nullopt;
        for (unsigned index = 0; index < UA_MAXOP && instruction.ops[index].type != o_void; ++index)
            if (instruction.ops[index].type == o_reg && has_cf_chg(features, index))
                defined.insert(instruction.ops[index].reg);
        ea += ea_t(size);
    }
    return std::nullopt;
}

std::optional<range_t> frame_fragment(ea_t root, ea_t target)
{
    const func_t *function = get_func(target);
    if (!function || function->start_ea != target || target == root || function->end_ea <= target ||
        function->end_ea - target > 4096 || (function->flags & (FUNC_LIB | FUNC_THUNK)) != 0 ||
        has_user_name(get_flags(target)) || is_userti(target) || get_func_tail_qty(target) != 0)
        return std::nullopt;
    xrefblk_t xref;
    for (bool ok = xref.first_to(target, XREF_FAR); ok; ok = xref.next_to())
        if (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF))
            return std::nullopt;
    return incoming_frame_prefix(target, function->end_ea);
}

struct recovery_region_t
{
    ea_t target = BADADDR, end = BADADDR, clear_start = BADADDR, clear_end = BADADDR;
    std::vector<std::pair<ea_t, int>> instructions;
    std::vector<range_t> removals;
    std::vector<uint8_t> bytes;
    bool overlap = false;
    const char *status = "ready";
};

recovery_region_t inspect_recovery_region(ea_t target)
{
    recovery_region_t region;
    region.target = target;
    const auto refuse = [&](const char *reason)
    {
        region.status = reason;
        return region;
    };
    const segment_t *segment = getseg(target);
    if (!segment || (segment->perm & SEGPERM_EXEC) == 0 || get_func(target))
        return refuse("owned or non-executable");
    ea_t cursor = target;
    bool terminal = false;
    while (region.instructions.size() < 256 && cursor - target < 4096)
    {
        insn_t instruction;
        const int size = decode_insn(&instruction, cursor);
        if (size <= 0 || size > 15 || cursor + ea_t(size) > segment->end_ea ||
            cursor + ea_t(size) - target > 4096)
            return refuse("invalid or excessive region");
        const uint32_t features = instruction.get_canon_feature(PH);
        if ((features & CF_JUMP) != 0 && (features & (CF_CALL | CF_STOP)) == 0)
            return refuse("nonlinear region");
        region.instructions.emplace_back(cursor, size);
        cursor += ea_t(size);
        if ((features & CF_STOP) != 0)
        {
            terminal = true;
            break;
        }
    }
    if (!terminal || !incoming_frame_prefix(target, cursor))
        return refuse("no bounded incoming-frame continuation");
    region.end = cursor;
    region.clear_start = get_item_head(target);
    region.clear_end = get_item_end(cursor - 1);
    if (region.clear_start > target || target - region.clear_start > 14 ||
        region.clear_end < cursor || region.clear_end - cursor > 14 ||
        region.clear_start < segment->start_ea || region.clear_end > segment->end_ea)
        return refuse("invalid item boundaries");
    std::set<ea_t> new_heads;
    for (const auto &[address, size] : region.instructions)
    {
        new_heads.insert(address);
        region.overlap |= is_tail(get_flags(address)) ||
                          (is_head(get_flags(address)) && get_item_size(address) != asize_t(size));
        if (!is_head(get_flags(address)) || get_item_size(address) != asize_t(size))
        {
            const range_t removal(get_item_head(address), get_item_end(address + ea_t(size) - 1));
            if (!region.removals.empty() && region.removals.back().end_ea >= removal.start_ea)
                region.removals.back().end_ea = qmax(region.removals.back().end_ea, removal.end_ea);
            else
                region.removals.push_back(removal);
        }
    }
    region.overlap |= region.clear_start != target || region.clear_end != cursor;
    for (ea_t address = region.clear_start; address < region.clear_end; ++address)
    {
        const flags64_t flags = get_flags(address);
        if (get_func(address) || !is_loaded(address) || is_data(flags) || has_user_name(flags) ||
            has_cmt(flags) || has_extra_cmts(flags) || is_userti(address) ||
            is_manual_insn(address))
            return refuse("protected bytes or metadata");
        for (const auto &removal : region.removals)
            if (removal.contains(address))
                for (int index = 0; index < UA_MAXOP; ++index)
                    if (is_forced_operand(address, index))
                        return refuse("forced operand in replaced item");
        xrefblk_t xref;
        for (bool ok = xref.first_to(address, XREF_ALL); ok; ok = xref.next_to())
            if (xref.user || (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF)) ||
                (new_heads.count(address) == 0 &&
                 (xref.from < region.clear_start || xref.from >= region.clear_end)))
                return refuse("protected incoming reference");
    }
    region.bytes.resize(size_t(region.clear_end - region.clear_start));
    if (!chernobog::ida_memory::read_exact(region.bytes.data(), region.bytes.size(),
                                           region.clear_start))
        return refuse("unavailable bytes");
    return region;
}

bool record_projection(mbl_array_t *mba, ea_t site, const chernobog::finite_targets_t &finite,
                       const qstring &comment)
{
    if ((!arch::is_arm64() && !arch::is_x86_64()) || finite.targets.size() > 2)
        return false;
    projection_t proof;
    proof.site = site;
    proof.targets = finite.targets;
    proof.dependencies = finite.dependencies;
    proof.frame_offset = mba->frsize - mba->fpd;
    const func_t *root = get_func(mba->entry_ea);
    if (!root || !capture_function(proof, root, proof.root_ranges))
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
    if (source_owner != root && !capture_function(proof, source_owner, proof.source_ranges))
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
    bool all_covered = true;
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
        else
        {
            bool present = false;
            for (int index = 0; index < mba->qty; ++index)
                present |= mba->get_mblock(index)->start == target;
            all_covered &= present;
        }
    }
    // Partial projection cannot establish the complete switch before native
    // liveness analysis. Do not retain an orphan fragment with lost inputs.
    if (!all_covered)
        proof.fragments.clear();
    const projection_key_t key{get_dbctx_id(), mba->entry_ea};
    if (projections.size() >= 128 && projections.count(key) == 0)
        return false;
    auto &sites = projections[key];
    const auto old = sites.find(site);
    if (old != sites.end() && fresh_projection(old->second))
    {
        for (ea_t target : old->second.targets)
            if (std::find(proof.targets.begin(), proof.targets.end(), target) ==
                proof.targets.end())
                proof.targets.push_back(target);
        for (const range_t &fragment : old->second.fragments)
            if (std::find(proof.fragments.begin(), proof.fragments.end(), fragment) ==
                proof.fragments.end())
                proof.fragments.push_back(fragment);
        std::map<std::pair<ea_t, size_t>, chernobog::finite_targets_t::dependency_t> dependencies;
        for (const auto &dependency : old->second.dependencies)
            dependencies[{dependency.address, dependency.bytes.size()}] = dependency;
        for (const auto &dependency : proof.dependencies)
            dependencies[{dependency.address, dependency.bytes.size()}] = dependency;
        proof.dependencies.clear();
        for (auto &[location, dependency] : dependencies)
            proof.dependencies.push_back(std::move(dependency));
    }
    std::sort(proof.targets.begin(), proof.targets.end());
    std::sort(proof.fragments.begin(), proof.fragments.end(),
              [](const range_t &a, const range_t &b) { return a.start_ea < b.start_ea; });
    if (proof.targets.size() > 128 || proof.dependencies.size() > 8192)
        return false;
    if (old != sites.end() && old->second.targets == proof.targets &&
        old->second.fragments == proof.fragments && fresh_projection(old->second))
        return false;
    if (sites.size() >= 32 && old == sites.end())
        return false;
    if (old != sites.end())
        revoke_projection(old->second);
    get_cmt(&proof.previous_comment, site, false);
    proof.published_comment = comment;
    for (ea_t target : proof.targets)
    {
        bool present = false;
        xrefblk_t xref;
        for (bool ok = xref.first_from(site, XREF_FAR); ok; ok = xref.next_from())
            present |= xref.iscode && xref.to == target;
        if (!present && add_cref(site, target, fl_JN))
            proof.owned_edges.push_back(target);
    }
    deobf::set_cmt_if_changed(site, comment.c_str(), false);
    // Even an internal edge can introduce another predecessor after the SDK
    // has propagated values. Discard that entire MBA before using those values.
    deobf::log_verbose(
        "[indirect_branch] Discovered %zu target addresses at %a; projecting %zu frame fragments\n",
        proof.targets.size(), site, proof.fragments.size());
    sites[site] = std::move(proof);
    projection_restarts.insert(key);
    return true;
}

void rebuild_flowchart(qflow_chart_t *flowchart, const rangevec_t &ranges)
{
    const qstring title = flowchart->title;
    flowchart->create(title.c_str(), ranges, flowchart->flags);
}

bool discovered_targets(mba_t *mba, ea_t site, const chernobog::finite_targets_t &finite)
{
    const auto function = projections.find({get_dbctx_id(), mba->entry_ea});
    if (function == projections.end())
        return false;
    const auto proof = function->second.find(site);
    return proof != function->second.end() && fresh_projection(proof->second) &&
           std::all_of(finite.targets.begin(), finite.targets.end(),
                       [&](ea_t target)
                       {
                           return std::find(proof->second.targets.begin(),
                                            proof->second.targets.end(),
                                            target) != proof->second.targets.end();
                       });
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
                {
                    extra_ranges.push_back(fragment);
                    // A function's extra ranges are only accepted, also when
                    // saved microcode is loaded again, with this flag.
                    mba->set_mba_flags2(MBA2_HAS_OUTLINES);
                }
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
            // Snippet mode lets microcode generation accept fragments owned by
            // other functions. Remember the function to restore it afterwards.
            auto &decompilation = const_cast<decomp_ranges_t &>(mba->get_decomp_ranges());
            if (!decompilation.is_snippet())
                projected_functions[mba] = {get_dbctx_id(), decompilation};
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

int lower_two_way(mbl_array_t *mba, mblock_t *src, const mop_t &condition,
                  std::array<mblock_t *, 2> destinations,
                  const chernobog::finite_targets_t *proof = nullptr)
{
    if (!destinations[0] || !destinations[1] || destinations[0] == destinations[1])
        return 0;
    // At this maturity, adding another native predecessor would invalidate
    // propagated values elsewhere. Discovery must install it after a restart.
    for (mblock_t *destination : destinations)
        if (std::find(src->succset.begin(), src->succset.end(), destination->serial) ==
            src->succset.end())
            return 0;
    mop_t predicate = condition;
    mblock_t *capture_block = nullptr;
    minsn_t *capture_before = nullptr;
    if (proof && proof->condition_before != src->tail)
    {
        if (!proof->condition_before || !proof->condition_block ||
            proof->condition_block->mba != mba)
            return 0;
        capture_block = const_cast<mblock_t *>(proof->condition_block);
        for (minsn_t *ins = capture_block->head; ins; ins = ins->next)
            if (ins == proof->condition_before)
                capture_before = ins;
        if (!capture_before)
            return 0;
    }
    else if (proof && condition.has_side_effects(true))
    {
        // A load in the predicate is read once, before the retained target
        // guard and at the transfer's own memory state; the branch tests that
        // copy, so the guard's own evaluation cannot change what was tested.
        capture_block = src;
        capture_before = src->tail;
    }
    mop_t left = predicate, right;
    mcode_t relation = m_jnz;
    if (condition.t == mop_d && condition.d && is_mcode_convertible_to_jmp(condition.d->opcode))
    {
        relation = set2jcnd(condition.d->opcode);
        left = condition.d->l;
        right = condition.d->r;
    }
    else
        right.make_number(0, left.size);
    const bool inverted = destinations[1]->serial == src->serial + 1;
    if (inverted)
    {
        relation = negate_mcode_relation(relation);
        std::swap(destinations[0], destinations[1]);
    }
    minsn_t *branch = src->tail;
    const mreg_t temporary = capture_before ? mba->alloc_kreg(size_t(condition.size)) : mr_none;
    if (capture_before && temporary == mr_none)
        return 0;
    const mop_t &original_target = branch->opcode == m_jtbl ? branch->l : branch->d;
    if (!chernobog::preserve_indirect_target_effects(src, branch, original_target))
        return 0;
    if (capture_before)
    {
        auto *capture = new minsn_t(capture_before->ea);
        capture->opcode = m_mov;
        capture->l = condition;
        capture->d.make_reg(temporary, condition.size);
        capture_block->insert_into_block(capture, capture_before->prev);
        capture_block->mark_lists_dirty();
        left.make_reg(temporary, condition.size);
        right.make_number(0, condition.size);
        relation = inverted ? m_jz : m_jnz;
    }
    mblock_t *fallthrough = destinations[0];
    if (fallthrough->serial != src->serial + 1)
    {
        // The SDK insertion API renumbers existing block and case references.
        // A local bridge supplies the physical fallthrough without moving or
        // cloning either destination's instructions or observable effects.
        fallthrough = mba->insert_block(src->serial + 1);
        const ea_t address = mba->alloc_fict_ea(branch->ea);
        fallthrough->start = address;
        fallthrough->end = address + 1;
        fallthrough->flags |= MBL_FAKE;
        fallthrough->type = BLT_1WAY;
        fallthrough->flags &= ~(MBL_NORET | MBL_TCAL);
        fallthrough->maxbsp = src->maxbsp;
        fallthrough->minbstkref = src->minbstkref;
        fallthrough->minbargref = src->minbargref;
        auto *jump = new minsn_t(address);
        jump->opcode = m_goto;
        jump->l.make_blkref(destinations[0]->serial);
        fallthrough->insert_into_block(jump, nullptr);
        fallthrough->succset.push_back(destinations[0]->serial);
        auto &predecessors = destinations[0]->predset;
        predecessors.push_back(fallthrough->serial);
        std::sort(predecessors.begin(), predecessors.end());
    }
    branch->opcode = relation;
    branch->l = left;
    branch->r = right;
    branch->d.make_blkref(destinations[1]->serial);
    replace_cfg_successors(mba, src, destinations[1]->serial);
    src->succset.insert(src->succset.begin(), fallthrough->serial);
    auto &predecessors = fallthrough->predset;
    if (std::find(predecessors.begin(), predecessors.end(), src->serial) == predecessors.end())
        predecessors.push_back(src->serial);
    std::sort(predecessors.begin(), predecessors.end());
    src->type = BLT_2WAY;
    src->flags &= ~(MBL_NORET | MBL_TCAL);
    src->mark_lists_dirty();
    fallthrough->mark_lists_dirty();
    destinations[0]->mark_lists_dirty();
    destinations[1]->mark_lists_dirty();
    mba->mark_chains_dirty();
    return 1;
}

int lower_conditional_targets(mbl_array_t *mba, mblock_t *src,
                              const chernobog::finite_targets_t &finite)
{
    if (finite.condition.empty() || finite.targets.size() != 2 ||
        finite.condition.has_side_effects(false))
        return 0;
    std::array<mblock_t *, 2> destinations = {nullptr, nullptr};
    const minsn_t *table = src->tail;
    if (table->opcode == m_jtbl)
    {
        if (table->r.t != mop_c || !table->r.c ||
            table->r.c->values.size() != table->r.c->targets.size())
            return 0;
        // Case edges remain authoritative after prolog/epilog elimination
        // moves a destination's first instruction away from its native entry.
        for (unsigned outcome = 0; outcome < 2; ++outcome)
            for (size_t entry = 0; entry < table->r.c->values.size(); ++entry)
            {
                const auto &values = table->r.c->values[entry];
                if (std::find(values.begin(), values.end(), finite.targets_by_condition[outcome]) ==
                    values.end())
                    continue;
                const int destination = table->r.c->targets[entry];
                if (destination < 0 || destination >= mba->qty)
                    return 0;
                mblock_t *candidate = mba->get_mblock(destination);
                if (destinations[outcome] && destinations[outcome] != candidate)
                    return 0;
                destinations[outcome] = candidate;
            }
    }
    else
    {
        for (int index = 0; index < mba->qty; ++index)
            for (unsigned outcome = 0; outcome < 2; ++outcome)
            {
                mblock_t *candidate = mba->get_mblock(index);
                if (candidate->start != finite.targets_by_condition[outcome])
                    continue;
                if (destinations[outcome])
                    return 0;
                destinations[outcome] = candidate;
            }
    }
    return lower_two_way(mba, src, finite.condition, destinations, &finite);
}

int lower_boolean_switch(mbl_array_t *mba, mblock_t *src)
{
    const minsn_t *table = src->tail;
    if (!table || table->opcode != m_jtbl || !table->l.is01() || table->l.has_side_effects(true) ||
        table->r.t != mop_c || !table->r.c ||
        table->r.c->values.size() != table->r.c->targets.size() || table->r.c->values.size() > 3)
        return 0;
    std::array<mblock_t *, 2> destinations = {nullptr, nullptr};
    mblock_t *fallback = nullptr;
    for (size_t entry = 0; entry < table->r.c->values.size(); ++entry)
    {
        const int index = table->r.c->targets[entry];
        if (index < 0 || index >= mba->qty)
            return 0;
        mblock_t *destination = mba->get_mblock(index);
        const auto &values = table->r.c->values[entry];
        if (values.empty())
        {
            if (fallback)
                return 0;
            fallback = destination;
        }
        for (uint64 value : values)
        {
            if (value > 1 || destinations[size_t(value)])
                return 0;
            destinations[size_t(value)] = destination;
        }
    }
    for (auto &destination : destinations)
        if (!destination)
            destination = fallback;
    return lower_two_way(mba, src, table->l, destinations);
}

int lower_finite_switch(mba_t *mba, mblock_t *src)
{
    minsn_t *table = src->tail;
    if (!table || table->opcode != m_jtbl || table->r.t != mop_c || !table->r.c ||
        table->r.c->values.size() != table->r.c->targets.size())
        return 0;
    const auto finite = chernobog::evaluate_finite_values(table->l, table, src);
    if (!finite || finite->values.empty())
        return 0;
    std::vector<mblock_t *> destinations;
    for (uint64_t value : finite->values)
    {
        int selected = -1, fallback = -1;
        for (size_t entry = 0; entry < table->r.c->values.size(); ++entry)
        {
            const auto &cases = table->r.c->values[entry];
            if (cases.empty())
                fallback = table->r.c->targets[entry];
            else if (std::find(cases.begin(), cases.end(), value) != cases.end())
            {
                if (selected != -1)
                    return 0;
                selected = table->r.c->targets[entry];
            }
        }
        if (selected == -1)
            selected = fallback;
        if (selected < 0 || selected >= mba->qty ||
            std::find(src->succset.begin(), src->succset.end(), selected) == src->succset.end())
            return 0;
        destinations.push_back(mba->get_mblock(selected));
    }
    const bool singleton =
        std::all_of(destinations.begin(), destinations.end(),
                    [&](mblock_t *block) { return block == destinations.front(); });
    if ((!singleton && destinations.size() != 2) ||
        !chernobog::remember_finite_values(mba->entry_ea, *finite))
        return 0;
    if (singleton)
    {
        if (!chernobog::preserve_indirect_target_effects(src, table, table->l))
            return 0;
        const int destination = destinations.front()->serial;
        table->opcode = m_goto;
        table->l.make_blkref(destination);
        table->r.erase();
        table->d.erase();
        replace_cfg_successors(mba, src, destination);
        src->type = BLT_1WAY;
        src->flags &= ~(MBL_NORET | MBL_TCAL);
        return 1;
    }
    // Test the already computed selector, not an earlier memory predicate.
    // A selector with effects is evaluated once at the original transfer.
    if (table->l.has_side_effects(true))
    {
        const mreg_t temporary = mba->alloc_kreg(size_t(table->l.size));
        if (temporary == mr_none)
            return 0;
        auto *capture = new minsn_t(table->ea);
        capture->opcode = m_mov;
        capture->l = table->l;
        capture->d.make_reg(temporary, table->l.size);
        src->insert_into_block(capture, table->prev);
        table->l.make_reg(temporary, table->l.size);
        src->mark_lists_dirty();
    }
    minsn_t comparison(table->ea);
    comparison.opcode = m_setz;
    comparison.l = table->l;
    comparison.r.make_number(finite->values[1], table->l.size);
    comparison.d.size = 1;
    mop_t condition;
    condition.create_from_insn(&comparison);
    return lower_two_way(mba, src, condition, {destinations[0], destinations[1]});
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
    mop_t address = ijmp->d;
    // A global in this top-level offset position is address-used. Nested
    // globals retain their ordinary memory semantics in the finite evaluator.
    if (address.t == mop_v)
        address.make_number(address.g, inf_is_64bit() ? 8 : 4);
    const auto finite =
        chernobog::evaluate_finite_targets(address, ijmp, src, false, arch::is_x86_64());
    if (!finite ||
        (finite->targets.size() != 1 && (finite->targets.size() != 2 || finite->condition.empty())))
        return 0;
    qstring comment;
    if (finite->targets.size() == 2)
        comment.sprnt("DEOBF: conditional indirect targets: false=%a, true=%a",
                      finite->targets_by_condition[0], finite->targets_by_condition[1]);
    else
        comment.sprnt("DEOBF: exact indirect target -> %a", finite->targets.front());
    if (finite->authentication_guarded)
        comment += " (authentication retained)";
    if (std::any_of(finite->targets.begin(), finite->targets.end(), [](ea_t target)
                    { return !is_code(get_flags(target)) || !is_head(get_flags(target)); }))
        comment += " (disassembly boundary unresolved)";
    if (record_projection(mba, ijmp->ea, *finite, comment) ||
        !discovered_targets(mba, ijmp->ea, *finite))
        return 0;
    if (finite->targets.size() == 2)
    {
        const int changes = lower_conditional_targets(mba, src, *finite);
        ctx->branches_simplified += changes;
        return changes;
    }
    const ea_t target_ea = finite->targets.front();
    const auto target = block_starts.find(target_ea);
    const int target_idx = target == block_starts.end() ? -1 : target->second;
    if (target_idx < 0)
    {
        const segment_t *segment = getseg(target_ea);
        const func_t *target_function = get_func(target_ea);
        if (!segment || (segment->perm & SEGPERM_EXEC) == 0 || !target_function ||
            target_function->start_ea != target_ea ||
            !chernobog::preserve_indirect_target_effects(src, ijmp, ijmp->d))
            return 0;
        if (ijmp->d.t == mop_v && ijmp->d.g == target_ea)
            return 0;
        ijmp->d.make_gvar(target_ea);
        ijmp->d.size = inf_is_64bit() ? 8 : 4;
        src->mark_lists_dirty();
        mba->mark_chains_dirty();
        ++ctx->branches_simplified;
        return 1;
    }
    if (std::find(src->succset.begin(), src->succset.end(), target_idx) == src->succset.end() ||
        !chernobog::preserve_indirect_target_effects(src, ijmp, ijmp->d))
        return 0;
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
        if (native_tail(blk))
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
            const int before = mba->qty;
            int changed = lower_finite_switch(mba, blk);
            if (!changed)
                changed = lower_boolean_switch(mba, blk);
            if (!changed)
            {
                const auto finite =
                    chernobog::evaluate_finite_targets(blk->tail->l, blk->tail, blk);
                if (finite && !finite->condition.empty())
                {
                    qstring comment;
                    comment.sprnt("DEOBF: discovered indirect destinations at %a", blk->tail->ea);
                    if (record_projection(mba, blk->tail->ea, *finite, comment))
                        break;
                    if (discovered_targets(mba, blk->tail->ea, *finite))
                        changed = lower_conditional_targets(mba, blk, *finite);
                }
            }
            ctx->branches_simplified += changed;
            changes += changed;
            if (mba->qty != before)
                break; // Rebuild the block-start index after SDK renumbering.
        }
        else if (native_tail(blk))
        {
            mop_t address = blk->tail->r;
            if (blk->tail->opcode == m_call)
                address.make_number(blk->tail->l.g, 8);
            const auto finite = chernobog::evaluate_finite_targets(address, blk->tail, blk, false,
                                                                   arch::is_x86_64());
            if (finite && (finite->targets.size() == 1 || !finite->condition.empty()))
            {
                qstring comment;
                if (finite->targets.size() == 1)
                    comment.sprnt("DEOBF: exact continuation target -> %a",
                                  finite->targets.front());
                else
                    comment.sprnt("DEOBF: conditional continuation targets: false=%a, true=%a",
                                  finite->targets_by_condition[0], finite->targets_by_condition[1]);
                record_projection(mba, blk->tail->ea, *finite, comment);
            }
        }
        if (projection_restarts.count({get_dbctx_id(), mba->entry_ea}) != 0)
            break;
    }

    deobf::log("[indirect_branch] Resolved %d exact indirect branches\n", changes);
    return changes;
}

bool indirect_branch_handler_t::take_projection_restart(ea_t function)
{
    return projection_restarts.erase({get_dbctx_id(), function}) != 0;
}

qstring indirect_branch_handler_t::recover_regions(ea_t function, unsigned flags)
{
    if (!arch::is_x86_64() || (flags != 0 && flags != 1 && flags != 3))
        return "{\"error\":\"requires AMD64 and flags 0, 1 or 3\"}";
    // Copy before mutating the IDB: notifications can invalidate cached proofs.
    std::map<ea_t, projection_t> candidates;
    const auto found = projections.find({get_dbctx_id(), function});
    if (found != projections.end())
        for (const auto &[site, proof] : found->second)
            if (fresh_projection(proof))
                for (ea_t target : proof.targets)
                    if (!get_func(target))
                        candidates.emplace(target, proof);
    qstring result("{\"regions\":[");
    size_t recovered = 0, count = 0;
    for (const auto &[target, proof] : candidates)
    {
        recovery_region_t region = inspect_recovery_region(target);
        if (strcmp(region.status, "ready") == 0 && flags != 0)
        {
            if (region.overlap && (flags & 2) == 0)
                region.status = "overlap requires flag 2";
            else if (!fresh_projection(proof))
                region.status = "stale proof";
            else
            {
                bool decoded = true;
                for (const auto &removal : region.removals)
                    if (!del_items(removal.start_ea, DELIT_SIMPLE, removal.size()))
                    {
                        decoded = false;
                        break;
                    }
                for (const auto &[address, size] : region.instructions)
                    if (!decoded || create_insn(address) != size)
                    {
                        decoded = false;
                        break;
                    }
                if (!decoded || !add_func(target, region.end))
                    region.status = "recovery incomplete after item removal";
                else
                {
                    region.status = "recovered";
                    ++recovered;
                }
                std::vector<uint8_t> after(region.bytes.size());
                if (!chernobog::ida_memory::read_exact(after.data(), after.size(),
                                                       region.clear_start) ||
                    after != region.bytes)
                    region.status = "native bytes changed externally";
            }
        }
        if (count++)
            result += ',';
        result.cat_sprnt(
            "{\"site\":%llu,\"target\":%llu,\"end\":%llu,"
            "\"clear_start\":%llu,\"clear_end\":%llu,\"instructions\":%zu,"
            "\"overlap\":%s,\"status\":\"%s\"}",
            static_cast<unsigned long long>(proof.site), static_cast<unsigned long long>(target),
            static_cast<unsigned long long>(region.end),
            static_cast<unsigned long long>(region.clear_start),
            static_cast<unsigned long long>(region.clear_end), region.instructions.size(),
            region.overlap ? "true" : "false", region.status);
    }
    result.cat_sprnt("],\"recovered\":%zu}", recovered);
    if (recovered)
        mark_cfunc_dirty(function);
    return result;
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
    for (auto it = projected_functions.begin(); it != projected_functions.end();)
        if (it->second.database == database)
            it = projected_functions.erase(it);
        else
            ++it;
}

void indirect_branch_handler_t::restore_projected_function(mba_t *mba)
{
    const auto found = projected_functions.find(mba);
    if (found == projected_functions.end())
        return;
    // A function request has to finish as a function: Hex-Rays caches the
    // result under the microcode's ranges and fails with an internal error
    // when they describe a snippet. The microcode is final by now, so the
    // fragments stay decompiled as extra ranges of the function.
    auto &decompilation = const_cast<decomp_ranges_t &>(mba->get_decomp_ranges());
    if (found->second.database == get_dbctx_id() && decompilation.is_snippet() &&
        mba->entry_ea == found->second.ranges.func_ea)
    {
        decompilation = found->second.ranges;
        // Without the flag, the decompiler rejects saved microcode whose
        // function request carries extra ranges when it loads it again.
        if (!decompilation.ranges.empty())
            mba->set_mba_flags2(MBA2_HAS_OUTLINES);
    }
    projected_functions.erase(found);
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
            for (ea_t ea = fragment.start_ea; ea < fragment.end_ea;)
            {
                const sval_t value = proof.inherited_spd + get_spd(owner, ea) - origin;
                projected[ea] = value;
                insn_t instruction;
                const int size = decode_insn(&instruction, ea);
                if (size <= 0 || ea + ea_t(size) > fragment.end_ea)
                    break;
                ea += ea_t(size);
            }
        }
    }
    points->clear();
    for (const auto &[ea, spd] : projected)
        points->push_back(stkpnt_t{ea, spd});
}

bool indirect_branch_handler_t::is_projected_return(const codegen_t &codegen)
{
    if (!codegen.mba || (!arch::is_arm64() && !arch::is_x86_64()))
        return false;
    if (arch::is_arm64())
    {
        const uint32_t word = uint32_t(get_dword(codegen.insn.ea));
        if (word != 0xD65F03C0U && word != 0xD65F0BFFU && word != 0xD65F0FFFU)
            return false;
    }
    else if (codegen.insn.itype != NN_retn || codegen.insn.Op1.type != o_void)
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
        if (!fresh_projection(proof))
            continue;
        bool connected = false;
        for (int index = 0; index < mba->qty; ++index)
        {
            mblock_t *block = mba->get_mblock(index);
            if (!block->tail || block->tail->ea != site || (block->flags & MBL_FAKE) != 0 ||
                (block->tail->opcode != m_ijmp && !native_tail(block)))
                continue;
            std::vector<std::pair<ea_t, mblock_t *>> destinations;
            for (ea_t target : proof.targets)
            {
                mblock_t *matched = nullptr;
                for (int destination = 0; destination < mba->qty; ++destination)
                    if (mba->get_mblock(destination)->start == target)
                    {
                        if (matched)
                        {
                            matched = nullptr;
                            break; // Ambiguous starts retain the native fallback.
                        }
                        matched = mba->get_mblock(destination);
                    }
                if (matched)
                    destinations.emplace_back(target, matched);
            }
            if (destinations.empty())
                continue;
            minsn_t *jump = block->tail;
            const bool tail_call = native_tail(block);
            if (tail_call && jump->d.t == mop_f && jump->d.f && !jump->d.f->args.empty())
                continue;
            mop_t address = tail_call ? (jump->opcode == m_icall ? jump->r : jump->l) : jump->d;
            if (tail_call && jump->opcode == m_call)
            {
                insn_t native;
                if (decode_insn(&native, site) <= 0)
                    continue;
                if (native.Op1.type == o_reg)
                {
                    if (arch::is_arm64() && chernobog::arm64e::decode(get_dword(site)))
                        continue;
                    const mreg_t native_register = reg2mreg(native.Op1.reg);
                    if (native_register == mr_none)
                        continue;
                    address.make_reg(native_register, 8);
                }
                else if (native.Op1.type != o_near)
                    continue;
            }
            if (!chernobog::bitvector::valid_byte_width(address.size))
                continue;
            // These top-level transfer operands use mop_v as an address;
            // an ordinary mov would instead load the bytes at that address.
            // An indirect call's operand retains its memory-value semantics.
            if (address.t == mop_v && (!tail_call || jump->opcode == m_call))
                address.make_number(address.g, address.size);
            const mreg_t temporary = mba->alloc_kreg(size_t(address.size));
            if (temporary == mr_none)
                continue;
            mop_t selector;
            if (!tail_call)
                selector = jump->r;
            else
                selector.make_number(getseg(site)->sel, 2);
            // Preserve the SDK's frame handling for the root; projected ARM
            // fragments need its omitted frame value made explicit.
            if (arch::is_arm64() && !proof.fragments.empty())
            {
                mop_t slot;
                slot.make_stkvar(mba, mba->tmpstk_size + proof.frame_offset);
                slot.size = NOSIZE;
                auto *frame = new minsn_t(site);
                frame->opcode = m_mov;
                frame->l.t = mop_a;
                frame->l.a = new mop_addr_t(slot, NOSIZE, NOSIZE);
                frame->l.size = 8;
                frame->d.make_reg(reg2mreg(str2reg("X29")), 8);
                block->insert_into_block(frame, jump->prev);
            }
            // Edge discovery is not a context-independent target proof. Test
            // the native target even for a singleton hint, evaluating it once.
            auto *capture = new minsn_t(site);
            capture->opcode = m_mov;
            capture->l = address;
            capture->d.make_reg(temporary, address.size);
            block->insert_into_block(capture, jump->prev);
            mblock_t *fallback = mba->insert_block(mba->qty - 1);
            const ea_t fictitious = mba->alloc_fict_ea(site);
            fallback->start = fictitious;
            fallback->end = fictitious + 1;
            fallback->flags |= MBL_FAKE;
            fallback->flags &= ~(MBL_NORET | MBL_TCAL);
            fallback->type = BLT_0WAY;
            fallback->maxbsp = block->maxbsp;
            fallback->minbstkref = block->minbstkref;
            fallback->minbargref = block->minbargref;
            auto *unresolved = new minsn_t(site);
            unresolved->opcode = m_ijmp;
            unresolved->r = selector;
            unresolved->d.make_reg(temporary, address.size);
            fallback->insert_into_block(unresolved, nullptr);
            jump->opcode = m_jtbl;
            jump->clr_tailcall();
            jump->l.make_reg(temporary, address.size);
            jump->d.erase();
            jump->r.erase();
            jump->r.t = mop_c;
            jump->r.c = new mcases_t;
            jump->r.size = NOSIZE;
            jump->r.c->resize(destinations.size() + 1);
            for (size_t outcome = 0; outcome < destinations.size(); ++outcome)
            {
                jump->r.c->values[outcome].push_back(destinations[outcome].first);
                jump->r.c->targets[outcome] = destinations[outcome].second->serial;
            }
            jump->r.c->targets[destinations.size()] = fallback->serial;
            block->flags &= ~(MBL_NORET | MBL_TCAL);
            block->mark_lists_dirty();
            fallback->mark_lists_dirty();
            mba->mark_chains_dirty();
            connected = true;
            break;
        }
        if (!connected)
            continue;
        if (!proof.fragments.empty())
            mba->set_mba_flags2(MBA2_HAS_OUTLINES);
        for (int index = 0; index < mba->qty; ++index)
        {
            mblock_t *block = mba->get_mblock(index);
            for (const auto &fragment : proof.fragments)
                if (fragment.contains(block->start))
                {
                    block->flags |= MBL_KEEP;
                    ++retained;
                    break;
                }
        }
    }
    deobf::log_verbose("[indirect_branch] Retained %d projected blocks with native-target guards\n",
                       retained);
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
