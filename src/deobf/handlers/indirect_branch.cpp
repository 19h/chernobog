#include "indirect_branch.h"

#include "../analysis/arch_utils.h"
#include "../analysis/opaque_eval.h"
#include "../analysis/finite_targets.h"
#include "../../common/arm64_branch.h"
#include "../../common/arm64e.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"
#include "../../hybrid/z3_bridge.hpp"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include <intel.hpp>
#include "../../common/warn_on.h"

#include <unordered_map>
#include <gdl.hpp>
#include <frame.hpp>

namespace
{

constexpr int MAX_TARGET_EVAL_DEPTH = 16;

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
    if (old != sites.end() && old->second.targets == proof.targets &&
        old->second.fragments == proof.fragments && fresh_projection(old->second))
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

int lower_two_way(mbl_array_t *mba, mblock_t *src, const mop_t &condition,
                  std::array<mblock_t *, 2> destinations,
                  const chernobog::finite_targets_t *proof = nullptr)
{
    if (!destinations[0] || !destinations[1] || destinations[0] == destinations[1])
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
        finite.condition.has_side_effects(true))
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
        const auto finite =
            chernobog::evaluate_finite_targets(ijmp->d, ijmp, src, false, arch::is_x86_64());
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
            if (finite->authentication_guarded)
                comment += " (authentication retained)";
            if (std::any_of(
                    finite->targets.begin(), finite->targets.end(), [](ea_t address)
                    { return !is_code(get_flags(address)) || !is_head(get_flags(address)); }))
                comment += " (disassembly boundary unresolved)";
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
        // Constant address arithmetic can take the fast evaluator above.
        // Shared-frame admission still needs a dependency-carrying proof,
        // including a plain address origin already canonicalized as mop_v.
        if (ijmp->d.t == mop_v)
        {
            mop_t address;
            address.make_number(target_ea, 8);
            if (const auto direct = chernobog::evaluate_finite_targets(address, ijmp, src))
            {
                qstring comment;
                comment.sprnt("DEOBF: exact indirect target -> %a", target_ea);
                record_projection(mba, ijmp->ea, *direct, comment);
            }
        }
        else if (const auto finite = chernobog::evaluate_finite_targets(ijmp->d, ijmp, src);
                 finite && finite->targets.size() == 1 && finite->targets.front() == target_ea)
        {
            qstring comment;
            comment.sprnt("DEOBF: exact indirect target -> %a", target_ea);
            record_projection(mba, ijmp->ea, *finite, comment);
        }
        // An exact target outside the current MBA cannot become m_goto, but
        // canonicalizing the ijmp operand is still semantics-preserving and
        // exposes a tail target to ctree. Require an executable function entry
        // so an interior address cannot be mislabeled as an external call.
        const segment_t *segment = getseg(target_ea);
        const func_t *target_function = get_func(target_ea);
        if (segment && (segment->perm & SEGPERM_EXEC) != 0 && target_function &&
            target_function->start_ea == target_ea)
        {
            if (!chernobog::preserve_indirect_target_effects(src, ijmp, ijmp->d))
                return 0;
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

    if (!chernobog::preserve_indirect_target_effects(src, ijmp, ijmp->d))
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
            int changed = lower_boolean_switch(mba, blk);
            if (!changed)
            {
                const auto finite =
                    chernobog::evaluate_finite_targets(blk->tail->l, blk->tail, blk);
                if (finite && !finite->condition.empty())
                    changed = lower_conditional_targets(mba, blk, *finite);
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
        decompilation = found->second.ranges;
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
        if (!fresh_projection(proof) || proof.fragments.empty())
            continue;
        bool connected = false;
        for (int index = 0; index < mba->qty; ++index)
        {
            mblock_t *block = mba->get_mblock(index);
            if (!block->tail || block->tail->ea != site ||
                (block->tail->opcode != m_ijmp && !native_tail(block)))
                continue;
            if (proof.targets.empty() || proof.targets.size() > 2)
                continue;
            std::array<mblock_t *, 2> destinations = {nullptr, nullptr};
            for (int destination = 0; destination < mba->qty; ++destination)
                for (unsigned outcome = 0; outcome < proof.targets.size(); ++outcome)
                    if (mba->get_mblock(destination)->start == proof.targets[outcome])
                        destinations[outcome] = mba->get_mblock(destination);
            if (!destinations[0] || (proof.targets.size() == 2 && !destinations[1]))
                continue;
            minsn_t *jump = block->tail;
            if (native_tail(block))
            {
                // This was a native jump. A projected shared-frame target is
                // internal flow, so the generated tail-call ABI is inapplicable.
                if (jump->d.t == mop_f && jump->d.f && !jump->d.f->args.empty())
                    continue;
                mop_t address = jump->opcode == m_icall ? jump->r : jump->l;
                jump->opcode = m_ijmp;
                jump->l.erase();
                jump->r.erase();
                jump->d = address;
                jump->clr_tailcall();
            }
            if (proof.targets.size() == 1 &&
                !chernobog::preserve_indirect_target_effects(block, jump, jump->d))
                continue;
            // Function-mode generation elides the frame-pointer setup. The
            // extra ranges must see that same frame, rather than an unrelated
            // incoming X29 supplied by their standalone IDB prototypes.
            if (arch::is_arm64())
            {
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
            }
            // Publish control edges before liveness can discard registers
            // consumed by the projected fragments. KEEP alone is insufficient.
            if (proof.targets.size() == 1)
            {
                jump->opcode = m_goto;
                jump->l.make_blkref(destinations[0]->serial);
                jump->r.erase();
                jump->d.erase();
                block->flags &= ~(MBL_NORET | MBL_TCAL);
                block->mark_lists_dirty();
                connected = true;
                continue;
            }
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
            connected = true;
        }
        if (!connected)
            continue;
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
