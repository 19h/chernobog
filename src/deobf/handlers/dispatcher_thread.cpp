#include "dispatcher_thread.h"

#include "../analysis/opaque_eval.h"
#include "../../common/bitvector.h"

#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

namespace dispatcher_thread
{
namespace
{
struct key_t
{
    mopt_t type;
    sval_t id;
    int size;
    bool operator<(const key_t &other) const
    {
        return std::tie(type, id, size) < std::tie(other.type, other.id, other.size);
    }
};
using values_t = std::map<key_t, uint64_t>;

std::optional<key_t> key(const mop_t &operand)
{
    if (operand.size <= 0 || operand.size > 8)
        return std::nullopt;
    if (operand.t == mop_S && operand.s)
        return key_t{mop_S, operand.s->off, operand.size};
    if (operand.t == mop_r)
        return key_t{mop_r, operand.r, operand.size};
    return std::nullopt;
}

bool substitute(mop_t &operand, const values_t &values, unsigned depth = 0)
{
    if (depth > 32 || operand.is_undef_val() || operand.probably_floating())
        return false;
    if (operand.t == mop_z || operand.t == mop_n)
        return true;
    if (operand.t == mop_d && operand.d)
    {
        if (operand.d->has_side_effects(true))
            return false;
        return substitute(operand.d->l, values, depth + 1) &&
               substitute(operand.d->r, values, depth + 1);
    }
    const auto location = key(operand);
    if (!location)
        return false;
    const auto found = values.find(*location);
    if (found != values.end())
    {
        operand.make_number(found->second, operand.size);
        return true;
    }
    // Comparisons commonly read EAX after the dispatcher zero-extended a
    // state into RAX. A narrower read is determined by an enclosing exact
    // value; a wider read is never invented from an incomplete definition.
    for (const auto &[known, value] : values)
    {
        if (known.type != location->type || known.id > location->id || known.size < location->size)
            continue;
        const uint64_t delta = uint64_t(location->id) - uint64_t(known.id);
        if (delta > uint64_t(known.size - location->size))
            continue;
        const unsigned byte_offset = known.type == mop_S && inf_is_be()
                                         ? known.size - location->size - unsigned(delta)
                                         : unsigned(delta);
        operand.make_number(
            chernobog::bitvector::truncate(value >> (8 * byte_offset), location->size),
            location->size);
        return true;
    }
    return false;
}

void invalidate(values_t &values, const minsn_t &instruction, mblock_t *block)
{
    const mlist_t definitions = block->build_def_list(instruction, MAY_ACCESS);
    for (auto it = values.begin(); it != values.end();)
    {
        mop_t operand;
        if (it->first.type == mop_S)
            operand.make_stkvar(block->mba, it->first.id);
        else
            operand.make_reg(static_cast<mreg_t>(it->first.id), it->first.size);
        operand.size = it->first.size;
        mlist_t location;
        block->append_use_list(&location, operand, MUST_ACCESS);
        it = definitions.has_common(location) ? values.erase(it) : std::next(it);
    }
}

bool assignment(const minsn_t &ins, mblock_t *block, values_t &values)
{
    if (ins.opcode == m_ext)
    {
        values.clear();
        return false;
    }
    if (ins.is_mbarrier() || ins.is_persistent() || ins.is_fpinsn())
    {
        invalidate(values, ins, block);
        return false;
    }
    if (ins.opcode == m_nop || ins.is_assert())
        return true;
    minsn_t expression(ins);
    const auto destination = key(ins.d);
    std::optional<uint64_t> result;
    if (destination && !ins.has_side_effects(true) && substitute(expression.l, values) &&
        substitute(expression.r, values))
        result = opaque_eval_t::evaluate_expr(&expression);
    invalidate(values, ins, block);
    if (destination && result && values.size() < 512)
        values[*destination] = *result;
    return destination && result.has_value();
}

std::optional<int> successor(mblock_t *block, const values_t &values)
{
    const minsn_t *tail = block->tail;
    if (!tail)
        return block->nsucc() == 1 ? std::optional<int>(block->succ(0)) : std::nullopt;
    if (tail->opcode == m_goto && tail->l.t == mop_b && block->nsucc() == 1 &&
        block->succ(0) == tail->l.b)
        return tail->l.b;
    if (block->nsucc() == 1 && tail->opcode != m_goto && tail->opcode != m_ret &&
        tail->opcode != m_ijmp && tail->opcode != m_jtbl && !is_mcode_jcond(tail->opcode) &&
        !tail->contains_call(true))
        return block->succ(0);
    if (!is_mcode_jcond(tail->opcode) || tail->d.t != mop_b || block->nsucc() != 2)
        return std::nullopt;
    minsn_t condition(*tail);
    if (!substitute(condition.l, values) || !substitute(condition.r, values))
        return std::nullopt;
    bool taken = false;
    if (!opaque_eval_t::evaluate_condition(&condition, &taken))
        return std::nullopt;
    bool found_taken = false;
    int other = -1;
    for (int target : block->succset)
        if (target == tail->d.b)
            found_taken = true;
        else
            other = target;
    if (!found_taken || other < 0)
        return std::nullopt;
    return taken ? tail->d.b : other;
}

struct rewrite_t
{
    int source;
    int target;
    std::vector<minsn_t> assignments;
};

std::optional<rewrite_t> trace(mba_t *mba, int source, int first, values_t values, bool compared)
{
    rewrite_t rewrite{source, first, {}};
    std::set<int> visited{source};
    for (unsigned step = 0; step < 64; ++step)
    {
        const int current = rewrite.target;
        if (current < 0 || current >= mba->qty || !visited.insert(current).second)
            return std::nullopt;
        mblock_t *next = mba->get_mblock(current);
        values_t candidate_values = values;
        std::vector<minsn_t> candidate_assignments;
        bool complete = true;
        for (const minsn_t *ins = next->head; ins; ins = ins->next)
        {
            if (ins == next->tail && (ins->opcode == m_goto || is_mcode_jcond(ins->opcode)))
                break;
            if (!assignment(*ins, next, candidate_values))
            {
                complete = false;
                break;
            }
            if (ins->opcode != m_nop && !ins->is_assert())
            {
                if (rewrite.assignments.size() + candidate_assignments.size() >= 32)
                {
                    complete = false;
                    break;
                }
                // The original expression's value is proved at this exact
                // path position. Emit that value with fresh value-number
                // metadata rather than transplanting another block's SSA
                // annotations and temporary-expression dependencies.
                const auto destination = key(ins->d);
                if (!destination || candidate_values.count(*destination) == 0)
                {
                    complete = false;
                    break;
                }
                minsn_t copy(ins->ea);
                copy.opcode = m_mov;
                copy.l.make_number(candidate_values.at(*destination), ins->d.size);
                copy.d = ins->d;
                copy.d.valnum = 0;
                candidate_assignments.emplace_back(copy);
            }
        }
        if (!complete || rewrite.assignments.size() + candidate_assignments.size() > 32)
            return compared ? std::optional<rewrite_t>(std::move(rewrite)) : std::nullopt;
        const auto target = successor(next, candidate_values);
        if (!target)
            return compared ? std::optional<rewrite_t>(std::move(rewrite)) : std::nullopt;
        compared |= next->tail && is_mcode_jcond(next->tail->opcode);
        values = std::move(candidate_values);
        for (const auto &ins : candidate_assignments)
            rewrite.assignments.emplace_back(ins);
        rewrite.target = *target;
    }
    return std::nullopt;
}

values_t outgoing(mblock_t *block)
{
    values_t values;
    for (const minsn_t *ins = block->head; ins; ins = ins->next)
    {
        if (ins == block->tail && (ins->opcode == m_goto || is_mcode_jcond(ins->opcode)))
            break;
        assignment(*ins, block, values);
    }
    return values;
}

std::optional<rewrite_t> analyze(mba_t *mba, int source)
{
    mblock_t *block = mba->get_mblock(source);
    if (!block->tail || (block->nsucc() != 1 && !is_mcode_jcond(block->tail->opcode)))
        return std::nullopt;
    values_t values = outgoing(block);
    if (values.empty())
        return std::nullopt;
    const auto first = successor(block, values);
    return first
               ? trace(mba, source, *first, std::move(values), is_mcode_jcond(block->tail->opcode))
               : std::nullopt;
}

void remove_predecessor(mblock_t *block, int predecessor)
{
    auto found = std::find(block->predset.begin(), block->predset.end(), predecessor);
    if (found != block->predset.end())
        block->predset.erase(found);
    // Only the edge changed. Keep the target's instruction use/def lists,
    // particularly the return-use list of a stop block after call analysis.
}

struct conditional_t
{
    minsn_t branch;
    values_t values;
    std::vector<minsn_t> prefix;
    int fallthrough;
    int taken;
};

struct clear_value_numbers_t : mop_visitor_t
{
    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool) override
    {
        if (operand)
            operand->valnum = 0;
        return 0;
    }
};

// A shared conditional move may merge unrelated pairs of state constants.
// Follow a single incoming edge with its exact values until that condition,
// so each pair can be dispatched without losing its predecessor context.
std::optional<conditional_t> find_conditional(mba_t *mba, int source, int first, values_t values)
{
    std::set<int> visited{source};
    std::vector<minsn_t> prefix;
    int current = first;
    for (unsigned step = 0; step < 64; ++step)
    {
        if (user_cancelled() || current < 0 || current >= mba->qty ||
            !visited.insert(current).second)
            return std::nullopt;
        mblock_t *block = mba->get_mblock(current);
        for (const minsn_t *ins = block->head; ins; ins = ins->next)
        {
            if (ins == block->tail && (ins->opcode == m_goto || is_mcode_jcond(ins->opcode)))
                break;
            if (!assignment(*ins, block, values))
                return std::nullopt;
            if (ins->opcode == m_nop || ins->is_assert())
                continue;
            const auto destination = key(ins->d);
            if (!destination || values.count(*destination) == 0 || prefix.size() >= 32)
                return std::nullopt;
            minsn_t copy(ins->ea);
            copy.opcode = m_mov;
            copy.l.make_number(values.at(*destination), ins->d.size);
            copy.d = ins->d;
            copy.d.valnum = 0;
            prefix.emplace_back(copy);
        }
        const auto next = successor(block, values);
        if (next)
        {
            current = *next;
            continue;
        }
        const minsn_t *branch = block->tail;
        if (!branch || !is_mcode_jcond(branch->opcode) || branch->d.t != mop_b ||
            block->nsucc() != 2 || branch->has_side_effects(true))
            return std::nullopt;
        int fallthrough = -1;
        for (int target : block->succset)
            if (target != branch->d.b)
                fallthrough = target;
        if (fallthrough != current + 1 || branch->d.b < 0 || branch->d.b >= mba->qty)
            return std::nullopt;
        return conditional_t{*branch, std::move(values), std::move(prefix), fallthrough,
                             branch->d.b};
    }
    return std::nullopt;
}

// A conditional state assignment often merges through a shared store before
// dispatching. Preserve that store on each original arm, without evaluating
// the runtime condition twice or assuming its value at the merge.
int thread_conditional(mba_t *mba)
{
    for (int index = 0; index < mba->qty; ++index)
    {
        if (user_cancelled())
            return 0;
        mblock_t *source = mba->get_mblock(index);
        minsn_t *branch = source->tail;
        if (!branch)
            continue;
        auto values = outgoing(source);
        if (values.empty())
            continue;
        std::optional<conditional_t> shared;
        int taken = -1;
        int fallthrough = -1;
        if (is_mcode_jcond(branch->opcode) && branch->d.t == mop_b && source->nsucc() == 2 &&
            !successor(source, values))
        {
            taken = branch->d.b;
            for (int target : source->succset)
                if (target != taken)
                    fallthrough = target;
            if (fallthrough != index + 1 || taken < 0 || taken >= mba->qty)
                continue;
        }
        else if (source->nsucc() == 1)
        {
            const auto first = successor(source, values);
            if (!first)
                continue;
            shared = find_conditional(mba, index, *first, values);
            if (!shared)
                continue;
            values = shared->values;
            taken = shared->taken;
            fallthrough = shared->fallthrough;
        }
        else
            continue;
        auto false_path = trace(mba, index, fallthrough, values, false);
        auto true_path = trace(mba, index, taken, values, false);
        if ((!false_path || false_path->target == fallthrough) &&
            (!true_path || true_path->target == taken))
            continue;
        const rewrite_t plans[] = {
            false_path ? *false_path : rewrite_t{index, fallthrough, {}},
            true_path ? *true_path : rewrite_t{index, taken, {}},
        };
        mblock_t *targets[] = {mba->get_mblock(plans[0].target), mba->get_mblock(plans[1].target)};
        const auto old_successors = source->succset;
        for (int target : old_successors)
            remove_predecessor(mba->get_mblock(target), source->serial);
        source->succset.clear();
        if (shared)
        {
            if (branch->opcode != m_goto)
            {
                branch = new minsn_t(shared->branch.ea);
                source->insert_into_block(branch, source->tail);
            }
            for (const auto &ins : shared->prefix)
                source->insert_into_block(new minsn_t(ins), branch->prev);
            branch->opcode = shared->branch.opcode;
            branch->l = shared->branch.l;
            branch->r = shared->branch.r;
            branch->d = shared->branch.d;
            clear_value_numbers_t clear_value_numbers;
            branch->for_all_ops(clear_value_numbers);
            source->type = BLT_2WAY;
        }
        mblock_t *bridges[2];
        for (int arm = 0; arm < 2; ++arm)
        {
            mblock_t *bridge = mba->insert_block(source->serial + 1 + arm);
            bridges[arm] = bridge;
            bridge->start = mba->alloc_fict_ea(branch->ea);
            bridge->end = bridge->start + 1;
            bridge->flags |= MBL_FAKE;
            bridge->type = BLT_1WAY;
            bridge->maxbsp = source->maxbsp;
            bridge->minbstkref = source->minbstkref;
            bridge->minbargref = source->minbargref;
            minsn_t *last = nullptr;
            for (const auto &ins : plans[arm].assignments)
            {
                last = new minsn_t(ins);
                bridge->insert_into_block(last, bridge->tail);
            }
            auto *jump = new minsn_t(bridge->start);
            jump->opcode = m_goto;
            jump->l.make_blkref(targets[arm]->serial);
            bridge->insert_into_block(jump, last);
        }
        // The second insertion may renumber the first arm's destination.
        for (int arm = 0; arm < 2; ++arm)
        {
            auto *bridge = bridges[arm];
            bridge->tail->l.make_blkref(targets[arm]->serial);
            bridge->predset.push_back(source->serial);
            bridge->succset.push_back(targets[arm]->serial);
            targets[arm]->predset.push_back(bridge->serial);
            std::sort(targets[arm]->predset.begin(), targets[arm]->predset.end());
            bridge->mark_lists_dirty();
            source->succset.push_back(bridge->serial);
        }
        branch->d.make_blkref(bridges[1]->serial);
        source->mark_lists_dirty();
        mba->mark_chains_dirty();
        return 1;
    }
    return 0;
}
} // namespace

static int run_once(mbl_array_t *mba)
{
    if (!mba || mba->maturity < MMAT_LOCOPT || mba->maturity > MMAT_GLBOPT2 || mba->qty > 10000)
        return 0;
    std::vector<rewrite_t> rewrites;
    size_t copies = 0;
    for (int i = 0; i < mba->qty; ++i)
    {
        if (user_cancelled())
            return 0;
        auto rewrite = analyze(mba, i);
        if (rewrite &&
            (mba->get_mblock(i)->nsucc() != 1 || rewrite->target != mba->get_mblock(i)->succ(0)))
        {
            copies += rewrite->assignments.size();
            if (copies > 4096)
                break;
            rewrites.push_back(std::move(*rewrite));
        }
    }
    for (const auto &rewrite : rewrites)
    {
        mblock_t *source = mba->get_mblock(rewrite.source);
        const auto old_targets = source->succset;
        // Paths are proved on the same snapshot. Copy their original
        // assignments even if another source edge has since been threaded.
        minsn_t *jump = source->tail;
        if (jump->opcode != m_goto && !is_mcode_jcond(jump->opcode))
        {
            jump = new minsn_t(source->tail->ea);
            source->insert_into_block(jump, source->tail);
        }
        for (const auto &assignment : rewrite.assignments)
            source->insert_into_block(new minsn_t(assignment), jump->prev);
        jump->opcode = m_goto;
        jump->l.make_blkref(rewrite.target);
        jump->r.erase();
        jump->d.erase();
        source->type = BLT_1WAY;
        source->succset.clear();
        source->succset.push_back(rewrite.target);
        for (int old_target : old_targets)
        {
            mblock_t *old = mba->get_mblock(old_target);
            auto predecessor = std::find(old->predset.begin(), old->predset.end(), rewrite.source);
            if (predecessor != old->predset.end())
                old->predset.erase(predecessor);
        }
        mblock_t *target = mba->get_mblock(rewrite.target);
        if (std::find(target->predset.begin(), target->predset.end(), rewrite.source) ==
            target->predset.end())
            target->predset.push_back(rewrite.source);
        std::sort(target->predset.begin(), target->predset.end());
        source->mark_lists_dirty();
    }
    if (!rewrites.empty())
    {
        mba->mark_chains_dirty();
        deobf::log("[dispatcher_thread] Resolved %zu exact dispatcher paths\n", rewrites.size());
    }
    return static_cast<int>(rewrites.size());
}

int run(mbl_array_t *mba)
{
    if (!mba || mba->maturity < MMAT_LOCOPT || mba->maturity > MMAT_GLBOPT2 || mba->qty > 10000)
        return 0;
    int changes = 0;
    // An optblock callback may still own a bypassed block. Leave block
    // deletion to the decompiler after the callback has returned.
    for (unsigned round = 0; round < 8; ++round)
    {
        int current = run_once(mba);
        if (deobf::debug_enabled())
            mba->verify(true);
        current += thread_conditional(mba);
        if (deobf::debug_enabled())
            mba->verify(true);
        changes += current;
        if (current == 0)
            break;
    }
    return changes;
}
} // namespace dispatcher_thread
