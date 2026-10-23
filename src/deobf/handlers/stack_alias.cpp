#include "stack_alias.h"

#include "../analysis/arch_utils.h"

#include <deque>
#include <map>
#include <optional>
#include <tuple>
#include <vector>

namespace stack_alias
{
namespace
{
constexpr size_t max_facts = 512;
constexpr size_t max_visits = 100000;
constexpr size_t max_instructions = 1000000;

struct key_t
{
    mopt_t type;
    sval_t offset;
    int size;

    bool operator<(const key_t &other) const
    {
        return std::tie(type, offset, size) < std::tie(other.type, other.offset, other.size);
    }
    bool operator==(const key_t &other) const
    {
        return type == other.type && offset == other.offset && size == other.size;
    }
};

using facts_t = std::map<key_t, sval_t>;

std::optional<key_t> key(const mop_t &operand)
{
    if (operand.size <= 0 || operand.size > 16)
        return std::nullopt;
    if (operand.t == mop_S && operand.s)
        return key_t{mop_S, operand.s->off, operand.size};
    if (operand.t == mop_r)
        return key_t{mop_r, operand.r, operand.size};
    return std::nullopt;
}

// Refine call clobbers only when a separate may-pointer analysis proves that
// no address in this frame reaches a call or escapes through a memory store.
// The proof uses the same calling-convention memory model as Hex-Rays.
struct exposure_t : mop_visitor_t
{
    std::set<key_t> pointers;
    std::set<std::pair<sval_t, int>> addresses;
    bool reads_pointer = false;
    mreg_t stack_register = mr_none;
    mreg_t frame_register = mr_none;
    int pointer_size = 0;
    int frame_size = 0;

    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool target) override
    {
        if (!operand || target)
            return 0;
        if (operand->t == mop_a && operand->a && operand->a->t == mop_S && operand->a->s)
        {
            addresses.emplace(operand->a->s->off, std::max(operand->a->size, 1));
            reads_pointer = true;
        }
        const auto location = key(*operand);
        if (location)
        {
            if (location->type == mop_r && ((location->offset < stack_register + pointer_size &&
                                             stack_register < location->offset + location->size) ||
                                            (location->offset < frame_register + pointer_size &&
                                             frame_register < location->offset + location->size)))
            {
                // A raw frame base has no bounded object provenance. Even
                // the opt-in object model cannot protect an adjacent cell.
                addresses.emplace(0, frame_size);
                reads_pointer = true;
            }
            for (const auto &pointer : pointers)
                if (pointer.type == location->type &&
                    pointer.offset < location->offset + location->size &&
                    location->offset < pointer.offset + pointer.size)
                    reads_pointer = true;
        }
        return 0;
    }
};

mop_t storage(mba_t *mba, const key_t &key);

std::set<key_t> private_cells(mba_t *mba)
{
    if (mba->maturity < MMAT_CALLS)
        return {};
    qstring object_option;
    const bool bounded_objects =
        qgetenv("CHERNOBOG_STACK_ALIAS_OBJECTS", &object_option) && object_option == "1";
    using pointers_t = std::set<key_t>;
    std::vector<pointers_t> outputs(static_cast<size_t>(mba->qty));
    pointers_t candidates;
    exposure_t exposure;
    exposure.pointer_size = arch::get_ptr_size();
    exposure.stack_register = reg2mreg(str2reg(exposure.pointer_size == 8 ? "rsp" : "esp"));
    exposure.frame_register = reg2mreg(str2reg(exposure.pointer_size == 8 ? "rbp" : "ebp"));
    if (exposure.stack_register == mr_none || exposure.frame_register == mr_none)
        return {};
    const sval_t frame_size = mba->tmpstk_size + mba->frsize;
    if (frame_size < 0 || frame_size > INT_MAX)
        return {};
    exposure.frame_size = static_cast<int>(frame_size);
    bool changed = true;
    size_t rounds = 0;
    size_t inspected = 0;
    while (changed)
    {
        changed = false;
        if (++rounds > 64 || user_cancelled())
            return {};
        for (int i = 0; i < mba->qty; ++i)
        {
            mblock_t *block = mba->get_mblock(i);
            exposure.pointers.clear();
            for (int predecessor : block->predset)
            {
                if (predecessor < 0 || predecessor >= mba->qty)
                    return {};
                exposure.pointers.insert(outputs[predecessor].begin(), outputs[predecessor].end());
            }
            for (minsn_t *ins = block->head; ins; ins = ins->next)
            {
                if (++inspected > max_instructions * 8)
                    return {};
                if (ins->is_assert())
                    continue;
                exposure.reads_pointer = false;
                ins->for_all_ops(exposure);
                const minsn_t *call = ins->find_call(true);
                if (call && (call->d.t != mop_f || (exposure.reads_pointer && !bounded_objects)))
                {
                    deobf::log_verbose("[stack_alias] Frame may escape through call at %a: %s\n",
                                       ins->ea, ins->dstr());
                    return {};
                }
                if (ins->opcode == m_stx)
                {
                    exposure.reads_pointer = false;
                    ins->l.for_all_ops(exposure);
                    if (exposure.reads_pointer)
                    {
                        deobf::log_verbose("[stack_alias] Frame may escape through store at %a\n",
                                           ins->ea);
                        return {};
                    }
                }
                exposure.reads_pointer = false;
                ins->l.for_all_ops(exposure);
                ins->r.for_all_ops(exposure);
                const auto destination = ins->modifies_d() ? key(ins->d) : std::nullopt;
                const bool derived = exposure.reads_pointer;
                if (derived && ins->modifies_d() && !destination && ins->opcode != m_stx &&
                    !is_mcode_call(ins->opcode))
                {
                    deobf::log_verbose(
                        "[stack_alias] Frame may escape through assignment at %a: %s\n", ins->ea,
                        ins->dstr());
                    return {};
                }
                // May-pointer facts survive a possibly aliasing memory write:
                // it may leave the old pointer intact. Only definite writes
                // kill them; source provenance is sampled before that kill.
                const auto definitions = block->build_def_list(*ins, MUST_ACCESS);
                for (auto it = exposure.pointers.begin(); it != exposure.pointers.end();)
                {
                    mlist_t location;
                    block->append_use_list(&location, storage(mba, *it), MUST_ACCESS);
                    it = definitions.has_common(location) ? exposure.pointers.erase(it)
                                                          : std::next(it);
                }
                if (destination && derived)
                {
                    exposure.pointers.insert(*destination);
                    candidates.insert(*destination);
                }
                if (exposure.pointers.size() > max_facts)
                    return {};
            }
            if (outputs[i] != exposure.pointers)
            {
                outputs[i] = exposure.pointers;
                changed = true;
            }
        }
    }
    pointers_t result;
    for (const auto &pointer : candidates)
    {
        if (pointer.type != mop_S)
            continue;
        const bool exposed = std::any_of(exposure.addresses.begin(), exposure.addresses.end(),
                                         [&](const auto &range)
                                         {
                                             return pointer.offset < range.first + range.second &&
                                                    range.first < pointer.offset + pointer.size;
                                         });
        if (!exposed)
            result.insert(pointer);
    }
    deobf::log_verbose("[stack_alias] Proved %zu private pointer cells in %a\n", result.size(),
                       mba->entry_ea);
    return result;
}

mop_t storage(mba_t *mba, const key_t &key)
{
    mop_t result;
    if (key.type == mop_S)
        result.make_stkvar(mba, key.offset);
    else
        result.make_reg(static_cast<mreg_t>(key.offset), key.size);
    result.size = key.size;
    return result;
}

std::optional<sval_t> address(const mop_t &operand, const facts_t &facts, int pointer_size,
                              unsigned depth = 0)
{
    if (operand.size != pointer_size || depth > 16)
        return std::nullopt;
    if (operand.t == mop_a && operand.a && operand.a->t == mop_S && operand.a->s)
        return operand.a->s->off;
    const auto location = key(operand);
    if (location)
    {
        const auto found = facts.find(*location);
        return found == facts.end() ? std::nullopt : std::optional<sval_t>(found->second);
    }
    if (operand.t == mop_d && operand.d && operand.d->opcode == m_mov)
        return address(operand.d->l, facts, pointer_size, depth + 1);
    // Arithmetic on a stack address is deliberately not admitted here. It
    // needs a separate bounds proof before it becomes a direct stack access.
    return std::nullopt;
}

bool stack_access(mba_t *mba, sval_t offset, int size)
{
    const sval_t end = mba->tmpstk_size + mba->frsize;
    return size > 0 && size <= 16 && offset >= 0 && offset <= end && size <= end - offset;
}

bool normalize(minsn_t &instruction, mba_t *mba, const facts_t &facts, int pointer_size)
{
    if ((instruction.opcode != m_stx && instruction.opcode != m_ldx) ||
        (instruction.iprops & IPROP_EXTSTX) != 0)
        return false;
    // Only the architecture's ordinary flat data segment is eligible. An
    // FS/GS or other segment-relative access is not an ordinary stack access.
    const mop_t &segment = instruction.opcode == m_stx ? instruction.r : instruction.l;
    if (segment.t != mop_r || segment.r != reg2mreg(str2reg("ds")))
        return false;
    const mop_t &pointer = instruction.opcode == m_stx ? instruction.d : instruction.r;
    const int size = instruction.opcode == m_stx ? instruction.l.size : instruction.d.size;
    const auto offset = address(pointer, facts, pointer_size);
    if (!offset || !stack_access(mba, *offset, size))
        return false;
    mop_t slot;
    slot.make_stkvar(mba, *offset);
    slot.size = size;
    if (instruction.opcode == m_stx)
        instruction.d = slot;
    else
        instruction.l = slot;
    instruction.r.erase();
    instruction.opcode = m_mov;
    return true;
}

void transfer(mblock_t *block, const minsn_t &original, facts_t &facts, int pointer_size,
              const std::set<key_t> &private_slots, bool apply, int &changes)
{
    minsn_t instruction(original);
    const bool normalized = normalize(instruction, block->mba, facts, pointer_size);
    const auto destination = instruction.opcode == m_mov ? key(instruction.d) : std::nullopt;
    const auto value =
        instruction.opcode == m_mov ? address(instruction.l, facts, pointer_size) : std::nullopt;
    const mlist_t definitions = block->build_def_list(instruction, MAY_ACCESS);
    const bool calls = instruction.contains_call(true);
    const mlist_t definite = calls ? block->build_def_list(instruction, MUST_ACCESS) : mlist_t();
    for (auto it = facts.begin(); it != facts.end();)
    {
        mlist_t location;
        const mop_t operand = storage(block->mba, it->first);
        block->append_use_list(&location, operand, MUST_ACCESS);
        const bool private_call =
            calls && private_slots.count(it->first) != 0 && !definite.has_common(location);
        it = !private_call && definitions.has_common(location) ? facts.erase(it) : std::next(it);
    }
    if (destination && destination->size == pointer_size && value && facts.size() < max_facts)
        facts[*destination] = *value;
    if (apply && normalized)
    {
        auto &target = const_cast<minsn_t &>(original);
        // Assign only opcode/operands: copying a whole instruction would also
        // replace its links in the owning block's instruction list.
        target.opcode = instruction.opcode;
        target.l = instruction.l;
        target.r = instruction.r;
        target.d = instruction.d;
        ++changes;
        block->mark_lists_dirty();
    }
}

facts_t incoming(mblock_t *block, const std::vector<std::optional<facts_t>> &outputs)
{
    facts_t result;
    bool first = true;
    for (int predecessor : block->predset)
    {
        if (predecessor < 0 || predecessor >= int(outputs.size()) || !outputs[predecessor])
            continue;
        if (first)
        {
            result = *outputs[predecessor];
            first = false;
            continue;
        }
        const auto &other = *outputs[predecessor];
        for (auto it = result.begin(); it != result.end();)
        {
            const auto found = other.find(it->first);
            it = found == other.end() || found->second != it->second ? result.erase(it)
                                                                     : std::next(it);
        }
    }
    return result;
}
} // namespace

int run(mbl_array_t *mba)
{
    if (!mba || mba->qty < 2 || mba->qty > 100000 || !arch::is_x86())
        return 0;
    size_t count = 0;
    bool candidate = false;
    for (int i = 0; i < mba->qty; ++i)
        for (const minsn_t *ins = mba->get_mblock(i)->head; ins; ins = ins->next)
        {
            if (++count > max_instructions)
                return 0;
            // A later discovered indirect edge could add a reaching pointer
            // definition. Do not freeze an alias proof on an incomplete CFG.
            if (ins->opcode == m_ijmp || ins->opcode == m_ext)
                return 0;
            candidate |= ins->opcode == m_stx || ins->opcode == m_ldx;
        }
    if (!candidate)
        return 0;

    const int pointer_size = arch::get_ptr_size();
    const auto private_slots = private_cells(mba);
    std::vector<std::optional<facts_t>> outputs(static_cast<size_t>(mba->qty));
    std::vector<bool> queued(static_cast<size_t>(mba->qty), false);
    std::deque<int> work{0};
    queued[0] = true;
    size_t visits = 0;
    size_t instructions = 0;
    int ignored = 0;
    while (!work.empty())
    {
        if (++visits > max_visits || user_cancelled())
            return 0;
        const int index = work.front();
        work.pop_front();
        queued[index] = false;
        mblock_t *block = mba->get_mblock(index);
        facts_t facts = index == 0 ? facts_t{} : incoming(block, outputs);
        for (const minsn_t *ins = block->head; ins; ins = ins->next)
        {
            if (++instructions > max_instructions * 8)
                return 0;
            transfer(block, *ins, facts, pointer_size, private_slots, false, ignored);
        }
        if (outputs[index] && *outputs[index] == facts)
            continue;
        outputs[index] = std::move(facts);
        for (int successor : block->succset)
            if (successor >= 0 && successor < mba->qty && !queued[successor])
            {
                work.push_back(successor);
                queued[successor] = true;
            }
    }

    int changes = 0;
    for (int index = 0; index < mba->qty; ++index)
    {
        if (!outputs[index])
            continue;
        mblock_t *block = mba->get_mblock(index);
        facts_t facts = index == 0 ? facts_t{} : incoming(block, outputs);
        for (const minsn_t *ins = block->head; ins; ins = ins->next)
            transfer(block, *ins, facts, pointer_size, private_slots, true, changes);
    }
    if (changes)
    {
        mba->mark_chains_dirty();
        deobf::log("[stack_alias] Resolved %d exact stack accesses\n", changes);
    }
    return changes;
}
} // namespace stack_alias
