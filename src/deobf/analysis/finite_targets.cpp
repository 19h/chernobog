#include "finite_targets.h"

#include "../../common/finite_domain.h"
#include "../../common/arm64e.h"
#include "../../common/ida_memory.h"

#include <limits>
#include <chrono>
#include <tuple>

namespace chernobog
{
namespace
{

using finite_domain::Graph;
using finite_domain::Id;
using finite_domain::Op;
constexpr Id invalid = finite_domain::invalid;
using HistoryKey = std::pair<ssize_t, ea_t>;
using ReadKey = std::pair<ea_t, size_t>;
std::map<HistoryKey, std::map<ReadKey, finite_targets_t::dependency_t>> fold_history;

std::optional<uint64_t> read_immutable(uint64_t address, int bytes)
{
    if (!bitvector::valid_byte_width(bytes) || address > uint64_t(BADADDR) - uint64_t(bytes))
        return std::nullopt;
    const segment_t *segment = getseg(ea_t(address));
    if (!segment || (segment->perm & SEGPERM_READ) == 0 || (segment->perm & SEGPERM_WRITE) != 0 ||
        address + uint64_t(bytes) > segment->end_ea || segment->type == SEG_XTRN)
        return std::nullopt;
    return ida_memory::read_integer(ea_t(address), bytes);
}

bool stable_key_interval(ea_t sign, ea_t use)
{
    if (sign == BADADDR || use <= sign || use - sign > 256 || (sign & 3U) || (use & 3U))
        return false;
    func_t *function = get_func(sign);
    if (!function || get_func(use) != function)
        return false;
    for (ea_t ea = sign + 4; ea < use; ea += 4)
    {
        insn_t ins;
        if (!func_contains(function, ea) || decode_insn(&ins, ea) != 4 ||
            (ins.get_canon_feature(PH) & (CF_CALL | CF_JUMP | CF_STOP)) != 0)
            return false;
        const uint32_t word = get_dword(ea);
        if ((word & 0xFF000000U) == 0xD4000000U ||
            ((word & 0xFFC00000U) == 0xD5000000U && word != 0xD503201FU && !arm64e::decode(word)))
            return false;
    }
    return true;
}

class Builder
{
  public:
    explicit Builder(const mblock_t *block)
        : graph([this](uint64_t address, int bytes) { return read(address, bytes); }), block_(block)
    {
        if (block_ && block_->mba)
            for (int index = 0; index < block_->mba->qty; ++index)
            {
                const mblock_t *owner = block_->mba->get_mblock(index);
                for (const minsn_t *ins = owner->head; ins; ins = ins->next)
                {
                    if (owners_.size() >= 8192)
                    {
                        bounded_ = false;
                        return;
                    }
                    owners_.emplace(ins, owner);
                }
            }
    }

    Graph graph;
    std::map<uint64_t, mop_t> conditions;
    std::map<uint64_t, std::pair<const mblock_t *, const minsn_t *>> condition_points;
    std::vector<finite_targets_t::dependency_t> dependencies;
    bool authentication_guarded = false;

    Id value(const minsn_t &ins, const minsn_t *before)
    {
        return bounded_ ? instruction(ins, before, 0) : invalid;
    }

    Id operand(const mop_t &op, const minsn_t *before, unsigned depth = 0)
    {
        if (!bounded_ || depth > 96 || !bitvector::valid_byte_width(op.size) || op.is_undef_val())
            return invalid;
        switch (op.t)
        {
        case mop_n:
            return op.nnn ? graph.constant(op.nnn->value, op.size) : invalid;
        case mop_z:
            return graph.constant(0, op.size);
        case mop_a:
            if (op.a && op.a->t == mop_v)
                return graph.constant(op.a->g, op.size);
            if (op.a && op.a->t == mop_S && op.a->s && op.a->oprops == 0 && block_ &&
                op.a->s->mba == block_->mba)
            {
                const auto key =
                    std::make_tuple(op.a->s->off, op.a->size, op.a->insize, op.a->outsize);
                auto [entry, inserted] = address_tokens_.emplace(key, next_token_);
                if (inserted)
                    ++next_token_;
                return graph.variable(entry->second, op.size, unsigned(op.size * 8));
            }
            return invalid;
        case mop_v:
            if (const auto value = read(op.g, op.size))
                return graph.constant(*value, op.size);
            if (op.valnum != 0 && !op.is_undef_val())
                return unknown(7, op.valnum, op.size, nullptr);
            // Repeated nonvolatile reads inside one IR expression observe
            // the same memory state. Distinct top-level instructions keep
            // separate identities unless Hex-Rays supplied a value number.
            return unknown(1, op.g, op.size, before);
        case mop_S:
            return op.s ? stack(op, before, depth + 1) : invalid;
        case mop_r:
            return reg(op, before, depth + 1);
        case mop_d:
            return op.d ? instruction(*op.d, before, depth + 1) : invalid;
        default:
            return invalid;
        }
    }

  private:
    const mblock_t *block_;
    struct SignedPointer
    {
        Id raw;
        Id modifier;
        arm64e::Key key;
        ea_t site;
    };
    std::map<Id, SignedPointer> signed_;
    std::map<std::tuple<mcode_t, Id, Id, int>, Id> predicates_;
    std::map<std::tuple<ea_t, Id, Id, arm64e::Key, const minsn_t *>, Id> signatures_;
    bool bounded_ = true;
    size_t scans_ = 0;
    uint64_t next_token_ = 1;
    using Key = std::tuple<int, uint64_t, int, const minsn_t *>;
    std::map<Key, uint64_t> tokens_;
    std::map<std::tuple<sval_t, int, int, int>, uint64_t> address_tokens_;
    std::map<std::pair<const minsn_t *, int>, Id> definitions_;
    std::map<const minsn_t *, const mblock_t *> owners_;

    std::optional<uint64_t> read(uint64_t address, int bytes)
    {
        const auto value = read_immutable(address, bytes);
        if (value)
        {
            finite_targets_t::dependency_t dependency{ea_t(address), getseg(ea_t(address))->perm,
                                                      std::vector<uint8_t>(size_t(bytes))};
            if (!ida_memory::read_exact(dependency.bytes.data(), dependency.bytes.size(),
                                        dependency.address))
                return std::nullopt;
            dependencies.push_back(std::move(dependency));
        }
        return value;
    }

    uint64_t token(int kind, uint64_t location, int bytes, const minsn_t *epoch)
    {
        const Key key{kind, location, bytes, epoch};
        auto [item, inserted] = tokens_.emplace(key, next_token_);
        if (inserted)
            ++next_token_;
        return item->second;
    }

    Id unknown(int kind, uint64_t location, int bytes, const minsn_t *epoch)
    {
        return graph.variable(token(kind, location, bytes, epoch), bytes, unsigned(bytes * 8));
    }

    const minsn_t *memory_epoch(const minsn_t *before)
    {
        for (const minsn_t *ins = before ? before->prev : nullptr; ins; ins = ins->prev)
        {
            if (++scans_ > 32768)
                return before;
            if (ins->contains_call(true) || ins->opcode == m_ext || ins->opcode == m_stx ||
                ins->d.t == mop_v || ins->d.t == mop_S)
                return ins;
        }
        return nullptr;
    }

    Id local_stack(const mop_t &op, const minsn_t *before, unsigned depth)
    {
        if (!block_ || op.s->mba != block_->mba)
            return invalid;
        for (const minsn_t *ins = before ? before->prev : nullptr; ins; ins = ins->prev)
        {
            if (++scans_ > 32768)
                return invalid;
            if (mcode_modifies_d(ins->opcode) && ins->d.t == mop_S && ins->d.s &&
                ins->d.s->mba == op.s->mba && ins->d.s->off < op.s->off + op.size &&
                op.s->off < ins->d.s->off + ins->d.size)
            {
                if (ins->d.s->off > op.s->off || ins->d.s->off + ins->d.size < op.s->off + op.size)
                    break;
                Id value = instruction(*ins, ins, depth + 1);
                if (value == invalid)
                    return invalid;
                if (op.s->off != ins->d.s->off)
                    value =
                        graph.make(Op::shr, ins->d.size, value,
                                   graph.constant(uint64_t((op.s->off - ins->d.s->off) * 8), 1));
                return graph.make(Op::low, op.size, value);
            }
            if (ins->opcode == m_ext || ins->opcode == m_stx)
                break;
            if (ins->contains_call(true) || ins->is_mbarrier())
            {
                struct Effects : minsn_visitor_t
                {
                    size_t &work;
                    bool safe = true;
                    explicit Effects(size_t &counter) : work(counter) {}
                    int idaapi visit_minsn() override
                    {
                        if (++work > 32768)
                            safe = false;
                        else if (is_mcode_call(curins->opcode))
                            safe &= curins->opcode == m_call && curins->l.t == mop_h &&
                                    curins->l.helper &&
                                    arm64e::helper_instruction(curins->l.helper) &&
                                    curins->d.t == mop_f && curins->d.f &&
                                    curins->d.f->visible_memory.empty() &&
                                    curins->d.f->spoiled.mem.empty();
                        else if (curins->is_mbarrier() || curins->opcode == m_ext ||
                                 curins->opcode == m_stx)
                            safe = false;
                        return safe ? 0 : 1;
                    }
                } effects(scans_);
                // Check every nested call: an intrinsic argument can itself
                // contain a real call that writes the stack slot.
                const_cast<minsn_t *>(ins)->for_all_insns(effects);
                if (!effects.safe)
                    break;
            }
        }
        return unknown(2, uint64_t(op.s->off), op.size, memory_epoch(before));
    }

    Id stack(const mop_t &op, const minsn_t *before, unsigned depth)
    {
        if (PH.id != PLFM_386 || !inf_is_64bit())
            return local_stack(op, before, depth);
        if (!block_ || op.s->mba != block_->mba)
            return invalid;
        const auto owner = owners_.find(before);
        const mblock_t *block = owner == owners_.end() ? block_ : owner->second;
        mlist_t slot;
        block->append_use_list(&slot, op, MUST_ACCESS);
        if (slot.mem.empty())
            return invalid;
        std::set<int> visited;
        const minsn_t *epoch = before;
        const minsn_t *ins = before ? before->prev : nullptr;
        while (block)
        {
            if (!ins)
            {
                epoch = block->head ? block->head : before;
                if (!visited.insert(block->serial).second || block->predset.size() != 1)
                    break;
                const int predecessor = block->predset.front();
                if (predecessor < 0 || predecessor >= block->mba->qty || visited.count(predecessor))
                    break;
                block = block->mba->get_mblock(predecessor);
                ins = block->tail;
                continue;
            }
            epoch = ins;
            if (++scans_ > 32768)
                return invalid;
            if (mcode_modifies_d(ins->opcode) && ins->d.t == mop_S && ins->d.s &&
                ins->d.s->mba == op.s->mba && ins->d.s->off < op.s->off + op.size &&
                op.s->off < ins->d.s->off + ins->d.size)
            {
                if (ins->d.s->off > op.s->off || ins->d.s->off + ins->d.size < op.s->off + op.size)
                    break;
                Id value = instruction(*ins, ins, depth + 1);
                if (value == invalid)
                    return invalid;
                if (op.s->off != ins->d.s->off)
                    value =
                        graph.make(Op::shr, ins->d.size, value,
                                   graph.constant(uint64_t((op.s->off - ins->d.s->off) * 8), 1));
                return graph.make(Op::low, op.size, value);
            }
            if (ins->opcode == m_ext)
                break;
            if (ins->opcode == m_stx || ins->contains_call(true) || ins->is_mbarrier())
            {
                // Use the SDK's complete may-def memory effects. An escaped
                // stack slot stops here; a disjoint unaliased local may retain
                // its reaching definition across ordinary ABI calls.
                const mlist_t effects =
                    block->build_def_list(*ins, MAY_ACCESS | INCLUDE_RESTRICTED);
                if (effects.has_common(slot))
                    break;
                if (!ins->contains_call(true) && ins->is_mbarrier())
                    break;
            }
            ins = ins->prev;
        }
        return unknown(2, uint64_t(op.s->off), op.size, epoch);
    }

    Id reg(const mop_t &op, const minsn_t *before, unsigned depth)
    {
        const auto owner = owners_.find(before);
        const mblock_t *block = owner == owners_.end() ? block_ : owner->second;
        std::set<int> visited;
        const minsn_t *ins = before ? before->prev : nullptr;
        while (block)
        {
            if (!ins)
            {
                if (!visited.insert(block->serial).second || block->predset.size() != 1)
                    break;
                const int predecessor = block->predset.front();
                if (predecessor < 0 || predecessor >= block->mba->qty || visited.count(predecessor))
                    break;
                block = block->mba->get_mblock(predecessor);
                ins = block->tail;
                continue;
            }
            if (++scans_ > 32768)
                return invalid;
            if (ins->d.t == mop_r && ins->d.r < op.r + op.size && op.r < ins->d.r + ins->d.size)
            {
                if (ins->d.r > op.r || ins->d.r + ins->d.size < op.r + op.size)
                    return unknown(3, uint64_t(op.r), op.size, ins);
                const auto key = std::make_pair(ins, ins->d.size);
                auto found = definitions_.find(key);
                Id value;
                if (found == definitions_.end())
                {
                    value = instruction(*ins, ins, depth + 1);
                    if (value == invalid && op.size == 1 && ins->d.size == 1 &&
                        (ins->opcode == m_mul || ins->opcode == m_add || ins->opcode == m_sub))
                    {
                        // Preserve a bounded Boolean input when it is
                        // available. An unsupported arithmetic byte still
                        // admits the conservative domain of all 256 values.
                        value = unknown(6, uint64_t(op.r), 1, ins);
                    }
                    definitions_[key] = value;
                }
                else
                    value = found->second;
                if (value == invalid)
                    return invalid;
                if (op.r != ins->d.r)
                    value = graph.make(Op::shr, ins->d.size, value,
                                       graph.constant(uint64_t((op.r - ins->d.r) * 8), 1));
                return graph.make(Op::low, op.size, value);
            }
            if (ins->opcode == m_ext || (ins->is_mbarrier() && !ins->contains_call(true)))
                return invalid;
            if (ins->contains_call(true))
            {
                // Reaching definitions must stop at ABI clobbers. In
                // particular, never correlate two caller-saved values across
                // a call just because their printed register names agree.
                if (block->build_def_list(*ins, MAY_ACCESS).has_any(op.r, op.size))
                    return unknown(3, uint64_t(op.r), op.size, ins);
            }
            ins = ins->prev;
        }
        return unknown(3, uint64_t(op.r), op.size, nullptr);
    }

    Id helper(const minsn_t &ins, const minsn_t *before, unsigned depth)
    {
        if (ins.opcode != m_call || ins.l.t != mop_h || !ins.l.helper || ins.d.t != mop_f ||
            !ins.d.f)
            return invalid;
        const auto native = arm64e::decode(get_dword(ins.ea));
        if (!native)
            return invalid;
        const auto &arguments = ins.d.f->args;
        if (std::string_view(ins.l.helper) == "__arm64e_load64")
        {
            if (native->kind != arm64e::Kind::load || arguments.size() != 1 ||
                arguments[0].size != 8)
                return invalid;
            return graph.make(Op::load, 8, operand(arguments[0], before, depth + 1));
        }
        const auto primitive = arm64e::helper_instruction(ins.l.helper);
        if (!primitive || primitive->key != native->key ||
            (primitive->kind != native->kind &&
             !(primitive->kind == arm64e::Kind::authenticate &&
               native->kind == arm64e::Kind::load) &&
             !(primitive->kind == arm64e::Kind::branch && native->kind == arm64e::Kind::call)) ||
            arguments.size() != (primitive->kind == arm64e::Kind::strip ? 1 : 2) ||
            std::any_of(arguments.begin(), arguments.end(),
                        [](const auto &arg) { return arg.size != 8; }))
            return invalid;
        if (primitive->kind == arm64e::Kind::generic)
            return unknown(9, ins.ea, 8, before);
        const Id input = operand(arguments[0], before, depth + 1);
        if (input == invalid)
            return invalid;
        if (primitive->kind == arm64e::Kind::sign)
        {
            const Id modifier = operand(arguments[1], before, depth + 1);
            if (modifier == invalid)
                return invalid;
            const auto signature = std::make_tuple(ins.ea, input, modifier, primitive->key, before);
            const auto old = signatures_.find(signature);
            if (old != signatures_.end())
                return old->second;
            const Id signed_value = graph.variable(next_token_++, 8, 64);
            signatures_[signature] = signed_value;
            signed_[signed_value] = {input, modifier, primitive->key, ins.ea};
            return signed_value;
        }
        const auto origin = signed_.find(input);
        if (origin == signed_.end())
        {
            // IDB relocations expose raw address origins, without runtime PAC
            // fields. A combined authenticating branch/load has only these
            // normal-completion addresses; its non-pure IR guard stays live.
            // Standalone AUT/XPAC and arbitrary signed integers get no such
            // interpretation.
            if ((primitive->kind != arm64e::Kind::authenticate ||
                 native->kind != arm64e::Kind::load) &&
                (primitive->kind != arm64e::Kind::branch ||
                 (native->kind != arm64e::Kind::branch && native->kind != arm64e::Kind::call)))
                return invalid;
            const auto addresses = graph.enumerate(input);
            if (!addresses || addresses->results.empty())
                return invalid;
            for (uint64_t address : addresses->results)
            {
                const segment_t *segment = getseg(ea_t(address));
                const flags64_t flags = get_flags(ea_t(address));
                const bool memory = native->kind == arm64e::Kind::load;
                if (!segment || (memory ? (segment->perm & SEGPERM_READ) == 0
                                        : !((segment->perm & SEGPERM_EXEC) && is_code(flags) &&
                                            is_head(flags)) &&
                                              !(segment->type == SEG_XTRN && has_any_name(flags))))
                    return invalid;
            }
            authentication_guarded = true;
            return input;
        }
        if (!stable_key_interval(origin->second.site, ins.ea))
            return invalid;
        // Signing overwrites PAC bits. An arbitrary integer is not an address
        // identity under AUT/XPAC, even when its key and modifier match.
        const auto raw_addresses = graph.enumerate(origin->second.raw);
        if (!raw_addresses || raw_addresses->results.empty() ||
            std::any_of(raw_addresses->results.begin(), raw_addresses->results.end(),
                        [](uint64_t address)
                        {
                            const segment_t *segment = getseg(ea_t(address));
                            return !segment ||
                                   ((segment->perm & (SEGPERM_READ | SEGPERM_EXEC)) == 0 &&
                                    segment->type != SEG_XTRN);
                        }))
            return invalid;
        if (primitive->kind == arm64e::Kind::strip)
            return arm64e::same_strip_domain(primitive->key, origin->second.key)
                       ? origin->second.raw
                       : invalid;
        const Id modifier = operand(arguments[1], before, depth + 1);
        return primitive->key == origin->second.key && modifier == origin->second.modifier
                   ? origin->second.raw
                   : invalid;
    }

    Id instruction(const minsn_t &ins, const minsn_t *before, unsigned depth)
    {
        if (depth > 96 || ins.is_fpinsn())
            return invalid;
        if (ins.opcode == m_call)
            return helper(ins, before, depth);
        if (ins.is_mbarrier())
            return invalid;
        const int bytes = ins.d.size > 0 ? ins.d.size : 8;
        if (!bitvector::valid_byte_width(bytes))
            return invalid;
        auto left = [&] { return operand(ins.l, before, depth + 1); };
        auto right = [&] { return operand(ins.r, before, depth + 1); };
        switch (ins.opcode)
        {
        case m_mov:
        case m_xdu:
        case m_low:
            return graph.make(Op::low, bytes, left());
        case m_xds:
            return graph.make(Op::sign_extend, bytes, left(), invalid, ins.l.size);
        case m_high:
            return graph.make(
                Op::low, bytes,
                graph.make(Op::shr, ins.l.size, left(), graph.constant(uint64_t(bytes * 8), 1)));
        case m_add:
            return graph.make(Op::add, bytes, left(), right());
        case m_sub:
            return graph.make(Op::sub, bytes, left(), right());
        case m_mul:
            return graph.make(Op::mul, bytes, left(), right());
        case m_and:
            return graph.make(Op::bit_and, bytes, left(), right());
        case m_or:
            return graph.make(Op::bit_or, bytes, left(), right());
        case m_xor:
            return graph.make(Op::bit_xor, bytes, left(), right());
        case m_shl:
            return graph.make(Op::shl, bytes, left(), right());
        case m_shr:
            return graph.make(Op::shr, bytes, left(), right());
        case m_sar:
            return graph.make(Op::sar, bytes, left(), right());
        case m_bnot:
            return graph.make(Op::bit_not, bytes, left());
        case m_neg:
            return graph.make(Op::neg, bytes, left());
        case m_lnot:
            return graph.make(Op::logical_not, bytes, left());
        case m_ldx:
        {
            const Id address = right();
            if (address == invalid)
                return invalid;
            if (const auto value = graph.literal(address))
            {
                if (const auto loaded = read(*value, bytes))
                    return graph.constant(*loaded, bytes);
                const segment_t *segment = getseg(ea_t(*value));
                if (segment && (segment->perm & SEGPERM_WRITE) != 0)
                {
                    if (ins.d.valnum != 0 && !ins.d.is_undef_val())
                        return unknown(7, ins.d.valnum, bytes, nullptr);
                    return unknown(1, *value, bytes, before);
                }
            }
            // An unbounded runtime address supplies an unknown value, not
            // an immutable lookup. Abstract its contents before narrowing
            // to a byte; this never substitutes bytes from the database.
            // Bounded lookup addresses still require every read to succeed.
            if (!graph.bounded_inputs(address))
                return unknown(5, uint64_t(address), bytes, before);
            return graph.make(Op::load, bytes, address);
        }
        case m_setz:
        case m_setnz:
        case m_setb:
        case m_setbe:
        case m_seta:
        case m_setae:
        case m_setl:
        case m_setle:
        case m_setg:
        case m_setge:
        {
            // A comparison is always Boolean, even when its data inputs are
            // not enumerable. Preserve the actual comparison for CFG output.
            const Id lhs = left(), rhs = right();
            const auto predicate = std::make_tuple(ins.opcode, lhs, rhs, bytes);
            if (lhs != invalid && rhs != invalid)
            {
                const auto old = predicates_.find(predicate);
                if (old != predicates_.end())
                    return old->second;
            }
            const uint64_t key =
                token(4, uint64_t(reinterpret_cast<uintptr_t>(&ins)), bytes, memory_epoch(before));
            minsn_t comparison(ins.ea);
            comparison.opcode = ins.opcode;
            comparison.l = ins.l;
            comparison.r = ins.r;
            comparison.d.size = bytes;
            mop_t condition;
            condition.create_from_insn(&comparison);
            conditions.emplace(key, std::move(condition));
            const auto owner = owners_.find(before);
            condition_points.emplace(
                key, std::make_pair(owner == owners_.end() ? block_ : owner->second, before));
            const Id value = graph.variable(key, bytes, 1);
            if (lhs != invalid && rhs != invalid)
                predicates_[predicate] = value;
            return value;
        }
        default:
            return invalid;
        }
    }
};

} // namespace

bool preserve_indirect_target_effects(mblock_t *block, minsn_t *top, const mop_t &target,
                                      const minsn_t *selected_call)
{
    if (!target.has_side_effects(true))
        return true;
    if (!block || !top || !bitvector::valid_byte_width(target.size))
        return false;
    struct Calls : minsn_visitor_t
    {
        std::set<const minsn_t *> calls;
        size_t inspected = 0;
        int idaapi visit_minsn() override
        {
            if (++inspected > 32768)
                return 1;
            if (is_mcode_call(curins->opcode))
                calls.insert(curins);
            return 0;
        }
    } allowed, enclosing;
    if (target.t == mop_d && target.d)
        target.d->for_all_insns(allowed);
    if (selected_call)
        allowed.calls.insert(selected_call);
    top->for_all_insns(enclosing);
    if (allowed.inspected > 32768 || enclosing.inspected > 32768 ||
        !std::includes(allowed.calls.begin(), allowed.calls.end(), enclosing.calls.begin(),
                       enclosing.calls.end(), std::less<const minsn_t *>()))
        return false;
    const mreg_t temporary = block->mba->alloc_kreg(size_t(target.size));
    if (temporary == mr_none)
        return false;
    auto *evaluation = new minsn_t(top->ea);
    evaluation->opcode = m_mov;
    evaluation->l = target;
    evaluation->d.make_reg(temporary, target.size);
    block->insert_into_block(evaluation, top->prev);
    block->mark_lists_dirty();
    block->mba->mark_chains_dirty();
    return true;
}

void reset_finite_table_history(ea_t function)
{
    const HistoryKey key{get_dbctx_id(), function};
    fold_history.erase(key);
    if (fold_history.size() >= 32)
        fold_history.erase(fold_history.begin());
}

int fold_finite_table_expressions(mba_t *mba)
{
    if (!mba || mba->qty > 512)
        return 0;
    struct Folder : minsn_visitor_t
    {
        int changes = 0;
        size_t inspected = 0;
        size_t attempted = 0;
        const std::chrono::steady_clock::time_point deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(20);

        int idaapi visit_minsn() override
        {
            if (++inspected > 4096 || attempted >= 32 ||
                std::chrono::steady_clock::now() >= deadline)
                return 1;
            minsn_t *ins = curins;
            if (!blk || !topins || !bitvector::valid_byte_width(ins->d.size) ||
                ins->contains_call(true) || ins->is_mbarrier() || ins->is_fpinsn() ||
                ins->is_persistent() || ins->is_assert() || !mcode_modifies_d(ins->opcode))
                return 0;
            const auto has_load = [](const auto &self, const mop_t &operand, unsigned depth) -> bool
            {
                return depth < 32 && operand.t == mop_d && operand.d &&
                       (operand.d->opcode == m_ldx || self(self, operand.d->l, depth + 1) ||
                        self(self, operand.d->r, depth + 1));
            };
            if (ins->opcode != m_ldx && !has_load(has_load, ins->l, 0) &&
                !has_load(has_load, ins->r, 0))
                return 0;
            ++attempted;
            Builder builder(blk);
            const Id root = builder.value(*ins, topins);
            const auto values = builder.graph.enumerate(root);
            if (!values || values->results.empty() || builder.dependencies.empty() ||
                !std::all_of(values->results.begin(), values->results.end(),
                             [&](uint64_t value) { return value == values->results.front(); }))
                return 0;
            const HistoryKey key{get_dbctx_id(), blk->mba->entry_ea};
            auto history = fold_history[key];
            for (const auto &dependency : builder.dependencies)
                history[{dependency.address, dependency.bytes.size()}] = dependency;
            if (history.size() > 4096)
                return 0;
            fold_history[key] = std::move(history);
            ins->opcode = m_mov;
            ins->l.make_number(values->results.front(), ins->d.size);
            ins->r.erase();
            blk->mark_lists_dirty();
            ++changes;
            return 0;
        }
    } folder;
    mba->for_all_insns(folder);
    if (folder.changes > 0)
        mba->mark_chains_dirty();
    return folder.changes;
}

std::optional<finite_targets_t> evaluate_finite_targets(const mop_t &operand, const minsn_t *before,
                                                        const mblock_t *block, bool allow_imports,
                                                        bool allow_undecoded_code)
{
    if (!before || !block)
        return std::nullopt;
    Builder builder(block);
    const Id root = builder.operand(operand, before);
    const auto values = builder.graph.enumerate(root);
    if (!values || values->results.empty() || builder.graph.failed())
        return std::nullopt;
    finite_targets_t result;
    result.authentication_guarded = builder.authentication_guarded;
    result.dependencies = std::move(builder.dependencies);
    const auto history = fold_history.find({get_dbctx_id(), block->mba->entry_ea});
    if (history != fold_history.end())
        for (const auto &[address, dependency] : history->second)
            result.dependencies.push_back(dependency);
    for (uint64_t value : values->results)
    {
        const ea_t target = ea_t(value);
        const segment_t *segment = getseg(target);
        const flags64_t flags = get_flags(target);
        const bool imported =
            allow_imports && segment && segment->type == SEG_XTRN && has_any_name(flags);
        bool instruction_origin = is_code(flags) && is_head(flags);
        if (!instruction_origin && allow_undecoded_code && segment &&
            (segment->perm & SEGPERM_EXEC) != 0)
        {
            insn_t instruction;
            const int size = decode_insn(&instruction, target);
            instruction_origin = size > 0 && target + ea_t(size) <= segment->end_ea;
        }
        if (!imported && (target == BADADDR || !segment || (segment->perm & SEGPERM_EXEC) == 0 ||
                          !instruction_origin))
            return std::nullopt;
        if (std::find(result.targets.begin(), result.targets.end(), target) == result.targets.end())
            result.targets.push_back(target);
    }
    if (values->inputs.size() == 1 && values->results.size() == 2)
    {
        const auto &node = builder.graph.node(values->inputs.front());
        const auto found = builder.conditions.find(node.value);
        if (found != builder.conditions.end())
        {
            result.condition = found->second;
            const auto point = builder.condition_points.find(node.value);
            if (point != builder.condition_points.end())
            {
                result.condition_block = point->second.first;
                result.condition_before = point->second.second;
            }
            result.targets_by_condition = {ea_t(values->results[0]), ea_t(values->results[1])};
        }
    }
    return result;
}

} // namespace chernobog
