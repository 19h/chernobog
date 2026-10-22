#include "finite_targets.h"

#include "../../common/finite_domain.h"
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
    std::vector<finite_targets_t::dependency_t> dependencies;

    Id operand(const mop_t &op, const minsn_t *before, unsigned depth = 0)
    {
        if (!bounded_ || depth > 96 || !bitvector::valid_byte_width(op.size))
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
            return op.s ? unknown(2, uint64_t(op.s->off), op.size, memory_epoch(before)) : invalid;
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
    bool bounded_ = true;
    size_t scans_ = 0;
    uint64_t next_token_ = 1;
    using Key = std::tuple<int, uint64_t, int, const minsn_t *>;
    std::map<Key, uint64_t> tokens_;
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
            if (ins->opcode == m_call || ins->opcode == m_icall || ins->opcode == m_stx ||
                ins->d.t == mop_v || ins->d.t == mop_S)
                return ins;
        }
        return nullptr;
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
                if (op.size == 1 && ins->d.size == 1 &&
                    (ins->opcode == m_mul || ins->opcode == m_add || ins->opcode == m_sub))
                {
                    // All 256 values cover this arithmetic result regardless
                    // of how deeply its runtime inputs were computed. Use the
                    // reaching definition as the identity of the cut, so all
                    // repeated uses remain correlated through later lookups.
                    return unknown(6, uint64_t(op.r), 1, ins);
                }
                const auto key = std::make_pair(ins, ins->d.size);
                auto found = definitions_.find(key);
                Id value;
                if (found == definitions_.end())
                {
                    value = instruction(*ins, ins, depth + 1);
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
            if (ins->opcode == m_call || ins->opcode == m_icall)
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

    Id instruction(const minsn_t &ins, const minsn_t *before, unsigned depth)
    {
        if (depth > 96 || ins.is_fpinsn() || ins.is_mbarrier())
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
            const uint64_t key =
                token(4, uint64_t(reinterpret_cast<uintptr_t>(&ins)), bytes, memory_epoch(before));
            mop_t condition;
            condition.create_from_insn(&ins);
            conditions.emplace(key, std::move(condition));
            return graph.variable(key, bytes, 1);
        }
        default:
            return invalid;
        }
    }
};

} // namespace

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
    int changes = 0;
    size_t inspected = 0;
    size_t attempted = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(20);
    const auto has_load = [](const auto &self, const mop_t &operand, unsigned depth) -> bool
    {
        return depth < 32 && operand.t == mop_d && operand.d &&
               (operand.d->opcode == m_ldx || self(self, operand.d->l, depth + 1) ||
                self(self, operand.d->r, depth + 1));
    };
    for (int index = 0; index < mba->qty; ++index)
    {
        mblock_t *block = mba->get_mblock(index);
        for (minsn_t *ins = block->head; ins; ins = ins->next)
        {
            if (++inspected > 4096 || std::chrono::steady_clock::now() >= deadline)
            {
                if (changes > 0)
                    mba->mark_chains_dirty();
                return changes;
            }
            if (ins->d.t != mop_r || ins->opcode == m_call || ins->opcode == m_icall ||
                ins->opcode == m_mov || ins->is_mbarrier() || ins->is_fpinsn())
                continue;
            if (ins->opcode != m_ldx && !has_load(has_load, ins->l, 0) &&
                !has_load(has_load, ins->r, 0))
                continue;
            if (++attempted > 32)
                break;
            mop_t expression;
            expression.create_from_insn(ins);
            Builder builder(block);
            const Id root = builder.operand(expression, ins);
            const auto values = builder.graph.enumerate(root);
            if (!values || values->results.empty() || builder.dependencies.empty() ||
                !std::all_of(values->results.begin(), values->results.end(),
                             [&](uint64_t value) { return value == values->results.front(); }))
                continue;
            auto history = fold_history[{get_dbctx_id(), mba->entry_ea}];
            for (const auto &dependency : builder.dependencies)
                history[{dependency.address, dependency.bytes.size()}] = dependency;
            if (history.size() > 4096)
                continue;
            fold_history[{get_dbctx_id(), mba->entry_ea}] = std::move(history);
            ins->opcode = m_mov;
            ins->l.make_number(values->results.front(), ins->d.size);
            ins->r.erase();
            block->mark_lists_dirty();
            ++changes;
        }
    }
    if (changes > 0)
        mba->mark_chains_dirty();
    return changes;
}

std::optional<finite_targets_t> evaluate_finite_targets(const mop_t &operand, const minsn_t *before,
                                                        const mblock_t *block, bool allow_imports)
{
    if (!before || !block)
        return std::nullopt;
    Builder builder(block);
    const Id root = builder.operand(operand, before);
    const auto values = builder.graph.enumerate(root);
    if (!values || values->results.empty() || builder.graph.failed())
        return std::nullopt;
    finite_targets_t result;
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
        if (!imported && (target == BADADDR || !segment || (segment->perm & SEGPERM_EXEC) == 0 ||
                          !is_code(flags) || !is_head(flags)))
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
            result.targets_by_condition = {ea_t(values->results[0]), ea_t(values->results[1])};
        }
    }
    return result;
}

} // namespace chernobog
