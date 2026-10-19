#include "recovery.hpp"
#include "loop_model.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
bool typed(const z3::expr &value, const z3::context &context, unsigned bits, bool boolean = false)
{
    return &value.ctx() == &context &&
           (boolean ? value.is_bool() : value.is_bv() && value.get_sort().bv_size() == bits);
}
bool memory_array(const z3::expr &value, const z3::context &context)
{
    if (&value.ctx() != &context || !value.is_array())
        return false;
    const auto sort = value.get_sort();
    return sort.array_domain().is_bv() && sort.array_domain().bv_size() == 64 &&
           sort.array_range().is_bv() && sort.array_range().bv_size() == 8;
}
}
Recovery::Recovery(std::shared_ptr<z3::context> context, const Lease &source)
    : arena(std::move(context)), lease(source)
{
    if (!arena)
        throw std::invalid_argument("recovery requires an owning context");
}
RecoveryRecorder::RecoveryRecorder(std::shared_ptr<z3::context> arena, const Lease &lease,
                                   size_t bytes)
    : data_(std::make_shared<Recovery>(std::move(arena), lease)), limit_(bytes)
{
    if (bytes > 32 * 1024 * 1024)
        throw std::invalid_argument("invalid recovery recorder arena or budget");
}
bool RecoveryRecorder::reserve(size_t bytes)
{
    if (!data_->capture_complete)
        return false;
    if (bytes > limit_ || data_->estimated_bytes > limit_ - bytes)
    {
        data_->capture_complete = false;
        data_->omission = "retained recovery budget";
        return false;
    }
    data_->estimated_bytes += bytes;
    return true;
}
void RecoveryRecorder::expression(const z3::expr &value, unsigned bits, bool boolean) const
{
    if (!typed(value, *data_->arena, bits, boolean))
        throw std::invalid_argument("recovery expression context or sort mismatch");
}
uint32_t RecoveryRecorder::state(uint64_t key, uint64_t site, uint32_t effects,
                                 bool table_unchanged, bool imports_unchanged,
                                 bool dispatch_unchanged, const std::vector<z3::expr> &registers,
                                 const std::vector<z3::expr> &vectors,
                                 const std::vector<z3::expr> &flags, const ByteMemory &memory,
                                 const StackState &stack, const PoolState &pool,
                                 const z3::expr &domain, const std::vector<uint64_t> &calls,
                                 uint64_t epoch)
{
    if (!memory.uses_context(*data_->arena) || registers.size() != 36 || vectors.size() != 16 ||
        flags.size() != 7 || (effects != no_record && effects >= data_->effects.size()))
        throw std::invalid_argument("invalid recovery state shape");
    for (const auto &value : registers)
        expression(value, 64);
    for (const auto &value : vectors)
        expression(value, 128);
    for (const auto &value : flags)
        expression(value, 0, true);
    expression(stack.floor, 64);
    expression(stack.native_top, 64);
    expression(stack.reserved, 64);
    expression(domain, 0, true);
    for (const auto &block : pool.blocks)
    {
        expression(block.address, 64);
        expression(block.bytes, 64);
        expression(block.tag, 64);
    }
    // COW backing and expression DAGs may be shared. Charge each snapshot's
    // overlay conservatively; this remains an estimate, not allocator isolation.
    const size_t cost = sizeof(RecoveryState) +
                        (registers.size() + vectors.size() + flags.size()) * 64 +
                        memory.concrete_bytes() * 96 + pool.blocks.size() * 192 + calls.size() * 8;
    if (!reserve(cost))
        return no_record;
    const auto id = uint32_t(data_->states.size());
    data_->states.push_back({key, site, effects, table_unchanged, imports_unchanged,
                             dispatch_unchanged, registers, vectors, flags, memory, stack, pool,
                             domain, calls, epoch});
    return id;
}
uint32_t RecoveryRecorder::effect(uint32_t previous, EffectOrigin origin, EffectKind kind,
                                  uint64_t site, unsigned bits, const z3::expr &address,
                                  const z3::expr &value, const z3::expr &bytes)
{
    expression(address, 64);
    expression(bytes, 64);
    if (kind == EffectKind::Havoc)
    {
        if (!memory_array(value, *data_->arena))
            throw std::invalid_argument("invalid recovery havoc array");
    }
    else
        expression(value, bits, kind == EffectKind::Alignment);
    if (unsigned(origin) > unsigned(EffectOrigin::External) ||
        unsigned(kind) > unsigned(EffectKind::Repeat) ||
        (kind == EffectKind::Repeat && bits != 128) ||
        (previous != no_record && previous >= data_->effects.size()) ||
        (kind != EffectKind::Havoc && kind != EffectKind::Alignment && bits != 8 && bits != 16 &&
         bits != 32 && bits != 64 && bits != 128))
        throw std::invalid_argument("invalid recovery effect");
    if (!reserve(sizeof(MemoryEffect) + 192))
        return previous;
    const auto id = uint32_t(data_->effects.size());
    data_->effects.push_back({previous, origin, kind, site, bits, address, value, bytes});
    return id;
}
void RecoveryRecorder::instruction(uint64_t site, const rax_smir_instruction &instruction,
                                   const std::vector<rax_smir_op> &operations, const uint8_t *bytes)
{
    if (instruction.struct_size != sizeof(instruction) ||
        instruction.abi_version != RAX_SMIR_ABI_VERSION || instruction.flags != RAX_SMIR_COMPLETE ||
        !instruction.bytes_consumed || instruction.bytes_consumed > 15 ||
        operations.size() != instruction.op_count || !bytes)
        throw std::invalid_argument("invalid retained SMIR instruction");
    if (const auto found = data_->instructions.find(site); found != data_->instructions.end())
    {
        if (found->second.bytes != std::vector<uint8_t>(bytes, bytes + instruction.bytes_consumed))
            throw std::invalid_argument("conflicting retained instruction bytes");
        return;
    }
    if (!reserve(sizeof(NativeInstruction) + instruction.bytes_consumed +
                 operations.size() * sizeof(rax_smir_op)))
        return;
    data_->instructions.emplace(
        site, NativeInstruction{
                  site, instruction, operations, {bytes, bytes + instruction.bytes_consumed}});
}
void RecoveryRecorder::flow(uint64_t key, uint64_t source, uint64_t target, FlowKind kind,
                            const z3::expr &domain)
{
    expression(domain, 0, true);
    if (unsigned(kind) > unsigned(FlowKind::ExternalCall))
        throw std::invalid_argument("invalid recovery flow kind");
    if (!reserve(sizeof(FlowEdge) + 64))
        return;
    data_->flow.push_back({key, source, target, kind, domain});
}
void RecoveryRecorder::relation(uint32_t input, uint32_t output, const z3::expr &key,
                                const z3::expr &domain)
{
    expression(key, 64);
    expression(domain, 0, true);
    if (!data_->capture_complete || input == no_record || output == no_record)
        return;
    if (input >= data_->states.size() || output >= data_->states.size())
        throw std::invalid_argument("invalid recovery relation state");
    if (!reserve(sizeof(HandlerRelation) + 128))
        return;
    data_->relations.push_back({input, output, key, domain});
}
void RecoveryRecorder::loop(uint32_t input, uint32_t output, uint32_t effect, uint64_t entry,
                            uint64_t exit, uint64_t bound, const z3::expr &iterations,
                            const z3::expr &domain)
{
    expression(iterations, 64);
    expression(domain, 0, true);
    if (!data_->capture_complete || input == no_record || output == no_record)
        return;
    if (input >= data_->states.size() || output >= data_->states.size() ||
        effect >= data_->effects.size() || !bound || bound > store_loop_limit)
        throw std::invalid_argument("invalid retained store loop");
    if (!reserve(sizeof(StoreLoopRelation) + 128))
        return;
    data_->loops.push_back({input, output, effect, entry, exit, bound, iterations, domain});
}
uint32_t RecoveryRecorder::phi(uint32_t left, uint32_t right, uint64_t site,
                               const z3::expr &condition)
{
    expression(condition, 0, true);
    if ((left != no_record && left >= data_->effects.size()) ||
        (right != no_record && right >= data_->effects.size()))
        throw std::invalid_argument("invalid effect phi predecessor");
    if (left == right)
        return left;
    if (!reserve(sizeof(MemoryEffect) + 192))
        return no_record;
    const auto zero = data_->arena->bv_val(0, 64);
    const auto id = uint32_t(data_->effects.size());
    data_->effects.push_back(
        {left, EffectOrigin::Native, EffectKind::Phi, site, 0, zero, condition, zero, right});
    return id;
}
void RecoveryRecorder::join(uint32_t left, uint32_t right, uint32_t output, uint32_t entry,
                            const z3::expr &condition, const z3::expr &domain)
{
    expression(condition, 0, true);
    expression(domain, 0, true);
    if (!data_->capture_complete)
        return;
    for (auto id : {left, right, output, entry})
        if (id >= data_->states.size())
            throw std::invalid_argument("invalid state join record");
    if (!reserve(sizeof(StateJoin) + 128))
        return;
    data_->joins.push_back({left, right, output, entry, condition, domain});
}
std::shared_ptr<const Recovery> RecoveryRecorder::finish(bool complete)
{
    data_->exploration_complete = complete;
    return std::move(data_);
}
std::vector<uint32_t> Recovery::ordered_effects(const HandlerRelation &relation) const
{
    if (relation.input >= states.size() || relation.output >= states.size())
        throw std::invalid_argument("invalid recovery relation");
    const auto stop = states[relation.input].effects;
    std::vector<uint32_t> pending{states[relation.output].effects};
    std::vector<bool> visited(effects.size(), false);
    std::vector<uint32_t> result;
    while (!pending.empty())
    {
        const auto cursor = pending.back();
        pending.pop_back();
        if (cursor == stop)
            continue;
        if (cursor == no_record || cursor >= effects.size())
            throw std::invalid_argument("broken recovery effect ancestry");
        if (visited[cursor])
            continue;
        visited[cursor] = true;
        result.push_back(cursor);
        const auto &effect = effects[cursor];
        const auto previous = effect.previous;
        if (previous != no_record && previous >= cursor)
            throw std::invalid_argument("cyclic recovery effect ancestry");
        pending.push_back(previous);
        if (effect.kind == EffectKind::Phi)
        {
            if (effect.alternative != no_record && effect.alternative >= cursor)
                throw std::invalid_argument("cyclic recovery effect phi");
            pending.push_back(effect.alternative);
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}
bool Recovery::valid() const
{
    if (!arena)
        return false;
    try
    {
        static_assert(sizeof(rax_smir_instruction) == 136 && sizeof(rax_smir_op) == 184,
                      "SMIR record ABI changed");
        for (const auto &[site, native] : instructions)
        {
            if (site != native.site ||
                native.instruction.struct_size != sizeof(rax_smir_instruction) ||
                native.instruction.abi_version != RAX_SMIR_ABI_VERSION ||
                native.instruction.flags != RAX_SMIR_COMPLETE || native.bytes.empty() ||
                native.bytes.size() > 15 ||
                native.bytes.size() != native.instruction.bytes_consumed ||
                native.operations.size() != native.instruction.op_count ||
                native.operations.size() > 256)
                return false;
            rax_smir_instruction checked{};
            rax_smir_op checked_ops[256]{};
            if (rax_smir_lift_x64(site, native.bytes.data(), native.bytes.size(), &checked,
                                  checked_ops, 256) != RAX_OK ||
                std::memcmp(&checked, &native.instruction, sizeof(checked)) != 0 ||
                (!native.operations.empty() &&
                 std::memcmp(checked_ops, native.operations.data(),
                             native.operations.size() * sizeof(rax_smir_op)) != 0))
                return false;
        }
        for (const auto &s : states)
        {
            if (!s.memory.uses_context(*arena) || s.registers.size() != 36 ||
                s.vectors.size() != 16 || s.flags.size() != 7 ||
                (s.effects != no_record && s.effects >= effects.size()) ||
                !typed(s.domain, *arena, 0, true) || !typed(s.stack.floor, *arena, 64) ||
                !typed(s.stack.native_top, *arena, 64) || !typed(s.stack.reserved, *arena, 64))
                return false;
            for (const auto &v : s.registers)
                if (!typed(v, *arena, 64))
                    return false;
            for (const auto &v : s.vectors)
                if (!typed(v, *arena, 128))
                    return false;
            for (const auto &v : s.flags)
                if (!typed(v, *arena, 0, true))
                    return false;
            for (const auto &b : s.pool.blocks)
                if (!typed(b.address, *arena, 64) || !typed(b.bytes, *arena, 64) ||
                    !typed(b.tag, *arena, 64))
                    return false;
        }
        for (size_t i = 0; i < effects.size(); ++i)
        {
            const auto &e = effects[i];
            if (unsigned(e.origin) > unsigned(EffectOrigin::External) ||
                unsigned(e.kind) > unsigned(EffectKind::Phi) ||
                (e.kind == EffectKind::Phi &&
                 (e.bits != 0 || (e.alternative != no_record && e.alternative >= i))) ||
                (e.kind != EffectKind::Phi && e.alternative != no_record) ||
                (e.kind == EffectKind::Repeat && e.bits != 128) ||
                (e.kind != EffectKind::Havoc && e.kind != EffectKind::Alignment &&
                 e.kind != EffectKind::Phi && e.bits != 8 && e.bits != 16 && e.bits != 32 &&
                 e.bits != 64 && e.bits != 128) ||
                (e.previous != no_record && e.previous >= i) || !typed(e.address, *arena, 64) ||
                !typed(e.bytes, *arena, 64) ||
                (e.kind == EffectKind::Havoc
                     ? !memory_array(e.value, *arena)
                     : !typed(e.value, *arena, e.bits,
                              e.kind == EffectKind::Alignment || e.kind == EffectKind::Phi)))
                return false;
        }
        for (const auto &r : relations)
        {
            if (!typed(r.next_key, *arena, 64) || !typed(r.domain, *arena, 0, true))
                return false;
            (void)ordered_effects(r);
        }
        for (const auto &edge : flow)
            if (unsigned(edge.kind) > unsigned(FlowKind::ExternalCall) ||
                !typed(edge.domain, *arena, 0, true))
                return false;
        for (const auto &loop : loops)
        {
            if (loop.input >= states.size() || loop.output >= states.size() ||
                loop.effect >= effects.size() || !loop.iteration_bound ||
                loop.iteration_bound > store_loop_limit || !typed(loop.iterations, *arena, 64) ||
                !typed(loop.domain, *arena, 0, true) || loop.entry != states[loop.input].site ||
                loop.exit != states[loop.output].site ||
                loop.exit - loop.entry != store_loop_bytes.size() ||
                effects[loop.effect].kind != EffectKind::Repeat ||
                states[loop.output].effects != loop.effect ||
                effects[loop.effect].previous != states[loop.input].effects)
                return false;
            for (size_t i = 0; i < store_loop_offsets.size(); ++i)
            {
                const auto offset = store_loop_offsets[i];
                const auto end = i + 1 == store_loop_offsets.size() ? store_loop_bytes.size()
                                                                    : store_loop_offsets[i + 1];
                const auto found = instructions.find(loop.entry + offset);
                if (found == instructions.end() ||
                    found->second.bytes != std::vector<uint8_t>(store_loop_bytes.begin() + offset,
                                                                store_loop_bytes.begin() + end))
                    return false;
            }
        }
        for (const auto &join : joins)
        {
            if (join.left >= states.size() || join.right >= states.size() ||
                join.output >= states.size() || join.entry >= states.size() ||
                !typed(join.condition, *arena, 0, true) || !typed(join.domain, *arena, 0, true))
                return false;
            const auto &left = states[join.left], &right = states[join.right];
            const auto &output = states[join.output];
            if (left.site != right.site || output.site != left.site || left.key != right.key ||
                output.key != left.key || states[join.entry].key != left.key ||
                left.epoch != right.epoch || output.epoch != left.epoch ||
                left.calls != right.calls || output.calls != left.calls ||
                left.table_unchanged != right.table_unchanged ||
                left.imports_unchanged != right.imports_unchanged ||
                left.dispatch_unchanged != right.dispatch_unchanged ||
                output.table_unchanged != left.table_unchanged ||
                output.imports_unchanged != left.imports_unchanged ||
                output.dispatch_unchanged != left.dispatch_unchanged ||
                left.pool.blocks.size() != right.pool.blocks.size() ||
                output.pool.blocks.size() != left.pool.blocks.size() ||
                !z3::eq(join.condition, left.domain) || !z3::eq(join.domain, output.domain))
                return false;
            for (size_t i = 0; i < left.pool.blocks.size(); ++i)
            {
                const auto &a = left.pool.blocks[i], &b = right.pool.blocks[i];
                const auto &c = output.pool.blocks[i];
                if (a.live != b.live || a.live != c.live || !z3::eq(a.address, b.address) ||
                    !z3::eq(a.address, c.address) || !z3::eq(a.bytes, b.bytes) ||
                    !z3::eq(a.bytes, c.bytes) || !z3::eq(a.tag, b.tag) || !z3::eq(a.tag, c.tag))
                    return false;
            }
            if (left.effects == right.effects)
            {
                if (output.effects != left.effects)
                    return false;
            }
            else
            {
                if (output.effects >= effects.size())
                    return false;
                const auto &phi = effects[output.effects];
                if (phi.kind != EffectKind::Phi || phi.previous != left.effects ||
                    phi.alternative != right.effects || !z3::eq(phi.value, join.condition))
                    return false;
            }
            (void)ordered_effects({join.entry, join.output, arena->bv_val(0, 64), join.domain});
        }
    }
    catch (const std::exception &)
    {
        return false;
    }
    return true;
}
}
