#include "jump_optimizer.h"
#include "../analysis/opaque_eval.h"
#include "../../common/bitvector.h"
#include <map>
#include <optional>
#include <vector>

namespace {

struct stack_slot_t
{
    sval_t offset = 0;
    int size = 0;

    bool operator<(const stack_slot_t &other) const
    {
        return std::tie(offset, size) < std::tie(other.offset, other.size);
    }
};

bool valid_stack_slot(const mop_t &operand, stack_slot_t *out)
{
    if ( operand.t != mop_S || operand.s == nullptr
      || !chernobog::bitvector::valid_byte_width(operand.size) )
    {
        return false;
    }
    if ( out != nullptr )
    {
        out->offset = operand.s->off;
        out->size = operand.size;
    }
    return true;
}

bool stack_slots_overlap(const stack_slot_t &left, const stack_slot_t &right)
{
    if ( left.size <= 0 || right.size <= 0 )
        return true;
    if ( left.offset <= right.offset )
    {
        return static_cast<uint64_t>(right.offset)
             - static_cast<uint64_t>(left.offset)
             < static_cast<uint64_t>(left.size);
    }
    return static_cast<uint64_t>(left.offset)
         - static_cast<uint64_t>(right.offset)
         < static_cast<uint64_t>(right.size);
}

struct local_value_t
{
    mopt_t type = mop_z;
    sval_t identity = 0;
    int size = 0;

    bool operator<(const local_value_t &other) const
    {
        return std::tie(type, identity, size)
             < std::tie(other.type, other.identity, other.size);
    }
};

bool valid_local_value(const mop_t &operand, local_value_t *out)
{
    if ( !chernobog::bitvector::valid_byte_width(operand.size) )
        return false;
    local_value_t value;
    value.type = operand.t;
    value.size = operand.size;
    if ( operand.t == mop_S && operand.s != nullptr )
        value.identity = operand.s->off;
    else if ( operand.t == mop_r )
        value.identity = static_cast<sval_t>(operand.r);
    else
        return false;
    if ( out != nullptr )
        *out = value;
    return true;
}

bool local_values_overlap(const local_value_t &left,
                          const local_value_t &right)
{
    if ( left.type != right.type || left.size <= 0 || right.size <= 0 )
        return false;
    if ( left.identity <= right.identity )
    {
        return static_cast<uint64_t>(right.identity)
             - static_cast<uint64_t>(left.identity)
             < static_cast<uint64_t>(left.size);
    }
    return static_cast<uint64_t>(left.identity)
         - static_cast<uint64_t>(right.identity)
         < static_cast<uint64_t>(right.size);
}

struct stack_address_collector_t final : public mop_visitor_t
{
    std::vector<stack_slot_t> addressed;

    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool) override
    {
        if ( operand == nullptr || operand->t != mop_a || operand->a == nullptr )
            return 0;
        stack_slot_t slot;
        if ( !valid_stack_slot(*operand->a, &slot) )
            return 0;
        if ( std::find_if(this->addressed.begin(), this->addressed.end(),
                          [&](const auto &existing) {
                              return existing.offset == slot.offset
                                  && existing.size == slot.size;
                          }) == this->addressed.end() )
        {
            this->addressed.push_back(slot);
        }
        return 0;
    }
};

struct local_constant_replacer_t final : public mop_visitor_t
{
    explicit local_constant_replacer_t(
        const std::map<local_value_t, uint64_t> &constants)
        : constants(constants)
    {
    }

    const std::map<local_value_t, uint64_t> &constants;
    bool unresolved = false;
    int replacements = 0;

    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool is_target) override
    {
        if ( operand == nullptr || is_target
          || (operand->t != mop_S && operand->t != mop_r) )
            return 0;
        local_value_t value;
        if ( !valid_local_value(*operand, &value) )
        {
            unresolved = true;
            return 1;
        }
        const auto found = constants.find(value);
        if ( found == constants.end() )
        {
            unresolved = true;
            return 1;
        }
        operand->make_number(found->second, value.size);
        ++replacements;
        return 0;
    }
};

bool stack_value_is_addressed(
    const local_value_t &value,
    const std::vector<stack_slot_t> &known_addressed)
{
    if ( value.type != mop_S )
        return false;
    const stack_slot_t slot{value.identity, value.size};
    return std::any_of(known_addressed.begin(), known_addressed.end(),
                       [&](const auto &addressed) {
                           return stack_slots_overlap(slot, addressed);
                       });
}

// Resolve branch-only stack/register temporaries whose latest same-block
// definitions form a constant expression. Calls invalidate register facts;
// stack facts survive only when the slot's address never occurs in the MBA.
// This is a bounded straight-line proof within one microblock and never uses
// predecessor state.
std::optional<bool> evaluate_local_constant_branch(mblock_t *block,
                                                   minsn_t *branch,
                                                   const std::vector<stack_slot_t>
                                                       *known_addressed = nullptr)
{
    if ( block == nullptr || block->mba == nullptr || branch == nullptr
      || !is_mcode_jcond(branch->opcode) || branch->is_fpinsn() )
    {
        return std::nullopt;
    }

    stack_address_collector_t local_addresses;
    if ( known_addressed == nullptr )
    {
        block->mba->for_all_ops(local_addresses);
        known_addressed = &local_addresses.addressed;
    }
    std::map<local_value_t, uint64_t> constants;
    for ( minsn_t *instruction = block->head;
          instruction != nullptr && instruction != branch;
          instruction = instruction->next )
    {
        if ( instruction->contains_call(true) )
        {
            for ( auto iterator = constants.begin();
                  iterator != constants.end(); )
            {
                iterator = iterator->first.type == mop_r
                         ? constants.erase(iterator) : std::next(iterator);
            }
        }

        if ( !instruction->modifies_d() )
            continue;

        local_value_t written;
        if ( !valid_local_value(instruction->d, &written) )
            continue;
        for ( auto iterator = constants.begin(); iterator != constants.end(); )
        {
            iterator = local_values_overlap(iterator->first, written)
                     ? constants.erase(iterator) : std::next(iterator);
        }

        if ( stack_value_is_addressed(written, *known_addressed) )
            continue;

        minsn_t value(*instruction);
        local_constant_replacer_t source_replacer(constants);
        value.l.for_all_ops(source_replacer, nullptr, false);
        if ( source_replacer.unresolved )
            continue;
        value.r.for_all_ops(source_replacer, nullptr, false);
        if ( source_replacer.unresolved )
            continue;
        const auto constant = opaque_eval_t::evaluate_expr(&value);
        if ( constant )
        {
            constants[written] = chernobog::bitvector::truncate(
                *constant, written.size);
        }
    }

    minsn_t resolved(*branch);
    local_constant_replacer_t replacer(constants);
    resolved.l.for_all_ops(replacer, nullptr, false);
    if ( replacer.unresolved || replacer.replacements == 0 )
        return std::nullopt;
    resolved.r.for_all_ops(replacer, nullptr, false);
    if ( replacer.unresolved )
        return std::nullopt;

    bool result = false;
    return opaque_eval_t::evaluate_condition(&resolved, &result)
         ? std::optional<bool>(result) : std::nullopt;
}

std::optional<int> find_not_taken_successor(const mblock_t* blk,
                                            int taken_target)
{
    if ( !blk || taken_target < 0 )
        return std::nullopt;

    std::optional<int> candidate;
    bool saw_taken = false;
    for ( int successor : blk->succset ) {
        if ( successor == taken_target ) {
            saw_taken = true;
            continue;
        }
        if ( candidate && *candidate != successor )
            return std::nullopt;
        candidate = successor;
    }
    if ( candidate )
        return candidate;
    if ( saw_taken && taken_target == blk->serial + 1 )
        return taken_target;
    return std::nullopt;
}

} // namespace

namespace chernobog {

// Static member initialization
size_t jump_optimizer_handler_t::jumps_simplified_ = 0;
size_t jump_optimizer_handler_t::jumps_converted_goto_ = 0;
size_t jump_optimizer_handler_t::jumps_removed_ = 0;

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------

bool jump_optimizer_handler_t::detect(mbl_array_t* mba)
{
    if ( !mba ) 
        return false;

    // Look for conditional jumps with complex conditions
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t* blk = mba->get_mblock(i);
        if ( !blk || !blk->tail ) 
            continue;

        minsn_t* tail = blk->tail;
        if ( !is_mcode_jcond(tail->opcode) ) 
            continue;

        // Check if condition is complex (involves nested operations)
        if ( tail->l.t == mop_d && tail->l.d ) {
            return true;  // Has nested instruction in condition
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main pass
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    // Initialize rule registry
    rules::JumpRuleRegistry::instance().initialize();

    int total_changes = 0;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t* blk = mba->get_mblock(i);
        if ( !blk || !blk->tail ) 
            continue;

        minsn_t* tail = blk->tail;
        if ( !is_mcode_jcond(tail->opcode) ) 
            continue;

        int changes = simplify_jcc(blk, tail, ctx);
        total_changes += changes;
    }

    if ( total_changes > 0 ) {
        ctx->branches_simplified += total_changes;
        deobf::log_verbose("[JumpOpt] Simplified %d conditional jumps\n", total_changes);
    }

    return total_changes;
}

int jump_optimizer_handler_t::run_local_constant_branches(
    mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( mba == nullptr )
        return 0;

    stack_address_collector_t addresses;
    mba->for_all_ops(addresses);

    int changes = 0;
    for ( int index = 0; index < mba->qty; ++index )
    {
        mblock_t *block = mba->get_mblock(index);
        minsn_t *branch = block != nullptr ? block->tail : nullptr;
        if ( branch == nullptr || !is_mcode_jcond(branch->opcode) )
            continue;
        const auto result = evaluate_local_constant_branch(
            block, branch, &addresses.addressed);
        if ( result )
            changes += apply_optimization(block, branch, *result ? 1 : 0);
    }
    if ( ctx != nullptr )
        ctx->branches_simplified += changes;
    if ( changes > 0 )
    {
        deobf::log_verbose(
            "[JumpOpt] Simplified %d same-block constant branches\n",
            changes);
    }
    return changes;
}

//--------------------------------------------------------------------------
// Instruction-level optimization
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::simplify_jcc(mblock_t* blk, minsn_t* jcc, deobf_ctx_t* ctx) {
    if ( !blk || !jcc || !is_mcode_jcond(jcc->opcode) || jcc->is_fpinsn() )
        return 0;

    int result = rules::JumpRuleRegistry::instance().try_apply(blk, jcc);
    if ( result == -1 )
    {
        const auto local_result = evaluate_local_constant_branch(blk, jcc);
        if ( !local_result )
            return 0;  // No rule or bounded local proof matched
        result = *local_result ? 1 : 0;
    }

    return apply_optimization(blk, jcc, result);
}

//--------------------------------------------------------------------------
// Apply optimization
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::apply_optimization(mblock_t* blk, minsn_t* jcc, int result)
{
    if ( result == 1 ) {
        if ( jcc->d.t != mop_b )
            return 0;

        // Jump is always taken - convert to unconditional goto
        ea_t orig_ea = jcc->ea;

        // Get the target block
        int target_block = jcc->d.b;

        // Convert to unconditional goto
        jcc->opcode = m_goto;
        jcc->l.make_blkref(target_block);
        jcc->r.erase();
        jcc->d.erase();
        jcc->ea = orig_ea;
        blk->type = BLT_1WAY;
        replace_successors(blk, target_block);

        jumps_simplified_++;
        jumps_converted_goto_++;

        deobf::log_verbose("[JumpOpt] Converted always-taken jcc at %a to goto\n", orig_ea);
        return 1;
    }
    else if ( result == 0 ) {
        if ( jcc->d.t != mop_b )
            return 0;
        const auto not_taken = find_not_taken_successor(blk, jcc->d.b);
        if ( !not_taken || *not_taken < 0 || *not_taken >= blk->mba->qty )
            return 0;

        // Jump is never taken - remove it (becomes fall-through)
        ea_t orig_ea = jcc->ea;

        // Convert to nop
        jcc->opcode = m_nop;
        jcc->l.erase();
        jcc->r.erase();
        jcc->d.erase();
        jcc->ea = orig_ea;
        blk->type = BLT_1WAY;
        replace_successors(blk, *not_taken);

        jumps_simplified_++;
        jumps_removed_++;

        deobf::log_verbose("[JumpOpt] Removed never-taken jcc at %a\n", orig_ea);
        return 1;
    }

    return 0;
}

void jump_optimizer_handler_t::replace_successors(mblock_t* blk, int new_target)
{
    if ( !blk || !blk->mba )
        return;

    for ( int old_target : blk->succset ) {
        if ( old_target < 0 || old_target >= blk->mba->qty || old_target == new_target )
            continue;
        mblock_t* old_dst = blk->mba->get_mblock(old_target);
        if ( old_dst ) {
            auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(), blk->serial);
            if ( pred != old_dst->predset.end() )
                old_dst->predset.erase(pred);
            old_dst->mark_lists_dirty();
        }
    }

    blk->succset.clear();
    if ( new_target >= 0 && new_target < blk->mba->qty ) {
        blk->succset.push_back(new_target);
        mblock_t* new_dst = blk->mba->get_mblock(new_target);
        if ( new_dst
          && std::find(new_dst->predset.begin(), new_dst->predset.end(), blk->serial)
             == new_dst->predset.end() ) {
            new_dst->predset.push_back(blk->serial);
            new_dst->mark_lists_dirty();
        }
    }
    blk->mark_lists_dirty();
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------

void jump_optimizer_handler_t::dump_statistics()
{
    msg("[chernobog] Jump Optimizer Statistics:\n");
    msg("  Total simplified: %zu\n", jumps_simplified_);
    msg("  Converted to goto: %zu\n", jumps_converted_goto_);
    msg("  Removed (nop): %zu\n", jumps_removed_);

    rules::JumpRuleRegistry::instance().dump_statistics();
}

void jump_optimizer_handler_t::reset_statistics()
{
    jumps_simplified_ = 0;
    jumps_converted_goto_ = 0;
    jumps_removed_ = 0;

    rules::JumpRuleRegistry::instance().reset_statistics();
}

} // namespace chernobog
