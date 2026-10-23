#pragma once

#include "../deobf_types.h"

#include <array>

namespace chernobog
{

struct finite_targets_t
{
    struct dependency_t
    {
        ea_t address;
        int permissions;
        std::vector<uint8_t> bytes;
    };
    std::vector<ea_t> targets;
    // Address projection is conditional on the retained native-authentication
    // guard completing normally; it is not a PAC/key validation result.
    bool authentication_guarded = false;
    // When present, targets_by_condition[0/1] preserves the original predicate.
    mop_t condition;
    // Ephemeral evaluation point in this MBA; never persisted in a projection.
    const minsn_t *condition_before = nullptr;
    const mblock_t *condition_block = nullptr;
    std::array<ea_t, 2> targets_by_condition = {BADADDR, BADADDR};
    std::vector<dependency_t> dependencies;
};

// A scalar case domain is not an executable-target certificate. It can only
// refine destinations which already exist in a switch's current CFG.
struct finite_values_t
{
    std::vector<uint64_t> values;
    std::vector<finite_targets_t::dependency_t> dependencies;
};
std::optional<finite_values_t> evaluate_finite_values(const mop_t &operand, const minsn_t *before,
                                                      const mblock_t *block);
bool remember_finite_values(ea_t function, const finite_values_t &values);

// Read-only proof over the actual operand and its reaching definitions. Work
// is bounded to 4096 expression nodes, 256 assignments and 2M evaluations.
// Undecoded executable origins are for branch diagnostics; they do not
// establish function boundaries or authorize call/projection rewrites.
std::optional<finite_targets_t> evaluate_finite_targets(const mop_t &operand, const minsn_t *before,
                                                        const mblock_t *block,
                                                        bool allow_imports = false,
                                                        bool allow_undecoded_code = false);
// Keep observable target evaluation when canonicalizing a transfer. Decline
// when lifting it out of a nested expression could reorder another call.
bool preserve_indirect_target_effects(mblock_t *block, minsn_t *top, const mop_t &target,
                                      const minsn_t *selected_call = nullptr);
// Late argument rewrites require the preallocation callback to restart allocation.
int fold_finite_call_arguments(mba_t *mba);
int fold_finite_table_expressions(mba_t *mba);
void reset_finite_table_history(ea_t function);

} // namespace chernobog
