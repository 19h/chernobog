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
    // When present, targets_by_condition[0/1] preserves the original predicate.
    mop_t condition;
    std::array<ea_t, 2> targets_by_condition = {BADADDR, BADADDR};
    std::vector<dependency_t> dependencies;
};

// Read-only proof over the actual operand and its reaching definitions. Work
// is bounded to 4096 expression nodes, 256 assignments and 2M evaluations.
std::optional<finite_targets_t> evaluate_finite_targets(const mop_t &operand, const minsn_t *before,
                                                        const mblock_t *block,
                                                        bool allow_imports = false);
int fold_finite_table_expressions(mba_t *mba);
void reset_finite_table_history(ea_t function);

} // namespace chernobog
