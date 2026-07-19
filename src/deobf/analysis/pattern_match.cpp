#include "pattern_match.h"
#include "../../common/compat.h"
#include <algorithm>
#include <deque>
#include <limits>

namespace pattern_match {

//--------------------------------------------------------------------------
// Control flow flattening detection
//--------------------------------------------------------------------------
// Helper: Check if a value looks like a Hikari state constant
// NOTE: Extended to handle non-magic constant patterns used by some obfuscators
//--------------------------------------------------------------------------
static bool is_hikari_state_const(uint64_t val) {
    // Hikari uses distinctive patterns for state constants
    // Common patterns: 0xAAAAxxxx, 0xBEEFxxxx, 0xCAFExxxx, 0xDEADxxxx, etc.

    // Must be at least 0x10000000 (has meaningful high bits)
    // and not look like an address (typical addresses are larger)
    if (val < 0x10000000 || val > 0xFFFFFFFF)
        return false;

    uint32_t high = (val >> 16) & 0xFFFF;

    // The high part must be non-zero
    if (high == 0)
        return false;

    // Check for known Hikari patterns (classic)
    switch (high) {
        case 0xAAAA:
        case 0xABCD:  // Common Hikari pattern (0xABCD0001, 0xABCD0002, etc.)
        case 0xBBBB:
        case 0xCCCC:
        case 0xDDDD:
        case 0xBEEF:
        case 0xCAFE:
        case 0xDEAD:
        case 0x1111:
        case 0x2222:
        case 0x3333:
        case 0x4444:
        case 0x5555:
        case 0x6666:
        case 0x7777:
        case 0x8888:
        case 0x9999:
        case 0xFEED:
        case 0xFACE:
        case 0xBABE:
        case 0xC0DE:
        case 0xF00D:
            return true;
        default:
            break;
    }

    // Extended detection: accept any 32-bit value with entropy in both halves
    // This catches non-standard obfuscators that use random-looking constants
    uint16_t low = val & 0xFFFF;
    
    // Both halves should have some bits set
    if (low == 0)
        return false;
    
    // Avoid 64-bit addresses
    if (val >= 0x100000000ULL)
        return false;
    
    // Check bit density - state constants typically have 6-26 bits set
    int bit_count = portable_popcount((uint32_t)val);
    if (bit_count >= 6 && bit_count <= 26) {
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Helper: Find comparisons against constants in a block
//--------------------------------------------------------------------------
struct state_cmp_t {
    minsn_t *insn;
    mop_t var;          // Variable being compared
    uint64_t const_val; // Constant it's compared against
    int block_idx;
};

static void find_state_comparisons(mbl_array_t *mba, std::vector<state_cmp_t> &cmps) {
    cmps.clear();

    // Also look for any large constants that could be state values
    std::set<uint64_t> potential_states;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Scan all instructions for potential state constants
            if (ins->l.t == mop_n && is_hikari_state_const(ins->l.nnn->value)) {
                potential_states.insert(ins->l.nnn->value);
            }
            if (ins->r.t == mop_n && is_hikari_state_const(ins->r.nnn->value)) {
                potential_states.insert(ins->r.nnn->value);
            }

            // Look for conditional jumps
            if (!deobf::is_jcc(ins->opcode))
                continue;

            // The condition is in ins->l (for jcc, it's the result of a setXX or cmp)
            // We need to trace back to find the actual comparison
            // In microcode, jcc typically follows a setXX instruction

            // Check if comparing against a constant
            // Pattern: jz/jnz after a comparison sub-instruction
            if (ins->l.t == mop_d && ins->l.d) {
                minsn_t *cond = ins->l.d;
                // setXX instructions compare their operands
                if (is_mcode_set(cond->opcode)) {
                    // l and r are the comparison operands
                    uint64_t const_val = 0;
                    mop_t var;
                    bool found = false;

                    if (cond->l.t == mop_n && cond->r.t != mop_n) {
                        const_val = cond->l.nnn->value;
                        var = cond->r;
                        found = true;
                    } else if (cond->r.t == mop_n && cond->l.t != mop_n) {
                        const_val = cond->r.nnn->value;
                        var = cond->l;
                        found = true;
                    }

                    if (found && is_hikari_state_const(const_val)) {
                        state_cmp_t cmp;
                        cmp.insn = ins;
                        cmp.var = var;
                        cmp.const_val = const_val;
                        cmp.block_idx = i;
                        cmps.push_back(cmp);
                    }
                }
            }

            // Also check direct comparison pattern
            // jcc with mop_n operand directly
            if (ins->r.t == mop_n) {
                uint64_t const_val = ins->r.nnn->value;
                if (is_hikari_state_const(const_val)) {
                    state_cmp_t cmp;
                    cmp.insn = ins;
                    cmp.var = ins->l;
                    cmp.const_val = const_val;
                    cmp.block_idx = i;
                    cmps.push_back(cmp);
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Helper: Find the most common comparison variable (likely the state var)
//--------------------------------------------------------------------------
static bool find_likely_state_var(const std::vector<state_cmp_t> &cmps, mop_t *out_var) {
    if (cmps.empty() || !out_var)
        return false;

    struct variable_count_t {
        mop_t variable;
        int count = 0;
    };
    std::vector<variable_count_t> groups;
    for ( const auto &cmp : cmps ) {
        auto group = std::find_if(
            groups.begin(), groups.end(), [&](const variable_count_t &entry) {
                return entry.variable.equal_mops(cmp.var, 0);
            });
        if ( group == groups.end() ) {
            variable_count_t entry;
            entry.variable = cmp.var;
            entry.count = 1;
            groups.push_back(std::move(entry));
        } else {
            ++group->count;
        }
    }

    const auto best = std::max_element(
        groups.begin(), groups.end(), [](const variable_count_t &a,
                                        const variable_count_t &b) {
            return a.count < b.count;
        });
    if ( best == groups.end() || best->count < 3 )
        return false;
    *out_var = best->variable;
    return true;
}

//--------------------------------------------------------------------------
// Helper: Find state variable assignments
//--------------------------------------------------------------------------
static void find_state_assignments(mbl_array_t *mba, const mop_t &state_var,
                                   std::map<uint64_t, int> &state_map) {
    state_map.clear();

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for mov with constant source to state variable location
            if (ins->opcode == m_mov && ins->l.t == mop_n) {
                uint64_t val = ins->l.nnn->value;
                if (is_hikari_state_const(val)) {
                    if ( ins->d.equal_mops(state_var, 0) ) {
                        state_map[val] = i;
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Switch-dispatch flattening detection. Modern variants frequently encode the
// state before indexing the table; consequently, neither small state constants
// nor the predecessor count of the final m_ijmp block are reliable signals.
//--------------------------------------------------------------------------
struct jmptbl_info_t {
    int block_idx = -1;                 // Block containing the ijmp
    ea_t jump_ea = BADADDR;             // Native switch instruction
    ea_t table_addr = BADADDR;          // Address of jump table
    std::size_t num_cases = 0;          // Number of case values
    bool ida_detected = false;
    std::set<ea_t> target_eas;
    std::set<int> target_blocks;
};

static int block_containing_ea(mbl_array_t *mba, ea_t ea)
{
    if ( !mba || ea == BADADDR )
        return -1;
    for ( int i = 0; i < mba->qty; ++i ) {
        const mblock_t *block = mba->get_mblock(i);
        if ( block && block->start <= ea && ea < block->end )
            return i;
    }
    return -1;
}

static void map_switch_targets(mbl_array_t *mba, jmptbl_info_t *info)
{
    if ( !mba || !info )
        return;
    struct block_interval_t {
        ea_t start;
        ea_t end;
        int index;
    };
    std::vector<block_interval_t> intervals;
    intervals.reserve(static_cast<std::size_t>(mba->qty));
    for ( int index = 0; index < mba->qty; ++index ) {
        const mblock_t *block = mba->get_mblock(index);
        if ( block && block->start != BADADDR && block->end > block->start )
            intervals.push_back({block->start, block->end, index});
    }
    std::sort(
        intervals.begin(), intervals.end(),
        [](const block_interval_t &left, const block_interval_t &right) {
            return left.start < right.start
                || (left.start == right.start && left.end < right.end);
        });
    for ( ea_t target : info->target_eas ) {
        const auto after = std::upper_bound(
            intervals.begin(), intervals.end(), target,
            [](ea_t address, const block_interval_t &interval) {
                return address < interval.start;
            });
        if ( after == intervals.begin() )
            continue;
        const block_interval_t &candidate = *std::prev(after);
        if ( candidate.start <= target && target < candidate.end )
            info->target_blocks.insert(candidate.index);
    }
    if ( info->block_idx < 0 || info->block_idx >= mba->qty )
        return;
    const mblock_t *switch_block = mba->get_mblock(info->block_idx);
    if ( !switch_block )
        return;
    for ( int target : switch_block->succset ) {
        if ( target >= 0 && target < mba->qty )
            info->target_blocks.insert(target);
    }
}

static jmptbl_info_t *find_switch_candidate(
    std::vector<jmptbl_info_t> *tables, int block_idx, ea_t jump_ea)
{
    if ( !tables )
        return nullptr;
    const auto found = std::find_if(
        tables->begin(), tables->end(), [&](const jmptbl_info_t &candidate) {
            return (block_idx >= 0 && candidate.block_idx == block_idx)
                || (jump_ea != BADADDR && candidate.jump_ea == jump_ea);
        });
    return found == tables->end() ? nullptr : &*found;
}

static void record_ida_switch(
    mbl_array_t *mba,
    std::vector<jmptbl_info_t> *tables,
    ea_t jump_ea,
    const switch_info_t &switch_info)
{
    if ( !mba || !tables )
        return;
    const std::size_t case_count = switch_info.get_jtable_size();
    if ( case_count < 8 )
        return;

    const int block_idx = block_containing_ea(mba, jump_ea);
    jmptbl_info_t *candidate = find_switch_candidate(
        tables, block_idx, jump_ea);
    if ( !candidate ) {
        tables->emplace_back();
        candidate = &tables->back();
    }
    candidate->block_idx = block_idx;
    candidate->jump_ea = jump_ea;
    candidate->table_addr = switch_info.jumps;
    candidate->num_cases = std::max(candidate->num_cases, case_count);
    candidate->ida_detected = true;

    eavec_t targets;
    if ( calc_switch_cases(nullptr, &targets, jump_ea, switch_info) ) {
        for ( ea_t target : targets ) {
            if ( target != BADADDR )
                candidate->target_eas.insert(target);
        }
    }
}

static bool detect_jump_table_pattern(
    mbl_array_t *mba, std::vector<jmptbl_info_t> *out_tables)
{
    if (!mba)
        return false;

    std::vector<jmptbl_info_t> tables;

    // Start from microcode indirect jumps and query native switch metadata at
    // their exact instruction addresses. This supplies relative-table targets
    // without walking every native instruction on every optimizer callback.
    deobf::log_verbose("[pattern] Scanning microcode for indirect jumps...\n");
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk || !blk->tail || blk->tail->opcode != m_ijmp )
            continue;

        jmptbl_info_t *candidate = find_switch_candidate(
            &tables, i, blk->tail->ea);
        switch_info_t si;
        if ( !candidate && get_switch_info(&si, blk->tail->ea) > 0 ) {
            record_ida_switch(mba, &tables, blk->tail->ea, si);
            candidate = find_switch_candidate(&tables, i, blk->tail->ea);
        }
        if ( !candidate && blk->succset.size() >= 8 ) {
            tables.emplace_back();
            candidate = &tables.back();
            candidate->block_idx = i;
            candidate->jump_ea = blk->tail->ea;
            candidate->num_cases = static_cast<std::size_t>(
                blk->succset.size());
        }
    }

    // Some early or unusual microcode forms can hide the native indirect jump.
    // Only then pay for a complete function-item scan as a compatibility
    // fallback; the normal path above is O(number of microblocks).
    if ( tables.empty() ) {
        func_t *pfn = get_func(mba->entry_ea);
        if ( pfn ) {
            func_item_iterator_t iterator(pfn);
            for ( bool ok = iterator.first(); ok; ok = iterator.next_code() ) {
                const ea_t ea = iterator.current();
                switch_info_t si;
                if ( get_switch_info(&si, ea) > 0 )
                    record_ida_switch(mba, &tables, ea, si);
            }
        }
    }
    for ( jmptbl_info_t &candidate : tables )
        map_switch_targets(mba, &candidate);

    if (out_tables)
        *out_tables = tables;

    return !tables.empty();
}

struct dispatcher_region_t {
    int switch_block = -1;
    int dispatcher_block = -1;
    std::vector<int> blocks;
};

// Walk backward only across an unambiguous single-predecessor selector chain.
// The block with maximal fan-in is the loop header. In the supplied sample,
// this maps switch block 12 (one predecessor) to selector block 11 (190).
static dispatcher_region_t find_dispatcher_region(
    mbl_array_t *mba, int switch_block_idx, std::size_t max_chain_blocks = 8)
{
    dispatcher_region_t region;
    if ( !mba || switch_block_idx < 0 || switch_block_idx >= mba->qty )
        return region;

    region.switch_block = switch_block_idx;
    region.dispatcher_block = switch_block_idx;
    region.blocks.push_back(switch_block_idx);
    std::set<int> visited{switch_block_idx};
    int current = switch_block_idx;

    while ( region.blocks.size() < max_chain_blocks ) {
        const mblock_t *block = mba->get_mblock(current);
        if ( !block || block->npred() != 1 )
            break;
        const int predecessor = *block->predset.begin();
        if ( predecessor < 0 || predecessor >= mba->qty
          || !visited.insert(predecessor).second )
            break;
        region.blocks.push_back(predecessor);
        current = predecessor;
    }

    int maximal_predecessors = -1;
    for ( int block_idx : region.blocks ) {
        const mblock_t *block = mba->get_mblock(block_idx);
        const int predecessors = block ? block->npred() : -1;
        if ( predecessors > maximal_predecessors ) {
            maximal_predecessors = predecessors;
            region.dispatcher_block = block_idx;
        }
    }
    return region;
}

static std::size_t instruction_count(const mblock_t *block)
{
    std::size_t count = 0;
    for ( const minsn_t *insn = block ? block->head : nullptr;
          insn != nullptr;
          insn = insn->next )
        ++count;
    return count;
}

static bool is_selector_transform(mcode_t opcode)
{
    switch ( opcode ) {
        case m_neg:
        case m_bnot:
        case m_add:
        case m_sub:
        case m_mul:
        case m_udiv:
        case m_sdiv:
        case m_umod:
        case m_smod:
        case m_or:
        case m_and:
        case m_xor:
        case m_shl:
        case m_shr:
        case m_sar:
            return true;
        default:
            return false;
    }
}

static std::size_t nested_transform_count(
    const minsn_t *instruction, std::size_t depth = 0)
{
    if ( !instruction || depth >= 32 )
        return 0;
    std::size_t count = is_selector_transform(instruction->opcode) ? 1U : 0U;
    const mop_t *operands[] = {
        &instruction->l, &instruction->r, &instruction->d,
    };
    for ( const mop_t *operand : operands ) {
        if ( operand->t == mop_d && operand->d )
            count += nested_transform_count(operand->d, depth + 1);
    }
    return count;
}

static std::size_t selector_transform_count(const mblock_t *block)
{
    std::size_t count = 0;
    for ( const minsn_t *instruction = block ? block->head : nullptr;
          instruction;
          instruction = instruction->next )
        count += nested_transform_count(instruction);
    return count;
}

static int count_state_index_assignments(
    mbl_array_t *mba,
    int max_index,
    const std::vector<int> *return_distance = nullptr,
    const std::vector<int> *target_distance = nullptr);

struct switch_dispatch_evidence_t {
    dispatcher_region_t region;
    switch_dispatch_features_t features;
    switch_dispatch_assessment_t assessment;
};

static switch_dispatch_evidence_t analyze_switch_dispatch(
    mbl_array_t *mba, const jmptbl_info_t &jump_table,
    std::size_t max_return_distance = 32)
{
    switch_dispatch_evidence_t evidence;
    evidence.region = find_dispatcher_region(mba, jump_table.block_idx);
    if ( !mba || evidence.region.switch_block < 0 )
        return evidence;

    const mblock_t *switch_block = mba->get_mblock(
        evidence.region.switch_block);
    const mblock_t *dispatcher_block = mba->get_mblock(
        evidence.region.dispatcher_block);
    if ( !switch_block || !dispatcher_block )
        return evidence;

    std::set<int> region_blocks(
        evidence.region.blocks.begin(), evidence.region.blocks.end());
    std::set<int> candidate_return_frontier;
    for ( int block_idx : evidence.region.blocks ) {
        const mblock_t *block = mba->get_mblock(block_idx);
        if ( !block )
            continue;
        for ( int predecessor : block->predset ) {
            if ( region_blocks.count(predecessor) == 0 )
                candidate_return_frontier.insert(predecessor);
        }
    }

    // One reverse BFS computes the shortest distance from every block that can
    // flow back into the dispatcher. This is O(V+E), rather than one traversal
    // per case target, and the depth bound keeps decompilation latency finite.
    std::vector<int> return_distance(
        static_cast<std::size_t>(mba->qty), -1);
    std::deque<int> worklist;
    for ( int block_idx : evidence.region.blocks ) {
        return_distance[static_cast<std::size_t>(block_idx)] = 0;
        worklist.push_back(block_idx);
    }
    while ( !worklist.empty() ) {
        const int block_idx = worklist.front();
        worklist.pop_front();
        const int distance = return_distance[
            static_cast<std::size_t>(block_idx)];
        if ( distance < 0
          || static_cast<std::size_t>(distance) >= max_return_distance )
            continue;
        const mblock_t *block = mba->get_mblock(block_idx);
        if ( !block )
            continue;
        for ( int predecessor : block->predset ) {
            if ( predecessor < 0 || predecessor >= mba->qty )
                continue;
            int &predecessor_distance = return_distance[
                static_cast<std::size_t>(predecessor)];
            if ( predecessor_distance >= 0 )
                continue;
            predecessor_distance = distance + 1;
            worklist.push_back(predecessor);
        }
    }

    auto &features = evidence.features;
    features.case_count = jump_table.num_cases != 0
        ? jump_table.num_cases : jump_table.target_blocks.size();
    features.unique_target_count = jump_table.target_blocks.size();
    for ( int target : jump_table.target_blocks ) {
        if ( target < 0 || target >= mba->qty )
            continue;
        const int distance = return_distance[static_cast<std::size_t>(target)];
        if ( distance < 0 )
            continue;
        ++features.returning_target_count;
        if ( distance <= 1 )
            ++features.direct_return_target_count;
        features.max_return_distance = std::max(
            features.max_return_distance,
            static_cast<std::size_t>(distance));
    }

    // Filter dispatcher predecessors by bounded forward reachability from an
    // actual switch target. This excludes unrelated entries into the loop
    // header, which would otherwise inflate the distributed-backedge signal.
    std::vector<int> target_distance(
        static_cast<std::size_t>(mba->qty), -1);
    worklist.clear();
    for ( int target : jump_table.target_blocks ) {
        if ( target < 0 || target >= mba->qty
          || region_blocks.count(target) != 0 )
            continue;
        target_distance[static_cast<std::size_t>(target)] = 0;
        worklist.push_back(target);
    }
    while ( !worklist.empty() ) {
        const int block_idx = worklist.front();
        worklist.pop_front();
        const int distance = target_distance[
            static_cast<std::size_t>(block_idx)];
        if ( distance < 0
          || static_cast<std::size_t>(distance) >= max_return_distance )
            continue;
        const mblock_t *block = mba->get_mblock(block_idx);
        if ( !block )
            continue;
        for ( int successor : block->succset ) {
            if ( successor < 0 || successor >= mba->qty
              || region_blocks.count(successor) != 0 )
                continue;
            int &successor_distance = target_distance[
                static_cast<std::size_t>(successor)];
            if ( successor_distance >= 0 )
                continue;
            successor_distance = distance + 1;
            worklist.push_back(successor);
        }
    }
    for ( int predecessor : candidate_return_frontier ) {
        if ( predecessor >= 0 && predecessor < mba->qty
          && target_distance[static_cast<std::size_t>(predecessor)] >= 0 )
            ++features.return_frontier_count;
    }
    features.dispatcher_predecessor_count = static_cast<std::size_t>(
        dispatcher_block->npred());
    features.dispatcher_chain_blocks = evidence.region.blocks.size();
    features.selector_instruction_count = instruction_count(dispatcher_block);
    features.selector_transform_count = selector_transform_count(
        dispatcher_block);
    if ( features.selector_transform_count < 3 ) {
        const int capped_cases = static_cast<int>(std::min<std::size_t>(
            features.case_count,
            static_cast<std::size_t>(std::numeric_limits<int>::max() - 10)));
        features.state_assignment_count = static_cast<std::size_t>(
            count_state_index_assignments(
                mba, capped_cases + 10, &return_distance, &target_distance));
    }
    features.has_indirect_jump = jump_table.ida_detected
        || (switch_block->tail && switch_block->tail->opcode == m_ijmp);

    const std::size_t expected_targets = !jump_table.target_eas.empty()
        ? jump_table.target_eas.size() : features.case_count;
    features.cfg_complete = features.unique_target_count >= 6
        && (expected_targets == 0
         || switch_dispatch_detail::ratio_at_least(
                features.unique_target_count, expected_targets, 80));
    evidence.assessment = assess_switch_dispatch(features);
    return evidence;
}

//--------------------------------------------------------------------------
// Count small state indices used as local variables
// Hikari table-based flattening initializes multiple state variables like:
//   var_14 = 0, var_24 = 1, var_44 = 3, var_54 = 4, etc.
//--------------------------------------------------------------------------
static int count_state_index_assignments(
    mbl_array_t *mba,
    int max_index,
    const std::vector<int> *return_distance,
    const std::vector<int> *target_distance)
{
    std::set<uint64_t> indices;

    for (int i = 0; i < mba->qty; i++) {
        const std::size_t block_index = static_cast<std::size_t>(i);
        if ( return_distance
          && (block_index >= return_distance->size()
           || (*return_distance)[block_index] < 0) )
            continue;
        if ( target_distance
          && (block_index >= target_distance->size()
           || (*target_distance)[block_index] < 0) )
            continue;
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for mov of small constants to stack variables
            if (ins->opcode == m_mov && ins->l.t == mop_n) {
                uint64_t val = ins->l.nnn->value;
                // Check if it's a small index (0-300 for most flattened functions)
                if (val <= (uint64_t)max_index) {
                    // Check if destination is a stack or local variable
                    if (ins->d.t == mop_S || ins->d.t == mop_l) {
                        indices.insert(val);
                    }
                }
            }
        }
    }

    return (int)indices.size();
}

//--------------------------------------------------------------------------
bool detect_flatten_pattern(mbl_array_t *mba, flatten_info_t *out) {
    if (!mba || mba->qty < 4)
        return false;
    if ( out )
        *out = flatten_info_t{};

    // Check for jump table-based flattening (index-based, not magic constants)
    // This is a different Hikari variant that uses small indices (0, 1, 2...)
    // into jump tables instead of magic constants
    deobf::log_verbose("[pattern] Checking for jump table-based flattening...\n");
    std::vector<jmptbl_info_t> jump_tables;
    if (detect_jump_table_pattern(mba, &jump_tables)) {
        deobf::log_verbose("[pattern] Found %zu jump tables\n", jump_tables.size());
        const jmptbl_info_t *best_table = nullptr;
        switch_dispatch_evidence_t best_evidence;
        std::vector<switch_dispatch_evidence_t> evidence_by_table;
        evidence_by_table.reserve(jump_tables.size());
        for (const auto& jt : jump_tables) {
            evidence_by_table.push_back(analyze_switch_dispatch(mba, jt));
            const switch_dispatch_evidence_t &evidence =
                evidence_by_table.back();
            const auto &features = evidence.features;
            const auto &assessment = evidence.assessment;
            deobf::log_verbose(
                "[pattern][cff-switch] switch=%d dispatcher=%d cases=%zu "
                "targets=%zu returning=%zu/%u%% direct=%zu/%u%% "
                "frontier=%zu/%u%% fanin=%zu chain=%zu selector=%zu/%zu "
                "state-writes=%zu "
                "maxdist=%zu complete=%d score=%u accepted=%d\n",
                evidence.region.switch_block,
                evidence.region.dispatcher_block,
                features.case_count,
                features.unique_target_count,
                features.returning_target_count,
                assessment.recurrence_percent,
                features.direct_return_target_count,
                assessment.direct_return_percent,
                features.return_frontier_count,
                assessment.frontier_percent,
                features.dispatcher_predecessor_count,
                features.dispatcher_chain_blocks,
                features.selector_instruction_count,
                features.selector_transform_count,
                features.state_assignment_count,
                features.max_return_distance,
                features.cfg_complete ? 1 : 0,
                assessment.score,
                assessment.accepted ? 1 : 0);
            if ( assessment.accepted
              && (!best_table
               || assessment.score > best_evidence.assessment.score
               || (assessment.score == best_evidence.assessment.score
                && features.returning_target_count
                   > best_evidence.features.returning_target_count)) ) {
                best_table = &jt;
                best_evidence = evidence;
            }
        }

        if ( best_table ) {
            const auto &features = best_evidence.features;
            deobf::log(
                "[pattern][cff-switch] Detected recurrent switch dispatcher: "
                "switch=%d dispatcher=%d cases=%zu returning=%zu "
                "frontier=%zu score=%u\n",
                best_evidence.region.switch_block,
                best_evidence.region.dispatcher_block,
                features.case_count,
                features.returning_target_count,
                features.return_frontier_count,
                best_evidence.assessment.score);
            if ( out ) {
                out->kind = flatten_pattern_kind_t::recurrent_switch;
                out->dispatcher_block = best_evidence.region.dispatcher_block;
                out->switch_block = best_evidence.region.switch_block;
                out->loop_end_block = -1;
                out->case_count = features.case_count;
                out->returning_target_count =
                    features.returning_target_count;
                out->direct_return_target_count =
                    features.direct_return_target_count;
                out->return_frontier_count =
                    features.return_frontier_count;
                out->confidence_score = best_evidence.assessment.score;
                out->dispatcher_blocks.insert(
                    best_evidence.region.blocks.begin(),
                    best_evidence.region.blocks.end());
            }
            return true;
        }

        // Retain the old small-index signature only when CFG extraction was
        // incomplete. A complete CFG that fails the recurrence gates is an
        // explicit negative and must not be re-admitted by constant counting.
        for ( std::size_t table_index = 0;
              table_index < jump_tables.size();
              ++table_index ) {
            const jmptbl_info_t &jt = jump_tables[table_index];
            const switch_dispatch_evidence_t &evidence =
                evidence_by_table[table_index];
            if ( evidence.features.cfg_complete || jt.num_cases < 20
              || evidence.region.dispatcher_block < 0 )
                continue;
            const mblock_t *dispatcher = mba->get_mblock(
                evidence.region.dispatcher_block);
            if ( !dispatcher || dispatcher->npred() < 3 )
                continue;
            const int capped_cases = static_cast<int>(std::min<std::size_t>(
                jt.num_cases,
                static_cast<std::size_t>(std::numeric_limits<int>::max() - 10)));
            const int index_count = count_state_index_assignments(
                mba, capped_cases + 10, nullptr, nullptr);
            if ( index_count < 5 )
                continue;
            deobf::log(
                "[pattern][cff-switch] Detected indexed dispatcher through "
                "incomplete-CFG fallback: dispatcher=%d cases=%zu indices=%d\n",
                evidence.region.dispatcher_block, jt.num_cases, index_count);
            if ( out ) {
                out->kind = flatten_pattern_kind_t::indexed_jump_table;
                out->dispatcher_block = evidence.region.dispatcher_block;
                out->switch_block = evidence.region.switch_block;
                out->loop_end_block = -1;
                out->case_count = jt.num_cases;
                const std::size_t state_count = std::min<std::size_t>(
                    jt.num_cases,
                    static_cast<std::size_t>(std::numeric_limits<int>::max()));
                for ( std::size_t state = 0; state < state_count; ++state )
                    out->state_to_block[static_cast<uint64_t>(state)] = -1;
            }
            return true;
        }
    } else {
        deobf::log_verbose("[pattern] No jump tables found\n");
    }

    // Strategy:
    // 1. Find all comparisons against Hikari-style state constants
    // 2. Identify the most commonly compared variable as the state var
    // 3. Find all assignments to the state variable
    // 4. If we have enough comparisons and assignments, it's flattened

    std::vector<state_cmp_t> comparisons;
    find_state_comparisons(mba, comparisons);

    deobf::log_verbose("[pattern] Found %zu state comparisons\n", comparisons.size());

    if (comparisons.size() < 3)
        return false;

    // Find the state variable
    mop_t state_var;
    if (!find_likely_state_var(comparisons, &state_var)) {
        return false;
    }

    deobf::log_verbose("[pattern] Identified state variable type %d, size %d\n",
              state_var.t, state_var.size);

    // Find state assignments
    std::map<uint64_t, int> state_map;
    find_state_assignments(mba, state_var, state_map);

    deobf::log_verbose("[pattern] Found %zu state assignments\n", state_map.size());

    // Also count unique state values from comparisons
    std::set<uint64_t> unique_states;
    for (const auto &cmp : comparisons) {
        if ( cmp.var.equal_mops(state_var, 0) )
            unique_states.insert(cmp.const_val);
    }

    deobf::log_verbose("[pattern] Found %zu unique state values in comparisons\n", unique_states.size());

    // Need at least a few states to confirm flattening
    if (unique_states.size() < 3 || state_map.size() < 2)
        return false;

    // Find the dispatcher block (block with most comparisons)
    std::map<int, int> block_cmp_count;
    for (const auto &cmp : comparisons) {
        if ( cmp.var.equal_mops(state_var, 0) )
            block_cmp_count[cmp.block_idx]++;
    }

    int dispatcher = -1;
    int max_cmps = 0;
    for (const auto &kv : block_cmp_count) {
        if (kv.second > max_cmps) {
            max_cmps = kv.second;
            dispatcher = kv.first;
        }
    }

    // If no single block has many comparisons, the dispatcher might be
    // spread across multiple blocks (cascading pattern)
    if (max_cmps < 3) {
        // Use the first block with comparisons as the entry point
        if (!comparisons.empty()) {
            dispatcher = comparisons[0].block_idx;
        }
    }

    if (out) {
        out->kind = flatten_pattern_kind_t::constant_state;
        out->dispatcher_block = dispatcher;
        out->loop_end_block = -1;  // Will need to find this later
        out->state_var = state_var;
        out->state_to_block = state_map;
    }

    return true;
}

} // namespace pattern_match
