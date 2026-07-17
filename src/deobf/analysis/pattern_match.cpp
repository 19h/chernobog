#include "pattern_match.h"
#include "../../common/compat.h"
#include "../../common/ida_memory.h"
#include <algorithm>

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
// Jump table-based flattening detection (index-based, not magic constants)
// This pattern uses small integers (0, 1, 2...) as indices into a jump table
//--------------------------------------------------------------------------
struct jmptbl_info_t {
    int block_idx;              // Block containing the ijmp
    ea_t table_addr;            // Address of jump table
    int num_cases;              // Number of cases detected
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

static bool detect_jump_table_pattern(mbl_array_t *mba, std::vector<jmptbl_info_t> *out_tables) {
    if (!mba)
        return false;

    std::vector<jmptbl_info_t> tables;

    // First, check IDA's switch info for all addresses in the function
    // IDA often detects switches at the assembly level even if microcode doesn't have m_ijmp
    func_t *pfn = get_func(mba->entry_ea);
    if (pfn) {
        ea_t ea = pfn->start_ea;
        while (ea < pfn->end_ea) {
            switch_info_t si;
            if (get_switch_info(&si, ea) > 0 && si.get_jtable_size() >= 20) {
                jmptbl_info_t info;
                info.block_idx = block_containing_ea(mba, ea);
                info.table_addr = si.jumps;
                info.num_cases = (int)si.get_jtable_size();
                deobf::log_verbose("[pattern] IDA switch at %a: %d cases, table at 0x%llx\n",
                          ea, info.num_cases, (unsigned long long)info.table_addr);
                tables.push_back(info);
            }
            ea = next_head(ea, pfn->end_ea);
            if (ea == BADADDR) break;
        }
    }

    // If we found IDA-detected switches, don't need microcode search
    if (!tables.empty()) {
        if (out_tables)
            *out_tables = tables;
        return true;
    }

    // Fallback: scan microcode for indirect jumps
    deobf::log_verbose("[pattern] Scanning microcode for indirect jumps...\n");
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        // Log block terminator opcodes for debugging
        if (i < 5 || blk->tail->opcode == m_ijmp || blk->tail->opcode == m_goto) {
            deobf::log_verbose("[pattern] Block %d tail: opcode=%d (m_ijmp=%d, m_goto=%d)\n",
                      i, blk->tail->opcode, m_ijmp, m_goto);
        }

        // Look for indirect jumps (ijmp)
        if (blk->tail->opcode != m_ijmp)
            continue;

        jmptbl_info_t info;
        info.block_idx = i;
        info.table_addr = BADADDR;
        info.num_cases = 0;

        // The target of ijmp comes from a computation
        // Look backwards for the pattern: load from [table + index*8]
        // In microcode this could be: ldx / add / mul sequence

        // Try to extract jump table info from IDA's switch analysis
        switch_info_t si;
        if (get_switch_info(&si, blk->start) > 0 ||
            get_switch_info(&si, blk->tail->ea) > 0) {
            info.table_addr = si.jumps;
            info.num_cases = (int)si.get_jtable_size();
            deobf::log_verbose("[pattern] Found IDA-detected switch at block %d: %zu cases, table at 0x%llx\n",
                      i, (size_t)info.num_cases, (unsigned long long)info.table_addr);
            tables.push_back(info);
            continue;
        }

        // Fallback: manually scan for jump table pattern
        // Look for memory loads that could be jump table accesses
        for (minsn_t *ins = blk->tail->prev; ins; ins = ins->prev) {
            // ldx instruction loads from memory
            if (ins->opcode == m_ldx) {
                // Check if loading from a global variable (jump table base)
                if (ins->r.t == mop_v) {
                    info.table_addr = ins->r.g;
                    // Try to determine number of cases by analyzing table contents
                    ea_t ptr = info.table_addr;
                    info.num_cases = 0;
                    const int pointer_bytes = inf_is_64bit() ? 8 : 4;
                    for (int j = 0; j < 512; j++) {  // Reasonable limit
                        auto target_value = chernobog::ida_memory::read_integer(
                            ptr, pointer_bytes);
                        if (!target_value)
                            break;
                        const ea_t target = static_cast<ea_t>(*target_value);
                        if (target == 0 || target == BADADDR)
                            break;
                        // Validate it looks like a code address
                        if (is_code(get_flags(target)) || is_func(get_flags(target))) {
                            info.num_cases++;
                            if ( ptr > BADADDR - 1 -
                                      static_cast<ea_t>(pointer_bytes) )
                                break;
                            ptr += static_cast<ea_t>(pointer_bytes);
                        } else {
                            break;
                        }
                    }
                    if (info.num_cases > 10) {
                        deobf::log_verbose("[pattern] Found manual switch at block %d: %d cases, table at 0x%llx\n",
                                  i, info.num_cases, (unsigned long long)info.table_addr);
                        tables.push_back(info);
                    }
                    break;
                }
            }
        }
    }

    if (out_tables)
        *out_tables = tables;

    return !tables.empty();
}

//--------------------------------------------------------------------------
// Count small state indices used as local variables
// Hikari table-based flattening initializes multiple state variables like:
//   var_14 = 0, var_24 = 1, var_44 = 3, var_54 = 4, etc.
//--------------------------------------------------------------------------
static int count_state_index_assignments(mbl_array_t *mba, int max_index = 300) {
    std::set<uint64_t> indices;

    for (int i = 0; i < mba->qty; i++) {
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

    // Check for jump table-based flattening (index-based, not magic constants)
    // This is a different Hikari variant that uses small indices (0, 1, 2...)
    // into jump tables instead of magic constants
    deobf::log_verbose("[pattern] Checking for jump table-based flattening...\n");
    std::vector<jmptbl_info_t> jump_tables;
    if (detect_jump_table_pattern(mba, &jump_tables)) {
        deobf::log_verbose("[pattern] Found %zu jump tables\n", jump_tables.size());
        // Check if we have a large jump table (>20 cases is suspicious)
        for (const auto& jt : jump_tables) {
            deobf::log_verbose("[pattern] Jump table: block=%d, cases=%d\n", jt.block_idx, jt.num_cases);
            if (jt.num_cases >= 20) {
                mblock_t *dispatcher = jt.block_idx >= 0
                    ? mba->get_mblock(jt.block_idx) : nullptr;
                if ( !dispatcher || dispatcher->npred() < 3 )
                    continue;
                // Also check for many small index assignments
                int index_count = count_state_index_assignments(mba, jt.num_cases + 10);
                deobf::log_verbose("[pattern] Jump table at block %d has %d cases, found %d index assignments\n",
                          jt.block_idx, jt.num_cases, index_count);

                // If we have many small indices AND a large jump table, likely flattened
                if (index_count >= 5) {
                    deobf::log("[pattern] Detected jump table-based flattening!\n");
                    if (out) {
                        out->dispatcher_block = jt.block_idx;
                        out->loop_end_block = -1;
                        // For index-based flattening, state values are 0, 1, 2...
                        for (int i = 0; i < jt.num_cases; i++) {
                            out->state_to_block[i] = -1;  // Targets resolved via jump table
                        }
                    }
                    return true;
                }
            }
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
        out->dispatcher_block = dispatcher;
        out->loop_end_block = -1;  // Will need to find this later
        out->state_var = state_var;
        out->state_to_block = state_map;
    }

    return true;
}

} // namespace pattern_match
