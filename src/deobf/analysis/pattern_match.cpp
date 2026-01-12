#include "pattern_match.h"
#include "expr_simplify.h"
#include "../../common/compat.h"

namespace pattern_match {

//--------------------------------------------------------------------------
// Opaque predicate analysis
//--------------------------------------------------------------------------
opaque_pred_t analyze_predicate(mblock_t *blk, minsn_t *jcc_insn, deobf_ctx_t *ctx) {
    opaque_pred_t result;
    result.type = opaque_pred_t::OPAQUE_UNKNOWN;
    result.cond_insn = jcc_insn;
    result.true_block = -1;
    result.false_block = -1;

    if (!jcc_insn || !deobf::is_jcc(jcc_insn->opcode))
        return result;

    // Get branch targets
    if (jcc_insn->d.t == mop_b) {
        result.true_block = jcc_insn->d.b;
    }

    // Check if the condition can be evaluated statically
    sym_expr_ptr cond = deobf::mop_to_sym(jcc_insn->l, ctx);
    if (cond) {
        cond = deobf::simplify_expr(cond);
        auto val = deobf::eval_const_expr(cond);
        if (val.has_value()) {
            if (*val != 0)
                result.type = opaque_pred_t::OPAQUE_ALWAYS_TRUE;
            else
                result.type = opaque_pred_t::OPAQUE_ALWAYS_FALSE;
        }
    }

    // Check for common Hikari opaque predicate patterns:
    // Pattern 1: (x * (x + 1)) % 2 == 0  (always true for any x)
    // Pattern 2: y < 10 || y >= 10       (always true)
    // Pattern 3: Comparison of two constants

    if (jcc_insn->l.t == mop_d && jcc_insn->l.d) {
        minsn_t *nested = jcc_insn->l.d;

        // Check for setXX instructions with constant operands
        if (nested->opcode >= m_setz && nested->opcode <= m_setle) {
            if (nested->l.t == mop_n && nested->r.t == mop_n) {
                // Both operands are constants - evaluate
                int64_t l = nested->l.nnn->value;
                int64_t r = nested->r.nnn->value;
                bool cond_true = false;

                switch (nested->opcode) {
                    case m_setz:  cond_true = (l == r); break;
                    case m_setnz: cond_true = (l != r); break;
                    case m_setae: cond_true = ((uint64_t)l >= (uint64_t)r); break;
                    case m_setb:  cond_true = ((uint64_t)l < (uint64_t)r); break;
                    case m_seta:  cond_true = ((uint64_t)l > (uint64_t)r); break;
                    case m_setbe: cond_true = ((uint64_t)l <= (uint64_t)r); break;
                    case m_setg:  cond_true = (l > r); break;
                    case m_setge: cond_true = (l >= r); break;
                    case m_setl:  cond_true = (l < r); break;
                    case m_setle: cond_true = (l <= r); break;
                    default: break;
                }

                result.type = cond_true ? opaque_pred_t::OPAQUE_ALWAYS_TRUE
                                       : opaque_pred_t::OPAQUE_ALWAYS_FALSE;
            }
        }
    }

    return result;
}

bool is_always_true(minsn_t *insn) {
    if (!insn)
        return false;

    // Immediate non-zero value
    if (insn->l.t == mop_n && insn->l.nnn->value != 0)
        return true;

    return false;
}

bool is_always_false(minsn_t *insn) {
    if (!insn)
        return false;

    // Immediate zero value
    if (insn->l.t == mop_n && insn->l.nnn->value == 0)
        return true;

    return false;
}

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
    if (cmps.empty())
        return false;

    // Count how many times each variable type/location is compared
    // For simplicity, group by operand type and size
    std::map<std::pair<mopt_t, int>, int> var_counts;
    std::map<std::pair<mopt_t, int>, mop_t> var_examples;

    for (const auto &cmp : cmps) {
        auto key = std::make_pair(cmp.var.t, cmp.var.size);
        var_counts[key]++;
        var_examples[key] = cmp.var;
    }

    // Find the most common
    int max_count = 0;
    mop_t best_var;
    for (const auto &kv : var_counts) {
        if (kv.second > max_count) {
            max_count = kv.second;
            best_var = var_examples[kv.first];
        }
    }

    if (max_count >= 2) {
        *out_var = best_var;
        return true;
    }

    return false;
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
                    // Check if destination matches state variable pattern
                    // (same type and similar structure)
                    if (ins->d.t == state_var.t) {
                        state_map[val] = i;
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Alternative detection: find all Hikari-style constants in the function
//--------------------------------------------------------------------------
static int count_state_constants(mbl_array_t *mba, std::set<uint64_t> *out_constants = nullptr) {
    std::set<uint64_t> constants;
    std::set<uint64_t> all_numbers;  // For debugging

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check all operands for Hikari constants
            if (ins->l.t == mop_n) {
                uint64_t val = ins->l.nnn->value;
                if (val >= 0x10000000 && val <= 0xFFFFFFFF)
                    all_numbers.insert(val);
                if (is_hikari_state_const(val)) {
                    constants.insert(val);
                }
            }
            if (ins->r.t == mop_n) {
                uint64_t val = ins->r.nnn->value;
                if (val >= 0x10000000 && val <= 0xFFFFFFFF)
                    all_numbers.insert(val);
                if (is_hikari_state_const(val)) {
                    constants.insert(val);
                }
            }
            if (ins->d.t == mop_n) {
                uint64_t val = ins->d.nnn->value;
                if (val >= 0x10000000 && val <= 0xFFFFFFFF)
                    all_numbers.insert(val);
                if (is_hikari_state_const(val)) {
                    constants.insert(val);
                }
            }
        }
    }

    // Debug: log all large constants found
    if (!all_numbers.empty()) {
        deobf::log("[pattern] All large constants in microcode:\n");
        for (uint64_t v : all_numbers) {
            uint32_t high = (v >> 16) & 0xFFFF;
            deobf::log("[pattern]   0x%llx (high=0x%04x) %s\n",
                (unsigned long long)v, high,
                is_hikari_state_const(v) ? "MATCH" : "no-match");
        }
    }

    if (out_constants)
        *out_constants = constants;

    return (int)constants.size();
}

//--------------------------------------------------------------------------
// Jump table-based flattening detection (index-based, not magic constants)
// This pattern uses small integers (0, 1, 2...) as indices into a jump table
//--------------------------------------------------------------------------
struct jmptbl_info_t {
    int block_idx;              // Block containing the ijmp
    ea_t table_addr;            // Address of jump table
    int num_cases;              // Number of cases detected
    mop_t index_var;            // Variable holding the index
};

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
                info.block_idx = -1;  // Will find block later
                info.table_addr = si.jumps;
                info.num_cases = (int)si.get_jtable_size();
                deobf::log("[pattern] IDA switch at %a: %d cases, table at 0x%llx\n",
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
    deobf::log("[pattern] Scanning microcode for indirect jumps...\n");
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
            deobf::log("[pattern] Found IDA-detected switch at block %d: %zu cases, table at 0x%llx\n",
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
                    for (int j = 0; j < 512; j++) {  // Reasonable limit
                        ea_t target = 0;
                        if (get_bytes(&target, sizeof(ea_t), ptr) != sizeof(ea_t))
                            break;
                        if (target == 0 || target == BADADDR)
                            break;
                        // Validate it looks like a code address
                        if (is_code(get_flags(target)) || is_func(get_flags(target))) {
                            info.num_cases++;
                            ptr += sizeof(ea_t);
                        } else {
                            break;
                        }
                    }
                    if (info.num_cases > 10) {
                        deobf::log("[pattern] Found manual switch at block %d: %d cases, table at 0x%llx\n",
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

    // First, quick check: does this function use many Hikari-style constants?
    std::set<uint64_t> state_constants;
    int const_count = count_state_constants(mba, &state_constants);

    if (const_count >= 3) {
        deobf::log("[pattern] Found %d Hikari-style state constants\n", const_count);
        for (uint64_t c : state_constants) {
            deobf::log("[pattern]   0x%llx\n", (unsigned long long)c);
        }

        // If we have enough state constants, this is likely flattened
        if (out) {
            out->dispatcher_block = 0;  // Will be refined later
            out->loop_end_block = -1;
        }
        return true;
    }

    // Check for jump table-based flattening (index-based, not magic constants)
    // This is a different Hikari variant that uses small indices (0, 1, 2...)
    // into jump tables instead of magic constants
    deobf::log("[pattern] Checking for jump table-based flattening...\n");
    std::vector<jmptbl_info_t> jump_tables;
    if (detect_jump_table_pattern(mba, &jump_tables)) {
        deobf::log("[pattern] Found %zu jump tables\n", jump_tables.size());
        // Check if we have a large jump table (>20 cases is suspicious)
        for (const auto& jt : jump_tables) {
            deobf::log("[pattern] Jump table: block=%d, cases=%d\n", jt.block_idx, jt.num_cases);
            if (jt.num_cases >= 20) {
                // Also check for many small index assignments
                int index_count = count_state_index_assignments(mba, jt.num_cases + 10);
                deobf::log("[pattern] Jump table at block %d has %d cases, found %d index assignments\n",
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
        deobf::log("[pattern] No jump tables found\n");
    }

    // Strategy:
    // 1. Find all comparisons against Hikari-style state constants
    // 2. Identify the most commonly compared variable as the state var
    // 3. Find all assignments to the state variable
    // 4. If we have enough comparisons and assignments, it's flattened

    std::vector<state_cmp_t> comparisons;
    find_state_comparisons(mba, comparisons);

    deobf::log("[pattern] Found %zu state comparisons\n", comparisons.size());

    if (comparisons.size() < 3)
        return false;

    // Find the state variable
    mop_t state_var;
    if (!find_likely_state_var(comparisons, &state_var)) {
        return false;
    }

    deobf::log("[pattern] Identified state variable type %d, size %d\n",
              state_var.t, state_var.size);

    // Find state assignments
    std::map<uint64_t, int> state_map;
    find_state_assignments(mba, state_var, state_map);

    deobf::log("[pattern] Found %zu state assignments\n", state_map.size());

    // Also count unique state values from comparisons
    std::set<uint64_t> unique_states;
    for (const auto &cmp : comparisons) {
        unique_states.insert(cmp.const_val);
    }

    deobf::log("[pattern] Found %zu unique state values in comparisons\n", unique_states.size());

    // Need at least a few states to confirm flattening
    if (unique_states.size() < 3 && state_map.size() < 2)
        return false;

    // Find the dispatcher block (block with most comparisons)
    std::map<int, int> block_cmp_count;
    for (const auto &cmp : comparisons) {
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

//--------------------------------------------------------------------------
// String encryption detection
//--------------------------------------------------------------------------
bool detect_string_encryption(mbl_array_t *mba, ea_t func_ea, std::vector<string_enc_info_t> *out) {
    if (!mba)
        return false;

    bool found = false;

    // Look for XOR loops decrypting global data
    // Hikari pattern: load byte, XOR with key, store to workspace

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Look for XOR instructions with global variable operands
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_xor)
                continue;

            // Check if one operand is a global load
            ea_t enc_addr = BADADDR;
            uint64_t xor_key = 0;

            if (ins->l.t == mop_v && ins->r.t == mop_n) {
                enc_addr = ins->l.g;
                xor_key = ins->r.nnn->value;
            } else if (ins->r.t == mop_v && ins->l.t == mop_n) {
                enc_addr = ins->r.g;
                xor_key = ins->l.nnn->value;
            }

            if (enc_addr != BADADDR) {
                // Check if this looks like string data
                flags64_t flags = get_flags(enc_addr);
                if (is_data(flags)) {
                    string_enc_info_t info;
                    info.encrypted_addr = enc_addr;
                    info.decrypt_space_addr = BADADDR;
                    info.key_addr = BADADDR;
                    info.keys.push_back((uint8_t)xor_key);
                    info.element_size = ins->l.size;
                    info.num_elements = 1;

                    if (out)
                        out->push_back(info);
                    found = true;
                }
            }
        }
    }

    // Also check for Hikari-specific global variable names
    // "EncryptedString", "DecryptSpace", "StringEncryptionEncStatus"
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("EncryptedString") != qstring::npos ||
                        name.find("DecryptSpace") != qstring::npos) {
                        found = true;
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    return found;
}

//--------------------------------------------------------------------------
// Constant encryption detection
//--------------------------------------------------------------------------
bool detect_const_encryption(mblock_t *blk, std::vector<const_enc_info_t> *out) {
    if (!blk)
        return false;

    bool found = false;

    // Look for pattern: load global, XOR with constant
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_xor)
            continue;

        ea_t gv_addr = BADADDR;
        uint64_t key = 0;

        // Check both operand orderings
        if (ins->l.t == mop_v && ins->r.t == mop_n) {
            gv_addr = ins->l.g;
            key = ins->r.nnn->value;
        } else if (ins->r.t == mop_v && ins->l.t == mop_n) {
            gv_addr = ins->r.g;
            key = ins->l.nnn->value;
        }

        if (gv_addr != BADADDR) {
            // Read the encrypted value from the global
            uint64_t enc_val = 0;
            size_t size = ins->l.size;
            if (size <= 8) {
                get_bytes(&enc_val, size, gv_addr);
                uint64_t decrypted = enc_val ^ key;

                const_enc_info_t info;
                info.const_gv_addr = gv_addr;
                info.xor_key = key;
                info.decrypted_value = decrypted;

                if (out)
                    out->push_back(info);
                found = true;
            }
        }
    }

    return found;
}

//--------------------------------------------------------------------------
// Indirect branch detection
//--------------------------------------------------------------------------
bool detect_indirect_branch(mblock_t *blk, indirect_br_info_t *out) {
    if (!blk || !blk->tail)
        return false;

    // Look for ijmp (indirect jump) instruction
    if (blk->tail->opcode != m_ijmp)
        return false;

    // The jump target comes from some computation
    // Hikari stores targets in a jump table global variable

    // Check for GEP-like pattern loading from array
    mop_t *jump_target = &blk->tail->d;

    // Look backwards for the load instruction that provides the target
    ea_t table_addr = BADADDR;
    for (minsn_t *ins = blk->tail->prev; ins; ins = ins->prev) {
        if (ins->opcode == m_ldx) {
            // Memory load - check if from global
            if (ins->l.t == mop_v) {
                table_addr = ins->l.g;
                break;
            }
        }
    }

    if (table_addr != BADADDR) {
        if (out) {
            out->jump_table_addr = table_addr;
            out->is_encrypted = false;
            out->enc_key = 0;

            // Try to read targets from jump table
            ea_t ptr = table_addr;
            for (int i = 0; i < 64; i++) {  // Limit search
                ea_t target = BADADDR;
                if (get_bytes(&target, sizeof(ea_t), ptr) == sizeof(ea_t)) {
                    if (target == 0 || target == BADADDR)
                        break;
                    // Validate it's a code address
                    if (is_code(get_flags(target))) {
                        out->targets.push_back(target);
                    }
                }
                ptr += sizeof(ea_t);
            }
        }
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Substitution pattern matching
//--------------------------------------------------------------------------
bool match_substitution_pattern(minsn_t *insn, substitution_info_t *out) {
    if (!insn)
        return false;

    // Try to match known Hikari substitution patterns

    // Pattern: a - ~b - 1 = a + b (ADD substitution)
    // x - NOT(y) - 1
    if (insn->opcode == m_sub) {
        if (insn->r.t == mop_n && insn->r.nnn->value == 1) {
            // Check if left is also a subtraction with NOT
            if (insn->l.t == mop_d && insn->l.d->opcode == m_sub) {
                minsn_t *inner = insn->l.d;
                if (inner->r.t == mop_d && inner->r.d->opcode == m_bnot) {
                    // Found: a - ~b - 1
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_ADD;
                        out->complex_insn = insn;
                        out->operand1 = inner->l;
                        out->operand2 = inner->r.d->l;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: (a | b) + (a & b) = a + b (ADD substitution 2)
    if (insn->opcode == m_add) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_or && right->opcode == m_and) {
                // Check if operands match
                // left = a | b, right = a & b
                if (out) {
                    out->original_op = substitution_info_t::SUBST_ADD;
                    out->complex_insn = insn;
                    out->operand1 = left->l;
                    out->operand2 = left->r;
                }
                return true;
            }
        }
    }

    // Pattern: (a ^ b) + 2*(a & b) = a + b (ADD substitution 3)
    if (insn->opcode == m_add) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_xor && right->opcode == m_mul) {
                // Check for 2 * (a & b)
                if (right->l.t == mop_n && right->l.nnn->value == 2) {
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_ADD;
                        out->complex_insn = insn;
                        out->operand1 = left->l;
                        out->operand2 = left->r;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: a + ~b + 1 = a - b (SUB substitution)
    if (insn->opcode == m_add) {
        if (insn->r.t == mop_n && insn->r.nnn->value == 1) {
            if (insn->l.t == mop_d && insn->l.d->opcode == m_add) {
                minsn_t *inner = insn->l.d;
                if (inner->r.t == mop_d && inner->r.d->opcode == m_bnot) {
                    // Found: a + ~b + 1 = a - b
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_SUB;
                        out->complex_insn = insn;
                        out->operand1 = inner->l;
                        out->operand2 = inner->r.d->l;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: (a ^ ~b) & a = a & b (AND substitution)
    if (insn->opcode == m_and) {
        if (insn->l.t == mop_d && insn->l.d->opcode == m_xor) {
            minsn_t *xor_insn = insn->l.d;
            if (xor_insn->r.t == mop_d && xor_insn->r.d->opcode == m_bnot) {
                // Check if right operand of AND matches left of XOR
                if (out) {
                    out->original_op = substitution_info_t::SUBST_AND;
                    out->complex_insn = insn;
                    out->operand1 = xor_insn->l;
                    out->operand2 = xor_insn->r.d->l;
                }
                return true;
            }
        }
    }

    // Pattern: (a & b) | (a ^ b) = a | b (OR substitution)
    if (insn->opcode == m_or) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_and && right->opcode == m_xor) {
                if (out) {
                    out->original_op = substitution_info_t::SUBST_OR;
                    out->complex_insn = insn;
                    out->operand1 = left->l;
                    out->operand2 = left->r;
                }
                return true;
            }
        }
    }

    // Pattern: (~a & b) | (a & ~b) = a ^ b (XOR substitution)
    if (insn->opcode == m_or) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_and && right->opcode == m_and) {
                // Check for (~a & b) | (a & ~b) pattern
                if (out) {
                    out->original_op = substitution_info_t::SUBST_XOR;
                    out->complex_insn = insn;
                    // Need deeper analysis to extract operands
                }
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Split block detection
//--------------------------------------------------------------------------
bool detect_split_blocks(mbl_array_t *mba, std::vector<split_block_info_t> *out) {
    if (!mba)
        return false;

    bool found = false;

    // Look for chains of blocks with single unconditional jumps
    std::vector<bool> visited(mba->qty, false);

    for (int i = 0; i < mba->qty; i++) {
        if (visited[i])
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Count instructions in block
        int insn_count = 0;
        for (minsn_t *ins = blk->head; ins; ins = ins->next)
            insn_count++;

        // Small block with single successor might be a split
        if (insn_count <= 2 && blk->nsucc() == 1) {
            // Follow the chain
            split_block_info_t chain;
            chain.mergeable_blocks.push_back(i);
            visited[i] = true;

            int curr = blk->succ(0);
            while (curr >= 0 && curr < mba->qty && !visited[curr]) {
                mblock_t *next_blk = mba->get_mblock(curr);
                if (!next_blk)
                    break;

                // Check if this block is also small with single successor
                int next_count = 0;
                for (minsn_t *ins = next_blk->head; ins; ins = ins->next)
                    next_count++;

                if (next_count > 2 || next_blk->nsucc() != 1)
                    break;

                chain.mergeable_blocks.push_back(curr);
                visited[curr] = true;
                curr = next_blk->succ(0);
            }

            // Only report if we found a chain of 3+ blocks
            if (chain.mergeable_blocks.size() >= 3) {
                if (out)
                    out->push_back(chain);
                found = true;
            }
        }
    }

    return found;
}

} // namespace pattern_match
