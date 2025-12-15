#include "indirect_branch.h"
#include "../analysis/cfg_analysis.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Look for ijmp instructions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (blk->tail->opcode == m_ijmp) {
            return true;
        }
    }

    // Also check for global jump tables
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("IndirectBranchingGlobalTable") != qstring::npos ||
                        name.find("HikariConditionalLocalIndirectBranchingTable") != qstring::npos ||
                        name.find("IndirectBranchTable") != qstring::npos) {
                        return true;
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int indirect_branch_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[indirect_branch] Starting indirect branch resolution\n");

    int total_changes = 0;

    // Find all indirect branches
    auto ibrs = find_indirect_branches(mba);
    deobf::log("[indirect_branch] Found %zu indirect branches\n", ibrs.size());

    for (auto &ibr : ibrs) {
        mblock_t *blk = mba->get_mblock(ibr.block_idx);
        if (!blk)
            continue;

        // Try to trace index computation
        index_computation_t idx_comp;
        if (trace_index_computation(blk, ibr.ijmp_insn, &idx_comp)) {
            ibr.index_traced = true;
            ibr.possible_indices = emulate_index_values(mba, blk, idx_comp);
            deobf::log("[indirect_branch] Block %d: traced %zu possible indices\n",
                      blk->serial, ibr.possible_indices.size());
        }

        total_changes += replace_indirect_branch(mba, blk, ibr, ctx);
    }

    deobf::log("[indirect_branch] Resolved %d indirect branches\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find indirect branches
//--------------------------------------------------------------------------
std::vector<indirect_branch_handler_t::indirect_br_t>
indirect_branch_handler_t::find_indirect_branches(mbl_array_t *mba) {

    std::vector<indirect_br_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (blk->tail->opcode == m_ijmp) {
            indirect_br_t ibr;
            ibr.block_idx = i;
            ibr.ijmp_insn = blk->tail;
            ibr.is_encrypted = false;
            ibr.enc_key = 0;
            ibr.encoding = ENC_DIRECT;
            ibr.base_addr = BADADDR;
            ibr.entry_size = sizeof(ea_t);
            ibr.table_size = 0;
            ibr.index_traced = false;

            if (analyze_ijmp(blk, blk->tail, &ibr)) {
                result.push_back(ibr);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze table encoding
//--------------------------------------------------------------------------
indirect_branch_handler_t::table_encoding_t
indirect_branch_handler_t::analyze_table_encoding(mblock_t *blk, minsn_t *ijmp,
                                                  uint64_t *out_key, ea_t *out_base) {
    if (!blk || !ijmp)
        return ENC_UNKNOWN;

    bool has_xor = false;
    bool has_add = false;
    uint64_t xor_key = 0;
    ea_t base_addr = BADADDR;

    // Trace back through the block looking for XOR and ADD operations
    for (minsn_t *ins = blk->head; ins && ins != ijmp; ins = ins->next) {
        // Look for XOR with constant
        if (ins->opcode == m_xor) {
            if (ins->l.t == mop_n) {
                has_xor = true;
                xor_key = ins->l.nnn->value;
            } else if (ins->r.t == mop_n) {
                has_xor = true;
                xor_key = ins->r.nnn->value;
            }
        }

        // Look for ADD with global address (base offset)
        if (ins->opcode == m_add) {
            if (ins->l.t == mop_v) {
                has_add = true;
                base_addr = ins->l.g;
            } else if (ins->r.t == mop_v) {
                has_add = true;
                base_addr = ins->r.g;
            }
        }
    }

    if (out_key) *out_key = xor_key;
    if (out_base) *out_base = base_addr;

    if (has_xor && has_add) return ENC_OFFSET_XOR;
    if (has_xor) return ENC_XOR;
    if (has_add) return ENC_OFFSET;
    return ENC_DIRECT;
}

//--------------------------------------------------------------------------
// Trace index computation
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::trace_index_computation(mblock_t *blk, minsn_t *ijmp,
                                                        index_computation_t *out) {
    if (!blk || !ijmp || !out)
        return false;

    out->type = index_computation_t::OP_COMPLEX;
    out->mask = 0;
    out->sub_value = 0;
    out->max_index = 256;  // Default max

    // Trace back to find how the index is computed
    // Looking for patterns like:
    //   index = state_var & 0xFF       (AND mask)
    //   index = state_var % N          (MOD)
    //   index = (state_var - base) & mask

    for (minsn_t *ins = blk->tail; ins; ins = ins->prev) {
        if (ins == ijmp)
            continue;

        // Look for AND with constant mask
        if (ins->opcode == m_and) {
            if (ins->r.t == mop_n) {
                out->type = index_computation_t::OP_AND;
                out->mask = ins->r.nnn->value;
                out->max_index = (int)out->mask + 1;

                // Check if source is subtraction
                if (ins->l.t == mop_d && ins->l.d && ins->l.d->opcode == m_sub) {
                    minsn_t *sub = ins->l.d;
                    if (sub->r.t == mop_n) {
                        out->type = index_computation_t::OP_SUB_AND;
                        out->sub_value = sub->r.nnn->value;
                        out->source_var = sub->l;
                    }
                } else {
                    out->source_var = ins->l;
                }
                return true;
            }
        }

        // Look for MOD (unsigned remainder)
        if (ins->opcode == m_udiv || ins->opcode == m_sdiv) {
            // The remainder would be computed separately
            // Look for pattern: var - (var / N) * N
        }

        // Look for low byte extraction (common pattern)
        if (ins->opcode == m_low) {
            // Low byte extraction implies index < 256
            out->type = index_computation_t::OP_AND;
            out->mask = 0xFF;
            out->max_index = 256;
            out->source_var = ins->l;
            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Emulate index values
//--------------------------------------------------------------------------
std::set<int> indirect_branch_handler_t::emulate_index_values(
    mbl_array_t *mba, mblock_t *blk, const index_computation_t &idx_comp) {

    std::set<int> indices;

    // For AND mask, all values 0 to mask are possible
    if (idx_comp.type == index_computation_t::OP_AND ||
        idx_comp.type == index_computation_t::OP_SUB_AND) {

        for (int i = 0; i <= (int)idx_comp.mask && i < idx_comp.max_index; i++) {
            indices.insert(i);
        }
        return indices;
    }

    // For MOD, all values 0 to (divisor-1) are possible
    if (idx_comp.type == index_computation_t::OP_MOD) {
        for (int i = 0; i < (int)idx_comp.mask && i < idx_comp.max_index; i++) {
            indices.insert(i);
        }
        return indices;
    }

    // For direct or complex, try to find the actual values used
    // This would require more sophisticated dataflow analysis
    // For now, return empty to indicate we couldn't determine
    return indices;
}

//--------------------------------------------------------------------------
// Analyze indirect jump
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::analyze_ijmp(mblock_t *blk, minsn_t *ijmp, indirect_br_t *out) {
    if (!blk || !ijmp || ijmp->opcode != m_ijmp)
        return false;

    // Analyze encoding
    uint64_t key = 0;
    ea_t base = BADADDR;
    out->encoding = analyze_table_encoding(blk, ijmp, &key, &base);
    out->enc_key = key;
    out->base_addr = base;
    out->is_encrypted = (out->encoding == ENC_XOR || out->encoding == ENC_OFFSET_XOR);

    // Find the jump table
    ea_t table_addr = find_jump_table(blk, ijmp);
    if (table_addr == BADADDR) {
        deobf::log_verbose("[indirect_branch] Could not find jump table for block %d\n",
                          blk->serial);
        return false;
    }

    out->table_addr = table_addr;

    // Determine entry size (try 8 bytes first, then 4)
    out->entry_size = sizeof(ea_t);

    // Read targets from table
    out->targets = read_jump_targets(table_addr, 256, out->encoding,
                                     out->enc_key, out->base_addr, out->entry_size);

    // If no valid targets with pointer size, try 4-byte entries
    if (out->targets.empty() && sizeof(ea_t) == 8) {
        out->entry_size = 4;
        out->targets = read_jump_targets(table_addr, 256, out->encoding,
                                         out->enc_key, out->base_addr, out->entry_size);
    }

    out->table_size = (int)out->targets.size();

    if (out->targets.empty()) {
        deobf::log_verbose("[indirect_branch] No valid targets found at %a\n", table_addr);
        return false;
    }

    deobf::log_verbose("[indirect_branch] Found %zu targets at table %a (enc=%d, entry=%d)\n",
                      out->targets.size(), table_addr, out->encoding, out->entry_size);

    return true;
}

//--------------------------------------------------------------------------
// Find jump table
//--------------------------------------------------------------------------
ea_t indirect_branch_handler_t::find_jump_table(mblock_t *blk, minsn_t *ijmp) {
    // Trace back from ijmp to find the table address
    // Pattern: load from table[index]

    // Look for loads from global addresses
    for (minsn_t *ins = blk->head; ins && ins != ijmp; ins = ins->next) {
        if (ins->opcode == m_ldx) {
            // Memory load - check if from global
            if (ins->l.t == mop_v) {
                ea_t addr = ins->l.g;
                // Verify it looks like a jump table
                uint64_t first_entry = 0;
                if (get_bytes(&first_entry, sizeof(ea_t), addr) == sizeof(ea_t)) {
                    // Check if it's a reasonable code address
                    if (first_entry != 0 && first_entry != BADADDR) {
                        if (is_code(get_flags((ea_t)first_entry))) {
                            return addr;
                        }
                        // Might be offset - try adding to function base
                        func_t *func = get_func(blk->start);
                        if (func) {
                            ea_t resolved = func->start_ea + first_entry;
                            if (is_code(get_flags(resolved))) {
                                return addr;
                            }
                        }
                    }
                }
            }

            // Check for indexed access: table + index * 8
            if (ins->l.t == mop_d && ins->l.d) {
                minsn_t *addr_calc = ins->l.d;
                if (addr_calc->opcode == m_add) {
                    // One operand should be the table base
                    if (addr_calc->l.t == mop_v) {
                        return addr_calc->l.g;
                    }
                    if (addr_calc->r.t == mop_v) {
                        return addr_calc->r.g;
                    }
                }
            }
        }
    }

    // Check operand directly
    if (ijmp->d.t == mop_v) {
        return ijmp->d.g;
    }

    // Look for named tables in globals
    const char *table_names[] = {
        "IndirectBranchingGlobalTable",
        "HikariConditionalLocalIndirectBranchingTable",
        "IndirectBranchTable",
        nullptr
    };

    for (int i = 0; table_names[i]; i++) {
        ea_t table_ea = get_name_ea(BADADDR, table_names[i]);
        if (table_ea != BADADDR)
            return table_ea;
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Decode a single table entry
//--------------------------------------------------------------------------
ea_t indirect_branch_handler_t::decode_table_entry(uint64_t raw_value,
                                                   table_encoding_t encoding,
                                                   uint64_t key, ea_t base) {
    switch (encoding) {
        case ENC_DIRECT:
            return (ea_t)raw_value;

        case ENC_OFFSET:
            if (base != BADADDR)
                return base + raw_value;
            return (ea_t)raw_value;

        case ENC_XOR:
            return (ea_t)(raw_value ^ key);

        case ENC_OFFSET_XOR:
            if (base != BADADDR)
                return base + (raw_value ^ key);
            return (ea_t)(raw_value ^ key);

        default:
            return (ea_t)raw_value;
    }
}

//--------------------------------------------------------------------------
// Read jump targets from table
//--------------------------------------------------------------------------
std::vector<ea_t> indirect_branch_handler_t::read_jump_targets(
    ea_t table_addr, int max_entries,
    table_encoding_t encoding, uint64_t key, ea_t base, int entry_size) {

    std::vector<ea_t> targets;

    if (table_addr == BADADDR)
        return targets;

    // Get function containing the table for validation
    func_t *func = get_func(table_addr);
    ea_t func_start = func ? func->start_ea : BADADDR;
    ea_t func_end = func ? func->end_ea : BADADDR;

    for (int i = 0; i < max_entries; i++) {
        ea_t entry_addr = table_addr + i * entry_size;
        uint64_t raw_value = 0;

        if (get_bytes(&raw_value, entry_size, entry_addr) != entry_size)
            break;

        // Check for end of table (null entry)
        if (raw_value == 0)
            break;

        // Decode the entry
        ea_t target = decode_table_entry(raw_value, encoding, key, base);

        // Validate target
        if (target == 0 || target == BADADDR)
            break;

        // Check if target is valid code
        if (is_code(get_flags(target))) {
            targets.push_back(target);
            continue;
        }

        // If encoding is OFFSET, the base might be the function start
        if ((encoding == ENC_OFFSET || encoding == ENC_OFFSET_XOR) &&
            func_start != BADADDR) {
            ea_t alt_target = func_start + raw_value;
            if (encoding == ENC_OFFSET_XOR)
                alt_target = func_start + (raw_value ^ key);

            if (is_code(get_flags(alt_target))) {
                targets.push_back(alt_target);
                continue;
            }
        }

        // Invalid entry - might be end of table or wrong encoding
        // Allow a few invalid entries before giving up
        if (targets.size() > 2)
            break;
    }

    return targets;
}

//--------------------------------------------------------------------------
// Decrypt targets (legacy support)
//--------------------------------------------------------------------------
std::vector<ea_t> indirect_branch_handler_t::decrypt_targets(
    const std::vector<ea_t> &encrypted, uint64_t key) {

    std::vector<ea_t> decrypted;

    for (ea_t enc : encrypted) {
        ea_t dec = enc ^ key;
        decrypted.push_back(dec);
    }

    return decrypted;
}

//--------------------------------------------------------------------------
// Validate targets belong to the function
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::validate_targets(const std::vector<ea_t> &targets,
                                                 mbl_array_t *mba) {
    if (targets.empty())
        return false;

    ea_t func_start = mba->entry_ea;
    func_t *func = get_func(func_start);
    if (!func)
        return true;  // Can't validate without function bounds

    for (ea_t target : targets) {
        // Target should be within the function or a known external
        if (target < func->start_ea || target >= func->end_ea) {
            // Check if it's a valid code address at all
            if (!is_code(get_flags(target))) {
                return false;
            }
        }
    }

    return true;
}

//--------------------------------------------------------------------------
// Annotate indirect branch
//--------------------------------------------------------------------------
void indirect_branch_handler_t::annotate_indirect_branch(mblock_t *blk,
                                                         const indirect_br_t &ibr) {
    qstring comment;
    comment.sprnt("DEOBF: Indirect branch table at 0x%llX (%d entries)",
                 (unsigned long long)ibr.table_addr, (int)ibr.targets.size());

    if (ibr.is_encrypted) {
        comment.cat_sprnt(" [encrypted, key=0x%llX]", (unsigned long long)ibr.enc_key);
    }

    comment += "\nTargets:";
    for (size_t i = 0; i < ibr.targets.size() && i < 10; i++) {
        qstring name;
        if (get_name(&name, ibr.targets[i]) > 0) {
            comment.cat_sprnt("\n  [%d] 0x%llX (%s)", (int)i,
                             (unsigned long long)ibr.targets[i], name.c_str());
        } else {
            comment.cat_sprnt("\n  [%d] 0x%llX", (int)i,
                             (unsigned long long)ibr.targets[i]);
        }
    }

    if (ibr.targets.size() > 10) {
        comment.cat_sprnt("\n  ... and %d more", (int)(ibr.targets.size() - 10));
    }

    // Add comment to the block's starting address
    set_cmt(blk->start, comment.c_str(), false);
}

//--------------------------------------------------------------------------
// Build switch from indirect branch
//--------------------------------------------------------------------------
int indirect_branch_handler_t::build_switch(mbl_array_t *mba, mblock_t *blk,
                                           const indirect_br_t &ibr, deobf_ctx_t *ctx) {
    // Building a proper switch in microcode is complex
    // For now, we'll just annotate the targets

    annotate_indirect_branch(blk, ibr);
    return 0;
}

//--------------------------------------------------------------------------
// Replace indirect branch
//--------------------------------------------------------------------------
int indirect_branch_handler_t::replace_indirect_branch(mbl_array_t *mba, mblock_t *blk,
    const indirect_br_t &ibr, deobf_ctx_t *ctx) {

    if (!blk || ibr.targets.empty())
        return 0;

    // Log the indirect branch info
    deobf::log("[indirect_branch] Block %d: table at 0x%llX with %zu targets\n",
              blk->serial, (unsigned long long)ibr.table_addr, ibr.targets.size());

    // If single target, this might be convertible to unconditional jump
    if (ibr.targets.size() == 1) {
        minsn_t *ijmp = ibr.ijmp_insn;

        // For single target, we could convert to direct jump
        // But this requires finding the target block
        deobf::log("[indirect_branch]   Single target: 0x%llX\n",
                  (unsigned long long)ibr.targets[0]);

        // Annotate for now
        qstring comment;
        comment.sprnt("DEOBF: Indirect jump -> 0x%llX",
                     (unsigned long long)ibr.targets[0]);
        set_cmt(blk->start, comment.c_str(), false);

        ctx->branches_simplified++;
        return 1;
    }

    // Multiple targets - annotate the jump table
    annotate_indirect_branch(blk, ibr);

    // Log targets
    deobf::log("[indirect_branch]   Targets:\n");
    for (size_t i = 0; i < ibr.targets.size() && i < 16; i++) {
        qstring name;
        get_name(&name, ibr.targets[i]);
        deobf::log("[indirect_branch]     [%zu] 0x%llX %s\n",
                  i, (unsigned long long)ibr.targets[i],
                  name.empty() ? "" : name.c_str());
    }

    ctx->branches_simplified++;
    return 1;
}
