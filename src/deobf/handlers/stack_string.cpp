#include "stack_string.h"
#include "../analysis/pattern_match.h"
#include <algorithm>

//--------------------------------------------------------------------------
// Detection - Check if function likely has stack strings
//--------------------------------------------------------------------------
bool stack_string_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    int consecutive_byte_stores = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        consecutive_byte_stores = 0;
        sval_t last_offset = SVAL_MIN;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            byte_store_t store;
            if (is_stack_byte_store(ins, &store)) {
                // Check if this is sequential or near-sequential
                if (last_offset != SVAL_MIN) {
                    sval_t diff = store.offset - last_offset;
                    if (diff >= -2 && diff <= 2) {
                        consecutive_byte_stores++;
                        if (consecutive_byte_stores >= 4) {
                            // Found at least 4 consecutive byte stores - likely a string
                            return true;
                        }
                    } else {
                        consecutive_byte_stores = 1;
                    }
                } else {
                    consecutive_byte_stores = 1;
                }
                last_offset = store.offset;
            }
        }
    }

    return false;
}

bool stack_string_handler_t::detect_in_function(ea_t func_ea) {
    func_t *func = get_func(func_ea);
    if (!func)
        return false;

    // Look for byte store patterns at assembly level
    int consecutive = 0;
    ea_t last_addr = BADADDR;

    ea_t curr = func->start_ea;
    while (curr < func->end_ea) {
        insn_t insn;
        if (decode_insn(&insn, curr) == 0)
            break;

        // Look for mov [rbp-X], imm8 or mov [rsp+X], imm8 patterns
        // This is simplified - real implementation would check operand types

        curr = insn.ea + insn.size;
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int stack_string_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[stack_string] Starting stack string reconstruction\n");

    int total_strings = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        auto strings = find_stack_strings(blk);

        for (const auto &str : strings) {
            if (!str.value.empty()) {
                deobf::log("[stack_string] Found string at stack offset %d: \"%s\"\n",
                          (int)str.stack_offset, str.value.c_str());

                // Annotate in IDA
                annotate_string(str, ctx->func_ea);

                // Store in context
                ctx->decrypted_strings[str.start_addr] = str.value;

                total_strings++;
            }
        }
    }

    deobf::log("[stack_string] Reconstructed %d stack strings\n", total_strings);
    return total_strings;
}

//--------------------------------------------------------------------------
// Process a single block
//--------------------------------------------------------------------------
int stack_string_handler_t::process_block(mblock_t *blk, deobf_ctx_t *ctx) {
    if (!blk || !ctx)
        return 0;

    auto strings = find_stack_strings(blk);
    return (int)strings.size();
}

//--------------------------------------------------------------------------
// Find stack strings in a block
//--------------------------------------------------------------------------
std::vector<stack_string_handler_t::stack_string_t>
stack_string_handler_t::find_stack_strings(mblock_t *blk) {

    std::vector<stack_string_t> result;
    std::vector<byte_store_t> stores;

    // Collect all byte stores to stack
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        byte_store_t store;
        if (is_stack_byte_store(ins, &store)) {
            stores.push_back(store);
        }
    }

    if (stores.size() < 3)
        return result;

    // Sort by stack offset
    std::sort(stores.begin(), stores.end(),
              [](const byte_store_t &a, const byte_store_t &b) {
                  return a.offset < b.offset;
              });

    // Find sequences of consecutive stores
    std::vector<byte_store_t> current_seq;
    sval_t expected_offset = SVAL_MIN;

    for (size_t i = 0; i < stores.size(); i++) {
        const byte_store_t &store = stores[i];

        if (expected_offset == SVAL_MIN) {
            // Start new sequence
            current_seq.clear();
            current_seq.push_back(store);
            expected_offset = store.offset + 1;
        } else if (store.offset == expected_offset) {
            // Continue sequence
            current_seq.push_back(store);
            expected_offset = store.offset + 1;
        } else if (store.offset == expected_offset - 1) {
            // Same offset (duplicate store) - skip
            continue;
        } else {
            // Sequence broken - check if we have a string
            if (current_seq.size() >= 3) {
                stack_string_t str;
                if (analyze_byte_sequence(current_seq, &str)) {
                    result.push_back(str);
                }
            }

            // Start new sequence
            current_seq.clear();
            current_seq.push_back(store);
            expected_offset = store.offset + 1;
        }
    }

    // Check final sequence
    if (current_seq.size() >= 3) {
        stack_string_t str;
        if (analyze_byte_sequence(current_seq, &str)) {
            result.push_back(str);
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze a sequence of byte stores
//--------------------------------------------------------------------------
bool stack_string_handler_t::analyze_byte_sequence(
    const std::vector<byte_store_t> &stores, stack_string_t *out) {

    if (stores.empty())
        return false;

    std::string str;
    bool has_transform = false;
    bool has_null_term = false;

    for (const auto &store : stores) {
        uint8_t b = store.value;

        if (b == 0) {
            has_null_term = true;
            break;  // Stop at null terminator
        }

        if (!is_string_byte(b)) {
            // Not a printable character - might not be a string
            // Allow some control characters
            if (b != '\n' && b != '\r' && b != '\t') {
                return false;
            }
        }

        str += (char)b;
        if (store.transformed)
            has_transform = true;
    }

    // Require at least 3 printable characters
    if (str.length() < 3)
        return false;

    // If no null terminator found but string looks valid, still accept it
    // (sometimes the null is stored separately or implicitly)

    out->start_addr = stores[0].insn_addr;
    out->stack_offset = stores[0].offset;
    out->value = str;
    out->uses_transform = has_transform;

    for (const auto &store : stores) {
        out->insn_addrs.push_back(store.insn_addr);
    }

    return true;
}

//--------------------------------------------------------------------------
// Check if instruction is a byte store to stack
//--------------------------------------------------------------------------
bool stack_string_handler_t::is_stack_byte_store(minsn_t *ins, byte_store_t *out) {
    if (!ins)
        return false;

    // Look for mov to stack variable with immediate or computed byte value
    if (ins->opcode != m_mov && ins->opcode != m_stx)
        return false;

    // Destination must be a stack variable
    if (ins->d.t != mop_S)
        return false;

    // Size must be 1 byte
    if (ins->d.size != 1)
        return false;

    // Get the value being stored
    uint8_t value = 0;
    bool transformed = false;

    if (ins->l.t == mop_n) {
        // Immediate value
        value = (uint8_t)(ins->l.nnn->value & 0xFF);
    } else if (ins->l.t == mop_d && ins->l.d) {
        // Computed value - try to resolve
        value = resolve_byte_value(ins->l.d);
        transformed = (ins->l.d->opcode == m_bnot || ins->l.d->opcode == m_xor);
    } else {
        return false;
    }

    if (out) {
        out->offset = ins->d.s ? ins->d.s->off : 0;
        out->value = value;
        out->insn_addr = ins->ea;
        out->transformed = transformed;
    }

    return true;
}

//--------------------------------------------------------------------------
// Resolve transformed byte value (NOT, XOR)
//--------------------------------------------------------------------------
uint8_t stack_string_handler_t::resolve_byte_value(minsn_t *ins) {
    if (!ins)
        return 0;

    // Handle NOT (~)
    if (ins->opcode == m_bnot || ins->opcode == m_lnot) {
        if (ins->l.t == mop_n) {
            return (uint8_t)(~ins->l.nnn->value & 0xFF);
        }
        // Could be NOT of another value - try to resolve recursively
        if (ins->l.t == mop_d && ins->l.d) {
            return ~resolve_byte_value(ins->l.d);
        }
    }

    // Handle XOR
    if (ins->opcode == m_xor) {
        uint8_t left = 0, right = 0;

        if (ins->l.t == mop_n)
            left = (uint8_t)(ins->l.nnn->value & 0xFF);
        else if (ins->l.t == mop_d && ins->l.d)
            left = resolve_byte_value(ins->l.d);

        if (ins->r.t == mop_n)
            right = (uint8_t)(ins->r.nnn->value & 0xFF);
        else if (ins->r.t == mop_d && ins->r.d)
            right = resolve_byte_value(ins->r.d);

        return left ^ right;
    }

    // Direct value
    if (ins->l.t == mop_n) {
        return (uint8_t)(ins->l.nnn->value & 0xFF);
    }

    return 0;
}

//--------------------------------------------------------------------------
// Check if byte is a valid string character
//--------------------------------------------------------------------------
bool stack_string_handler_t::is_string_byte(uint8_t b) {
    // Printable ASCII
    if (b >= 0x20 && b <= 0x7E)
        return true;

    // Common control characters
    if (b == '\n' || b == '\r' || b == '\t')
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Annotate string in IDA
//--------------------------------------------------------------------------
void stack_string_handler_t::annotate_string(const stack_string_t &str, ea_t func_ea) {
    if (str.insn_addrs.empty())
        return;

    // Add comment at the first instruction
    qstring comment;
    comment.sprnt("Stack string: \"%s\"", str.value.c_str());

    // Escape special characters for display
    qstring escaped;
    for (char c : str.value) {
        if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else if (c == '"') escaped += "\\\"";
        else if (c == '\\') escaped += "\\\\";
        else escaped += c;
    }

    comment.sprnt("Stack string: \"%s\"", escaped.c_str());
    set_cmt(str.insn_addrs[0], comment.c_str(), false);

    // Also add to function comment if significant
    if (str.value.length() >= 8) {
        func_t *fn = get_func(func_ea);
        if (fn) {
            qstring func_cmt;
            func_cmt.sprnt("Contains string: \"%s\"", escaped.c_str());
            // Append to existing function comment
            qstring existing;
            if (get_func_cmt(&existing, fn, false) > 0) {
                existing += "\n";
                existing += func_cmt;
                set_func_cmt(fn, existing.c_str(), false);
            } else {
                set_func_cmt(fn, func_cmt.c_str(), false);
            }
        }
    }
}

//--------------------------------------------------------------------------
// Try to patch string usage
//--------------------------------------------------------------------------
int stack_string_handler_t::patch_string_usage(mbl_array_t *mba,
    const stack_string_t &str, deobf_ctx_t *ctx) {
    // This is complex - would require creating a string in the data segment
    // and replacing the stack construction with a reference to it
    // For now, just annotate and let the analyst see the string
    return 0;
}
