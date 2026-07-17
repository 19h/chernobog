#include "stack_string.h"
#include "../analysis/pattern_match.h"
#include <algorithm>

//--------------------------------------------------------------------------
// Detection - Check if function likely has stack strings
//--------------------------------------------------------------------------
bool stack_string_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    int consecutive_byte_stores = 0;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        consecutive_byte_stores = 0;
        sval_t last_offset = SVAL_MIN;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            byte_store_t store;
            if ( is_stack_byte_store(ins, &store) ) {
                // Check if this is sequential or near-sequential
                if ( last_offset != SVAL_MIN ) {
                    sval_t diff = store.offset - last_offset;
                    if ( diff >= -2 && diff <= 2 ) {
                        consecutive_byte_stores++;
                        if ( consecutive_byte_stores >= 4 ) {
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

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int stack_string_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[stack_string] Starting stack string reconstruction\n");

    int total_strings = 0;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        auto strings = find_stack_strings(blk);

        for ( const auto &str : strings ) {
            if ( !str.value.empty() ) {
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
    // Reconstruction currently produces database annotations only.
    return 0;
}

//--------------------------------------------------------------------------
// Find stack strings in a block
//--------------------------------------------------------------------------
std::vector<stack_string_handler_t::stack_string_t>
stack_string_handler_t::find_stack_strings(mblock_t *blk)
{

    std::vector<stack_string_t> result;
    std::vector<byte_store_t> stores;

    // Collect all byte stores to stack
    for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
        byte_store_t store;
        if ( is_stack_byte_store(ins, &store) ) {
            stores.push_back(store);
        }
    }

    if ( stores.size() < 3 ) 
        return result;

    // Conflicting writes do not establish one unambiguous constructed value.
    std::set<sval_t> seen_offsets;
    std::set<sval_t> duplicate_offsets;
    for ( const auto& store : stores )
    {
        if ( !seen_offsets.insert(store.offset).second )
            duplicate_offsets.insert(store.offset);
    }
    stores.erase(
        std::remove_if(stores.begin(), stores.end(),
            [&duplicate_offsets](const byte_store_t& store) {
                return duplicate_offsets.count(store.offset) != 0;
            }),
        stores.end());

    // Sort by stack offset
    std::sort(stores.begin(), stores.end(),
              [](const byte_store_t &a, const byte_store_t &b)
              {
                  return a.offset < b.offset;
              });

    // Find sequences of consecutive stores
    std::vector<byte_store_t> current_seq;
    sval_t expected_offset = SVAL_MIN;

    for ( size_t i = 0; i < stores.size(); ++i ) {
        const byte_store_t &store = stores[i];

        if ( expected_offset == SVAL_MIN ) {
            // Start new sequence
            current_seq.clear();
            current_seq.push_back(store);
            expected_offset = store.offset + 1;
        } else if ( store.offset == expected_offset ) {
            // Continue sequence
            current_seq.push_back(store);
            expected_offset = store.offset + 1;
        } else {
            // Sequence broken - check if we have a string
            if ( current_seq.size() >= 3 ) {
                stack_string_t str;
                if ( analyze_byte_sequence(current_seq, &str) ) {
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
    if ( current_seq.size() >= 3 ) {
        stack_string_t str;
        if ( analyze_byte_sequence(current_seq, &str) ) {
            result.push_back(str);
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze a sequence of byte stores
//--------------------------------------------------------------------------
bool stack_string_handler_t::analyze_byte_sequence(
    const std::vector<byte_store_t> &stores, stack_string_t *out)
    {

    if ( stores.empty() ) 
        return false;

    std::string str;
    bool has_transform = false;
    bool terminated = false;

    for ( const auto &store : stores ) {
        uint8_t b = store.value;

        if ( b == 0 ) {
            terminated = true;
            break;  // Stop at null terminator
        }

        if ( !is_string_byte(b) ) {
            // Not a printable character - might not be a string
            // Allow some control characters
            if ( b != '\n' && b != '\r' && b != '\t' ) {
                return false;
            }
        }

        str += (char)b;
        if ( store.transformed ) 
            has_transform = true;
    }

    // Require at least 3 printable characters
    if ( str.length() < 3 || !terminated )
        return false;

    out->start_addr = stores[0].insn_addr;
    out->stack_offset = stores[0].offset;
    out->value = str;
    out->uses_transform = has_transform;

    for ( const auto &store : stores ) {
        out->insn_addrs.push_back(store.insn_addr);
    }

    return true;
}

//--------------------------------------------------------------------------
// Check if instruction is a byte store to stack
//--------------------------------------------------------------------------
bool stack_string_handler_t::is_stack_byte_store(minsn_t *ins, byte_store_t *out)
{
    if ( !ins ) 
        return false;

    // Look for mov to stack variable with immediate or computed byte value
    if ( ins->opcode != m_mov && ins->opcode != m_stx ) 
        return false;

    // Destination must be a stack variable
    if ( ins->d.t != mop_S || !ins->d.s )
        return false;

    // Size must be 1 byte
    if ( ins->d.size != 1 ) 
        return false;

    // Get the value being stored
    uint8_t value = 0;
    bool transformed = false;

    if ( ins->l.t == mop_n && ins->l.nnn ) {
        // Immediate value
        value = (uint8_t)(ins->l.nnn->value & 0xFF);
    } else if ( ins->l.t == mop_d && ins->l.d ) {
        // Computed value - try to resolve
        auto resolved = resolve_byte_value(ins->l.d);
        if ( !resolved )
            return false;
        value = *resolved;
        transformed = (ins->l.d->opcode == m_bnot
                    || ins->l.d->opcode == m_lnot
                    || ins->l.d->opcode == m_xor);
    } else {
        return false;
    }

    if ( out ) {
        out->offset = ins->d.s->off;
        out->value = value;
        out->insn_addr = ins->ea;
        out->transformed = transformed;
    }

    return true;
}

//--------------------------------------------------------------------------
// Resolve transformed byte value (NOT, XOR)
//--------------------------------------------------------------------------
std::optional<uint8_t> stack_string_handler_t::resolve_byte_value(
    minsn_t *ins, int depth)
{
    if ( !ins || depth > 16 )
        return std::nullopt;

    if ( ins->opcode == m_bnot ) {
        if ( ins->l.t == mop_n && ins->l.nnn ) {
            return (uint8_t)(~ins->l.nnn->value & 0xFF);
        }
        if ( ins->l.t == mop_d && ins->l.d ) {
            auto value = resolve_byte_value(ins->l.d, depth + 1);
            return value ? std::optional<uint8_t>(static_cast<uint8_t>(~*value))
                         : std::nullopt;
        }
        return std::nullopt;
    }

    if ( ins->opcode == m_lnot ) {
        auto value = ins->l.t == mop_n && ins->l.nnn
            ? std::optional<uint8_t>(static_cast<uint8_t>(ins->l.nnn->value))
            : (ins->l.t == mop_d && ins->l.d
               ? resolve_byte_value(ins->l.d, depth + 1) : std::nullopt);
        return value ? std::optional<uint8_t>(*value == 0 ? 1 : 0)
                     : std::nullopt;
    }

    // Handle XOR
    if ( ins->opcode == m_xor ) {
        auto operand = [depth](const mop_t& op) -> std::optional<uint8_t> {
            if ( op.t == mop_n && op.nnn )
                return static_cast<uint8_t>(op.nnn->value);
            if ( op.t == mop_d && op.d )
                return stack_string_handler_t::resolve_byte_value(
                    op.d, depth + 1);
            return std::nullopt;
        };
        auto left = operand(ins->l);
        auto right = operand(ins->r);
        if ( !left || !right )
            return std::nullopt;
        return static_cast<uint8_t>(*left ^ *right);
    }

    if ( ins->opcode == m_mov && ins->l.t == mop_n && ins->l.nnn ) {
        return (uint8_t)(ins->l.nnn->value & 0xFF);
    }

    return std::nullopt;
}

//--------------------------------------------------------------------------
// Check if byte is a valid string character
//--------------------------------------------------------------------------
bool stack_string_handler_t::is_string_byte(uint8_t b)
{
    // Printable ASCII
    if ( b >= 0x20 && b <= 0x7E ) 
        return true;

    // Common control characters
    if ( b == '\n' || b == '\r' || b == '\t' ) 
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Annotate string in IDA
//--------------------------------------------------------------------------
void stack_string_handler_t::annotate_string(const stack_string_t &str, ea_t func_ea)
{
    if ( str.insn_addrs.empty() ) 
        return;

    // Add comment at the first instruction
    qstring comment;
    comment.sprnt("Stack string: \"%s\"", str.value.c_str());

    // Escape special characters for display
    qstring escaped;
    for ( char c : str.value ) {
        if ( c == '\n') escaped += "\\n";
        else if ( c == '\r') escaped += "\\r";
        else if ( c == '\t') escaped += "\\t";
        else if ( c == '"') escaped += "\\\"";
        else if ( c == '\\') escaped += "\\\\";
        else escaped += c;
    }

    comment.sprnt("Stack string: \"%s\"", escaped.c_str());
    set_cmt(str.insn_addrs[0], comment.c_str(), false);

    // Also add to function comment if significant
    if ( str.value.length() >= 8 ) {
        func_t *fn = get_func(func_ea);
        if ( fn ) {
            qstring func_cmt;
            func_cmt.sprnt("Contains string: \"%s\"", escaped.c_str());
            // Append to existing function comment
            qstring existing;
            if ( get_func_cmt(&existing, fn, false) > 0 ) {
                if ( strstr(existing.c_str(), func_cmt.c_str()) == nullptr ) {
                    existing += "\n";
                    existing += func_cmt;
                    set_func_cmt(fn, existing.c_str(), false);
                }
            } else {
                set_func_cmt(fn, func_cmt.c_str(), false);
            }
        }
    }
}
