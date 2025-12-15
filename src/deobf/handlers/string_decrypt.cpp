#include "string_decrypt.h"
#include "../analysis/pattern_match.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool string_decrypt_handler_t::detect(ea_t func_ea) {
    // Look for Hikari string encryption markers in the binary

    // Check for EncryptedString/DecryptSpace globals
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("EncryptedString") != qstring::npos ||
                        name.find("DecryptSpace") != qstring::npos ||
                        name.find("StringEncryptionEncStatus") != qstring::npos) {
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
int string_decrypt_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[string_decrypt] Starting string decryption\n");

    int total_changes = 0;

    // Find all encrypted strings
    auto encrypted_strings = find_encrypted_strings(ctx->func_ea);
    deobf::log("[string_decrypt] Found %zu potential encrypted strings\n",
              encrypted_strings.size());

    for (auto &str : encrypted_strings) {
        // Try to extract XOR keys
        if (!extract_xor_keys(mba, &str)) {
            deobf::log_verbose("[string_decrypt] Could not extract keys for %a\n",
                              str.encrypted_addr);
            continue;
        }

        // Decrypt the string
        std::string decrypted = decrypt_string(str);
        if (decrypted.empty())
            continue;

        deobf::log("[string_decrypt] Decrypted string at %a: \"%s\"\n",
                  str.encrypted_addr, decrypted.c_str());

        // Store in context
        ctx->decrypted_strings[str.encrypted_addr] = decrypted;

        // Annotate in IDA
        annotate_string(str, decrypted);

        // Patch references in microcode
        total_changes += patch_string_references(mba, str, decrypted, ctx);

        ctx->strings_decrypted++;
    }

    deobf::log("[string_decrypt] Decrypted %d strings\n", ctx->strings_decrypted);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find encrypted strings
//--------------------------------------------------------------------------
std::vector<string_decrypt_handler_t::encrypted_string_t>
string_decrypt_handler_t::find_encrypted_strings(ea_t func_ea) {

    std::vector<encrypted_string_t> result;

    // Scan data segments for EncryptedString patterns
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("EncryptedString") != qstring::npos) {
                        encrypted_string_t str;
                        str.encrypted_addr = ea;
                        str.element_size = 1;  // Default to byte

                        // Try to find the size from the type
                        tinfo_t ti;
                        if (get_tinfo(&ti, ea)) {
                            str.element_size = ti.get_size();
                            if (str.element_size == 0 || str.element_size > 8)
                                str.element_size = 1;
                        }

                        // Read encrypted data (up to 1KB)
                        size_t max_size = 1024;
                        str.encrypted_data.resize(max_size);
                        ssize_t read = get_bytes(str.encrypted_data.data(), max_size, ea);
                        if (read > 0) {
                            str.encrypted_data.resize(read);

                            // Look for corresponding DecryptSpace
                            qstring decrypt_name = name;
                            decrypt_name.replace("EncryptedString", "DecryptSpace");
                            str.decrypt_space_addr = get_name_ea(BADADDR, decrypt_name.c_str());

                            result.push_back(str);
                        }
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    return result;
}

//--------------------------------------------------------------------------
// Extract XOR keys from decryption code
//--------------------------------------------------------------------------
bool string_decrypt_handler_t::extract_xor_keys(mbl_array_t *mba, encrypted_string_t *str) {
    if (!mba || !str)
        return false;

    // Look for XOR instructions that reference the encrypted address
    // Pattern: load encrypted[i]; xor with key; store to decrypted[i]

    std::map<size_t, uint8_t> key_map;  // offset -> key

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_xor)
                continue;

            // Check if one operand is from encrypted address
            // and other is a constant (the key)

            ea_t ref_addr = BADADDR;
            uint64_t key_val = 0;
            bool found = false;

            // Check left operand for global reference
            if (ins->l.t == mop_v) {
                // Direct global variable access
                ea_t gv_addr = ins->l.g;
                if (gv_addr >= str->encrypted_addr &&
                    gv_addr < str->encrypted_addr + str->encrypted_data.size()) {
                    ref_addr = gv_addr;
                    if (ins->r.t == mop_n) {
                        key_val = ins->r.nnn->value;
                        found = true;
                    }
                }
            }

            // Check right operand similarly
            if (!found && ins->r.t == mop_v) {
                ea_t gv_addr = ins->r.g;
                if (gv_addr >= str->encrypted_addr &&
                    gv_addr < str->encrypted_addr + str->encrypted_data.size()) {
                    ref_addr = gv_addr;
                    if (ins->l.t == mop_n) {
                        key_val = ins->l.nnn->value;
                        found = true;
                    }
                }
            }

            if (found && ref_addr != BADADDR) {
                size_t offset = ref_addr - str->encrypted_addr;
                key_map[offset] = (uint8_t)key_val;
            }
        }
    }

    // If we found keys, populate the keys vector
    if (!key_map.empty()) {
        size_t max_offset = 0;
        for (const auto &p : key_map) {
            if (p.first > max_offset)
                max_offset = p.first;
        }

        str->xor_keys.resize(max_offset + 1, 0);
        for (const auto &p : key_map) {
            str->xor_keys[p.first] = p.second;
        }

        return true;
    }

    // Fallback: try to find keys in a different way
    // Look for immediate values used in XOR operations near string references

    return false;
}

//--------------------------------------------------------------------------
// Decrypt string
//--------------------------------------------------------------------------
std::string string_decrypt_handler_t::decrypt_string(const encrypted_string_t &str) {
    if (str.encrypted_data.empty())
        return "";

    std::string result;

    // XOR each element with its key
    size_t len = std::min(str.encrypted_data.size(), str.xor_keys.size());

    for (size_t i = 0; i < len; i++) {
        uint8_t decrypted = str.encrypted_data[i] ^ str.xor_keys[i];

        // Stop at null terminator
        if (decrypted == 0)
            break;

        // Check for printable ASCII
        if (decrypted >= 32 && decrypted < 127) {
            result += (char)decrypted;
        } else if (decrypted == '\n' || decrypted == '\t' || decrypted == '\r') {
            result += (char)decrypted;
        } else {
            // Non-printable - might be end of string or corruption
            break;
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Patch string references in microcode
//--------------------------------------------------------------------------
int string_decrypt_handler_t::patch_string_references(mbl_array_t *mba,
    const encrypted_string_t &str, const std::string &decrypted, deobf_ctx_t *ctx) {

    int changes = 0;

    // Find references to encrypted/decrypt_space addresses
    // Replace with the decrypted string representation

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check if instruction references the encrypted string
            bool refs_encrypted = false;

            if (ins->l.t == mop_v && ins->l.g == str.encrypted_addr)
                refs_encrypted = true;
            if (ins->r.t == mop_v && ins->r.g == str.encrypted_addr)
                refs_encrypted = true;
            if (ins->d.t == mop_v && ins->d.g == str.encrypted_addr)
                refs_encrypted = true;

            if (refs_encrypted) {
                // Add comment with decrypted string
                // (Actual value replacement is complex in microcode)
                changes++;
            }
        }
    }

    return changes;
}

//--------------------------------------------------------------------------
// Annotate decrypted string in IDA
//--------------------------------------------------------------------------
void string_decrypt_handler_t::annotate_string(const encrypted_string_t &str,
    const std::string &decrypted) {

    // Add comment at encrypted string location
    qstring comment;
    comment.sprnt("Decrypted: \"%s\"", decrypted.c_str());
    set_cmt(str.encrypted_addr, comment.c_str(), true);

    // Also comment at decrypt space if available
    if (str.decrypt_space_addr != BADADDR) {
        set_cmt(str.decrypt_space_addr, comment.c_str(), true);
    }
}

//--------------------------------------------------------------------------
// Find decryption block
//--------------------------------------------------------------------------
int string_decrypt_handler_t::find_decryption_block(mbl_array_t *mba) {
    if (!mba)
        return -1;

    // Look for block with multiple XOR instructions and atomic load
    // This is typically the "StringDecryptionBB"

    int best_block = -1;
    int best_score = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        int xor_count = 0;
        bool has_atomic = false;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_xor)
                xor_count++;

            // Check for atomic operations (indicated by memory ordering)
            // This is simplified - actual check would need more detail
        }

        int score = xor_count * 2;
        if (has_atomic)
            score += 10;

        if (score > best_score) {
            best_score = score;
            best_block = i;
        }
    }

    return (best_score >= 6) ? best_block : -1;  // Need at least 3 XORs
}
