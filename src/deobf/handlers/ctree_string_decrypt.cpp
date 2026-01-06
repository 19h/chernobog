#include "ctree_string_decrypt.h"
#include "../analysis/pattern_match.h"

//--------------------------------------------------------------------------
// Platform-specific crypto support
//--------------------------------------------------------------------------
#ifdef __APPLE__
#include <CommonCrypto/CommonCrypto.h>
#define HAS_COMMONCRYPTO 1
#else
#define HAS_COMMONCRYPTO 0
#endif

//--------------------------------------------------------------------------
// Debug logging
//--------------------------------------------------------------------------
#include <fcntl.h>
#include <unistd.h>

static void ctree_str_debug(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/ctree_string_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
}

//--------------------------------------------------------------------------
// AES Decryption Support
//--------------------------------------------------------------------------
#if HAS_COMMONCRYPTO

// AES-CBC decryption using CommonCrypto
// Returns decrypted data, empty on failure
static std::vector<uint8_t> aes_decrypt_cbc(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding = true)
{
    std::vector<uint8_t> plaintext;
    
    if (ciphertext.empty() || key.empty())
        return plaintext;
    
    // Validate key size (16=AES-128, 24=AES-192, 32=AES-256)
    size_t key_size = key.size();
    if (key_size != kCCKeySizeAES128 && 
        key_size != kCCKeySizeAES192 && 
        key_size != kCCKeySizeAES256) {
        ctree_str_debug("[aes] Invalid key size: %zu\n", key_size);
        return plaintext;
    }
    
    // IV must be 16 bytes for AES-CBC
    if (!iv.empty() && iv.size() != kCCBlockSizeAES128) {
        ctree_str_debug("[aes] Invalid IV size: %zu (expected 16)\n", iv.size());
        return plaintext;
    }
    
    // Allocate output buffer (same size as input + block for padding)
    size_t out_size = ciphertext.size() + kCCBlockSizeAES128;
    plaintext.resize(out_size);
    size_t decrypted_size = 0;
    
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        pkcs7_padding ? kCCOptionPKCS7Padding : 0,
        key.data(), key_size,
        iv.empty() ? nullptr : iv.data(),
        ciphertext.data(), ciphertext.size(),
        plaintext.data(), out_size,
        &decrypted_size
    );
    
    if (status != kCCSuccess) {
        ctree_str_debug("[aes] Decryption failed with status: %d\n", status);
        plaintext.clear();
        return plaintext;
    }
    
    plaintext.resize(decrypted_size);
    ctree_str_debug("[aes] Decrypted %zu bytes successfully\n", decrypted_size);
    return plaintext;
}

// Try to decrypt data at an address using extracted key/IV
static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    qstring *out_plaintext)
{
    if (data_addr == BADADDR || data_len == 0 || !out_plaintext)
        return false;
    
    // Read encrypted data from binary
    std::vector<uint8_t> ciphertext(data_len);
    if (get_bytes(ciphertext.data(), data_len, data_addr) != data_len) {
        ctree_str_debug("[aes] Failed to read %zu bytes from 0x%llx\n", 
                       data_len, (unsigned long long)data_addr);
        return false;
    }
    
    // Try decryption
    std::vector<uint8_t> plaintext = aes_decrypt_cbc(ciphertext, key, iv, true);
    if (plaintext.empty())
        return false;
    
    // Check if result looks like valid text
    bool is_printable = true;
    for (size_t i = 0; i < plaintext.size() && i < 256; i++) {
        uint8_t c = plaintext[i];
        if (c == 0) break;  // Null terminator is ok
        if (c < 0x20 || c > 0x7E) {
            if (c != '\n' && c != '\r' && c != '\t') {
                is_printable = false;
                break;
            }
        }
    }
    
    if (is_printable && !plaintext.empty()) {
        // Find null terminator or end
        size_t str_len = 0;
        for (size_t i = 0; i < plaintext.size(); i++) {
            if (plaintext[i] == 0) break;
            str_len++;
        }
        out_plaintext->append((const char*)plaintext.data(), str_len);
        return true;
    }
    
    return false;
}

#else
// No CommonCrypto - stub implementations
static std::vector<uint8_t> aes_decrypt_cbc(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding = true)
{
    ctree_str_debug("[aes] CommonCrypto not available on this platform\n");
    return {};
}

static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    qstring *out_plaintext)
{
    return false;
}
#endif

//--------------------------------------------------------------------------
// Visitor to find string function calls (strcpy, memcpy, etc.)
//--------------------------------------------------------------------------
struct string_call_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    std::vector<ctree_string_decrypt_handler_t::string_reveal_t> reveals;
    std::vector<ctree_string_decrypt_handler_t::crypto_call_t> crypto_calls;
    
    string_call_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        if (e->op != cot_call)
            return 0;
            
        // Get the called function
        cexpr_t *callee = e->x;
        if (!callee)
            return 0;
            
        qstring func_name;
        if (!get_func_name(&func_name, callee))
            return 0;
            
        // Check for string copy functions (including __strcpy_chk, ___strcpy_chk variants)
        // Use substring matching to handle all underscore prefix/suffix variations
        if (func_name.find("strcpy") != qstring::npos ||
            func_name.find("strncpy") != qstring::npos ||
            func_name.find("strlcpy") != qstring::npos) {
            process_strcpy(e, func_name);
        }
        else if (func_name.find("memcpy") != qstring::npos ||
                 func_name.find("memmove") != qstring::npos ||
                 func_name.find("qmemcpy") != qstring::npos ||
                 func_name.find("bcopy") != qstring::npos ||
                 func_name.find("memset") != qstring::npos) {
            process_memcpy(e, func_name);
        }
        else if (func_name.find("CCCrypt") != qstring::npos ||
                 func_name.find("AES_decrypt") != qstring::npos ||
                 func_name.find("AES_cbc_encrypt") != qstring::npos ||
                 func_name.find("EVP_Decrypt") != qstring::npos ||
                 func_name.find("EVP_Cipher") != qstring::npos) {
            process_crypto_call(e, func_name);
        }
        
        return 0;
    }
    
private:
    bool get_func_name(qstring *out, cexpr_t *callee) {
        if (callee->op == cot_obj) {
            // Direct function reference
            if (get_name(out, callee->obj_ea) > 0)
                return true;
        }
        else if (callee->op == cot_helper) {
            // Helper function
            *out = callee->helper;
            return true;
        }
        return false;
    }
    
    void process_strcpy(cexpr_t *call, const qstring &func_name) {
        // strcpy(dest, src)
        carglist_t *args = call->a;
        if (!args || args->size() < 2)
            return;
            
        cexpr_t *dest = &(*args)[0];
        cexpr_t *src = &(*args)[1];
        
        // Check if source is a string constant
        qstring str_val;
        if (!extract_string_constant(src, &str_val))
            return;
            
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 0;  // strcpy
        
        // Try to get destination info
        if (dest->op == cot_var) {
            lvars_t *lvars = cfunc->get_lvars();
            if (lvars && dest->v.idx < lvars->size()) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if (dest->op == cot_obj) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[strcpy] Found: %s -> \"%s\"\n", 
                       reveal.dest_name.c_str(), str_val.c_str());
        
        reveals.push_back(reveal);
    }
    
    void process_memcpy(cexpr_t *call, const qstring &func_name) {
        // memcpy(dest, src, size)
        carglist_t *args = call->a;
        if (!args || args->size() < 3)
            return;
            
        cexpr_t *dest = &(*args)[0];
        cexpr_t *src = &(*args)[1];
        cexpr_t *size = &(*args)[2];
        
        // Check if source is a string constant
        qstring str_val;
        if (!extract_string_constant(src, &str_val))
            return;
            
        // Verify size matches (or close to it)
        if (size->op == cot_num) {
            uint64_t sz = size->numval();
            if (sz > 0 && sz < 4096 && sz >= str_val.length()) {
                // Size looks reasonable
            }
        }
        
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 1;  // memcpy
        
        // Try to get destination info
        if (dest->op == cot_var) {
            lvars_t *lvars = cfunc->get_lvars();
            if (lvars && dest->v.idx < lvars->size()) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if (dest->op == cot_obj) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[memcpy] Found: %s -> \"%s\" (len=%zu)\n",
                       reveal.dest_name.c_str(), str_val.c_str(), str_val.length());
        
        reveals.push_back(reveal);
    }
    
    void process_crypto_call(cexpr_t *call, const qstring &func_name) {
        // CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved)
        // Args:  0    1      2      3     4     5     6        7        8          9            10
        carglist_t *args = call->a;
        if (!args)
            return;
            
        ctree_string_decrypt_handler_t::crypto_call_t crypto;
        crypto.location = call->ea;
        crypto.function = func_name;
        crypto.input_addr = BADADDR;
        crypto.input_len = 0;
        crypto.output_addr = BADADDR;
        
        if (func_name == "CCCrypt" || func_name == "_CCCrypt") {
            if (args->size() >= 8) {
                // Get key (arg 3) and keyLen (arg 4)
                cexpr_t *key_arg = &(*args)[3];
                cexpr_t *keylen_arg = &(*args)[4];
                
                // Try to extract key if it's a string constant or global
                qstring key_str;
                if (extract_string_constant(key_arg, &key_str)) {
                    for (size_t i = 0; i < key_str.length(); i++) {
                        crypto.key.push_back((uint8_t)key_str[i]);
                    }
                } else if (key_arg->op == cot_obj) {
                    // Key is at a global address - try to read it
                    ea_t key_addr = key_arg->obj_ea;
                    size_t key_len = 16;  // Default to AES-128
                    if (keylen_arg->op == cot_num) {
                        key_len = (size_t)keylen_arg->numval();
                    }
                    if (key_addr != BADADDR && key_len <= 32) {
                        crypto.key.resize(key_len);
                        if (get_bytes(crypto.key.data(), key_len, key_addr) == key_len) {
                            ctree_str_debug("[crypto] Read key from 0x%llx (%zu bytes)\n",
                                           (unsigned long long)key_addr, key_len);
                        } else {
                            crypto.key.clear();
                        }
                    }
                }
                
                // Determine algorithm based on key length
                if (keylen_arg->op == cot_num) {
                    uint64_t keylen = keylen_arg->numval();
                    crypto.algorithm = (keylen == 32) ? 1 : 0;  // AES-256 or AES-128
                }
                
                // Try to get IV (arg 5)
                cexpr_t *iv_arg = &(*args)[5];
                qstring iv_str;
                if (extract_string_constant(iv_arg, &iv_str)) {
                    for (size_t i = 0; i < iv_str.length() && i < 16; i++) {
                        crypto.iv.push_back((uint8_t)iv_str[i]);
                    }
                } else if (iv_arg->op == cot_obj && iv_arg->obj_ea != BADADDR) {
                    // IV is at a global address
                    crypto.iv.resize(16);
                    if (get_bytes(crypto.iv.data(), 16, iv_arg->obj_ea) != 16) {
                        crypto.iv.clear();
                    }
                }
                
                // Get input data address and length (args 6 and 7)
                cexpr_t *data_in_arg = &(*args)[6];
                cexpr_t *data_in_len_arg = &(*args)[7];
                
                if (data_in_arg->op == cot_obj) {
                    crypto.input_addr = data_in_arg->obj_ea;
                }
                if (data_in_len_arg->op == cot_num) {
                    crypto.input_len = (size_t)data_in_len_arg->numval();
                }
                
                // Get output address (arg 8) if available
                if (args->size() >= 9) {
                    cexpr_t *data_out_arg = &(*args)[8];
                    if (data_out_arg->op == cot_obj) {
                        crypto.output_addr = data_out_arg->obj_ea;
                    }
                }
                
                // If we have key and input data, try to decrypt
                if (!crypto.key.empty() && crypto.input_addr != BADADDR && crypto.input_len > 0) {
                    ctree_str_debug("[crypto] Attempting AES decryption: input=0x%llx len=%zu key_len=%zu\n",
                                   (unsigned long long)crypto.input_addr, crypto.input_len, crypto.key.size());
                    
                    if (try_aes_decrypt_at_address(crypto.input_addr, crypto.input_len,
                                                   crypto.key, crypto.iv, &crypto.decrypted)) {
                        ctree_str_debug("[crypto] Decryption SUCCESS: \"%s\"\n", crypto.decrypted.c_str());
                    }
                }
                
                if (!crypto.key.empty()) {
                    ctree_str_debug("[crypto] Found CCCrypt: key_len=%zu iv_len=%zu input=0x%llx len=%zu\n",
                                   crypto.key.size(), crypto.iv.size(),
                                   (unsigned long long)crypto.input_addr, crypto.input_len);
                    crypto_calls.push_back(crypto);
                }
            }
        }
    }
    
    bool extract_string_constant(cexpr_t *e, qstring *out) {
        if (!e || !out)
            return false;
            
        // Direct string constant
        if (e->op == cot_str) {
            *out = e->string;
            return true;
        }
        
        // Reference to global string
        if (e->op == cot_obj) {
            // Try to read string from address
            ea_t addr = e->obj_ea;
            if (addr != BADADDR) {
                qstring buf;
                ssize_t len = get_strlit_contents(&buf, addr, -1, STRTYPE_C);
                if (len > 0) {
                    *out = buf;
                    return true;
                }
                // Also try just reading bytes
                len = get_max_strlit_length(addr, STRTYPE_C, ALOPT_IGNCLT);
                if (len > 0 && len < 1024) {
                    char raw_buf[1024];
                    get_bytes(raw_buf, len, addr);
                    raw_buf[len] = 0;
                    *out = raw_buf;
                    return true;
                }
            }
        }
        
        // Cast expression - unwrap and try again
        if (e->op == cot_cast) {
            return extract_string_constant(e->x, out);
        }
        
        // Reference expression
        if (e->op == cot_ref) {
            return extract_string_constant(e->x, out);
        }
        
        return false;
    }
};

//--------------------------------------------------------------------------
// Visitor to find character-by-character assignments
//--------------------------------------------------------------------------
struct char_assign_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    
    // Map: variable -> (offset -> (value, ea))
    std::map<int, std::map<int, std::pair<uint8_t, ea_t>>> var_assignments;
    std::map<ea_t, std::map<int, std::pair<uint8_t, ea_t>>> global_assignments;
    
    char_assign_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Look for: var[index] = value
        if (e->op != cot_asg)
            return 0;
            
        cexpr_t *lhs = e->x;
        cexpr_t *rhs = e->y;
        
        if (!lhs || !rhs)
            return 0;
            
        // Value must be a constant (or simple transform of constant)
        uint8_t value;
        if (!extract_byte_value(rhs, &value))
            return 0;
        
        // Check for array index pattern: buffer[index] = value
        if (lhs->op == cot_idx) {
            cexpr_t *base = lhs->x;
            cexpr_t *index = lhs->y;
            
            if (!base || !index)
                return 0;
                
            // Index must be a constant
            if (index->op != cot_num)
                return 0;
            int idx = (int)index->numval();
                
            // Get the base variable
            if (base->op == cot_var) {
                int var_idx = base->v.idx;
                var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
            }
            else if (base->op == cot_obj) {
                ea_t addr = base->obj_ea;
                global_assignments[addr][idx] = std::make_pair(value, e->ea);
            }
        }
        // Check for pointer dereference pattern: *buffer = value (index 0)
        else if (lhs->op == cot_ptr) {
            cexpr_t *ptr_expr = lhs->x;
            if (!ptr_expr)
                return 0;
            
            // Simple case: *buffer = value (index 0)
            if (ptr_expr->op == cot_var) {
                int var_idx = ptr_expr->v.idx;
                var_assignments[var_idx][0] = std::make_pair(value, e->ea);
            }
            else if (ptr_expr->op == cot_obj) {
                ea_t addr = ptr_expr->obj_ea;
                global_assignments[addr][0] = std::make_pair(value, e->ea);
            }
            // Pointer arithmetic: *(buffer + N) = value
            else if (ptr_expr->op == cot_add) {
                cexpr_t *base = ptr_expr->x;
                cexpr_t *offset = ptr_expr->y;
                
                // Handle both orderings: (var + num) or (num + var)
                if (base && offset) {
                    if (base->op == cot_num && offset->op != cot_num) {
                        std::swap(base, offset);
                    }
                    
                    if (offset->op == cot_num) {
                        int idx = (int)offset->numval();
                        
                        if (base->op == cot_var) {
                            int var_idx = base->v.idx;
                            var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                        }
                        else if (base->op == cot_obj) {
                            ea_t addr = base->obj_ea;
                            global_assignments[addr][idx] = std::make_pair(value, e->ea);
                        }
                        // Handle cast around variable: *((_BYTE*)buffer + N)
                        else if (base->op == cot_cast && base->x) {
                            cexpr_t *inner = base->x;
                            if (inner->op == cot_var) {
                                int var_idx = inner->v.idx;
                                var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                            }
                            else if (inner->op == cot_obj) {
                                ea_t addr = inner->obj_ea;
                                global_assignments[addr][idx] = std::make_pair(value, e->ea);
                            }
                        }
                    }
                }
            }
            // Cast around the whole expression: *(_BYTE*)(buffer + N)
            else if (ptr_expr->op == cot_cast && ptr_expr->x && ptr_expr->x->op == cot_add) {
                cexpr_t *add_expr = ptr_expr->x;
                cexpr_t *base = add_expr->x;
                cexpr_t *offset = add_expr->y;
                
                if (base && offset) {
                    if (base->op == cot_num && offset->op != cot_num) {
                        std::swap(base, offset);
                    }
                    
                    if (offset->op == cot_num) {
                        int idx = (int)offset->numval();
                        
                        if (base->op == cot_var) {
                            int var_idx = base->v.idx;
                            var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                        }
                        else if (base->op == cot_obj) {
                            ea_t addr = base->obj_ea;
                            global_assignments[addr][idx] = std::make_pair(value, e->ea);
                        }
                    }
                }
            }
        }
        
        return 0;
    }
    
    // Convert collected assignments to strings
    std::vector<ctree_string_decrypt_handler_t::char_string_t> 
    get_reconstructed_strings() {
        std::vector<ctree_string_decrypt_handler_t::char_string_t> result;
        
        // Process local variable assignments
        lvars_t *lvars = cfunc->get_lvars();
        for (auto &kv : var_assignments) {
            int var_idx = kv.first;
            auto &offsets = kv.second;
            
            if (offsets.size() < 3)
                continue;
                
            ctree_string_decrypt_handler_t::char_string_t str;
            
            if (lvars && var_idx < lvars->size()) {
                str.var_name = (*lvars)[var_idx].name;
            } else {
                str.var_name.sprnt("var_%d", var_idx);
            }
            
            if (try_reconstruct(offsets, &str)) {
                ctree_str_debug("[char_assign] Variable %s: \"%s\"\n",
                               str.var_name.c_str(), str.reconstructed.c_str());
                result.push_back(str);
            }
        }
        
        // Process global assignments
        for (auto &kv : global_assignments) {
            ea_t addr = kv.first;
            auto &offsets = kv.second;
            
            if (offsets.size() < 3)
                continue;
                
            ctree_string_decrypt_handler_t::char_string_t str;
            str.var_addr = addr;
            get_name(&str.var_name, addr);
            if (str.var_name.empty()) {
                str.var_name.sprnt("global_%llX", (unsigned long long)addr);
            }
            
            if (try_reconstruct(offsets, &str)) {
                ctree_str_debug("[char_assign] Global %s: \"%s\"\n",
                               str.var_name.c_str(), str.reconstructed.c_str());
                result.push_back(str);
            }
        }
        
        return result;
    }
    
private:
    bool extract_byte_value(cexpr_t *e, uint8_t *out) {
        if (!e)
            return false;
            
        // Direct number
        if (e->op == cot_num) {
            *out = (uint8_t)(e->numval() & 0xFF);
            return true;
        }
        
        // NOT (~) operation
        if (e->op == cot_bnot && e->x && e->x->op == cot_num) {
            *out = (uint8_t)(~e->x->numval() & 0xFF);
            return true;
        }
        
        // XOR operation with constants
        if (e->op == cot_xor) {
            uint8_t left = 0, right = 0;
            if (e->x && e->x->op == cot_num)
                left = (uint8_t)(e->x->numval() & 0xFF);
            if (e->y && e->y->op == cot_num)
                right = (uint8_t)(e->y->numval() & 0xFF);
            *out = left ^ right;
            return true;
        }
        
        // Cast expression
        if (e->op == cot_cast) {
            return extract_byte_value(e->x, out);
        }
        
        return false;
    }
    
    bool try_reconstruct(const std::map<int, std::pair<uint8_t, ea_t>> &offsets,
                         ctree_string_decrypt_handler_t::char_string_t *out) {
        if (offsets.empty())
            return false;
            
        // Find the range of indices
        int min_idx = offsets.begin()->first;
        int max_idx = offsets.rbegin()->first;
        
        // Check for reasonable string length
        if (max_idx - min_idx > 4096)
            return false;
            
        // Build the string
        qstring str;
        bool all_printable = true;
        
        for (int i = min_idx; i <= max_idx; i++) {
            auto it = offsets.find(i);
            if (it == offsets.end()) {
                // Gap in assignments - might be end of string
                break;
            }
            
            uint8_t c = it->second.first;
            out->insn_addrs.push_back(it->second.second);
            
            if (c == 0) {
                // Null terminator
                break;
            }
            
            if (c < 0x20 || c > 0x7E) {
                if (c != '\n' && c != '\r' && c != '\t') {
                    all_printable = false;
                    break;
                }
            }
            
            str += (char)c;
        }
        
        if (!all_printable || str.length() < 3)
            return false;
            
        out->reconstructed = str;
        if (!out->insn_addrs.empty()) {
            out->start_addr = out->insn_addrs[0];
        }
        
        return true;
    }
};

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool ctree_string_decrypt_handler_t::detect(cfunc_t *cfunc) {
    if (!cfunc)
        return false;
        
    // Quick check: does the function have string-related calls?
    struct quick_visitor_t : public ctree_visitor_t {
        bool found = false;
        
        quick_visitor_t() : ctree_visitor_t(CV_FAST) {}
        
        int idaapi visit_expr(cexpr_t *e) override {
            if (found)
                return 1;  // Stop visiting
                
            if (e->op == cot_call && e->x) {
                cexpr_t *callee = e->x;
                if (callee->op == cot_obj) {
                    qstring name;
                    if (get_name(&name, callee->obj_ea) > 0) {
                        if (name.find("strcpy") != qstring::npos ||
                            name.find("memcpy") != qstring::npos ||
                            name.find("CCCrypt") != qstring::npos) {
                            found = true;
                            return 1;
                        }
                    }
                }
            }
            
            // Check for array index assignments
            if (e->op == cot_asg && e->x && e->x->op == cot_idx) {
                found = true;
                return 1;
            }
            
            return 0;
        }
    } visitor;
    
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.found;
}

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_string_decrypt_handler_t::run(cfunc_t *cfunc, deobf_ctx_t *ctx) {
    if (!cfunc || !ctx)
        return 0;
        
    ctree_str_debug("[ctree_string] Analyzing function at 0x%llx\n",
                   (unsigned long long)cfunc->entry_ea);
    
    int total_changes = 0;
    
    // Find string function calls (strcpy, memcpy, CCCrypt)
    string_call_visitor_t call_visitor(cfunc);
    call_visitor.apply_to(&cfunc->body, nullptr);
    
    for (const auto &reveal : call_visitor.reveals) {
        // Store in context
        if (reveal.dest_addr != BADADDR) {
            ctx->decrypted_strings[reveal.dest_addr] = reveal.plaintext.c_str();
        }
        
        // Annotate
        annotate_reveal(reveal);
        total_changes++;
    }
    
    for (const auto &crypto : call_visitor.crypto_calls) {
        // Store decrypted result in context if available
        if (!crypto.decrypted.empty()) {
            if (crypto.input_addr != BADADDR) {
                ctx->decrypted_strings[crypto.input_addr] = crypto.decrypted.c_str();
            }
            if (crypto.output_addr != BADADDR) {
                ctx->decrypted_strings[crypto.output_addr] = crypto.decrypted.c_str();
            }
            ctx->strings_decrypted++;
        }
        
        annotate_crypto_call(crypto);
        total_changes++;
    }
    
    // Find character-by-character assignments
    char_assign_visitor_t assign_visitor(cfunc);
    assign_visitor.apply_to(&cfunc->body, nullptr);
    
    auto char_strings = assign_visitor.get_reconstructed_strings();
    for (const auto &str : char_strings) {
        // Store in context
        if (str.var_addr != BADADDR) {
            ctx->decrypted_strings[str.var_addr] = str.reconstructed.c_str();
        }
        
        // Annotate
        annotate_char_string(str);
        total_changes++;
    }
    
    ctree_str_debug("[ctree_string] Found %zu strcpy/memcpy reveals, %zu crypto calls, %zu char strings\n",
                   call_visitor.reveals.size(), call_visitor.crypto_calls.size(), char_strings.size());
    
    return total_changes;
}

//--------------------------------------------------------------------------
// Find patterns - delegated to visitors
//--------------------------------------------------------------------------
std::vector<ctree_string_decrypt_handler_t::string_reveal_t>
ctree_string_decrypt_handler_t::find_strcpy_reveals(cfunc_t *cfunc) {
    string_call_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.reveals;
}

std::vector<ctree_string_decrypt_handler_t::string_reveal_t>
ctree_string_decrypt_handler_t::find_memcpy_reveals(cfunc_t *cfunc) {
    // Already handled in string_call_visitor_t
    return find_strcpy_reveals(cfunc);
}

std::vector<ctree_string_decrypt_handler_t::char_string_t>
ctree_string_decrypt_handler_t::find_char_assignments(cfunc_t *cfunc) {
    char_assign_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.get_reconstructed_strings();
}

std::vector<ctree_string_decrypt_handler_t::xor_decrypt_t>
ctree_string_decrypt_handler_t::find_xor_patterns(cfunc_t *cfunc) {
    // TODO: Implement XOR pattern detection at ctree level
    return {};
}

std::vector<ctree_string_decrypt_handler_t::crypto_call_t>
ctree_string_decrypt_handler_t::find_crypto_calls(cfunc_t *cfunc) {
    string_call_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.crypto_calls;
}

//--------------------------------------------------------------------------
// Annotation
//--------------------------------------------------------------------------
void ctree_string_decrypt_handler_t::annotate_reveal(const string_reveal_t &reveal) {
    if (reveal.location == BADADDR)
        return;
        
    qstring comment;
    const char *type = (reveal.reveal_type == 0) ? "strcpy" : "memcpy";
    
    if (!reveal.dest_name.empty()) {
        comment.sprnt("DEOBF: %s reveals \"%s\" -> %s",
                     type, reveal.plaintext.c_str(), reveal.dest_name.c_str());
    } else {
        comment.sprnt("DEOBF: %s reveals \"%s\"", type, reveal.plaintext.c_str());
    }
    
    set_cmt(reveal.location, comment.c_str(), false);
    
    // Also annotate at destination if it's a global
    if (reveal.dest_addr != BADADDR) {
        qstring dest_comment;
        dest_comment.sprnt("Decrypted: \"%s\"", reveal.plaintext.c_str());
        set_cmt(reveal.dest_addr, dest_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_char_string(const char_string_t &str) {
    if (str.insn_addrs.empty())
        return;
        
    qstring comment;
    comment.sprnt("DEOBF: Stack string \"%s\"", str.reconstructed.c_str());
    
    // Annotate at first instruction
    set_cmt(str.insn_addrs[0], comment.c_str(), false);
    
    // Also annotate at variable address if global
    if (str.var_addr != BADADDR) {
        qstring var_comment;
        var_comment.sprnt("Decrypted: \"%s\"", str.reconstructed.c_str());
        set_cmt(str.var_addr, var_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_xor_decrypt(const xor_decrypt_t &xor_info) {
    if (xor_info.location == BADADDR)
        return;
        
    qstring comment;
    comment.sprnt("DEOBF: XOR decrypts to \"%s\"", xor_info.decrypted.c_str());
    set_cmt(xor_info.location, comment.c_str(), false);
}

void ctree_string_decrypt_handler_t::annotate_crypto_call(const crypto_call_t &crypto) {
    if (crypto.location == BADADDR)
        return;
        
    qstring comment;
    const char *alg = (crypto.algorithm == 1) ? "AES-256" : "AES-128";
    
    // Convert key to hex for display
    qstring key_hex;
    for (size_t i = 0; i < crypto.key.size() && i < 16; i++) {
        key_hex.cat_sprnt("%02X", crypto.key[i]);
    }
    if (crypto.key.size() > 16) {
        key_hex += "...";
    }
    
    // Include decrypted result if available
    if (!crypto.decrypted.empty()) {
        // Truncate long decrypted strings for comment
        qstring decrypted_display = crypto.decrypted;
        if (decrypted_display.length() > 64) {
            decrypted_display.resize(64);
            decrypted_display += "...";
        }
        comment.sprnt("DEOBF: %s %s -> \"%s\" (key=%s)", 
                     crypto.function.c_str(), alg, decrypted_display.c_str(), key_hex.c_str());
    } else {
        comment.sprnt("DEOBF: %s %s key=%s", crypto.function.c_str(), alg, key_hex.c_str());
    }
    
    set_cmt(crypto.location, comment.c_str(), false);
    
    // If we have decrypted data and an output address, annotate there too
    if (!crypto.decrypted.empty() && crypto.output_addr != BADADDR) {
        qstring output_comment;
        output_comment.sprnt("AES Decrypted: \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.output_addr, output_comment.c_str(), true);
    }
    
    // Also annotate at input address with what was encrypted
    if (!crypto.decrypted.empty() && crypto.input_addr != BADADDR) {
        qstring input_comment;
        input_comment.sprnt("Encrypted data -> \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.input_addr, input_comment.c_str(), true);
    }
}

//--------------------------------------------------------------------------
// Helper functions
//--------------------------------------------------------------------------
bool ctree_string_decrypt_handler_t::get_string_constant(const cexpr_t *e, qstring *out) {
    if (!e || !out)
        return false;
        
    if (e->op == cot_str) {
        *out = e->string;
        return true;
    }
    
    return false;
}

ea_t ctree_string_decrypt_handler_t::get_address_from_expr(const cexpr_t *e, cfunc_t *cfunc) {
    if (!e)
        return BADADDR;
        
    if (e->op == cot_obj) {
        return e->obj_ea;
    }
    
    if (e->op == cot_var && cfunc) {
        // Local variable - no address
        return BADADDR;
    }
    
    return BADADDR;
}

bool ctree_string_decrypt_handler_t::is_string_function(const cexpr_t *e, qstring *func_name) {
    if (!e || e->op != cot_call)
        return false;
        
    cexpr_t *callee = e->x;
    if (!callee || callee->op != cot_obj)
        return false;
        
    qstring name;
    if (get_name(&name, callee->obj_ea) <= 0)
        return false;
        
    if (name.find("strcpy") != qstring::npos ||
        name.find("strncpy") != qstring::npos ||
        name.find("memcpy") != qstring::npos ||
        name.find("memmove") != qstring::npos) {
        if (func_name)
            *func_name = name;
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::is_crypto_function(const cexpr_t *e, qstring *func_name) {
    if (!e || e->op != cot_call)
        return false;
        
    cexpr_t *callee = e->x;
    if (!callee || callee->op != cot_obj)
        return false;
        
    qstring name;
    if (get_name(&name, callee->obj_ea) <= 0)
        return false;
        
    if (name.find("CCCrypt") != qstring::npos ||
        name.find("AES_") != qstring::npos ||
        name.find("EVP_") != qstring::npos ||
        name.find("aes_") != qstring::npos) {
        if (func_name)
            *func_name = name;
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::get_const_value(const cexpr_t *e, uint64_t *out) {
    if (!e || !out)
        return false;
        
    if (e->op == cot_num) {
        *out = e->numval();
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::get_buffer_contents(ea_t addr, size_t max_len,
                                                         std::vector<uint8_t> *out) {
    if (addr == BADADDR || !out)
        return false;
        
    out->resize(max_len);
    ssize_t read = get_bytes(out->data(), max_len, addr);
    if (read <= 0)
        return false;
        
    out->resize(read);
    return true;
}

int ctree_string_decrypt_handler_t::patch_ctree_reference(cfunc_t *cfunc, ea_t encrypted_addr,
                                                          const qstring &decrypted) {
    // TODO: Implement ctree patching to replace encrypted references
    // This is complex and requires careful modification of the ctree
    return 0;
}
