#include "ctree_string_decrypt.h"
#include "global_const.h"
#include "../analysis/pattern_match.h"
#include "../analysis/arch_utils.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"

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
#include "../../common/compat.h"

static void ctree_str_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    deobf::debug_vlog("/tmp/ctree_string_debug.log", fmt, args);
    va_end(args);
}

//--------------------------------------------------------------------------
// AES Decryption Support
//--------------------------------------------------------------------------
#if HAS_COMMONCRYPTO

// AES-CBC/ECB decryption using CommonCrypto
// Returns decrypted data, empty on failure
static std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding,
    bool use_ecb)
{
    std::vector<uint8_t> plaintext;
    
    if ( ciphertext.empty() || key.empty() ) 
        return plaintext;
    
    // Validate key size (16=AES-128, 24=AES-192, 32=AES-256)
    size_t key_size = key.size();
    if ( key_size != kCCKeySizeAES128 && 
        key_size != kCCKeySizeAES192 && 
        key_size != kCCKeySizeAES256)
        {
        ctree_str_debug("[aes] Invalid key size: %zu\n", key_size);
        return plaintext;
    }
    
    // IV must be 16 bytes for AES-CBC
    if ( !use_ecb && !iv.empty() && iv.size() != kCCBlockSizeAES128 ) {
        ctree_str_debug("[aes] Invalid IV size: %zu (expected 16)\n", iv.size());
        return plaintext;
    }
    
    // Allocate output buffer (same size as input + block for padding)
    size_t out_size = ciphertext.size() + kCCBlockSizeAES128;
    plaintext.resize(out_size);
    size_t decrypted_size = 0;
    
    int options = pkcs7_padding ? kCCOptionPKCS7Padding : 0;
    if ( use_ecb ) 
        options |= kCCOptionECBMode;

    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        options,
        key.data(), key_size,
        use_ecb ? nullptr : (iv.empty() ? nullptr : iv.data()),
        ciphertext.data(), ciphertext.size(),
        plaintext.data(), out_size,
        &decrypted_size
);
    
    if ( status != kCCSuccess ) {
        ctree_str_debug("[aes] Decryption failed with status: %d\n", status);
        plaintext.clear();
        return plaintext;
    }
    
    plaintext.resize(decrypted_size);
    ctree_str_debug("[aes] Decrypted %zu bytes successfully (ecb=%d)\n",
                   decrypted_size, use_ecb ? 1 : 0);
    return plaintext;
}

// Try to decrypt data at an address using extracted key/IV
static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding,
    bool use_ecb,
    qstring *out_plaintext)
{
    if ( data_addr == BADADDR || data_len == 0 || !out_plaintext ) 
        return false;
    
    // Read encrypted data from binary
    std::vector<uint8_t> ciphertext(data_len);
    if ( !chernobog::ida_memory::read_exact(
            ciphertext.data(), data_len, data_addr) ) {
        ctree_str_debug("[aes] Failed to read %zu bytes from 0x%llx\n", 
                       data_len, (unsigned long long)data_addr);
        return false;
    }
    
    // Decrypt using exactly the mode encoded by the CCCrypt call.
    std::vector<uint8_t> plaintext = aes_decrypt(ciphertext, key, iv, pkcs7_padding, use_ecb);
    if ( plaintext.empty() ) 
        return false;
    
    // Require a non-trivial printable C string prefix. This handler records
    // strings, not arbitrary successfully decrypted binary buffers.
    size_t str_len = 0;
    for ( size_t i = 0; i < plaintext.size(); ++i ) {
        uint8_t c = plaintext[i];
        if ( c == 0 )
            break;
        if ( c < 0x20 || c > 0x7E ) {
            if ( c != '\n' && c != '\r' && c != '\t' )
                return false;
        }
        ++str_len;
    }

    if ( str_len < 3 )
        return false;
    out_plaintext->clear();
    out_plaintext->append(reinterpret_cast<const char *>(plaintext.data()), str_len);
    return true;
}

#else
// No CommonCrypto - stub implementations
static std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding,
    bool use_ecb)
{
    ctree_str_debug("[aes] CommonCrypto not available on this platform\n");
    return {};
}

static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding,
    bool use_ecb,
    qstring *out_plaintext)
{
    return false;
}
#endif

//--------------------------------------------------------------------------
// Visitor to find string function calls (strcpy, memcpy, etc.)
//--------------------------------------------------------------------------
static std::string normalize_call_name(const qstring &ida_name)
{
    std::string name = ida_name.c_str();
    size_t start = 0;
    while ( start < name.size() && name[start] == '_' )
        ++start;
    name.erase(0, start);

    if ( name.compare(0, 4, "imp_") == 0 )
        name.erase(0, 4);
    if ( name.compare(0, 2, "j_") == 0 )
        name.erase(0, 2);
    while ( !name.empty() && name.front() == '_' )
        name.erase(name.begin());
    return name;
}

struct string_call_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    std::vector<ctree_string_decrypt_handler_t::string_reveal_t> reveals;
    std::vector<ctree_string_decrypt_handler_t::crypto_call_t> crypto_calls;
    
    string_call_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        if ( e->op != cot_call ) 
            return 0;
            
        // Get the called function
        cexpr_t *callee = e->x;
        if ( !callee ) 
            return 0;
            
        qstring func_name;
        if ( !get_func_name(&func_name, callee) ) 
            return 0;
            
        const std::string name = normalize_call_name(func_name);
        if ( name == "strcpy" || name == "strcpy_chk" ||
             name == "strncpy" || name == "strlcpy" ) {
            process_strcpy(e, name);
        } else if ( name == "memcpy" || name == "memcpy_chk" ||
                    name == "memmove" || name == "qmemcpy" ||
                    name == "bcopy" ) {
            process_memcpy(e, name);
        } else if ( name == "CCCrypt" ) {
            process_crypto_call(e, name.c_str());
        }
        
        return 0;
    }
    
private:
    bool get_func_name(qstring *out, cexpr_t *callee)
    {
        if ( callee->op == cot_obj ) {
            // Direct function reference
            if ( get_name(out, callee->obj_ea) > 0 ) 
                return true;
        }
        else if ( callee->op == cot_helper ) {
            // Helper function
            *out = callee->helper;
            return true;
        }
        return false;
    }
    
    void process_strcpy(cexpr_t *call, const std::string &func_name)
    {
        // strcpy(dest, src)
        carglist_t *args = call->a;
        if ( !args || args->size() < 2 ) 
            return;
            
        cexpr_t *dest = &(*args)[0];
        cexpr_t *src = &(*args)[1];
        
        // Check if source is a string constant
        qstring str_val;
        if ( !extract_string_constant(src, &str_val) ) 
            return;

        if ( func_name == "strncpy" || func_name == "strlcpy" ) {
            if ( args->size() < 3 || (*args)[2].op != cot_num )
                return;
            const uint64_t capacity = (*args)[2].numval();
            if ( func_name == "strncpy" ) {
                // strncpy terminates only when n exceeds the source length.
                if ( capacity <= str_val.length() )
                    return;
            } else {
                if ( capacity == 0 )
                    return;
                const size_t copied = std::min<size_t>(
                    str_val.length(), static_cast<size_t>(capacity - 1));
                str_val.resize(copied);
                if ( str_val.empty() )
                    return;
            }
        }
            
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 0;  // strcpy
        
        // Try to get destination info
        if ( dest->op == cot_var ) {
            lvars_t *lvars = cfunc->get_lvars();
            if ( lvars && dest->v.idx < lvars->size() ) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if ( dest->op == cot_obj ) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[strcpy] Found: %s -> \"%s\"\n", 
                       reveal.dest_name.c_str(), str_val.c_str());
        
        reveals.push_back(reveal);
    }
    
    void process_memcpy(cexpr_t *call, const std::string &func_name)
    {
        // memcpy(dest, src, size)
        carglist_t *args = call->a;
        if ( !args || args->size() < 3 ) 
            return;
            
        cexpr_t *dest = &(*args)[func_name == "bcopy" ? 1 : 0];
        cexpr_t *src = &(*args)[func_name == "bcopy" ? 0 : 1];
        cexpr_t *size = &(*args)[2];
        
        // Check if source is a string constant
        qstring str_val;
        if ( !extract_string_constant(src, &str_val) ) 
            return;
            
        // A string reveal requires proof that the copied region contains the
        // source's terminator and does not read beyond the source object.
        if ( size->op != cot_num || size->numval() != str_val.length() + 1 )
            return;
        
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 1;  // memcpy
        
        // Try to get destination info
        if ( dest->op == cot_var ) {
            lvars_t *lvars = cfunc->get_lvars();
            if ( lvars && dest->v.idx < lvars->size() ) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if ( dest->op == cot_obj ) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[memcpy] Found: %s -> \"%s\" (len=%zu)\n",
                       reveal.dest_name.c_str(), str_val.c_str(), str_val.length());
        
        reveals.push_back(reveal);
    }
    
    static cexpr_t *strip_casts(cexpr_t *expr)
    {
        while ( expr && expr->op == cot_cast )
            expr = expr->x;
        return expr;
    }

    static ea_t static_object_address(cexpr_t *expr)
    {
        expr = strip_casts(expr);
        if ( !expr )
            return BADADDR;
        if ( expr->op == cot_obj )
            return expr->obj_ea;
        if ( expr->op == cot_ref ) {
            cexpr_t *referent = strip_casts(expr->x);
            if ( referent && referent->op == cot_obj )
                return referent->obj_ea;
        }
        return BADADDR;
    }

    static bool is_null_pointer(cexpr_t *expr)
    {
        expr = strip_casts(expr);
        return expr && expr->op == cot_num && expr->numval() == 0;
    }

    void process_crypto_call(cexpr_t *call, const qstring &func_name)
    {
        // CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen,
        //         dataOut, dataOutAvail, dataOutMoved)
        constexpr size_t AES_BLOCK_BYTES = 16;
        constexpr size_t MAX_STATIC_CRYPTO_INPUT =
            size_t{16} * size_t{1024} * size_t{1024};
        constexpr uint64_t PKCS7_OPTION = 0x0001U;
        constexpr uint64_t ECB_OPTION = 0x0002U;
        carglist_t *args = call->a;
        if ( func_name != "CCCrypt" || !args || args->size() < 11 )
            return;

        cexpr_t *op_arg = strip_casts(&(*args)[0]);
        cexpr_t *alg_arg = strip_casts(&(*args)[1]);
        cexpr_t *options_arg = strip_casts(&(*args)[2]);
        cexpr_t *key_len_arg = strip_casts(&(*args)[4]);
        cexpr_t *input_len_arg = strip_casts(&(*args)[7]);
        if ( !op_arg || !alg_arg || !options_arg || !key_len_arg ||
             !input_len_arg || op_arg->op != cot_num ||
             alg_arg->op != cot_num || options_arg->op != cot_num ||
             key_len_arg->op != cot_num || input_len_arg->op != cot_num )
            return;

        // CommonCrypto: kCCDecrypt=1, kCCAlgorithmAES=0. Reject unknown
        // option bits rather than guessing call semantics.
        const uint64_t options = options_arg->numval();
        const uint64_t allowed_options = PKCS7_OPTION | ECB_OPTION;
        if ( op_arg->numval() != 1 || alg_arg->numval() != 0 ||
             (options & ~allowed_options) != 0 )
            return;

        const size_t key_len = static_cast<size_t>(key_len_arg->numval());
        if ( key_len != 16 && key_len != 24 && key_len != 32 )
            return;

        const size_t input_len = static_cast<size_t>(input_len_arg->numval());
        if ( input_len == 0 || input_len > MAX_STATIC_CRYPTO_INPUT ||
             (input_len % AES_BLOCK_BYTES) != 0 )
            return;

        ctree_string_decrypt_handler_t::crypto_call_t crypto;
        crypto.location = call->ea;
        crypto.function = func_name;
        crypto.algorithm_bits = static_cast<int>(key_len * 8);
        crypto.input_len = input_len;

        cexpr_t *key_arg = &(*args)[3];
        const ea_t key_addr = static_object_address(key_arg);
        if ( key_addr != BADADDR ) {
            crypto.key.resize(key_len);
            if ( !chernobog::ida_memory::read_exact(
                    crypto.key.data(), crypto.key.size(), key_addr) )
                return;
        } else {
            qstring key_string;
            if ( !extract_string_constant(key_arg, &key_string) ||
                 key_string.length() != key_len )
                return;
            crypto.key.assign(
                reinterpret_cast<const uint8_t *>(key_string.c_str()),
                reinterpret_cast<const uint8_t *>(key_string.c_str()) + key_len);
        }

        const bool use_ecb = (options & ECB_OPTION) != 0;
        const bool use_pkcs7 = (options & PKCS7_OPTION) != 0;
        if ( !use_ecb ) {
            cexpr_t *iv_arg = &(*args)[5];
            const ea_t iv_addr = static_object_address(iv_arg);
            if ( iv_addr != BADADDR ) {
                crypto.iv.resize(AES_BLOCK_BYTES);
                if ( !chernobog::ida_memory::read_exact(
                        crypto.iv.data(), crypto.iv.size(), iv_addr) )
                    return;
            } else if ( !is_null_pointer(iv_arg) ) {
                qstring iv_string;
                if ( !extract_string_constant(iv_arg, &iv_string) ||
                     iv_string.length() != AES_BLOCK_BYTES )
                    return;
                crypto.iv.assign(
                    reinterpret_cast<const uint8_t *>(iv_string.c_str()),
                    reinterpret_cast<const uint8_t *>(iv_string.c_str()) +
                        AES_BLOCK_BYTES);
            }
        }

        crypto.input_addr = static_object_address(&(*args)[6]);
        if ( crypto.input_addr == BADADDR )
            return;
        crypto.output_addr = static_object_address(&(*args)[8]);

        ctree_str_debug(
            "[crypto] Attempting AES-%d decryption: input=0x%llx len=%zu\n",
            crypto.algorithm_bits,
            static_cast<unsigned long long>(crypto.input_addr),
            crypto.input_len);
        if ( try_aes_decrypt_at_address(
                crypto.input_addr, crypto.input_len, crypto.key, crypto.iv,
                use_pkcs7, use_ecb, &crypto.decrypted) ) {
            ctree_str_debug("[crypto] Decryption SUCCESS: \"%s\"\n",
                           crypto.decrypted.c_str());
        }

        crypto_calls.push_back(std::move(crypto));
    }
    
    bool extract_string_constant(cexpr_t *e, qstring *out)
    {
        if ( !e || !out ) 
            return false;
            
        // Direct string constant
        if ( e->op == cot_str ) {
            *out = e->string;
            return true;
        }
        
        // Reference to global string
        if ( e->op == cot_obj ) {
            // Try to read string from address
            ea_t addr = e->obj_ea;
            if ( addr != BADADDR ) {
                qstring buf;
                ssize_t len = get_strlit_contents(&buf, addr, -1, STRTYPE_C);
                if ( len > 0 ) {
                    *out = buf;
                    return true;
                }
                // Also try just reading bytes
                len = get_max_strlit_length(addr, STRTYPE_C, ALOPT_IGNCLT);
                if ( len > 0 && len < 1024 ) {
                    char raw_buf[1024] = {};
                    if ( !chernobog::ida_memory::read_exact(raw_buf, len, addr) )
                        return false;
                    raw_buf[len] = 0;
                    *out = raw_buf;
                    return true;
                }
            }
        }
        
        // Cast expression - unwrap and try again
        if ( e->op == cot_cast ) {
            return extract_string_constant(e->x, out);
        }
        
        // Reference expression
        if ( e->op == cot_ref ) {
            return extract_string_constant(e->x, out);
        }
        
        return false;
    }
};

//--------------------------------------------------------------------------
// Expression evaluation helpers
//--------------------------------------------------------------------------
static cexpr_t *strip_cast_ref(cexpr_t *e)
{
    while ( e && (e->op == cot_cast || e->op == cot_ref) ) {
        e = e->x;
    }
    return e;
}

static bool read_value_at_address(ea_t addr, size_t size, uint64_t *out)
{
    if ( !out || addr == BADADDR || size == 0 || size > 8 )
        return false;

    const auto value = global_const_handler_t::read_admitted_scalar(
        addr, static_cast<int>(size));
    if ( !value )
        return false;
    *out = *value;
    return true;
}

static bool resolve_const_address(cexpr_t *e, ea_t *out_addr)
{
    if ( !e || !out_addr ) 
        return false;

    e = strip_cast_ref(e);
    if ( !e ) 
        return false;

    if ( e->op == cot_obj ) {
        *out_addr = e->obj_ea;
        return true;
    }

    if ( e->op == cot_num ) {
        *out_addr = (ea_t)e->numval();
        return true;
    }

    if ( e->op == cot_add ) {
        cexpr_t *base = e->x;
        cexpr_t *offset = e->y;
        if ( !base || !offset ) 
            return false;

        if ( base->op == cot_num && offset->op != cot_num ) 
            std::swap(base, offset);

        if ( offset->op != cot_num ) 
            return false;

        ea_t base_addr = BADADDR;
        if ( !resolve_const_address(base, &base_addr) ) 
            return false;

        const uint64_t displacement = offset->numval();
        if ( base_addr == BADADDR
          || displacement > uint64_t(BADADDR - base_addr - 1) )
            return false;
        *out_addr = base_addr + static_cast<ea_t>(displacement);
        return true;
    }

    return false;
}

static bool eval_expr_u64(cexpr_t *e, const std::map<int, uint64_t> &locals,
                          uint64_t *out, int size_hint, int depth = 0)
                          {
    if ( !e || !out || depth > 16 ) 
        return false;

    const size_t raw_expression_size = e->type.get_size();
    const int expression_size = raw_expression_size <= 8
        ? static_cast<int>(raw_expression_size) : 0;
    const int result_size = chernobog::bitvector::valid_byte_width(size_hint)
        ? size_hint
        : (chernobog::bitvector::valid_byte_width(expression_size)
           ? expression_size : 8);

    switch ( e->op ) {
        case cot_num:
            *out = chernobog::bitvector::truncate(e->numval(), result_size);
            return true;
        case cot_cast: {
            uint64_t value = 0;
            if ( !eval_expr_u64(e->x, locals, &value, 0, depth + 1) )
                return false;
            *out = chernobog::bitvector::truncate(value, result_size);
            return true;
        }
        case cot_var: {
            auto p = locals.find(e->v.idx);
            if ( p == locals.end() ) 
                return false;
            *out = chernobog::bitvector::truncate(p->second, result_size);
            return true;
        }
        case cot_obj: {
            const size_t raw_type_size = e->type.get_size();
            const int tsize = raw_type_size <= 8
                ? static_cast<int>(raw_type_size) : 0;
            int read_size = size_hint ? size_hint : tsize;
            if ( read_size <= 0 ) 
                read_size = size_hint ? size_hint : 1;
            if ( size_hint == 1 && tsize > 1 ) 
                return false;
            if ( size_hint == 8 && tsize > 0 && tsize < 8 ) 
                return false;
            return read_value_at_address(e->obj_ea, (size_t)read_size, out);
        }
        case cot_idx: {
            if ( !e->x || !e->y || e->y->op != cot_num )
                return false;
            ea_t base = BADADDR;
            if ( !resolve_const_address(e->x, &base) )
                return false;
            const size_t raw_type_size = e->type.get_size();
            const int element_size = raw_type_size <= 8
                ? static_cast<int>(raw_type_size) : 0;
            const int read_size = size_hint ? size_hint : element_size;
            if ( !chernobog::bitvector::valid_byte_width(read_size)
              || element_size <= 0 )
                return false;
            const uint64_t index = e->y->numval();
            if ( index > uint64_t(BADADDR) / static_cast<uint64_t>(element_size) )
                return false;
            const uint64_t displacement =
                index * static_cast<uint64_t>(element_size);
            if ( base == BADADDR || displacement > uint64_t(BADADDR - base - 1) )
                return false;
            return read_value_at_address(
                base + static_cast<ea_t>(displacement),
                static_cast<size_t>(read_size), out);
        }
        case cot_ptr: {
            ea_t addr = BADADDR;
            if ( !resolve_const_address(e->x, &addr) ) 
                return false;
            const size_t raw_type_size = e->type.get_size();
            const int tsize = raw_type_size <= 8
                ? static_cast<int>(raw_type_size) : 0;
            int read_size = size_hint ? size_hint : tsize;
            if ( read_size <= 0 ) 
                read_size = size_hint ? size_hint : 1;
            return read_value_at_address(addr, (size_t)read_size, out);
        }
        case cot_add:
        case cot_sub:
        case cot_mul:
        case cot_band:
        case cot_bor:
        case cot_xor:
        case cot_shl:
        case cot_sshr:
        case cot_ushr: {
            uint64_t l = 0, r = 0;
            if ( !eval_expr_u64(e->x, locals, &l, 0, depth + 1) )
                return false;
            if ( !eval_expr_u64(e->y, locals, &r, 0, depth + 1) )
                return false;
            const unsigned bits = chernobog::bitvector::bit_width(result_size);
            if ( (e->op == cot_shl || e->op == cot_sshr || e->op == cot_ushr)
              && r >= bits )
                return false;
            switch ( e->op ) {
                case cot_add: *out = chernobog::bitvector::truncate(l + r, result_size); break;
                case cot_sub: *out = chernobog::bitvector::truncate(l - r, result_size); break;
                case cot_mul: *out = chernobog::bitvector::truncate(l * r, result_size); break;
                case cot_band: *out = chernobog::bitvector::truncate(l & r, result_size); break;
                case cot_bor: *out = chernobog::bitvector::truncate(l | r, result_size); break;
                case cot_xor: *out = chernobog::bitvector::truncate(l ^ r, result_size); break;
                case cot_shl:
                    *out = chernobog::bitvector::shift_left(l, r, result_size);
                    break;
                case cot_sshr:
                    *out = chernobog::bitvector::shift_right_arithmetic(
                        l, r, result_size);
                    break;
                case cot_ushr:
                    *out = chernobog::bitvector::shift_right_logical(
                        l, r, result_size);
                    break;
                default: return false;
            }
            return true;
        }
        case cot_bnot: {
            uint64_t v = 0;
            if ( !eval_expr_u64(e->x, locals, &v, 0, depth + 1) )
                return false;
            *out = chernobog::bitvector::truncate(~v, result_size);
            return true;
        }
        case cot_neg: {
            uint64_t v = 0;
            if ( !eval_expr_u64(e->x, locals, &v, 0, depth + 1) )
                return false;
            *out = chernobog::bitvector::negate(v, result_size);
            return true;
        }
        default:
            break;
    }

    return false;
}

//--------------------------------------------------------------------------
// Visitor to find character-by-character assignments
//--------------------------------------------------------------------------
struct char_assign_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;

    using context_t = const citem_t *;
    using byte_assignments_t =
        std::map<int, std::pair<uint8_t, ea_t>>;

    // Target -> exact ctree block -> byte offset -> (value, instruction EA).
    // This admits linear assignments inside one conditional arm without ever
    // merging mutually exclusive branches.
    std::map<int, std::map<context_t, byte_assignments_t>> var_assignments;
    std::map<ea_t, std::map<context_t, byte_assignments_t>> global_assignments;
    std::map<context_t, std::map<int, uint64_t>> local_values;
    
    char_assign_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_PARENTS), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        if ( e->op != cot_asg ) 
            return 0;
            
        cexpr_t *lhs = e->x;
        cexpr_t *rhs = e->y;
        
        if ( !lhs || !rhs ) 
            return 0;

        const context_t context = linear_context();
        if ( context == nullptr )
            return 0;

        std::map<int, uint64_t> &context_values = local_values[context];
        if ( lhs->op == cot_var ) {
            uint64_t val = 0;
            const size_t raw_size_hint = lhs->type.get_size();
            int size_hint = raw_size_hint <= 8
                ? static_cast<int>(raw_size_hint) : 0;
            if ( size_hint <= 0 || size_hint > 8 ) 
                size_hint = 0;
            if ( eval_expr_u64(rhs, context_values, &val, size_hint) ) {
                context_values[lhs->v.idx] = val;
            } else {
                context_values.erase(lhs->v.idx);
            }
        }

        if ( try_handle_vector_assign(lhs, rhs, e->ea, context) )
            return 0;

        // Ordinary character reconstruction is byte-oriented. Recording the
        // low byte of wider array/member stores manufactures strings from
        // integer initializers.
        if ( lhs->type.get_size() != 1 )
            return 0;

        uint8_t value = 0;
        if ( !extract_byte_value(rhs, context_values, &value) )
            return 0;

        assign_target_t target;
        if ( !resolve_assignment_target(lhs, &target) ) 
            return 0;

        record_assignment(target, target.base_index, value, e->ea, context);
        return 0;
    }
    
    // Convert collected assignments to strings
    std::vector<ctree_string_decrypt_handler_t::char_string_t> 
    get_reconstructed_strings()
    {
        std::vector<ctree_string_decrypt_handler_t::char_string_t> result;
        
        // Process local variable assignments
        lvars_t *lvars = cfunc->get_lvars();
        for ( auto &kv : var_assignments ) {
            int var_idx = kv.first;
            std::vector<ctree_string_decrypt_handler_t::char_string_t>
                candidates;
            for ( auto &context_entry : kv.second )
            {
                auto &offsets = context_entry.second;
                if ( offsets.size() < 3 )
                    continue;
                ctree_string_decrypt_handler_t::char_string_t candidate;
                if ( lvars && var_idx >= 0
                  && static_cast<size_t>(var_idx) < lvars->size() )
                    candidate.var_name = (*lvars)[var_idx].name;
                else
                    candidate.var_name.sprnt("var_%d", var_idx);
                if ( try_reconstruct(offsets, &candidate) )
                    candidates.push_back(std::move(candidate));
            }
            if ( unique_reconstruction(candidates) )
            {
                ctree_str_debug("[char_assign] Variable %s: \"%s\"\n",
                    candidates.front().var_name.c_str(),
                    candidates.front().reconstructed.c_str());
                result.push_back(std::move(candidates.front()));
            }
        }
        
        // Process global assignments
        for ( auto &kv : global_assignments ) {
            ea_t addr = kv.first;
            std::vector<ctree_string_decrypt_handler_t::char_string_t>
                candidates;
            for ( auto &context_entry : kv.second )
            {
                auto &offsets = context_entry.second;
                if ( offsets.size() < 3 )
                    continue;
                ctree_string_decrypt_handler_t::char_string_t candidate;
                candidate.var_addr = addr;
                get_name(&candidate.var_name, addr);
                if ( candidate.var_name.empty() )
                {
                    candidate.var_name.sprnt(
                        "global_%llX", (unsigned long long)addr);
                }
                if ( try_reconstruct(offsets, &candidate) )
                    candidates.push_back(std::move(candidate));
            }
            if ( unique_reconstruction(candidates) )
            {
                ctree_str_debug("[char_assign] Global %s: \"%s\"\n",
                    candidates.front().var_name.c_str(),
                    candidates.front().reconstructed.c_str());
                result.push_back(std::move(candidates.front()));
            }
        }
        
        return result;
    }
    
private:
    struct assign_target_t {
        bool is_global = false;
        int var_idx = -1;
        ea_t addr = BADADDR;
        int base_index = 0;
    };

    context_t linear_context() const
    {
        context_t context = nullptr;
        for ( const citem_t *parent : parents ) {
            if ( !parent )
                continue;
            if ( parent->is_expr() ) {
                if ( parent->op == cot_tern || parent->op == cot_land ||
                     parent->op == cot_lor )
                    return nullptr;
                continue;
            }

            if ( parent->op == cit_block && context == nullptr )
                context = parent;
            else if ( parent->op == cit_if && context == nullptr )
                return nullptr; // Unbraced arm has no unique linear context.
            else if ( parent->op == cit_for || parent->op == cit_while
                 || parent->op == cit_do ||
                 parent->op == cit_switch || parent->op == cit_try )
                return nullptr;
        }
        return context;
    }

    bool get_call_name(qstring *out, cexpr_t *callee)
    {
        if ( !out || !callee ) 
            return false;
        if ( callee->op == cot_obj ) {
            return get_name(out, callee->obj_ea) > 0;
        }
        if ( callee->op == cot_helper ) {
            *out = callee->helper;
            return true;
        }
        return false;
    }

    bool resolve_base_target(cexpr_t *base, int idx, assign_target_t *out)
    {
        if ( !out ) 
            return false;

        base = strip_cast_ref(base);
        if ( !base ) 
            return false;

        if ( base->op == cot_var ) {
            out->is_global = false;
            out->var_idx = base->v.idx;
            out->base_index = idx;
            return true;
        }
        if ( base->op == cot_obj ) {
            out->is_global = true;
            out->addr = base->obj_ea;
            out->base_index = idx;
            return true;
        }

        return false;
    }

    bool resolve_ptr_target(cexpr_t *ptr_expr, assign_target_t *out)
    {
        if ( !ptr_expr || !out ) 
            return false;

        ptr_expr = strip_cast_ref(ptr_expr);
        if ( !ptr_expr ) 
            return false;

        if ( ptr_expr->op == cot_var || ptr_expr->op == cot_obj ) {
            return resolve_base_target(ptr_expr, 0, out);
        }

        if ( ptr_expr->op == cot_add ) {
            cexpr_t *base = ptr_expr->x;
            cexpr_t *offset = ptr_expr->y;
            if ( !base || !offset ) 
                return false;

            if ( base->op == cot_num && offset->op != cot_num ) 
                std::swap(base, offset);

            if ( offset->op != cot_num ) 
                return false;

            int idx = (int)offset->numval();
            return resolve_base_target(base, idx, out);
        }

        return false;
    }

    bool resolve_assignment_target(cexpr_t *lhs, assign_target_t *out)
    {
        if ( !lhs || !out ) 
            return false;

        lhs = strip_cast_ref(lhs);
        if ( !lhs ) 
            return false;

        if ( lhs->op == cot_idx ) {
            cexpr_t *base = lhs->x;
            cexpr_t *index = lhs->y;
            if ( !base || !index || index->op != cot_num ) 
                return false;
            return resolve_base_target(base, (int)index->numval(), out);
        }

        if ( lhs->op == cot_ptr ) {
            return resolve_ptr_target(lhs->x, out);
        }

        return false;
    }

    void record_assignment(const assign_target_t &target, int idx,
                           uint8_t value, ea_t ea, context_t context)
    {
        if ( idx < 0 || idx > 4096 )
            return;

        if ( target.is_global ) {
            auto &slots = global_assignments[target.addr][context];
            slots[idx] = std::make_pair(value, ea);
        } else {
            auto &slots = var_assignments[target.var_idx][context];
            slots[idx] = std::make_pair(value, ea);
        }
    }

    bool extract_byte_value(cexpr_t *e,
                            const std::map<int, uint64_t> &values,
                            uint8_t *out)
    {
        if ( !e || !out ) 
            return false;

        uint64_t val = 0;
        if ( !eval_expr_u64(e, values, &val, 1) )
            return false;

        *out = (uint8_t)(val & 0xFF);
        return true;
    }

    bool extract_qword_value(cexpr_t *e,
                             const std::map<int, uint64_t> &values,
                             uint64_t *out)
    {
        if ( !e || !out ) 
            return false;

        return eval_expr_u64(e, values, out, 8);
    }

    bool try_handle_vector_assign(cexpr_t *lhs, cexpr_t *rhs, ea_t ea,
                                  context_t context)
    {
        if ( !lhs || !rhs ) 
            return false;

        cexpr_t *call_expr = rhs;
        if ( call_expr->op == cot_cast ) 
            call_expr = call_expr->x;

        if ( !call_expr || call_expr->op != cot_call || !call_expr->x ) 
            return false;

        qstring func_name;
        if ( !get_call_name(&func_name, call_expr->x) ) 
            return false;

        const std::string normalized_name = normalize_call_name(func_name);
        if ( normalized_name != "veor_s8" && normalized_name != "veorq_s8" )
            return false;

        // The evaluator can prove only the low 64 bits. That is sufficient for
        // an 8-lane intrinsic; accepting half of a 16-lane assignment would
        // manufacture a partially initialized string. Scalar lane order below
        // is defined only for the supported little-endian target layout.
        if ( normalized_name == "veorq_s8" || inf_is_be() )
            return false;

        if ( !call_expr->a || call_expr->a->size() < 2 ) 
            return false;

        uint64_t left = 0;
        uint64_t right = 0;
        const auto values = local_values.find(context);
        if ( values == local_values.end()
          || !extract_qword_value(&(*call_expr->a)[0], values->second, &left) )
            return false;
        if ( !extract_qword_value(&(*call_expr->a)[1], values->second, &right) )
            return false;

        assign_target_t target;
        if ( !resolve_assignment_target(lhs, &target) ) 
            return false;

        uint64_t result = left ^ right;
        for ( int i = 0; i < 8; ++i ) {
            uint8_t b = (uint8_t)((result >> (i * 8)) & 0xFF);
            record_assignment(
                target, target.base_index + i, b, ea, context);
        }

        return true;
    }

    static bool unique_reconstruction(
        const std::vector<ctree_string_decrypt_handler_t::char_string_t>
            &candidates)
    {
        if ( candidates.empty() )
            return false;
        return std::all_of(
            std::next(candidates.begin()), candidates.end(),
            [&](const auto &candidate) {
                return candidate.reconstructed
                    == candidates.front().reconstructed;
            });
    }
    
    bool try_reconstruct(const std::map<int, std::pair<uint8_t, ea_t>> &offsets,
                         ctree_string_decrypt_handler_t::char_string_t *out)
                         {
        if ( offsets.empty() ) 
            return false;
            
        // A C string starts at byte zero and must be fully defined through an
        // explicit terminator. Gaps and suffix-only fragments are ambiguous.
        int min_idx = offsets.begin()->first;
        int max_idx = offsets.rbegin()->first;
        if ( min_idx != 0 || max_idx > 4096 )
            return false;
            
        // Build the string
        qstring str;
        bool all_printable = true;
        int printable_count = 0;
        bool saw_terminator = false;

        for ( int i = 0; i <= max_idx; ++i ) {
            auto p = offsets.find(i);
            if ( p == offsets.end() )
                return false;
            
            uint8_t c = p->second.first;
            out->insn_addrs.push_back(p->second.second);
            
            if ( c == 0 ) {
                saw_terminator = true;
                break;
            }
            
            if ( c < 0x20 || c > 0x7E ) {
                if ( c != '\n' && c != '\r' && c != '\t' ) {
                    all_printable = false;
                    break;
                }
            }
            
            str += (char)c;
            printable_count++;
        }
        
        if ( !saw_terminator || !all_printable || printable_count < 3 )
            return false;
            
        out->reconstructed = str;
        if ( !out->insn_addrs.empty() ) {
            out->start_addr = out->insn_addrs[0];
        }
        
        return true;
    }
};

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool ctree_string_decrypt_handler_t::detect(cfunc_t *cfunc)
{
    if ( !cfunc ) 
        return false;

    // Detection uses the same semantic preconditions as recovery. A single
    // array or pointer store is ubiquitous and is not evidence of a string.
    string_call_visitor_t call_visitor(cfunc);
    call_visitor.apply_to(&cfunc->body, nullptr);
    if ( !call_visitor.reveals.empty() || !call_visitor.crypto_calls.empty() )
        return true;

    char_assign_visitor_t assign_visitor(cfunc);
    assign_visitor.apply_to(&cfunc->body, nullptr);
    return !assign_visitor.get_reconstructed_strings().empty();
}

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
static void record_plaintext_fact(
    deobf_ctx_t *ctx, ea_t address, const char *plaintext, const char *source)
{
    if ( ctx == nullptr || address == BADADDR || plaintext == nullptr
      || plaintext[0] == '\0'
      || ctx->ambiguous_decrypted_strings.count(address) != 0 )
    {
        return;
    }
    const auto inserted = ctx->decrypted_strings.emplace(address, plaintext);
    if ( !inserted.second && inserted.first->second != plaintext )
    {
        ctree_str_debug(
            "[mapping] Conflict at 0x%llx: \"%s\" versus \"%s\" (%s); rejected\n",
            (unsigned long long)address, inserted.first->second.c_str(),
            plaintext, source);
        ctx->decrypted_strings.erase(inserted.first);
        ctx->ambiguous_decrypted_strings.insert(address);
        return;
    }
    ctree_str_debug("[mapping] %s fact: 0x%llx -> \"%s\"\n",
                    source, (unsigned long long)address, plaintext);
}

int ctree_string_decrypt_handler_t::run(cfunc_t *cfunc, deobf_ctx_t *ctx)
{
    if ( !cfunc || !ctx ) 
        return 0;
        
    ctree_str_debug("[ctree_string] Analyzing function at 0x%llx\n",
                   (unsigned long long)cfunc->entry_ea);
    
    // Find string function calls (strcpy, memcpy, CCCrypt)
    string_call_visitor_t call_visitor(cfunc);
    call_visitor.apply_to(&cfunc->body, nullptr);
    
    for ( const auto &reveal : call_visitor.reveals ) {
        // Store in context
        if ( reveal.dest_addr != BADADDR ) {
            record_plaintext_fact(
                ctx, reveal.dest_addr, reveal.plaintext.c_str(), "strcpy/memcpy");
        }
        
        // Annotate
        annotate_reveal(reveal);
    }
    
    for ( const auto &crypto : call_visitor.crypto_calls ) {
        // Store decrypted result in context if available
        if ( !crypto.decrypted.empty() ) {
            if ( crypto.input_addr != BADADDR ) {
                record_plaintext_fact(
                    ctx, crypto.input_addr, crypto.decrypted.c_str(), "crypto input");
            }
            if ( crypto.output_addr != BADADDR ) {
                record_plaintext_fact(
                    ctx, crypto.output_addr, crypto.decrypted.c_str(), "crypto output");
            }
            ctx->strings_decrypted++;
        }
        
        annotate_crypto_call(crypto);
    }
    
    // Find character-by-character assignments
    char_assign_visitor_t assign_visitor(cfunc);
    assign_visitor.apply_to(&cfunc->body, nullptr);
    
    auto char_strings = assign_visitor.get_reconstructed_strings();
    for ( const auto &str : char_strings ) {
        // Store in context
        if ( str.var_addr != BADADDR ) {
            record_plaintext_fact(
                ctx, str.var_addr, str.reconstructed.c_str(), "bytewise");
        }
        
        // Annotate
        annotate_char_string(str);
    }
    
    ctree_str_debug("[ctree_string] Found %zu strcpy/memcpy reveals, %zu crypto calls, %zu char strings\n",
                   call_visitor.reveals.size(), call_visitor.crypto_calls.size(), char_strings.size());
    
    // Phase 2: Find encrypted strings in ctree and replace with decrypted values
    // Build a map of destination addresses -> plaintexts from ALL sources
    std::map<ea_t, qstring> addr_to_plaintext;

    // Admit only exact, non-conflicting address-to-plaintext facts collected
    // from the bounded producer analyses above.
    for ( const auto &entry : ctx->decrypted_strings ) {
        if ( entry.first != BADADDR && !entry.second.empty() ) {
            addr_to_plaintext.emplace(entry.first, entry.second.c_str());
            ctree_str_debug("[mapping] admitted fact: 0x%llx -> \"%s\"\n",
                           (unsigned long long)entry.first, entry.second.c_str());
        }
    }
    
    ctree_str_debug("[ctree_string] Built address->plaintext map with %zu entries\n", addr_to_plaintext.size());
    
    if ( !addr_to_plaintext.empty() ) {
        int replaced = replace_encrypted_strings(cfunc, addr_to_plaintext);
        if ( replaced > 0 ) {
            ctree_str_debug("[ctree_string] Annotated %d encrypted string references\n", replaced);
        }
    }

    // The current implementation records recovered strings and annotations;
    // it does not mutate the ctree.
    return 0;
}

//--------------------------------------------------------------------------
// Encrypted string replacement visitor
//--------------------------------------------------------------------------
struct encrypted_string_replacer_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    const std::map<ea_t, qstring> &known_plaintexts;
    std::map<ea_t, qstring> recovered_comments;
    int replacements = 0;
    
    encrypted_string_replacer_t(cfunc_t *cf, const std::map<ea_t, qstring> &plaintexts)
        : ctree_visitor_t(CV_FAST), cfunc(cf), known_plaintexts(plaintexts) {}
    
    // Check if data at address looks encrypted (has non-printable chars)
    static bool is_encrypted_string(ea_t addr, size_t max_len = 256)
    {
        if ( addr == BADADDR || !is_loaded(addr) ) 
            return false;
            
        int non_printable = 0;
        int total = 0;
        
        for ( size_t i = 0; i < max_len; ++i ) {
            if ( addr > BADADDR - 1 - static_cast<ea_t>(i) )
                return false;
            const auto byte = chernobog::ida_memory::read_integer(
                addr + static_cast<ea_t>(i), 1);
            if ( !byte )
                return false;
            const uint8_t c = static_cast<uint8_t>(*byte);
            if ( c == 0) break;
            total++;
            if ( c < 0x20 || c > 0x7E ) {
                if ( c != '\n' && c != '\r' && c != '\t' ) {
                    non_printable++;
                }
            }
        }
        
        // Consider encrypted if >30% non-printable and at least 4 chars
        return total >= 4 && non_printable > 0 && (non_printable * 100 / total) > 30;
    }

    // A validated CFString structure carries its exact byte length. If its
    // backing bytes are already printable in the IDB, they are direct
    // plaintext evidence and do not require a surviving producer call.
    static bool read_materialized_string(
        ea_t addr, uint64_t length, qstring *out)
    {
        if ( out == nullptr || addr == BADADDR || length == 0 || length >= 4096
          || length > static_cast<uint64_t>(SIZE_MAX)
          || addr > BADADDR - static_cast<ea_t>(length) )
        {
            return false;
        }
        std::vector<uint8_t> bytes(static_cast<size_t>(length));
        if ( !chernobog::ida_memory::read_exact(bytes.data(), bytes.size(), addr) )
            return false;
        for ( uint8_t byte : bytes )
        {
            if ( byte == 0 || ((byte < 0x20 || byte > 0x7E)
              && byte != '\n' && byte != '\r' && byte != '\t') )
            {
                return false;
            }
        }
        out->clear();
        out->append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        return true;
    }
    
    // Helper to get op name for debugging
    static const char* get_op_name(ctype_t op)
    {
        switch ( op ) {
            case cot_comma: return "cot_comma";
            case cot_asg: return "cot_asg";
            case cot_asgbor: return "cot_asgbor";
            case cot_asgxor: return "cot_asgxor";
            case cot_asgband: return "cot_asgband";
            case cot_asgadd: return "cot_asgadd";
            case cot_asgsub: return "cot_asgsub";
            case cot_asgmul: return "cot_asgmul";
            case cot_asgsshr: return "cot_asgsshr";
            case cot_asgushr: return "cot_asgushr";
            case cot_asgshl: return "cot_asgshl";
            case cot_asgsdiv: return "cot_asgsdiv";
            case cot_asgudiv: return "cot_asgudiv";
            case cot_asgsmod: return "cot_asgsmod";
            case cot_asgumod: return "cot_asgumod";
            case cot_tern: return "cot_tern";
            case cot_lor: return "cot_lor";
            case cot_land: return "cot_land";
            case cot_bor: return "cot_bor";
            case cot_xor: return "cot_xor";
            case cot_band: return "cot_band";
            case cot_eq: return "cot_eq";
            case cot_ne: return "cot_ne";
            case cot_sge: return "cot_sge";
            case cot_uge: return "cot_uge";
            case cot_sle: return "cot_sle";
            case cot_ule: return "cot_ule";
            case cot_sgt: return "cot_sgt";
            case cot_ugt: return "cot_ugt";
            case cot_slt: return "cot_slt";
            case cot_ult: return "cot_ult";
            case cot_sshr: return "cot_sshr";
            case cot_ushr: return "cot_ushr";
            case cot_shl: return "cot_shl";
            case cot_add: return "cot_add";
            case cot_sub: return "cot_sub";
            case cot_mul: return "cot_mul";
            case cot_sdiv: return "cot_sdiv";
            case cot_udiv: return "cot_udiv";
            case cot_smod: return "cot_smod";
            case cot_umod: return "cot_umod";
            case cot_fadd: return "cot_fadd";
            case cot_fsub: return "cot_fsub";
            case cot_fmul: return "cot_fmul";
            case cot_fdiv: return "cot_fdiv";
            case cot_fneg: return "cot_fneg";
            case cot_neg: return "cot_neg";
            case cot_cast: return "cot_cast";
            case cot_lnot: return "cot_lnot";
            case cot_bnot: return "cot_bnot";
            case cot_ptr: return "cot_ptr";
            case cot_ref: return "cot_ref";
            case cot_postinc: return "cot_postinc";
            case cot_postdec: return "cot_postdec";
            case cot_preinc: return "cot_preinc";
            case cot_predec: return "cot_predec";
            case cot_call: return "cot_call";
            case cot_idx: return "cot_idx";
            case cot_memref: return "cot_memref";
            case cot_memptr: return "cot_memptr";
            case cot_num: return "cot_num";
            case cot_fnum: return "cot_fnum";
            case cot_str: return "cot_str";
            case cot_obj: return "cot_obj";
            case cot_var: return "cot_var";
            case cot_insn: return "cot_insn";
            case cot_sizeof: return "cot_sizeof";
            case cot_helper: return "cot_helper";
            case cot_type: return "cot_type";
            default: return "unknown";
        }
    }
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Debug: log all cot_obj and cot_ref nodes to understand what we're seeing
        if ( e->op == cot_ref && e->x && e->x->op == cot_obj ) {
            qstring name;
            get_name(&name, e->x->obj_ea);
            ctree_str_debug("[visit] cot_ref -> cot_obj at 0x%llx (%s)\n",
                           (unsigned long long)e->x->obj_ea, name.c_str());
        }
        
        // Log all calls to understand what patterns exist
        if ( e->op == cot_call && e->x ) {
            const char *call_name = "unknown";
            if ( e->x->op == cot_helper ) {
                call_name = e->x->helper;
            } else if ( e->x->op == cot_obj ) {
                static char name_buf[256];
                qstring name;
                if ( get_name(&name, e->x->obj_ea) > 0 ) {
                    qstrncpy(name_buf, name.c_str(), sizeof(name_buf));
                    call_name = name_buf;
                }
            }
            
            // Log call details with args
            if ( e->a && e->a->size() > 0 ) {
                qstring args_info;
                for ( size_t i = 0; i < e->a->size() && i < 3; ++i ) {
                    cexpr_t *arg = &(*e->a)[i];
                    args_info.cat_sprnt(" arg%zu:%s", i, get_op_name(arg->op));
                    if ( arg->op == cot_str && arg->string ) {
                        size_t len = strlen(arg->string);
                        qstring hex;
                        for ( size_t j = 0; j < len && j < 8; ++j ) {
                            hex.cat_sprnt("%02X", (uint8_t)arg->string[j]);
                        }
                        args_info.cat_sprnt("(hex=%s)", hex.c_str());
                    } else if ( arg->op == cot_obj ) {
                        args_info.cat_sprnt("(0x%llx)", (unsigned long long)arg->obj_ea);
                    }
                }
                ctree_str_debug("[call] %s%s\n", call_name, args_info.c_str());
            }
        }
        
        // Look for CFSTR or string references that might be encrypted
        // CFSTR appears as: call to CFSTR helper with cot_obj argument
        // Or direct cot_obj/cot_str
        
        ea_t str_addr = BADADDR;
        const char *existing_str = nullptr;
        cexpr_t *target_expr = e;  // Expression to modify
        
        // Check for CFSTR(x) call pattern - this is how IDA shows CFString references
        if ( e->op == cot_call && e->x ) {
            // Check both helper and regular call
            const char *func_name = nullptr;
            if ( e->x->op == cot_helper ) {
                func_name = e->x->helper;
                ctree_str_debug("[replace] Call to helper: %s\n", func_name);
            } else if ( e->x->op == cot_obj ) {
                qstring name;
                if ( get_name(&name, e->x->obj_ea) > 0 ) {
                    static char name_buf[256];
                    qstrncpy(name_buf, name.c_str(), sizeof(name_buf));
                    func_name = name_buf;
                }
            }
            
            if ( func_name && (strstr(func_name, "CFSTR") || strstr(func_name, "CFString") ||
                              strstr(func_name, "__CFString")))
                              {
                ctree_str_debug("[replace] Found CFSTR-like call: %s\n", func_name);
                // The argument to CFSTR is what we want to decrypt
                if ( e->a && e->a->size() > 0 ) {
                    cexpr_t *arg = &(*e->a)[0];
                    ctree_str_debug("[replace] CFSTR arg op: %s\n", get_op_name(arg->op));
                    if ( arg->op == cot_obj ) {
                        str_addr = arg->obj_ea;
                        target_expr = arg;  // We'll modify the argument
                        ctree_str_debug("[replace] Found CFSTR() call, arg at 0x%llx\n",
                                       (unsigned long long)str_addr);
                    } else if ( arg->op == cot_str && arg->string ) {
                        existing_str = arg->string;
                        target_expr = arg;
                        ctree_str_debug("[replace] Found CFSTR() with string arg: \"%s\"\n",
                                       existing_str);
                    }
                }
            }
        }
        // CFSTR() shows up as cot_ref -> cot_obj (taking address of CFString structure)
        // This is the main pattern for CFSTR() in pseudocode
        else if ( e->op == cot_ref && e->x && e->x->op == cot_obj ) {
            str_addr = e->x->obj_ea;
            target_expr = e;  // The whole cot_ref expression
            ctree_str_debug("[replace] Found cot_ref->cot_obj (CFSTR pattern) at 0x%llx\n",
                           (unsigned long long)str_addr);
        }
        // Direct cot_obj reference
        else if ( e->op == cot_obj ) {
            str_addr = e->obj_ea;
        }
        // Direct cot_str 
        else if ( e->op == cot_str && e->string ) {
            existing_str = e->string;
            // Log raw bytes for debugging
            size_t slen = strlen(existing_str);
            qstring hex_dump;
            for ( size_t i = 0; i < slen && i < 32; ++i ) {
                hex_dump.cat_sprnt("%02X ", (uint8_t)existing_str[i]);
            }
            ctree_str_debug("[replace] Found cot_str: len=%zu hex=[%s]\n", 
                           slen, hex_dump.c_str());
        } else {
            return 0;
        }
        
        if ( str_addr == BADADDR && !existing_str ) 
            return 0;
        
        // Try to find matching plaintext
        qstring decrypted;
        bool found = false;
        
        // Case 1: We have an existing string (cot_str) - check if it's encrypted
        if ( existing_str ) {
            // Without an address tying these bytes to one of the independently
            // recovered plaintexts, choosing plaintext P and defining
            // K = ciphertext XOR P is circular evidence: every equal-length P
            // passes the subsequent decrypt check. Do not infer a mapping.
            return 0;
        }
        // Case 2: We have an address (cot_obj) - read from memory
        else if ( str_addr != BADADDR ) {
            // Check if this is a CFSTR - typically in __cfstring section
            segment_t *seg = getseg(str_addr);
            if ( !seg ) 
                return 0;
                
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            
            ea_t actual_str_addr = str_addr;
            
            ctree_str_debug("[replace] cot_obj at 0x%llx in segment %s\n", 
                           (unsigned long long)str_addr, seg_name.c_str());
            
            // Check if this looks like a CFString structure by checking name, segment, or layout
            qstring name_at_addr;
            get_name(&name_at_addr, str_addr);
            bool is_cfstring_struct = seg_name.find("cfstring") != qstring::npos ||
                                       name_at_addr.find("cfstr_") != qstring::npos ||
                                       name_at_addr.find("CFString") != qstring::npos ||
                                       name_at_addr.find("stru_") != qstring::npos;  // May be unnamed CFString
            
            // If it looks like a struct, verify it's actually a CFString by checking the layout
            // CFString layout uses four pointer-sized ABI slots.
            const int pointer_bytes = arch::get_ptr_size();
            const ea_t flags_offset = static_cast<ea_t>(pointer_bytes);
            const ea_t pointer_offset = static_cast<ea_t>(2 * pointer_bytes);
            const ea_t length_offset = static_cast<ea_t>(3 * pointer_bytes);
            if ( str_addr > BADADDR - 1 - length_offset )
                return 0;

            if ( !is_cfstring_struct && seg_name == "__data" ) {
                // Check if this could be a CFString by validating the structure
                const auto maybe_flags = chernobog::ida_memory::read_integer(
                    str_addr + flags_offset, pointer_bytes);
                const ea_t maybe_ptr = arch::read_ptr(str_addr + pointer_offset);
                const auto maybe_len = chernobog::ida_memory::read_integer(
                    str_addr + length_offset, pointer_bytes);
                
                // Heuristic: flags should be non-zero but reasonable, ptr should be valid, len should be small
                if ( maybe_flags && *maybe_flags != 0 && *maybe_flags < 0x10000 &&
                    maybe_ptr != 0 && maybe_ptr != BADADDR && is_loaded(maybe_ptr) &&
                    maybe_len && *maybe_len > 0 && *maybe_len < 4096)
                    {
                    // Check if the pointer points to a known plaintext address
                    auto p = known_plaintexts.find(maybe_ptr);
                    if ( p != known_plaintexts.end() ) {
                        is_cfstring_struct = true;
                        ctree_str_debug("[replace] Detected CFString structure by layout at 0x%llx (ptr=0x%llx)\n",
                                       (unsigned long long)str_addr, (unsigned long long)maybe_ptr);
                    }
                }
            }
            
            ctree_str_debug("[replace] Name at 0x%llx = '%s', is_cfstring=%d\n",
                           (unsigned long long)str_addr, name_at_addr.c_str(), is_cfstring_struct);
            
            // IMPORTANT: Only replace CFSTR references, not destination buffers
            // A CFSTR reference has a structure pointer that points to the string data
            // A destination buffer is just the raw data location (what strcpy writes to)
            // We skip non-CFSTR structures to avoid breaking strcpy/memcpy calls
            if ( !is_cfstring_struct ) {
                ctree_str_debug("[replace] Skipping non-CFSTR cot_obj at 0x%llx\n",
                               (unsigned long long)str_addr);
                return 0;
            }
            
            const ea_t ptr = arch::read_ptr(str_addr + pointer_offset);
            const auto length_value = chernobog::ida_memory::read_integer(
                str_addr + length_offset, pointer_bytes);
            if ( !length_value )
                return 0;
            const uint64_t len_field = *length_value;
            ctree_str_debug("[replace] Checking as CFSTR structure: ptr = 0x%llx, len = %llu, is_loaded=%d\n",
                           (unsigned long long)ptr, (unsigned long long)len_field, is_loaded(ptr));
            if ( ptr != 0 && ptr != BADADDR && is_loaded(ptr) ) {
                const uint64_t len = len_field;
                if ( len > 0 && len < 4096 ) {
                    actual_str_addr = ptr;
                    ctree_str_debug("[replace] Using CFSTR string ptr 0x%llx, len=%llu\n",
                                   (unsigned long long)ptr, (unsigned long long)len);
                } else {
                    // Length field invalid, but pointer looks valid - use it anyway
                    // Compute actual length by scanning for null terminator
                    ctree_str_debug("[replace] Length field invalid (len=%llu), computing actual length\n",
                                   (unsigned long long)len);
                    size_t actual_len = 0;
                    for ( size_t i = 0; i < 256; ++i ) {
                        if ( ptr > BADADDR - 1 - static_cast<ea_t>(i) )
                            break;
                        const auto byte = chernobog::ida_memory::read_integer(
                            ptr + static_cast<ea_t>(i), 1);
                        if ( !byte )
                            break;
                        const uint8_t b = static_cast<uint8_t>(*byte);
                        if ( b == 0 ) {
                            actual_len = i;
                            break;
                        }
                    }
                    ctree_str_debug("[replace] Computed actual_len=%zu\n", actual_len);
                    if ( actual_len > 0 ) {
                        actual_str_addr = ptr;
                        ctree_str_debug("[replace] Using CFSTR string ptr 0x%llx (computed len=%zu)\n",
                                       (unsigned long long)ptr, actual_len);
                    }
                }
            }
            
            // Only an independently recovered plaintext associated with this
            // exact address is sufficient provenance for an annotation.
            auto p = known_plaintexts.find(actual_str_addr);
            if ( p != known_plaintexts.end() ) {
                decrypted = p->second;
                found = true;
                ctree_str_debug(
                    "[replace] Direct address match%s! Using plaintext: \"%s\"\n",
                    is_encrypted_string(actual_str_addr)
                        ? " (encrypted bytes)" : " (materialized bytes)",
                    decrypted.c_str());
            }
            else if ( read_materialized_string(
                          actual_str_addr, len_field, &decrypted) )
            {
                found = true;
                ctree_str_debug(
                    "[replace] Exact materialized CFSTR bytes: \"%s\"\n",
                    decrypted.c_str());
            }
            else {
                return 0;
            }
        }
        
        if ( !found ) 
            return 0;
            
        // Add comment at the expression's address  
        if ( target_expr->ea != BADADDR ) {
            qstring comment;
            comment.sprnt("DEOBF: Decrypted CFSTR = \"%s\"", decrypted.c_str());
            set_cmt(target_expr->ea, comment.c_str(), false);
        }
        
        ctree_str_debug("[replace] Added comment at 0x%llx for \"%s\"\n",
                       (unsigned long long)target_expr->ea, decrypted.c_str());

        // A disassembly comment added during CMAT_FINAL is not guaranteed to
        // appear in the already-built pseudocode. Retain one exact-address
        // ctree comment for the final rendering as well; install it after the
        // visitor completes so traversing the current tree is side-effect
        // free.
        recovered_comments.emplace(target_expr->ea, decrypted);
        return 0;
    }
};

int ctree_string_decrypt_handler_t::replace_encrypted_strings(
    cfunc_t *cfunc, 
    const std::map<ea_t, qstring> &known_plaintexts)
{
    encrypted_string_replacer_t replacer(cfunc, known_plaintexts);
    replacer.apply_to(&cfunc->body, nullptr);
    bool comments_changed = false;
    for ( const auto &entry : replacer.recovered_comments )
    {
        static constexpr char DECRYPTED_PREFIX[] =
            "DEOBF: Decrypted CFSTR = ";
        treeloc_t location{entry.first, ITP_SEMI};
        const char *existing = cfunc->get_user_cmt(
            location, RETRIEVE_ALWAYS);
        if ( existing != nullptr && existing[0] != '\0'
          && qstrncmp(existing, DECRYPTED_PREFIX,
                      sizeof(DECRYPTED_PREFIX) - 1) != 0 )
        {
            continue; // Preserve unrelated analyst comments verbatim.
        }
        qstring comment;
        comment.sprnt("DEOBF: Decrypted CFSTR = \"%s\"",
                      entry.second.c_str());
        if ( existing == nullptr || comment != existing )
        {
            cfunc->set_user_cmt(location, comment.c_str());
            comments_changed = true;
        }
        ++replacer.replacements;
    }
    if ( comments_changed )
        cfunc->save_user_cmts();
    return replacer.replacements;
}

//--------------------------------------------------------------------------
// Annotation
//--------------------------------------------------------------------------
void ctree_string_decrypt_handler_t::annotate_reveal(const string_reveal_t &reveal)
{
    if ( reveal.location == BADADDR ) 
        return;
        
    qstring comment;
    const char *type = (reveal.reveal_type == 0) ? "strcpy" : "memcpy";
    
    if ( !reveal.dest_name.empty() ) {
        comment.sprnt("DEOBF: %s reveals \"%s\" -> %s",
                     type, reveal.plaintext.c_str(), reveal.dest_name.c_str());
    } else {
        comment.sprnt("DEOBF: %s reveals \"%s\"", type, reveal.plaintext.c_str());
    }
    
    set_cmt(reveal.location, comment.c_str(), false);
    
    // Also annotate at destination if it's a global
    if ( reveal.dest_addr != BADADDR ) {
        qstring dest_comment;
        dest_comment.sprnt("Decrypted: \"%s\"", reveal.plaintext.c_str());
        set_cmt(reveal.dest_addr, dest_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_char_string(const char_string_t &str)
{
    if ( str.insn_addrs.empty() ) 
        return;
        
    qstring comment;
    comment.sprnt("DEOBF: Stack string \"%s\"", str.reconstructed.c_str());
    
    // Annotate at first instruction
    set_cmt(str.insn_addrs[0], comment.c_str(), false);
    
    // Also annotate at variable address if global
    if ( str.var_addr != BADADDR ) {
        qstring var_comment;
        var_comment.sprnt("Decrypted: \"%s\"", str.reconstructed.c_str());
        set_cmt(str.var_addr, var_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_crypto_call(const crypto_call_t &crypto)
{
    if ( crypto.location == BADADDR ) 
        return;
        
    qstring comment;
    // Convert key to hex for display
    qstring key_hex;
    for ( size_t i = 0; i < crypto.key.size() && i < 16; ++i ) {
        key_hex.cat_sprnt("%02X", crypto.key[i]);
    }
    if ( crypto.key.size() > 16 ) {
        key_hex += "...";
    }
    
    // Include decrypted result if available
    if ( !crypto.decrypted.empty() ) {
        // Truncate long decrypted strings for comment
        qstring decrypted_display = crypto.decrypted;
        if ( decrypted_display.length() > 64 ) {
            decrypted_display.resize(64);
            decrypted_display += "...";
        }
        comment.sprnt("DEOBF: %s AES-%d -> \"%s\" (key=%s)",
                     crypto.function.c_str(), crypto.algorithm_bits,
                     decrypted_display.c_str(), key_hex.c_str());
    } else {
        comment.sprnt("DEOBF: %s AES-%d key=%s", crypto.function.c_str(),
                     crypto.algorithm_bits, key_hex.c_str());
    }
    
    set_cmt(crypto.location, comment.c_str(), false);
    
    // If we have decrypted data and an output address, annotate there too
    if ( !crypto.decrypted.empty() && crypto.output_addr != BADADDR ) {
        qstring output_comment;
        output_comment.sprnt("AES Decrypted: \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.output_addr, output_comment.c_str(), true);
    }
    
    // Also annotate at input address with what was encrypted
    if ( !crypto.decrypted.empty() && crypto.input_addr != BADADDR ) {
        qstring input_comment;
        input_comment.sprnt("Encrypted data -> \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.input_addr, input_comment.c_str(), true);
    }
}
