#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree String Decryption Handler
//
// Analyzes the decompiled ctree to detect and resolve string obfuscation
// patterns that are easier to identify at the high-level IR than at
// microcode level.
//
// Detected patterns:
//
// 1. strcpy/memcpy reveals:
//    strcpy(decrypted_buffer, "plaintext_value");
//    memcpy(buffer, "AES_KEY_HERE", 16);
//    -> The destination variable gets associated with the plaintext
//
// 2. Character-by-character construction:
//    buffer[0] = 'h'; buffer[1] = 'e'; buffer[2] = 'l'; ...
//    buffer[0] = 104; buffer[1] = 101; buffer[2] = 108; ...
//    -> Reconstructs the string from individual assignments
//
// 3. AES/Crypto parameter detection:
//    CCCrypt(kCCDecrypt, kCCAlgorithmAES, ..., key, 16, iv, ...);
//    -> Extracts exact static parameters and decrypts static ciphertext
//
// Output:
//   - Annotates decompiled code with decrypted strings
//   - Populates ctx->decrypted_strings for other handlers
//   - Annotates ctree references with recovered plaintext
//--------------------------------------------------------------------------

#include <set>
#include <map>

class ctree_string_decrypt_handler_t {
public:
    // Main entry point - run on decompiled function
    static int run(cfunc_t *cfunc, deobf_ctx_t *ctx);
    
    // Detection - check if function likely has string obfuscation
    static bool detect(cfunc_t *cfunc);

    //----------------------------------------------------------------------
    // Public types (used by visitor classes in .cpp)
    //----------------------------------------------------------------------
    
    // Info about a revealed string
    struct string_reveal_t {
        ea_t location = BADADDR;    // Where in the code
        qstring dest_name;          // Destination variable name
        ea_t dest_addr = BADADDR;   // Destination address (if global)
        qstring plaintext;          // The revealed plaintext
        int reveal_type = 0;        // 0=strcpy, 1=memcpy, 2=assignment
    };
    
    //----------------------------------------------------------------------
    // Character-by-character string detection
    //----------------------------------------------------------------------
    
    // Info about a constructed string
    struct char_string_t {
        ea_t start_addr = BADADDR;  // First assignment address
        qstring var_name;           // Variable being assigned to
        ea_t var_addr = BADADDR;    // Global address if applicable
        qstring reconstructed;      // The reconstructed string
        std::vector<ea_t> insn_addrs;  // All assignment addresses
    };
    
    //----------------------------------------------------------------------
    // XOR decryption detection
    //----------------------------------------------------------------------
    
    //----------------------------------------------------------------------
    // Crypto function detection
    //----------------------------------------------------------------------
    
    // Info about a crypto call
    struct crypto_call_t {
        ea_t location = BADADDR;    // Call location
        qstring function;           // "CCCrypt", "AES_decrypt", etc.
        int algorithm_bits = 0;     // AES key size in bits: 128, 192, or 256
        std::vector<uint8_t> key;   // Extracted key
        std::vector<uint8_t> iv;    // Extracted IV
        ea_t input_addr = BADADDR;  // Input buffer address
        size_t input_len = 0;       // Input buffer length
        ea_t output_addr = BADADDR; // Output buffer address
        qstring decrypted;          // Decrypted plaintext (if successful)
    };
    
private:
    //----------------------------------------------------------------------
    // Annotation and patching
    //----------------------------------------------------------------------
    
    // Add comment with decrypted string
    static void annotate_reveal(const string_reveal_t &reveal);
    static void annotate_char_string(const char_string_t &str);
    static void annotate_crypto_call(const crypto_call_t &crypto);
    
    // Replace all encrypted strings in ctree using known plaintexts
    static int replace_encrypted_strings(cfunc_t *cfunc,
                                        const std::map<ea_t, qstring> &known_plaintexts,
                                        bool persist_annotations);
    
};
