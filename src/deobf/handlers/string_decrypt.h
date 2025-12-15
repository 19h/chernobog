#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// String Decryption Handler
//
// Hikari's string encryption:
//   - Stores XOR-encrypted strings in global variables
//   - Creates decryption code at function entry
//   - Uses per-element XOR keys
//   - Atomic status flag to prevent re-decryption
//
// Detection:
//   - Global variables named "EncryptedString", "DecryptSpace"
//   - XOR loops in function prologue
//   - Atomic load/store of status flag
//
// Reversal:
//   1. Find encrypted string globals
//   2. Extract XOR keys from decryption code
//   3. Decrypt strings
//   4. Patch references to point to decrypted data
//   5. Optionally remove decryption code
//--------------------------------------------------------------------------
class string_decrypt_handler_t {
public:
    // Detection
    static bool detect(ea_t func_ea);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    // Find encrypted strings in the binary
    struct encrypted_string_t {
        ea_t encrypted_addr;     // EncryptedString global
        ea_t decrypt_space_addr; // DecryptSpace global
        std::vector<uint8_t> encrypted_data;
        std::vector<uint8_t> xor_keys;
        int element_size;        // 1, 2, 4, or 8 bytes
        std::string decrypted;
    };

    static std::vector<encrypted_string_t> find_encrypted_strings(ea_t func_ea);

    // Extract XOR keys from decryption code
    static bool extract_xor_keys(mbl_array_t *mba, encrypted_string_t *str);

    // Decrypt a string
    static std::string decrypt_string(const encrypted_string_t &str);

    // Patch references in microcode
    static int patch_string_references(mbl_array_t *mba, const encrypted_string_t &str,
                                      const std::string &decrypted, deobf_ctx_t *ctx);

    // Add decrypted string as IDA comment/name
    static void annotate_string(const encrypted_string_t &str, const std::string &decrypted);

    // Find decryption block (StringDecryptionBB pattern)
    static int find_decryption_block(mbl_array_t *mba);
};
