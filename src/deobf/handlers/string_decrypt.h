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
//   - A function data-reference to a global whose normalized name begins with
//     "EncryptedString"
//
// Reversal:
//   1. Find encrypted string globals
//   2. Extract a conflict-free contiguous prefix of per-byte XOR keys
//   3. Decrypt printable text with an explicit source terminator
//   4. Annotate the encrypted object and its corresponding decrypt space
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
        ea_t encrypted_addr = BADADDR;     // EncryptedString global
        ea_t decrypt_space_addr = BADADDR; // DecryptSpace global
        std::vector<uint8_t> encrypted_data;
        std::vector<uint8_t> xor_keys;
    };

    static std::vector<encrypted_string_t> find_encrypted_strings(ea_t func_ea);

    // Extract XOR keys from decryption code
    static bool extract_xor_keys(mbl_array_t *mba, encrypted_string_t *str);

    // Decrypt a string
    static std::string decrypt_string(const encrypted_string_t &str);

    // Add decrypted string as IDA comment/name
    static void annotate_string(const encrypted_string_t &str, const std::string &decrypted);
};
