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
//   - Exact contiguous static global-to-global XOR/NOT initializer runs that
//     decode as valid UTF-8/UTF-16/UTF-32 text
//   - A function data-reference to a legacy Hikari "EncryptedString" object
//
// Reversal:
//   1. Evaluate exact-width global XOR/NOT/identity writes, including a
//      same-block register-mediated final store
//   2. Require contiguous disjoint ranges, sufficient transformed writes,
//      and strict text/terminator validation
//   3. Patch only the runtime destination and replace accepted stores with
//      plaintext immediates so Hex-Rays can collapse the initializer
//   4. Retain the named-object Hikari key-vector path as a legacy fallback
//--------------------------------------------------------------------------
class string_decrypt_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

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
