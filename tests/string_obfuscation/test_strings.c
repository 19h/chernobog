/*
 * Test program for Chernobog string decryption handlers
 * 
 * This file contains various string obfuscation patterns found in:
 * - Hikari LLVM obfuscator (XOR encryption, string encryption)
 * - Aldaz and similar tools (character-by-character construction)
 * - Generic patterns (strcpy reveals, stack strings, AES)
 *
 * Compile with: clang -O0 -g -o test_strings test_strings.c
 * For macOS: clang -O0 -g -framework Foundation -o test_strings test_strings.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Prevent compiler from optimizing away our patterns
#ifdef __clang__
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
#else
#define NOINLINE __attribute__((noinline))
#define OPTNONE
#endif

volatile int g_sink = 0; // Sink to prevent optimization

//=============================================================================
// Pattern 1: Hikari-style XOR encrypted string with runtime decryption
//=============================================================================

// Simulated encrypted string (XOR key = 0x5A for each byte)
// Original: "SecretPassword123"
static char EncryptedString_100001[18] = {
    0x09, 0x3F, 0x39, 0x0C, 0x3F, 0x0E, 0x1A, 0x3B, // "SecretPa" ^ 0x5A
    0x0D, 0x0D, 0x17, 0x3F, 0x0C, 0x39, 0x6B, 0x6C, // "ssword12" ^ 0x5A
    0x69, 0x00                                      // "3\0" ^ 0x5A (null stays 0)
};
static char DecryptSpace_100001[18];
static volatile int StringEncryptionEncStatus_100001 = 0;

NOINLINE OPTNONE void decrypt_string_hikari_style(void)
{
    // Hikari pattern: check status, XOR decrypt, set status
    if (StringEncryptionEncStatus_100001 == 0)
    {
        for (int i = 0; i < 17; i++)
        {
            DecryptSpace_100001[i] = EncryptedString_100001[i] ^ 0x5A;
        }
        DecryptSpace_100001[17] = 0;
        StringEncryptionEncStatus_100001 = 1;
    }
}

NOINLINE OPTNONE const char *get_secret_password(void)
{
    decrypt_string_hikari_style();
    return DecryptSpace_100001;
}

//=============================================================================
// Pattern 2: Character-by-character string construction (Aldaz style)
//=============================================================================

NOINLINE OPTNONE void build_api_url(char *buffer)
{
    // This pattern is common in obfuscated code
    // The decompiler shows: buffer[0] = 'h'; buffer[1] = 't'; etc.
    buffer[0] = 104;  // 'h'
    buffer[1] = 116;  // 't'
    buffer[2] = 116;  // 't'
    buffer[3] = 112;  // 'p'
    buffer[4] = 115;  // 's'
    buffer[5] = 58;   // ':'
    buffer[6] = 47;   // '/'
    buffer[7] = 47;   // '/'
    buffer[8] = 97;   // 'a'
    buffer[9] = 112;  // 'p'
    buffer[10] = 105; // 'i'
    buffer[11] = 46;  // '.'
    buffer[12] = 101; // 'e'
    buffer[13] = 120; // 'x'
    buffer[14] = 97;  // 'a'
    buffer[15] = 109; // 'm'
    buffer[16] = 112; // 'p'
    buffer[17] = 108; // 'l'
    buffer[18] = 101; // 'e'
    buffer[19] = 46;  // '.'
    buffer[20] = 99;  // 'c'
    buffer[21] = 111; // 'o'
    buffer[22] = 109; // 'm'
    buffer[23] = 0;   // null terminator
}

//=============================================================================
// Pattern 3: strcpy/memcpy that reveals plaintext
//=============================================================================

static char g_encrypted_key[32] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                                   0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static char g_decrypted_key[32];

NOINLINE OPTNONE void decrypt_and_copy_key(void)
{
    // In obfuscated code, this pattern reveals the plaintext
    // The strcpy destination gets the decrypted value
    char temp[32];

    // Simulate some "decryption"
    for (int i = 0; i < 16; i++)
    {
        temp[i] = g_encrypted_key[i] ^ 0xFF;
    }

    // This strcpy reveals what the decrypted value should be
    // Pattern: strcpy(decrypted_buffer, "KNOWN_PLAINTEXT");
    strcpy(g_decrypted_key, "MySecretAPIKey99");

    g_sink = temp[0]; // Prevent optimization
}

NOINLINE OPTNONE void copy_with_memcpy(void)
{
    char buffer[64];

    // memcpy/qmemcpy pattern that reveals plaintext
    memcpy(buffer, "AES256_ENCRYPTION_KEY_HERE!!", 28);

    g_sink = buffer[0];
}

//=============================================================================
// Pattern 4: XOR with variable key (per-byte different keys)
//=============================================================================

// Original: "admin:password" encrypted with varying XOR keys
static unsigned char EncryptedCreds[15] = {0x61 ^ 0x11, // 'a' ^ 0x11 = 0x70
                                           0x64 ^ 0x22, // 'd' ^ 0x22 = 0x46
                                           0x6D ^ 0x33, // 'm' ^ 0x33 = 0x5E
                                           0x69 ^ 0x44, // 'i' ^ 0x44 = 0x2D
                                           0x6E ^ 0x55, // 'n' ^ 0x55 = 0x3B
                                           0x3A ^ 0x66, // ':' ^ 0x66 = 0x5C
                                           0x70 ^ 0x77, // 'p' ^ 0x77 = 0x07
                                           0x61 ^ 0x88, // 'a' ^ 0x88 = 0xE9
                                           0x73 ^ 0x99, // 's' ^ 0x99 = 0xEA
                                           0x73 ^ 0xAA, // 's' ^ 0xAA = 0xD9
                                           0x77 ^ 0xBB, // 'w' ^ 0xBB = 0xCC
                                           0x6F ^ 0xCC, // 'o' ^ 0xCC = 0xA3
                                           0x72 ^ 0xDD, // 'r' ^ 0xDD = 0xAF
                                           0x64 ^ 0xEE, // 'd' ^ 0xEE = 0x8A
                                           0x00};

static unsigned char XorKeys[14] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

NOINLINE OPTNONE void decrypt_with_keystream(char *output)
{
    for (int i = 0; i < 14; i++)
    {
        output[i] = EncryptedCreds[i] ^ XorKeys[i];
    }
    output[14] = 0;
}

//=============================================================================
// Pattern 5: NOT-based obfuscation (~char)
//=============================================================================

NOINLINE OPTNONE void build_string_with_not(char *buffer)
{
    // Obfuscators sometimes use NOT instead of XOR
    // ~0x97 = 'h', ~0x96 = 'i', etc.
    buffer[0] = ~0x97; // 'h'
    buffer[1] = ~0x96; // 'i'
    buffer[2] = ~0x9B; // 'd'
    buffer[3] = ~0x9B; // 'd'
    buffer[4] = ~0x9A; // 'e'
    buffer[5] = ~0x91; // 'n'
    buffer[6] = 0;
}

//=============================================================================
// Pattern 6: Simulated AES decryption pattern
//=============================================================================

// Mock CCCrypt-like function
int mock_CCCrypt(int op, int alg, int options, const void *key, size_t keyLength, const void *iv,
                 const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable,
                 size_t *dataOutMoved)
{
    // Just copy for simulation
    if (dataOutMoved)
        *dataOutMoved = dataInLength;
    memcpy(dataOut, dataIn, dataInLength < dataOutAvailable ? dataInLength : dataOutAvailable);
    return 0;
}

#define kCCDecrypt 1
#define kCCAlgorithmAES128 0
#define kCCOptionPKCS7Padding 1

NOINLINE OPTNONE void decrypt_aes_data(const unsigned char *encrypted, size_t len, char *output)
{
    char key[16];
    char iv[16];
    size_t decrypted_len = 0;

    // Key setup pattern - this is what we want to detect
    memcpy(key, "9QxK3vPf2sL8tW0r", 16); // AES-128 key
    memcpy(iv, "0123456789ABCDEF", 16);  // IV

    // CCCrypt call pattern
    mock_CCCrypt(kCCDecrypt,            // operation
                 kCCAlgorithmAES128,    // algorithm
                 kCCOptionPKCS7Padding, // options
                 key, 16,               // key, keyLength
                 iv,                    // iv
                 encrypted, len,        // input
                 output, 256,           // output
                 &decrypted_len);
}

//=============================================================================
// Pattern 7: Objective-C style CFSTR (simulated)
//=============================================================================

typedef struct
{
    void *isa;
    int flags;
    const char *str;
    long length;
} CFStringStruct;

// Encrypted CFSTR-like string
static const char cfstr_encrypted[] = "\xF2\x0B\xCF\xB6\xBA"; // Encrypted "data" + null
static char cfstr_decrypted[8];

NOINLINE OPTNONE const char *get_cfstr_decrypted(void)
{
    // XOR decrypt (key = 0x96 for this example)
    // 'data' = 0x64, 0x61, 0x74, 0x61
    // encrypted: 0x64^0x96=0xF2, 0x61^0x96=0xF7... (simplified)
    for (int i = 0; i < 4; i++)
    {
        cfstr_decrypted[i] = cfstr_encrypted[i] ^ 0x96;
    }
    cfstr_decrypted[4] = 0;
    return cfstr_decrypted;
}

//=============================================================================
// Pattern 8: Base64-like encoded string with decode
//=============================================================================

static const char base64_encoded[] = "SGVsbG9Xb3JsZA=="; // "HelloWorld" in base64

NOINLINE OPTNONE void decode_base64_string(char *output)
{
    // Simplified - just copy for pattern demonstration
    // In real code, this would be actual base64 decode
    strcpy(output, "HelloWorld");
}

//=============================================================================
// Main - exercise all patterns
//=============================================================================

int main(int argc, char **argv)
{
    char buffer[256];

    printf("Testing string obfuscation patterns for Chernobog\n");
    printf("=================================================\n\n");

    // Pattern 1: Hikari XOR
    printf("Pattern 1 (Hikari XOR): %s\n", get_secret_password());

    // Pattern 2: Character-by-character
    build_api_url(buffer);
    printf("Pattern 2 (Char-by-char): %s\n", buffer);

    // Pattern 3: strcpy reveal
    decrypt_and_copy_key();
    printf("Pattern 3 (strcpy reveal): %s\n", g_decrypted_key);

    // Pattern 4: memcpy reveal
    copy_with_memcpy();
    printf("Pattern 4 (memcpy reveal): done\n");

    // Pattern 5: Variable XOR keys
    decrypt_with_keystream(buffer);
    printf("Pattern 5 (Keystream XOR): %s\n", buffer);

    // Pattern 6: NOT-based
    build_string_with_not(buffer);
    printf("Pattern 6 (NOT-based): %s\n", buffer);

    // Pattern 7: Mock AES
    unsigned char fake_encrypted[32] = {0};
    decrypt_aes_data(fake_encrypted, 32, buffer);
    printf("Pattern 7 (AES): decrypted %zu bytes\n", strlen(buffer));

    // Pattern 8: CFSTR-like
    printf("Pattern 8 (CFSTR): %s\n", get_cfstr_decrypted());

    // Pattern 9: Base64
    decode_base64_string(buffer);
    printf("Pattern 9 (Base64): %s\n", buffer);

    return 0;
}
