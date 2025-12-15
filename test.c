/*
 * Hikari Obfuscation Test Program
 * ================================
 * Faithfully replicates all Hikari/OLLVM obfuscation techniques:
 * 1. Control Flow Flattening (CFF) - nested state machines
 * 2. String Encryption - XOR, stack strings, global array manipulation
 * 3. Function Call Obfuscation - wrapper indirection
 * 4. Indirect Branching - computed jumps via function pointers
 * 5. Instruction Substitution - complex equivalent operations
 * 6. Bogus Control Flow - opaque predicates
 * 7. Mixed Boolean Arithmetic (MBA)
 * 
 * Compile: gcc -O0 -fno-inline -o hikari_test hikari_test_obfuscated.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

// ============================================================================
// GLOBAL ENCRYPTED DATA ARRAYS (String Encryption via Global XOR Arrays)
// ============================================================================

// Encrypted: "/etc/passwd" ^ 0x37
static unsigned char byte_100014110[] = {0x18, 0x52, 0x43, 0x54, 0x18, 0x47, 0x56, 0x44, 0x44, 0x40, 0x53, 0x00};
static unsigned char byte_100014170[32] = {0};

// Encrypted: "Configuration loaded successfully" ^ 0x4C
static unsigned char byte_100014200[] = {
    0x0F, 0x23, 0x22, 0x2A, 0x25, 0x2B, 0x39, 0x3E, 0x2D, 0x38, 0x25, 0x23, 0x22, 0x6C,
    0x20, 0x23, 0x2D, 0x28, 0x29, 0x28, 0x6C, 0x3F, 0x39, 0x2F, 0x2F, 0x29, 0x3F, 0x3F,
    0x2A, 0x39, 0x20, 0x20, 0x35, 0x00
};
static unsigned char byte_100014280[64] = {0};

// Encrypted: "sudo rm -rf /tmp/cache/*" ^ 0x5A
static unsigned char byte_100014300[] = {
    0x29, 0x2F, 0x3E, 0x35, 0x7A, 0x28, 0x37, 0x7A, 0x77, 0x28, 0x3C, 0x7A,
    0x75, 0x2E, 0x37, 0x2A, 0x75, 0x39, 0x3B, 0x39, 0x32, 0x3F, 0x75, 0x70, 0x00
};
static unsigned char byte_100014380[64] = {0};

// Encrypted: "https://api.example.com/check" ^ 0x1F
static unsigned char byte_100014400[] = {
    0x77, 0x6B, 0x6B, 0x6F, 0x6C, 0x25, 0x30, 0x30, 0x7E, 0x6F, 0x76, 0x31,
    0x7A, 0x67, 0x7E, 0x72, 0x6F, 0x73, 0x7A, 0x31, 0x7C, 0x70, 0x72, 0x30,
    0x7C, 0x77, 0x7A, 0x7C, 0x74, 0x00
};
static unsigned char byte_100014480[64] = {0};

// Encrypted: "AUTH_TOKEN=%s&USER=%s" ^ 0x23
static unsigned char byte_100014500[] = {
    0x62, 0x76, 0x77, 0x6B, 0x7C, 0x77, 0x6C, 0x68, 0x66, 0x6D, 0x1E, 0x06,
    0x50, 0x05, 0x76, 0x70, 0x66, 0x71, 0x1E, 0x06, 0x50, 0x00
};
static unsigned char byte_100014580[64] = {0};

// ============================================================================
// STATE CONSTANTS FOR CONTROL FLOW FLATTENING
// ============================================================================

// Main dispatcher states
#define STATE_INIT              0xDEAD0001
#define STATE_CHECK_ENV         0xDEAD0002
#define STATE_VALIDATE_ARGS     0xDEAD0003
#define STATE_LOAD_CONFIG       0xDEAD0004
#define STATE_DECRYPT_STRINGS   0xDEAD0005
#define STATE_CHECK_NETWORK     0xDEAD0006
#define STATE_PROCESS_DATA      0xDEAD0007
#define STATE_CLEANUP           0xDEAD0008
#define STATE_EXIT_SUCCESS      0xDEAD0009
#define STATE_EXIT_FAILURE      0xDEAD000A
#define STATE_ERROR_HANDLER     0xDEAD000B
#define STATE_NESTED_DISPATCH   0xDEAD000C

// Sub-dispatcher states (nested CFF)
#define SUBSTATE_PARSE_INPUT    0xBEEF0001
#define SUBSTATE_VALIDATE       0xBEEF0002
#define SUBSTATE_TRANSFORM      0xBEEF0003
#define SUBSTATE_ENCODE         0xBEEF0004
#define SUBSTATE_OUTPUT         0xBEEF0005
#define SUBSTATE_RETURN         0xBEEF0006

// Config loader states
#define CFG_STATE_OPEN          0xCAFE0001
#define CFG_STATE_READ          0xCAFE0002
#define CFG_STATE_PARSE         0xCAFE0003
#define CFG_STATE_VALIDATE      0xCAFE0004
#define CFG_STATE_APPLY         0xCAFE0005
#define CFG_STATE_CLOSE         0xCAFE0006
#define CFG_STATE_ERROR         0xCAFE0007
#define CFG_STATE_DONE          0xCAFE0008

// Dead/unreachable states (bogus control flow)
#define STATE_DEAD_1            0x00000000
#define STATE_DEAD_2            0xFFFFFFFF
#define STATE_DEAD_3            0x12345678

// ============================================================================
// OPAQUE PREDICATES (Always true/false but hard to analyze statically)
// ============================================================================

volatile int g_opaque_var1 = 0x12345678;
volatile int g_opaque_var2 = 0x87654321;

// (x * (x + 1)) is always even - opaque predicate returning 1
#define OPAQUE_TRUE_1(x) (((x) * ((x) + 1)) % 2 == 0)

// (x^2 + x) % 2 == 0 - always true
#define OPAQUE_TRUE_2(x) ((((x) * (x)) + (x)) % 2 == 0)

// (x | 1) > 0 for any x - always true for non-negative
#define OPAQUE_TRUE_3(x) (((x) | 1) > 0)

// 7 * y^2 - 1 != z^2 for any integers (number theory) - always true
#define OPAQUE_TRUE_4(y, z) ((7 * (y) * (y) - 1) != ((z) * (z)))

// (x & 1) == 0 && (x & 1) == 1 - always false
#define OPAQUE_FALSE_1(x) (((x) & 1) == 0 && ((x) & 1) == 1)

// x < x - always false
#define OPAQUE_FALSE_2(x) ((x) < (x))

// ============================================================================
// MIXED BOOLEAN ARITHMETIC (MBA) - Obfuscated arithmetic
// ============================================================================

// Obfuscated: a + b
static inline int mba_add(int a, int b) {
    return (a ^ b) + 2 * (a & b);
}

// Obfuscated: a - b
static inline int mba_sub(int a, int b) {
    return (a ^ b) - 2 * (~a & b);
}

// Obfuscated: a * 2
static inline int mba_mul2(int a) {
    return (a << 1) ^ (a & 0) | (a + a);
}

// Obfuscated: a == b comparison
static inline int mba_eq(int a, int b) {
    int t = a ^ b;
    return ((t | (~t + 1)) >> 31) + 1;
}

// Obfuscated constant: returns 0 in a convoluted way
static inline int mba_zero(int x) {
    return (x ^ x) & ((x | ~x) ^ (x | ~x));
}

// Obfuscated constant: returns 1
static inline int mba_one(int x) {
    return ((x | ~x) >> 31) & 1 | (((unsigned)(~x + 1) | (unsigned)x) >> 31) ^ 1;
}

// ============================================================================
// FUNCTION WRAPPERS (Function Call Obfuscation)
// ============================================================================

typedef void (*wrapper_func_t)(void);
typedef int (*wrapper_func_int_t)(void);
typedef void (*wrapper_func_str_t)(const char*);
typedef int (*wrapper_func_check_t)(const char*, int);

// Wrapper table for indirect calls
static void* g_wrapper_table[32];
static int g_wrapper_initialized = 0;

void _HikariFunctionWrapper_001(const char* str) {
    // Wraps: printf for logging
    volatile int check = 1;
    if (OPAQUE_TRUE_1(g_opaque_var1)) {
        check = mba_add(check, mba_zero(42));
    }
    if (check) {
        printf("[LOG] %s\n", str);
    }
}

void _HikariFunctionWrapper_002(const char* str) {
    // Wraps: fprintf(stderr, ...)
    volatile int check = 1;
    if (OPAQUE_TRUE_2(g_opaque_var2)) {
        fprintf(stderr, "[ERR] %s\n", str);
    }
    if (OPAQUE_FALSE_1(g_opaque_var1)) {
        abort(); // Never reached
    }
}

int _HikariFunctionWrapper_003(void) {
    // Wraps: getuid()
    int result;
    volatile int junk = g_opaque_var1 ^ g_opaque_var2;
    junk = mba_add(junk, 0);
    result = getuid();
    junk = mba_sub(junk, junk);
    return result + junk;
}

int _HikariFunctionWrapper_004(const char* path) {
    // Wraps: access(path, F_OK)
    struct stat st;
    volatile int x = 0;
    if (OPAQUE_TRUE_3(g_opaque_var1)) {
        x = stat(path, &st);
    }
    return (x == 0) ? 1 : 0;
}

void _HikariFunctionWrapper_005(const char* cmd) {
    // Wraps: system()
    volatile int safety = 1;
    if (OPAQUE_TRUE_4(g_opaque_var1, g_opaque_var2)) {
        if (safety) {
            printf("[SYSCALL] Would execute: %s\n", cmd);
            // system(cmd); // Commented for safety in test
        }
    }
}

int _HikariFunctionWrapper_006(const char* s1, const char* s2) {
    // Wraps: strcmp with obfuscation
    int i = 0;
    int result = 0;
    volatile int junk = mba_zero(g_opaque_var1);
    
    while (s1[i] != '\0' || s2[i] != '\0') {
        int diff = mba_sub((int)s1[i], (int)s2[i]);
        if (diff != 0) {
            result = diff;
            break;
        }
        i = mba_add(i, 1);
    }
    return result + junk;
}

void _HikariFunctionWrapper_007(void* dst, const void* src, size_t n) {
    // Wraps: memcpy with byte-by-byte obfuscation
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    size_t i;
    
    for (i = 0; i < n; i++) {
        volatile int junk = mba_zero(i);
        d[i] = s[i] ^ (unsigned char)junk;
    }
}

size_t _HikariFunctionWrapper_008(const char* str) {
    // Wraps: strlen
    size_t len = 0;
    volatile int x = mba_one(g_opaque_var1);
    
    while (str[len] != '\0') {
        len = mba_add(len, x);
    }
    return len;
}

// Initialize wrapper table with function pointers
void _HikariFunctionWrapper_InitTable(void) {
    if (g_wrapper_initialized) return;
    
    volatile int idx = 0;
    g_wrapper_table[mba_add(idx, 0)] = (void*)_HikariFunctionWrapper_001;
    g_wrapper_table[mba_add(idx, 1)] = (void*)_HikariFunctionWrapper_002;
    g_wrapper_table[mba_add(idx, 2)] = (void*)_HikariFunctionWrapper_003;
    g_wrapper_table[mba_add(idx, 3)] = (void*)_HikariFunctionWrapper_004;
    g_wrapper_table[mba_add(idx, 4)] = (void*)_HikariFunctionWrapper_005;
    g_wrapper_table[mba_add(idx, 5)] = (void*)_HikariFunctionWrapper_006;
    g_wrapper_table[mba_add(idx, 6)] = (void*)_HikariFunctionWrapper_007;
    g_wrapper_table[mba_add(idx, 7)] = (void*)_HikariFunctionWrapper_008;
    
    g_wrapper_initialized = mba_one(42);
}

// Indirect call dispatcher - simulates JUMPOUT behavior
void* _HikariFunctionWrapper_GetPtr(int index) {
    volatile int safe_idx = index & 0x1F; // Mask to table size
    volatile int check = OPAQUE_TRUE_1(safe_idx);
    
    if (check) {
        return g_wrapper_table[safe_idx];
    }
    return NULL; // Never reached
}

// ============================================================================
// STRING DECRYPTION ROUTINES
// ============================================================================

void _decrypt_global_array(unsigned char* dst, unsigned char* src, size_t len, unsigned char key) {
    // CFF within decryption
    uint32_t state = 0xABCD0001;
    size_t i = 0;
    volatile int junk = 0;
    
    while (1) {
        switch (state) {
            case 0xABCD0001: // Init
                i = 0;
                junk = mba_zero(key);
                state = 0xABCD0002;
                break;
                
            case 0xABCD0002: // Loop check
                if (i < len) {
                    state = 0xABCD0003;
                } else {
                    state = 0xABCD0004;
                }
                break;
                
            case 0xABCD0003: // Decrypt byte
                dst[i] = src[i] ^ key;
                dst[i] = dst[i] ^ (unsigned char)junk; // junk is 0
                i = mba_add(i, 1);
                state = 0xABCD0002;
                break;
                
            case 0xABCD0004: // Terminate
                dst[len] = '\0';
                return;
                
            default: // Dead code
                if (OPAQUE_FALSE_1(g_opaque_var1)) {
                    abort();
                }
                state = 0xABCD0001;
                break;
        }
    }
}

// Stack string builder - constructs strings byte by byte
void _build_stack_string_1(char* buf) {
    // Builds: "Initializing..."
    volatile int offset = 0;
    
    buf[mba_add(offset, 0)] = 'I';
    buf[mba_add(offset, 1)] = 'n';
    buf[mba_add(offset, 2)] = 'i';
    buf[mba_add(offset, 3)] = 't';
    buf[mba_add(offset, 4)] = 'i';
    buf[mba_add(offset, 5)] = 'a';
    buf[mba_add(offset, 6)] = 'l';
    buf[mba_add(offset, 7)] = 'i';
    buf[mba_add(offset, 8)] = 'z';
    buf[mba_add(offset, 9)] = 'i';
    buf[mba_add(offset, 10)] = 'n';
    buf[mba_add(offset, 11)] = 'g';
    buf[mba_add(offset, 12)] = '.';
    buf[mba_add(offset, 13)] = '.';
    buf[mba_add(offset, 14)] = '.';
    buf[mba_add(offset, 15)] = '\0';
}

void _build_stack_string_2(char* buf) {
    // Builds: "Access denied" with XOR obfuscation
    // A=0x41 c=0x63 e=0x65 s=0x73 ' '=0x20 d=0x64 n=0x6E i=0x69
    unsigned char key = 0x42;
    volatile int i = 0;
    
    // XOR encrypted bytes: "Access denied" ^ 0x42
    unsigned char enc[] = {0x03, 0x21, 0x21, 0x27, 0x31, 0x31, 0x62, 0x26, 0x27, 0x2C, 0x2B, 0x27, 0x26, 0x00};
    
    while (enc[i] != 0x00) {
        buf[i] = enc[i] ^ key;
        i = mba_add(i, 1);
    }
    buf[i] = '\0';
}

void _build_stack_string_3(char* buf) {
    // Builds: "Operation completed" via indirect construction
    const char* parts[] = {"Oper", "ation", " comp", "leted"};
    int p, c;
    int pos = 0;
    
    for (p = 0; p < 4; p++) {
        for (c = 0; parts[p][c] != '\0'; c++) {
            buf[pos] = parts[p][c];
            pos = mba_add(pos, 1);
        }
    }
    buf[pos] = '\0';
}

// ============================================================================
// NESTED CONTROL FLOW FLATTENED FUNCTION (Sub-routine with own state machine)
// ============================================================================

int _processData_CFF(const char* input, char* output, int mode) {
    uint32_t substate = SUBSTATE_PARSE_INPUT;
    int result = 0;
    size_t input_len = 0;
    size_t i = 0;
    volatile int junk = mba_zero(g_opaque_var1);
    
    // Nested CFF state machine
    while (2) { // while(2) is Hikari signature
        switch (substate) {
            case SUBSTATE_PARSE_INPUT:
                input_len = _HikariFunctionWrapper_008(input);
                if (OPAQUE_TRUE_1(input_len)) {
                    substate = SUBSTATE_VALIDATE;
                } else {
                    substate = SUBSTATE_RETURN;
                    result = -1;
                }
                junk = mba_add(junk, 0);
                break;
                
            case SUBSTATE_VALIDATE:
                if (input_len > 0 && input_len < 1024) {
                    if (OPAQUE_TRUE_2(mode)) {
                        substate = SUBSTATE_TRANSFORM;
                    }
                } else {
                    result = -2;
                    substate = SUBSTATE_RETURN;
                }
                break;
                
            case SUBSTATE_TRANSFORM:
                i = 0;
                substate = SUBSTATE_ENCODE;
                break;
                
            case SUBSTATE_ENCODE:
                if (i < input_len) {
                    // ROT13-like transform with MBA
                    char c = input[i];
                    if (c >= 'a' && c <= 'z') {
                        c = 'a' + mba_sub(mba_add(c - 'a', 13), 0) % 26;
                    } else if (c >= 'A' && c <= 'Z') {
                        c = 'A' + mba_sub(mba_add(c - 'A', 13), 0) % 26;
                    }
                    output[i] = c ^ (unsigned char)junk; // junk is 0
                    i = mba_add(i, 1);
                    // Stay in ENCODE state
                } else {
                    output[i] = '\0';
                    substate = SUBSTATE_OUTPUT;
                }
                break;
                
            case SUBSTATE_OUTPUT:
                result = (int)input_len;
                substate = SUBSTATE_RETURN;
                break;
                
            case SUBSTATE_RETURN:
                return result;
                
            default:
                // Dead code with opaque predicate
                if (OPAQUE_FALSE_2(g_opaque_var1)) {
                    _HikariFunctionWrapper_002("Unreachable code executed");
                    abort();
                }
                substate = SUBSTATE_RETURN;
                result = -99;
                break;
        }
    }
    
    return result; // Never reached
}

// ============================================================================
// CONFIG LOADER WITH TRIPLE-NESTED CFF
// ============================================================================

typedef struct {
    int debug_mode;
    int network_enabled;
    int max_retries;
    char server_url[128];
    char auth_token[64];
} AppConfig;

static AppConfig g_config = {0};

int _loadConfig_CFF(const char* path) {
    uint32_t cfg_state = CFG_STATE_OPEN;
    int result = 0;
    FILE* fp = NULL;
    char line_buffer[256];
    volatile int junk = 0;
    int line_count = 0;
    
    // Decrypt path first
    _decrypt_global_array(byte_100014170, byte_100014110, 11, 0x37);
    
    while (1) {
        switch (cfg_state) {
            case CFG_STATE_OPEN:
                junk = mba_add(junk, mba_zero(42));
                fp = fopen(path, "r");
                if (fp != NULL) {
                    cfg_state = CFG_STATE_READ;
                } else {
                    // Try fallback path
                    if (OPAQUE_TRUE_1(g_opaque_var1)) {
                        fp = fopen((char*)byte_100014170, "r"); // /etc/passwd as test
                    }
                    if (fp != NULL) {
                        cfg_state = CFG_STATE_READ;
                    } else {
                        cfg_state = CFG_STATE_ERROR;
                    }
                }
                break;
                
            case CFG_STATE_READ:
                if (fgets(line_buffer, sizeof(line_buffer), fp) != NULL) {
                    line_count = mba_add(line_count, 1);
                    cfg_state = CFG_STATE_PARSE;
                } else {
                    cfg_state = CFG_STATE_VALIDATE;
                }
                break;
                
            case CFG_STATE_PARSE:
                // Simulated config parsing
                if (line_buffer[0] != '#' && line_buffer[0] != '\n') {
                    // Would parse key=value here
                    if (strncmp(line_buffer, "debug=", 6) == 0) {
                        g_config.debug_mode = atoi(line_buffer + 6);
                    }
                }
                cfg_state = CFG_STATE_READ;
                break;
                
            case CFG_STATE_VALIDATE:
                if (line_count > 0) {
                    cfg_state = CFG_STATE_APPLY;
                } else {
                    cfg_state = CFG_STATE_ERROR;
                }
                break;
                
            case CFG_STATE_APPLY:
                // Apply defaults with MBA
                g_config.max_retries = mba_add(3, mba_zero(g_opaque_var1));
                g_config.network_enabled = mba_one(42);
                cfg_state = CFG_STATE_CLOSE;
                break;
                
            case CFG_STATE_CLOSE:
                if (fp != NULL) {
                    fclose(fp);
                    fp = NULL;
                }
                cfg_state = CFG_STATE_DONE;
                break;
                
            case CFG_STATE_ERROR:
                result = -1;
                if (fp != NULL) {
                    fclose(fp);
                }
                cfg_state = CFG_STATE_DONE;
                break;
                
            case CFG_STATE_DONE:
                return result;
                
            default:
                if (OPAQUE_FALSE_1(line_count)) {
                    goto error_label; // Never taken
                }
                cfg_state = CFG_STATE_ERROR;
                break;
        }
    }
    
error_label:
    return -99; // Never reached
}

// ============================================================================
// NETWORK CHECK WITH INDIRECT FUNCTION CALLS
// ============================================================================

int _checkNetwork_CFF(void) {
    uint32_t state = 0x11110001;
    int result = 0;
    char url_buffer[128] = {0};
    volatile int iterations = 0;
    wrapper_func_str_t log_func;
    
    while (1) {
        switch (state) {
            case 0x11110001: // Decrypt URL
                _decrypt_global_array(byte_100014480, byte_100014400, 29, 0x1F);
                state = 0x11110002;
                break;
                
            case 0x11110002: // Copy to buffer
                _HikariFunctionWrapper_007(url_buffer, byte_100014480, 29);
                state = 0x11110003;
                break;
                
            case 0x11110003: // Get log function indirectly
                log_func = (wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(0);
                if (log_func != NULL && OPAQUE_TRUE_3(g_opaque_var2)) {
                    state = 0x11110004;
                } else {
                    state = 0x11110006;
                }
                break;
                
            case 0x11110004: // Log attempt
                log_func("Checking network connectivity...");
                iterations = mba_add(iterations, 1);
                state = 0x11110005;
                break;
                
            case 0x11110005: // Simulate check
                // Would do actual network check here
                if (OPAQUE_TRUE_2(iterations)) {
                    result = 1; // Success
                    state = 0x11110006;
                } else {
                    if (iterations < g_config.max_retries) {
                        state = 0x11110004;
                    } else {
                        result = 0;
                        state = 0x11110006;
                    }
                }
                break;
                
            case 0x11110006: // Return
                return result;
                
            default:
                // Bogus control flow
                if (OPAQUE_FALSE_2(state)) {
                    state = 0x11110001;
                } else {
                    state = 0x11110006;
                    result = -1;
                }
                break;
        }
    }
}

// ============================================================================
// CLEANUP ROUTINE (Mirrors original _cleanupSystem analysis)
// ============================================================================

int _cleanupSystem_CFF(int force) {
    uint32_t dispatch_key = STATE_INIT;
    uint64_t combined_state = 0; // HIDWORD/LODWORD access pattern
    int result = 0;
    int confirmed = 0;
    char msg_buffer[128] = {0};
    char cmd_buffer[128] = {0};
    char input_buffer[16] = {0};
    volatile int junk_math = 0;
    
    // Simulate HIDWORD(v286) access pattern
    #define HIDWORD(x) ((uint32_t)((x) >> 32))
    #define LODWORD(x) ((uint32_t)(x))
    
    combined_state = ((uint64_t)STATE_INIT << 32) | 0;
    
    while (2) { // Hikari signature
        switch (HIDWORD(combined_state)) {
            case STATE_INIT:
                _HikariFunctionWrapper_InitTable();
                junk_math = (junk_math ^ 0x1234) + 1;
                combined_state = ((uint64_t)STATE_CHECK_ENV << 32) | junk_math;
                break;
                
            case STATE_CHECK_ENV:
                // Build stack string for message
                _build_stack_string_1(msg_buffer);
                ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(0))(msg_buffer);
                
                junk_math = mba_add(junk_math, mba_zero(42));
                combined_state = ((uint64_t)STATE_VALIDATE_ARGS << 32) | junk_math;
                break;
                
            case STATE_VALIDATE_ARGS:
                // Check root privileges (mirrors original)
                {
                    int uid = _HikariFunctionWrapper_003();
                    if (uid != 0) {
                        _build_stack_string_2(msg_buffer); // "Access denied"
                        ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(1))(msg_buffer);
                        combined_state = ((uint64_t)STATE_EXIT_FAILURE << 32) | 0;
                    } else {
                        combined_state = ((uint64_t)STATE_LOAD_CONFIG << 32) | 1;
                    }
                }
                break;
                
            case STATE_LOAD_CONFIG:
                result = _loadConfig_CFF("/etc/app.conf");
                if (result == 0 || OPAQUE_TRUE_1(force)) {
                    combined_state = ((uint64_t)STATE_DECRYPT_STRINGS << 32) | result;
                } else {
                    combined_state = ((uint64_t)STATE_ERROR_HANDLER << 32) | result;
                }
                break;
                
            case STATE_DECRYPT_STRINGS:
                // Decrypt all global strings
                _decrypt_global_array(byte_100014280, byte_100014200, 33, 0x4C);
                _decrypt_global_array(byte_100014380, byte_100014300, 24, 0x5A);
                _decrypt_global_array(byte_100014580, byte_100014500, 19, 0x23);
                
                combined_state = ((uint64_t)STATE_CHECK_NETWORK << 32) | 0;
                break;
                
            case STATE_CHECK_NETWORK:
                if (g_config.network_enabled) {
                    result = _checkNetwork_CFF();
                    if (result <= 0) {
                        ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(1))("Network check failed");
                    }
                }
                combined_state = ((uint64_t)STATE_PROCESS_DATA << 32) | result;
                break;
                
            case STATE_PROCESS_DATA:
                // User confirmation (mirrors original scanf pattern)
                if (!force) {
                    printf("This will perform cleanup. Are you sure? (y/n): ");
                    if (scanf("%1s", input_buffer) == 1) {
                        if (input_buffer[0] == 'y' || input_buffer[0] == 'Y') {
                            confirmed = 1;
                        }
                    }
                } else {
                    confirmed = 1;
                }
                
                if (confirmed) {
                    combined_state = ((uint64_t)STATE_NESTED_DISPATCH << 32) | 1;
                } else {
                    combined_state = ((uint64_t)STATE_EXIT_FAILURE << 32) | 0;
                }
                break;
                
            case STATE_NESTED_DISPATCH:
                // Nested state machine for actual processing
                {
                    char test_input[] = "TestInput";
                    char test_output[64] = {0};
                    int proc_result = _processData_CFF(test_input, test_output, 1);
                    
                    if (proc_result > 0) {
                        _build_stack_string_3(msg_buffer);
                        ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(0))(msg_buffer);
                    }
                }
                combined_state = ((uint64_t)STATE_CLEANUP << 32) | 0;
                break;
                
            case STATE_CLEANUP:
                // Execute cleanup commands
                ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(0))((char*)byte_100014280);
                _HikariFunctionWrapper_005((char*)byte_100014380);
                
                combined_state = ((uint64_t)STATE_EXIT_SUCCESS << 32) | 0;
                break;
                
            case STATE_ERROR_HANDLER:
                ((wrapper_func_str_t)_HikariFunctionWrapper_GetPtr(1))("Error occurred during execution");
                result = -1;
                combined_state = ((uint64_t)STATE_EXIT_FAILURE << 32) | result;
                break;
                
            case STATE_EXIT_SUCCESS:
                result = 0;
                return result;
                
            case STATE_EXIT_FAILURE:
                return result != 0 ? result : -1;
                
            // Dead code blocks
            case STATE_DEAD_1:
                if (OPAQUE_FALSE_1(g_opaque_var1)) {
                    combined_state = ((uint64_t)STATE_INIT << 32) | 0;
                }
                break;
                
            case STATE_DEAD_2:
                junk_math = mba_add(junk_math, 0xDEADBEEF);
                // Indirect jump simulation - but still need valid exit
                {
                    volatile void* target = &&dead_label;
                    goto *target;
                }
dead_label:
                // Dead code that looks reachable but transitions to exit
                combined_state = ((uint64_t)STATE_EXIT_FAILURE << 32) | -99;
                break;
                
            case STATE_DEAD_3:
                _HikariFunctionWrapper_002("This code path is unreachable");
                abort();
                break;
                
            default:
                // JUMPOUT simulation - computed goto
                if (OPAQUE_TRUE_4(g_opaque_var1, g_opaque_var2)) {
                    combined_state = ((uint64_t)STATE_EXIT_FAILURE << 32) | -99;
                }
                break;
        }
    }
    
    #undef HIDWORD
    #undef LODWORD
    
    return result; // Never reached due to while(2)
}

// ============================================================================
// ADDITIONAL OBFUSCATED UTILITY FUNCTIONS
// ============================================================================

// Obfuscated checksum calculation
uint32_t _calculateChecksum_CFF(const unsigned char* data, size_t len) {
    uint32_t state = 0xCCCC0001;
    uint32_t checksum = 0;
    size_t i = 0;
    volatile int junk = 0;
    
    while (1) {
        switch (state) {
            case 0xCCCC0001:
                checksum = 0xFFFFFFFF;
                i = 0;
                state = 0xCCCC0002;
                break;
                
            case 0xCCCC0002:
                if (i < len) {
                    state = 0xCCCC0003;
                } else {
                    state = 0xCCCC0004;
                }
                break;
                
            case 0xCCCC0003:
                // CRC32-like update with MBA
                {
                    uint32_t byte_val = data[i];
                    checksum = mba_add(checksum, byte_val);
                    checksum = checksum ^ (checksum << 5);
                    checksum = mba_sub(checksum, (checksum >> 3) & 0xFF);
                    junk = mba_add(junk, mba_zero(byte_val));
                }
                i = mba_add(i, 1);
                state = 0xCCCC0002;
                break;
                
            case 0xCCCC0004:
                checksum = checksum ^ 0xFFFFFFFF;
                checksum = mba_add(checksum, junk); // junk is 0
                return checksum;
                
            default:
                if (OPAQUE_FALSE_2(state)) {
                    return 0xDEADDEAD;
                }
                state = 0xCCCC0004;
                break;
        }
    }
}

// Obfuscated memory comparison
int _secureMemcmp_CFF(const void* a, const void* b, size_t n) {
    uint32_t state = 0xDDDD0001;
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    int result = 0;
    size_t i = 0;
    volatile int accumulator = 0;
    
    while (1) {
        switch (state) {
            case 0xDDDD0001:
                i = 0;
                accumulator = 0;
                state = 0xDDDD0002;
                break;
                
            case 0xDDDD0002:
                if (i < n) {
                    state = 0xDDDD0003;
                } else {
                    state = 0xDDDD0004;
                }
                break;
                
            case 0xDDDD0003:
                // Constant-time comparison via OR accumulation
                accumulator = accumulator | (pa[i] ^ pb[i]);
                i = mba_add(i, 1);
                state = 0xDDDD0002;
                break;
                
            case 0xDDDD0004:
                result = (accumulator != 0) ? 1 : 0;
                return result;
                
            default:
                state = 0xDDDD0004;
                break;
        }
    }
}

// ============================================================================
// MAIN ENTRY POINT WITH CFF
// ============================================================================

int main(int argc, char* argv[]) {
    uint32_t main_state = 0xAAAA0001;
    int exit_code = 0;
    int force_mode = 0;
    volatile int junk = 0;
    char banner[64] = {0};
    
    while (1) {
        switch (main_state) {
            case 0xAAAA0001: // Banner construction
                // Build banner byte by byte
                banner[0] = '='; banner[1] = '='; banner[2] = '=';
                banner[3] = ' '; banner[4] = 'H'; banner[5] = 'i';
                banner[6] = 'k'; banner[7] = 'a'; banner[8] = 'r';
                banner[9] = 'i'; banner[10] = ' '; banner[11] = 'T';
                banner[12] = 'e'; banner[13] = 's'; banner[14] = 't';
                banner[15] = ' '; banner[16] = '='; banner[17] = '=';
                banner[18] = '='; banner[19] = '\0';
                
                printf("%s\n", banner);
                fflush(stdout);
                main_state = 0xAAAA0002;
                break;
                
            case 0xAAAA0002: // Parse arguments
                if (argc > 1) {
                    if (_HikariFunctionWrapper_006(argv[1], "-f") == 0 ||
                        _HikariFunctionWrapper_006(argv[1], "--force") == 0) {
                        force_mode = 1;
                    }
                }
                junk = mba_add(junk, argc);
                main_state = 0xAAAA0003;
                break;
                
            case 0xAAAA0003: // Initialize wrappers
                _HikariFunctionWrapper_InitTable();
                main_state = 0xAAAA0004;
                break;
                
            case 0xAAAA0004: // Run main logic
                exit_code = _cleanupSystem_CFF(force_mode);
                main_state = 0xAAAA0005;
                break;
                
            case 0xAAAA0005: // Checksum test
                {
                    unsigned char test_data[] = "Test data for checksum";
                    uint32_t chk = _calculateChecksum_CFF(test_data, sizeof(test_data) - 1);
                    printf("Checksum: 0x%08X\n", chk);
                }
                main_state = 0xAAAA0006;
                break;
                
            case 0xAAAA0006: // Memory compare test
                {
                    char buf1[] = "TestString";
                    char buf2[] = "TestString";
                    int cmp = _secureMemcmp_CFF(buf1, buf2, 10);
                    printf("Compare result: %d\n", cmp);
                }
                main_state = 0xAAAA0007;
                break;
                
            case 0xAAAA0007: // Exit
                printf("Exit code: %d\n", exit_code);
                return exit_code;
                
            default:
                if (OPAQUE_FALSE_1(main_state)) {
                    main_state = 0xAAAA0001;
                } else {
                    return -99;
                }
                break;
        }
    }
    
    return exit_code; // Never reached
}

// ============================================================================
// ADDITIONAL PATTERNS FOR DEOBFUSCATOR TESTING
// ============================================================================

/*
 * Test cases this program covers:
 * 
 * 1. CFF Patterns:
 *    - while(1)/while(2) + switch dispatcher
 *    - HIDWORD/LODWORD state encoding
 *    - Nested state machines (3 levels deep)
 *    - State transitions via computed values
 *    - Multiple entry/exit points per function
 * 
 * 2. String Encryption:
 *    - Global XOR arrays with runtime decryption
 *    - Stack strings built byte-by-byte
 *    - Part-based string concatenation
 *    - Mixed encryption keys
 * 
 * 3. Function Obfuscation:
 *    - Wrapper functions hiding actual calls
 *    - Function pointer tables
 *    - Indirect calls via dispatcher
 *    - JUMPOUT-equivalent patterns
 * 
 * 4. Bogus Control Flow:
 *    - Opaque predicates (always true/false)
 *    - Dead code blocks
 *    - Unreachable states
 *    - Computed gotos
 * 
 * 5. Instruction Substitution:
 *    - MBA (Mixed Boolean Arithmetic)
 *    - Obfuscated add/sub/mul
 *    - Obfuscated comparisons
 *    - Complex boolean expressions
 * 
 * 6. Data Flow Obfuscation:
 *    - Junk variable accumulation
 *    - Interleaved real/fake computations
 *    - Register pressure simulation
 * 
 * Expected deobfuscator capabilities to test:
 *    - CFF reconstruction → proper if/else/loop recovery
 *    - String recovery → extract all encrypted strings
 *    - Call graph recovery → resolve wrapper indirection
 *    - Dead code elimination → remove opaque predicates
 *    - MBA simplification → recover original arithmetic
 *    - Constant propagation → simplify computed states
 */