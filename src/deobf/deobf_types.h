#pragma once
#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <ua.hpp>
#include "../common/warn_on.h"

#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <functional>
#include <optional>
#include <memory>
#include <algorithm>
#include <cstdarg>

// Forward declarations
struct deobf_ctx_t;
class mblock_visitor_t;

//--------------------------------------------------------------------------
// Obfuscation detection flags
//--------------------------------------------------------------------------
enum obf_type_t : uint32_t {
    OBF_NONE            = 0,
    OBF_FLATTENED       = 1U << 0,   // Control flow flattening
    OBF_BOGUS_CF        = 1U << 1,   // Bogus control flow
    OBF_STRING_ENC      = 1U << 2,   // String encryption
    OBF_CONST_ENC       = 1U << 3,   // Constant encryption
    OBF_INDIRECT_BR     = 1U << 4,   // Indirect branches
    OBF_SUBSTITUTION    = 1U << 5,   // Instruction substitution (legacy, now MBA)
    OBF_SPLIT_BLOCKS    = 1U << 6,   // Split basic blocks
    OBF_FUNC_WRAPPER    = 1U << 7,   // Hikari function wrappers
    OBF_IDENTITY_CALL   = 1U << 8,   // Identity function indirect calls
    OBF_STACK_STRING    = 1U << 9,   // Stack string construction
    OBF_SAVEDREGS       = 1U << 10,  // Register demotion (savedregs patterns)
    OBF_OBJC_OBFUSC     = 1U << 11,  // Obfuscated ObjC method calls
    OBF_GLOBAL_CONST    = 1U << 12,  // Global constants that can be inlined
    OBF_PTR_INDIRECT    = 1U << 13,  // Indirect pointer references (off_XXXX -> symbol)
    OBF_MBA_COMPLEX     = 1U << 14,  // Complex MBA expressions (Mixed Boolean-Arithmetic)
    OBF_CHAIN_OPS       = 1U << 15,  // Chained XOR/AND/OR/ADD operations
    OBF_OPAQUE_JUMP     = 1U << 16,  // Opaque predicate jumps
    OBF_CONST_OBFUSC    = 1U << 17,  // Obfuscated constants (detectable via Z3)
    OBF_INDIRECT_CALL   = 1U << 18,  // Indirect call obfuscation (Hikari IndirectCall)
    OBF_VM_MBA          = 1U << 19,  // Opt-in VM-family MBA handlers
    OBF_SELECT_CHAIN    = 1U << 20,  // Long compiler-lowered select/cmov chains
};

//--------------------------------------------------------------------------
// Deobfuscation context - maintains state during analysis
//--------------------------------------------------------------------------
struct deobf_ctx_t {
    mbl_array_t *mba;           // Microcode block array
    cfunc_t *cfunc;             // Current function being analyzed
    ea_t func_ea;               // Function entry address

    uint32_t detected_obf;      // Bitmap of detected obfuscations

    // String encryption
    std::map<ea_t, std::string> decrypted_strings;

    // Constant encryption
    std::map<ea_t, uint64_t> decrypted_consts;

    // Statistics
    int blocks_merged;
    int branches_simplified;
    int strings_decrypted;
    int consts_decrypted;
    int expressions_simplified;
    int indirect_resolved;

    // MBA simplification statistics
    int mba_simplified;           // MBA expressions simplified
    int chains_simplified;        // Chain operations simplified
    int opaque_jumps_resolved;    // Opaque predicate jumps resolved
    int z3_consts_recovered;      // Constants recovered via Z3
    int peephole_opts;            // Peephole optimizations applied

    deobf_ctx_t()
        : mba(nullptr), cfunc(nullptr), func_ea(BADADDR),
          detected_obf(OBF_NONE),
          blocks_merged(0), branches_simplified(0), strings_decrypted(0),
          consts_decrypted(0), expressions_simplified(0), indirect_resolved(0),
          mba_simplified(0), chains_simplified(0), opaque_jumps_resolved(0),
          z3_consts_recovered(0), peephole_opts(0)
    {}
};

//--------------------------------------------------------------------------
// Utility functions declarations
//--------------------------------------------------------------------------
namespace deobf {
    // Logging
    void log(const char *fmt, ...);
    void log_verbose(const char *fmt, ...);
    void set_verbose(bool v);
    bool debug_enabled();
    void debug_vlog(const char *path, const char *fmt, va_list va);

    // Microcode helpers
    bool is_jcc(mcode_t op);
}
