#pragma once
#include "../deobf_types.h"
#include "../analysis/stack_tracker.h"

//--------------------------------------------------------------------------
// SavedRegs Pattern Handler
//
// Handles "Register Demotion" / Stack Spilling obfuscation where:
//   - Arguments/values normally in registers are forced to stack
//   - Indirect calls use stack slots: *(&savedregs - N)(args)
//   - Function pointers stored on stack before being called
//   - Selector strings stored on stack for ObjC calls
//
// Example patterns:
//   *(&savedregs - 133) = "countByEnumeratingWithState:objects:count:";
//   *(&savedregs - 132) = &objc_msgSend;
//   v153 = (*(&savedregs - 132))(..., *(&savedregs - 133), ...);
//
// Resolution approach:
//   1. Analyze all writes to savedregs slots
//   2. Track function pointers and strings
//   3. Resolve indirect calls through savedregs
//   4. Annotate calls with resolved targets and selectors
//--------------------------------------------------------------------------
class savedregs_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main processing
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Per-instruction simplification (called from optinsn_t)
    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

private:
    // Resolved call information
    struct resolved_call_t {
        ea_t call_addr;             // Address of the call instruction
        ea_t target_func;           // Resolved function target
        qstring target_name;        // Name of target function
        qstring selector;           // ObjC selector (if applicable)
        std::vector<qstring> args;  // String arguments from savedregs
        bool is_objc;               // True if this is an ObjC call
    };

    // Slot classification
    enum slot_type_t {
        SLOT_UNKNOWN,
        SLOT_FUNC_PTR,      // Function pointer
        SLOT_SELECTOR,      // ObjC selector string
        SLOT_STRING,        // Other string
        SLOT_VALUE,         // Numeric value
        SLOT_OBJECT,        // Object pointer
    };

    struct slot_info_ext_t {
        sval_t offset;
        slot_type_t type;
        ea_t func_addr;         // For SLOT_FUNC_PTR
        qstring string_val;     // For SLOT_STRING/SLOT_SELECTOR
        uint64_t value;         // For SLOT_VALUE
        bool is_objc_msgsend;   // True if func is objc_msgSend variant
    };

    // Analysis functions
    static void analyze_savedregs_writes(mbl_array_t *mba,
                                         std::map<sval_t, slot_info_ext_t> &slots);

    static bool is_savedregs_ref(const mop_t &op, sval_t *out_offset);

    static slot_type_t classify_value(ea_t addr);

    static bool is_objc_msgsend(ea_t addr);

    // Call resolution
    static bool resolve_indirect_call(mblock_t *blk, minsn_t *call_insn,
                                     const std::map<sval_t, slot_info_ext_t> &slots,
                                     resolved_call_t *out);

    static bool extract_call_args(minsn_t *call_insn,
                                 const std::map<sval_t, slot_info_ext_t> &slots,
                                 resolved_call_t *out);

    // Transformation
    static bool transform_call(mblock_t *blk, minsn_t *call_insn,
                              const resolved_call_t &resolved);

    // Annotation
    static void annotate_call(ea_t call_addr, const resolved_call_t &resolved);

    // ObjC specific
    static qstring format_objc_call(const resolved_call_t &resolved);
};
