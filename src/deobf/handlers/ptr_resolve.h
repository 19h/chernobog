#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Pointer Reference Resolution Handler
//
// Resolves indirect pointer references to their actual targets.
// This is common in ObjC code where class references go through an
// indirection table.
//
// Example:
//   v164 = &off_1000102A8;   ; where off_1000102A8 -> _OBJC_CLASS_$_NSArray
// The decompiler shows this as an opaque pointer, but we can resolve it
// to show the actual class being referenced.
//
// Pattern:
//   __objc_classrefs:00000001000102A8 off_1000102A8 dq offset _OBJC_CLASS_$_NSConstantArray
//
// This handler:
//   1. Finds references to pointer globals (off_XXXX pattern)
//   2. Reads the pointer value
//   3. Resolves to the target symbol
//   4. Annotates or replaces the reference
//--------------------------------------------------------------------------
class ptr_resolve_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    struct ptr_ref_t {
        minsn_t *insn;          // Instruction using the pointer
        mop_t *ptr_mop;         // The pointer operand
        ea_t ptr_addr;          // Address of the pointer variable (e.g., off_XXXX)
        ea_t target_addr;       // What the pointer points to
        qstring ptr_name;       // Name of the pointer (off_XXXX)
        qstring target_name;    // Name of the target (_OBJC_CLASS_$_...)
        bool is_objc_class;     // Is this an ObjC class reference?
        qstring class_name;     // Extracted class name (without prefix)
    };

    // Find all indirect pointer references
    static std::vector<ptr_ref_t> find_ptr_refs(mbl_array_t *mba);

    // Check if an operand is an indirect pointer reference
    static bool is_indirect_ptr_ref(const mop_t &op, ptr_ref_t *out);

    // Resolve the target of a pointer
    static bool resolve_ptr_target(ea_t ptr_addr, ptr_ref_t *out);

    // Check if address is in ObjC reference sections
    static bool is_objc_ref_section(ea_t addr);

    // Extract class name from ObjC symbol
    static bool extract_objc_class_name(const char *symbol, qstring *out_class);

    // Annotate the resolved reference
    static void annotate_ptr_ref(const ptr_ref_t &ref);

    // Replace indirect reference with direct reference (where possible)
    static int replace_ptr_ref(mblock_t *blk, minsn_t *ins, const ptr_ref_t &ref);
};
