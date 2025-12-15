#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// ObjC Message Send Resolver
//
// Handles obfuscated Objective-C method calls:
//   - Indirect objc_msgSend calls through stack/registers
//   - Encrypted or split selector strings
//   - Wrapped objc_msgSend calls (through wrapper functions)
//   - sel_registerName / sel_getUid patterns
//   - NSSelectorFromString patterns
//
// Example patterns:
//   1. Direct obfuscation:
//      *(&savedregs - 132) = &objc_msgSend;
//      *(&savedregs - 133) = "doSomething:";
//      (*(&savedregs - 132))(obj, *(&savedregs - 133), arg);
//
//   2. Dynamic selector lookup:
//      sel = sel_registerName("methodName");
//      objc_msgSend(obj, sel, args);
//
//   3. Wrapper function:
//      HikariFunctionWrapper_1234(obj, selector, args);
//      // where wrapper just calls objc_msgSend
//
// Resolution approach:
//   1. Identify objc_msgSend call sites (direct and indirect)
//   2. Trace selector argument to find string value
//   3. Trace receiver to identify class if possible
//   4. Annotate with resolved method signature
//--------------------------------------------------------------------------
class objc_resolve_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main processing
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Check if a function is objc_msgSend variant
    static bool is_objc_msgsend(ea_t func_addr);
    static bool is_objc_msgsend(const char *name);

    // Get selector string from various sources
    static bool get_selector_string(mbl_array_t *mba, const mop_t &sel_op,
                                   qstring *out_selector);

private:
    // Resolved ObjC call information
    struct objc_call_info_t {
        ea_t call_addr;             // Address of the call
        ea_t msgsend_addr;          // Address of objc_msgSend variant
        qstring msgsend_variant;    // Which variant (msgSend, msgSendSuper, etc)
        qstring selector;           // Resolved selector string
        qstring receiver_class;     // Receiver class name (if determinable)
        bool is_class_method;       // True if class method (+), false if instance (-)
        bool is_super_call;         // True if msgSendSuper
        bool is_stret;              // True if returns struct (msgSend_stret)
    };

    // objc_msgSend variants
    enum msgsend_variant_t {
        MSGSEND_UNKNOWN,
        MSGSEND_NORMAL,         // objc_msgSend
        MSGSEND_SUPER,          // objc_msgSendSuper
        MSGSEND_SUPER2,         // objc_msgSendSuper2
        MSGSEND_STRET,          // objc_msgSend_stret
        MSGSEND_FPRET,          // objc_msgSend_fpret
        MSGSEND_FP2RET,         // objc_msgSend_fp2ret
    };

    // Analysis functions
    static msgsend_variant_t classify_msgsend(ea_t addr);
    static msgsend_variant_t classify_msgsend(const char *name);

    // Find all objc_msgSend calls (direct and indirect)
    static void find_msgsend_calls(mbl_array_t *mba,
                                  std::vector<std::pair<mblock_t*, minsn_t*>> &calls);

    // Resolve a single objc_msgSend call
    static bool resolve_msgsend_call(mbl_array_t *mba, mblock_t *blk,
                                    minsn_t *call_insn,
                                    objc_call_info_t *out);

    // Trace selector argument
    static bool trace_selector(mbl_array_t *mba, mblock_t *blk,
                              minsn_t *call_insn,
                              qstring *out_selector);

    // Get selector from sel_registerName / sel_getUid call
    static bool get_selector_from_registration(mbl_array_t *mba,
                                              const mop_t &op,
                                              qstring *out);

    // Get selector from NSSelectorFromString call
    static bool get_selector_from_nsselector(mbl_array_t *mba,
                                            const mop_t &op,
                                            qstring *out);

    // Trace receiver to find class
    static bool trace_receiver_class(mbl_array_t *mba, mblock_t *blk,
                                    minsn_t *call_insn,
                                    qstring *out_class);

    // Check if receiver is a class object (for class methods)
    static bool is_class_object(mbl_array_t *mba, const mop_t &receiver,
                               qstring *out_class);

    // Annotation
    static void annotate_objc_call(ea_t call_addr, const objc_call_info_t &info);

    // Format method signature
    static qstring format_method_signature(const objc_call_info_t &info);
};
