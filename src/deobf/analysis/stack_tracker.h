#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Virtual Stack Tracker
//
// Handles "Register Demotion" / Stack Spilling obfuscation where:
//   - Arguments/values normally in registers are forced to stack
//   - Indirect calls use stack slots: *(&savedregs - 132)(args)
//   - Function pointers stored on stack before being called
//
// Also handles "Frameless Continuation" obfuscation where:
//   - Obfuscated code jumps (not calls) to trampoline functions
//   - Trampolines don't set up their own stack frame
//   - They access caller's stack via unchanged RBP/frame pointer
//   - Common pattern: jmp to external code that uses [rbp+X] to compute next jump
//
// Example:
//   *(&savedregs - 133) = "countByEnumeratingWithState:objects:count:";
//   *(&savedregs - 132) = &objc_msgSend;
//   v153 = (*(&savedregs - 132))(..., *(&savedregs - 133), ...);
//
// Approach:
//   1. Track all writes to stack slots
//   2. When encountering indirect call through stack, resolve the target
//   3. Propagate known values through the function
//   4. For cross-function jumps, propagate caller context to callee
//--------------------------------------------------------------------------
class stack_tracker_t {
public:
    // Initialize for a function
    static void init(mbl_array_t *mba);

    // Clear tracked state
    static void clear();

    // Track a write to stack slot
    static void track_write(sval_t offset, uint64_t value, int size);
    static void track_write(sval_t offset, ea_t addr);  // For addresses
    static void track_write_string(sval_t offset, const char *str);

    // Read from stack slot
    static std::optional<uint64_t> read_value(sval_t offset, int size);
    static std::optional<ea_t> read_address(sval_t offset);
    static std::optional<std::string> read_string(sval_t offset);

    // Check if slot has known value
    static bool is_known(sval_t offset);

    // Resolve indirect call through stack
    // Returns: resolved function address, or BADADDR
    static ea_t resolve_stack_call(minsn_t *call_insn, mbl_array_t *mba);

    // Analyze a block and track all stack writes
    static void analyze_block(mblock_t *blk);

    // Analyze entire function
    static void analyze_function(mbl_array_t *mba);

    // Get info about a stack slot for annotation
    struct slot_info_t {
        sval_t offset;
        enum { VALUE, ADDRESS, STRING, UNKNOWN } type;
        uint64_t value;
        ea_t address;
        std::string string_val;
    };
    static std::optional<slot_info_t> get_slot_info(sval_t offset);

private:
    // Stack slot storage
    struct stack_slot_t {
        bool has_value;
        bool is_address;
        bool is_string;
        uint64_t value;
        ea_t address;
        std::string string_val;
        int size;
        ea_t write_addr;    // Where the write occurred
    };

    static std::map<sval_t, stack_slot_t> s_slots;
    static mbl_array_t *s_mba;

    // Extract value from mop
    static std::optional<uint64_t> get_mop_value(const mop_t &op);

    // Check if mop is a stack reference
    static bool is_stack_ref(const mop_t &op, sval_t *out_offset);

    // Trace back to find the value written to a register
    static std::optional<uint64_t> trace_register_value(mblock_t *blk, int reg, minsn_t *before);
};

//--------------------------------------------------------------------------
// Cross-Function Context Tracker
//
// Handles "frameless continuation" patterns where:
//   - Function A jumps (not calls) to Function B
//   - Function B doesn't set up its own frame (no push rbp; mov rbp, rsp)
//   - Function B accesses [rbp+X] which are actually A's stack slots
//   - Common in Hikari XOR-encrypted jump obfuscation
//
// Pattern example:
//   Function A:
//     mov [rbp-0x350], table_ptr   ; Store dispatch table
//     mov [rbp-0x4A8], index       ; Store index
//     jmp sub_100634814            ; Jump to continuation
//
//   Function B (sub_100634814):
//     mov rax, [rbp-0x7E0]         ; Access A's stack!
//     mov rdx, [rbp-0x4A8]         ; Access A's index!
//     ... compute target ...
//     jmp rcx                      ; Jump to computed target
//
// Solution:
//   1. When A jumps to B, capture A's stack state
//   2. When analyzing B, use A's context for [rbp+X] accesses
//   3. Resolve B's indirect jump using A's stack values
//--------------------------------------------------------------------------

// Context passed from caller to callee for frameless continuations
struct caller_context_t {
    ea_t caller_func;           // Caller function address
    ea_t callee_func;           // Callee (continuation) function address
    ea_t jump_site;             // Address where the jump occurs
    
    // Stack state from caller - maps RBP-relative offset to value
    std::map<sval_t, uint64_t> stack_values;
    
    // Register state at jump site
    std::map<int, uint64_t> register_values;
    
    // Global variable values (for XOR key resolution)
    std::map<ea_t, uint64_t> global_values;
    
    caller_context_t() : caller_func(BADADDR), callee_func(BADADDR), jump_site(BADADDR) {}
    
    bool has_stack_value(sval_t offset) const {
        return stack_values.find(offset) != stack_values.end();
    }
    
    std::optional<uint64_t> get_stack_value(sval_t offset) const {
        auto it = stack_values.find(offset);
        if (it != stack_values.end())
            return it->second;
        return std::nullopt;
    }
    
    std::optional<uint64_t> get_register_value(int reg) const {
        auto it = register_values.find(reg);
        if (it != register_values.end())
            return it->second;
        return std::nullopt;
    }
    
    std::optional<uint64_t> get_global_value(ea_t addr) const {
        auto it = global_values.find(addr);
        if (it != global_values.end())
            return it->second;
        return std::nullopt;
    }
};

//--------------------------------------------------------------------------
// Frameless Continuation Analyzer
//
// Detects and resolves indirect jumps in frameless continuations
// that use the caller's stack frame.
//--------------------------------------------------------------------------
class frameless_continuation_t {
public:
    // Check if a function appears to be a frameless continuation
    // (doesn't set up its own frame, uses deep RBP offsets)
    static bool is_frameless_continuation(ea_t func_ea);
    
    // Build caller context from a function before it jumps to continuation
    static caller_context_t build_caller_context(mbl_array_t *mba, mblock_t *jump_block);
    
    // Resolve indirect jump in continuation using caller's context
    // Returns: resolved target address, or BADADDR if cannot resolve
    static ea_t resolve_continuation_jump(ea_t continuation_ea, const caller_context_t &ctx);
    
    // Cache of analyzed continuations: continuation_ea -> resolved_target
    static std::map<ea_t, ea_t> s_resolution_cache;
    
    // Cache of caller contexts: caller_func -> context
    static std::map<ea_t, caller_context_t> s_context_cache;
    
    // Clear caches
    static void clear_caches();
    
private:
    // Analyze native code at addr to detect frameless pattern
    static bool analyze_prologue(ea_t func_ea);
    
    // Execute continuation code symbolically with caller's context
    static ea_t symbolic_execute(ea_t start_ea, const caller_context_t &ctx, int max_insns = 50);
    
    // Read a value from RBP-relative offset using caller context
    static std::optional<uint64_t> read_rbp_relative(sval_t offset, const caller_context_t &ctx);
    
    // Read a global variable value (with caching)
    static std::optional<uint64_t> read_global(ea_t addr, int size = 4);
};
