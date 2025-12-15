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
// Example:
//   *(&savedregs - 133) = "countByEnumeratingWithState:objects:count:";
//   *(&savedregs - 132) = &objc_msgSend;
//   v153 = (*(&savedregs - 132))(..., *(&savedregs - 133), ...);
//
// Approach:
//   1. Track all writes to stack slots
//   2. When encountering indirect call through stack, resolve the target
//   3. Propagate known values through the function
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
