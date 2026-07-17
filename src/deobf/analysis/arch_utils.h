#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Architecture Abstraction Layer
//
// This module provides architecture-independent utilities for analyzing
// native code patterns. It abstracts away differences between x86-64 and
// ARM64 (AArch64) architectures.
//
// Key abstractions:
//   - Register roles (first argument and return value)
//   - Instruction type classification (mov, branch, call, return)
//   - Pattern detection (identity functions, trampolines, indirect jumps)
//   - Calling convention awareness
//--------------------------------------------------------------------------

namespace arch {

// Convenience checks
bool is_x86();          // x86 or x86-64
bool is_x86_64();       // 64-bit x86 only
bool is_arm();          // ARM32 or ARM64
bool is_arm64();        // 64-bit ARM only
bool is_64bit();        // Any 64-bit architecture

//--------------------------------------------------------------------------
// Register role abstraction
// These functions return the native register number for each role
//--------------------------------------------------------------------------

// First function argument register
// x86-64 System V: RDI (7)
// x86-64 Windows:  RCX (1)
// ARM64:           X0 (0)
int get_first_arg_reg();

// Return value register
// x86-64: RAX (0)
// ARM64:  X0 (0)
int get_return_reg();

//--------------------------------------------------------------------------
// Instruction type classification
// These functions check native instruction types (insn_t.itype)
//--------------------------------------------------------------------------

// Check if instruction is a direct call
// x86: NN_call (call rel32)
// ARM64: ARM_bl (BL label)
bool is_direct_call(uint16_t itype);

// Check if instruction is an indirect call (call via register)
// x86: NN_callni (call rax, call [mem])
// ARM64: ARM_blr (BLR Xn)
bool is_indirect_call(uint16_t itype);

// Check if instruction is any call (direct or indirect)
bool is_call_insn(uint16_t itype);

// Check if instruction is a return
// x86: NN_retn, NN_retf
// ARM64: ARM_ret
bool is_return_insn(uint16_t itype);

// Check if instruction is a LEA (load effective address)
// x86: NN_lea
// ARM64: ARM_adr, ARM_adrp (PC-relative address calculation)
bool is_lea_insn(uint16_t itype);

// Check if instruction is a NOP
// x86: NN_nop, or specific encodings
// ARM64: ARM_nop
bool is_nop_insn(uint16_t itype);

//--------------------------------------------------------------------------
// Pattern analysis helpers
//--------------------------------------------------------------------------

// Check if an instruction is a NOP (also checks raw bytes for x86)
bool is_nop_at_ea(ea_t addr);

// Check if instruction is "mov <return_reg>, <first_arg_reg>"
// This is the core pattern for identity functions
// x86-64: mov rax, rdi
// ARM64:  mov x0, x0 (or just checking if x0 is unchanged)
bool is_identity_mov(const insn_t &insn);

// Check if instruction is an indirect jump via return register
// x86-64: jmp rax
// ARM64:  br x0 (or any register containing the target)
bool is_indirect_jump_via_return_reg(const insn_t &insn);

// Check if instruction is "mov <first_arg_reg>, [mem]" or equivalent load
// Used to detect argument loading before identity function calls
// x86-64: mov rdi, [mem]
// ARM64:  ldr x0, [mem]
bool is_arg_load_from_mem(const insn_t &insn, ea_t *out_mem_addr = nullptr);

//--------------------------------------------------------------------------
// Identity function analysis
//
// Identity functions return their first argument unchanged.
// Pattern varies by architecture:
//   x86-64: mov rax, rdi; ret
//   ARM64:  ret (x0 already contains first arg and is return reg)
//          or: mov x0, x0; ret (explicit identity)
//--------------------------------------------------------------------------

// Analyze if a function is an identity function
// Returns true if the function just returns its first argument
bool analyze_identity_function(ea_t func_ea);

//--------------------------------------------------------------------------
// Trampoline analysis
//
// Trampolines follow patterns like:
//   x86-64: mov rdi, [ptr]; call identity; jmp rax
//   ARM64:  ldr x0, [ptr]; bl identity; br x0
//--------------------------------------------------------------------------

// Check if code at addr is a trampoline pattern
// If so, optionally returns the global pointer address
bool is_trampoline_code(ea_t addr, ea_t *out_global_ptr = nullptr);

//--------------------------------------------------------------------------
// Pointer size helpers
//--------------------------------------------------------------------------

// Get pointer size in bytes (4 or 8)
int get_ptr_size();

// Read a pointer from the database
ea_t read_ptr(ea_t addr);

} // namespace arch
