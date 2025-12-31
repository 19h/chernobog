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
//   - Register roles (first argument, return value, link register)
//   - Instruction type classification (mov, branch, call, return)
//   - Pattern detection (identity functions, trampolines, indirect jumps)
//   - Calling convention awareness
//--------------------------------------------------------------------------

namespace arch {

//--------------------------------------------------------------------------
// Supported architectures
//--------------------------------------------------------------------------
enum arch_type_t {
    ARCH_UNKNOWN = 0,
    ARCH_X86,           // 32-bit x86
    ARCH_X86_64,        // 64-bit x86-64
    ARCH_ARM32,         // 32-bit ARM
    ARCH_ARM64,         // 64-bit ARM (AArch64)
};

//--------------------------------------------------------------------------
// Get current architecture
//--------------------------------------------------------------------------
arch_type_t get_arch();

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

// Second function argument register (for completeness)
// x86-64 System V: RSI (6)
// x86-64 Windows:  RDX (2)
// ARM64:           X1 (1)
int get_second_arg_reg();

// Return value register
// x86-64: RAX (0)
// ARM64:  X0 (0)
int get_return_reg();

// Link register (return address stored in register)
// x86-64: N/A (-1), return address is on stack
// ARM64:  X30/LR (30)
int get_link_reg();

// Stack pointer register
// x86-64: RSP (4)
// ARM64:  SP (31)
int get_stack_pointer_reg();

// Frame pointer register
// x86-64: RBP (5)
// ARM64:  X29/FP (29)
int get_frame_pointer_reg();

//--------------------------------------------------------------------------
// Instruction type classification
// These functions check native instruction types (insn_t.itype)
//--------------------------------------------------------------------------

// Check if instruction is a MOV-like data transfer
// x86: NN_mov
// ARM64: ARM_mov, ARM_movz, ARM_movn, ARM_movk
bool is_mov_insn(uint16_t itype);

// Check if instruction is a direct branch (unconditional jump)
// x86: NN_jmp
// ARM64: ARM_b
bool is_direct_branch(uint16_t itype);

// Check if instruction is a conditional branch
// x86: NN_jcc (jz, jnz, jl, jg, etc.)
// ARM64: ARM_b with condition, ARM_cbz, ARM_cbnz, ARM_tbz, ARM_tbnz
bool is_conditional_branch(uint16_t itype);

// Check if instruction is an indirect branch (jump via register)
// x86: NN_jmpni (jmp rax, jmp [mem])
// ARM64: ARM_br (BR Xn)
bool is_indirect_branch(uint16_t itype);

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

// Check if instruction is a load from memory
// x86: NN_mov with memory operand
// ARM64: ARM_ldr, ARM_ldp, ARM_ldrb, ARM_ldrh, etc.
bool is_load_insn(uint16_t itype);

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

// Check if operand is a register with the given role
bool is_reg_with_role(const op_t &op, int role_reg);

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
// Architecture-specific instruction building (for patching)
//--------------------------------------------------------------------------

// Build a direct jump instruction
// Returns the number of bytes written to 'buf'
// x86-64: E9 <rel32> (5 bytes)
// ARM64:  B <imm26> (4 bytes) - limited range, may need stub
size_t build_direct_jump(uint8_t *buf, size_t buf_size, ea_t from_ea, ea_t to_ea);

// Build a direct call instruction
// Returns the number of bytes written to 'buf'
// x86-64: E8 <rel32> (5 bytes)
// ARM64:  BL <imm26> (4 bytes)
size_t build_direct_call(uint8_t *buf, size_t buf_size, ea_t from_ea, ea_t to_ea);

// Get the typical NOP instruction byte(s)
// x86: 0x90
// ARM64: 0xD503201F (NOP encoding)
size_t get_nop_bytes(uint8_t *buf, size_t buf_size);

// Get minimum instruction size
// x86: 1 (variable length)
// ARM64: 4 (fixed length)
size_t get_min_insn_size();

//--------------------------------------------------------------------------
// Pointer size helpers
//--------------------------------------------------------------------------

// Get pointer size in bytes (4 or 8)
int get_ptr_size();

// Read a pointer from the database
ea_t read_ptr(ea_t addr);

} // namespace arch
