#include "arch_utils.h"

// Include x86 instruction definitions
// Note: ARM instruction IDs are not available via allins.hpp in plugins;
// we define them manually based on IDA's ARM processor module
#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

// ARM64 instruction IDs (from IDA's ARM processor module)
// These are the instruction types used by ARM64 disassembly
#ifndef ARM_mov
// Core data movement
#define ARM_mov     1
#define ARM_movz    2
#define ARM_movn    3
#define ARM_movk    4

// Branching
#define ARM_b       20
#define ARM_bl      21
#define ARM_br      22
#define ARM_blr     23
#define ARM_ret     24
#define ARM_cbz     25
#define ARM_cbnz    26
#define ARM_tbz     27
#define ARM_tbnz    28

// Load/Store
#define ARM_ldr     40
#define ARM_ldp     41
#define ARM_ldrb    42
#define ARM_ldrh    43
#define ARM_ldrsb   44
#define ARM_ldrsh   45
#define ARM_ldrsw   46
#define ARM_ldur    47
#define ARM_str     48
#define ARM_stp     49

// Address calculation
#define ARM_adr     60
#define ARM_adrp    61

// NOP
#define ARM_nop     70
#endif

namespace arch {

//--------------------------------------------------------------------------
// Architecture detection
//--------------------------------------------------------------------------
arch_type_t get_arch() {
    // Check processor ID (use PH macro for IDA 9.x compatibility)
    if (PH.id == PLFM_386) {
        return inf_is_64bit() ? ARCH_X86_64 : ARCH_X86;
    }
    else if (PH.id == PLFM_ARM) {
        return inf_is_64bit() ? ARCH_ARM64 : ARCH_ARM32;
    }
    return ARCH_UNKNOWN;
}

bool is_x86() {
    return PH.id == PLFM_386;
}

bool is_x86_64() {
    return PH.id == PLFM_386 && inf_is_64bit();
}

bool is_arm() {
    return PH.id == PLFM_ARM;
}

bool is_arm64() {
    return PH.id == PLFM_ARM && inf_is_64bit();
}

bool is_64bit() {
    return inf_is_64bit();
}

//--------------------------------------------------------------------------
// Register role abstraction
//--------------------------------------------------------------------------

int get_first_arg_reg() {
    if (is_x86_64()) {
        // System V AMD64 ABI: RDI = 7
        // Windows x64: RCX = 1
        // We default to System V (macOS, Linux)
        // TODO: Add Windows support via calling convention detection
        return 7;  // RDI
    }
    else if (is_arm64()) {
        return 0;  // X0
    }
    else if (is_x86()) {
        // 32-bit x86 typically uses stack, but fastcall uses ECX
        return 1;  // ECX for fastcall
    }
    else if (is_arm()) {
        return 0;  // R0
    }
    return -1;
}

int get_second_arg_reg() {
    if (is_x86_64()) {
        return 6;  // RSI (System V)
    }
    else if (is_arm64()) {
        return 1;  // X1
    }
    else if (is_x86()) {
        return 2;  // EDX for fastcall
    }
    else if (is_arm()) {
        return 1;  // R1
    }
    return -1;
}

int get_return_reg() {
    if (is_x86()) {
        return 0;  // (R/E)AX
    }
    else if (is_arm()) {
        return 0;  // (X/R)0
    }
    return -1;
}

int get_link_reg() {
    if (is_arm64()) {
        return 30;  // X30/LR
    }
    else if (is_arm()) {
        return 14;  // LR
    }
    // x86 uses stack for return address
    return -1;
}

int get_stack_pointer_reg() {
    if (is_x86_64()) {
        return 4;  // RSP
    }
    else if (is_x86()) {
        return 4;  // ESP
    }
    else if (is_arm64()) {
        return 31;  // SP
    }
    else if (is_arm()) {
        return 13;  // SP
    }
    return -1;
}

int get_frame_pointer_reg() {
    if (is_x86()) {
        return 5;  // (R/E)BP
    }
    else if (is_arm64()) {
        return 29;  // X29/FP
    }
    else if (is_arm()) {
        return 11;  // FP (R11)
    }
    return -1;
}

//--------------------------------------------------------------------------
// Instruction type classification
//--------------------------------------------------------------------------

bool is_mov_insn(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_mov;
    }
    else if (is_arm()) {
        // ARM64 has multiple MOV variants
        // ARM_mov is the canonical one, but also check aliases
        return itype == ARM_mov ||
               itype == ARM_movz ||
               itype == ARM_movn ||
               itype == ARM_movk;
    }
    return false;
}

bool is_direct_branch(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_jmp;
    }
    else if (is_arm()) {
        return itype == ARM_b;
    }
    return false;
}

bool is_conditional_branch(uint16_t itype) {
    if (is_x86()) {
        // All conditional jumps are in range NN_ja..NN_jz
        return (itype >= NN_ja && itype <= NN_jz);
    }
    else if (is_arm()) {
        // ARM conditional branches and compare-and-branch
        return itype == ARM_b ||  // B.cond
               itype == ARM_cbz ||
               itype == ARM_cbnz ||
               itype == ARM_tbz ||
               itype == ARM_tbnz;
    }
    return false;
}

bool is_indirect_branch(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_jmpni;
    }
    else if (is_arm()) {
        return itype == ARM_br;
    }
    return false;
}

bool is_direct_call(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_call;
    }
    else if (is_arm()) {
        return itype == ARM_bl;
    }
    return false;
}

bool is_indirect_call(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_callni;
    }
    else if (is_arm()) {
        return itype == ARM_blr;
    }
    return false;
}

bool is_call_insn(uint16_t itype) {
    return is_direct_call(itype) || is_indirect_call(itype);
}

bool is_return_insn(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_retn || itype == NN_retf;
    }
    else if (is_arm()) {
        return itype == ARM_ret;
    }
    return false;
}

bool is_load_insn(uint16_t itype) {
    if (is_x86()) {
        // x86 MOV can be a load when source is memory
        // But we check the operand type separately
        return itype == NN_mov;
    }
    else if (is_arm()) {
        return itype == ARM_ldr ||
               itype == ARM_ldrb ||
               itype == ARM_ldrh ||
               itype == ARM_ldrsb ||
               itype == ARM_ldrsh ||
               itype == ARM_ldrsw ||
               itype == ARM_ldp ||
               itype == ARM_ldur;
    }
    return false;
}

bool is_lea_insn(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_lea;
    }
    else if (is_arm()) {
        // ARM uses ADR/ADRP for PC-relative address computation
        return itype == ARM_adr || itype == ARM_adrp;
    }
    return false;
}

bool is_nop_insn(uint16_t itype) {
    if (is_x86()) {
        return itype == NN_nop;
    }
    else if (is_arm()) {
        return itype == ARM_nop;
    }
    return false;
}

//--------------------------------------------------------------------------
// Pattern analysis helpers
//--------------------------------------------------------------------------

bool is_nop_at_ea(ea_t addr) {
    insn_t insn;
    if (decode_insn(&insn, addr) == 0)
        return false;

    if (is_nop_insn(insn.itype))
        return true;

    // x86: Check for 0x90 byte (single-byte NOP)
    if (is_x86() && insn.size == 1 && get_byte(addr) == 0x90)
        return true;

    return false;
}

bool is_reg_with_role(const op_t &op, int role_reg) {
    if (op.type != o_reg)
        return false;
    return op.reg == role_reg;
}

bool is_identity_mov(const insn_t &insn) {
    if (is_x86_64()) {
        // Check for: mov rax, rdi
        if (insn.itype == NN_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == get_return_reg() &&
            insn.Op2.type == o_reg && insn.Op2.reg == get_first_arg_reg()) {
            return true;
        }
    }
    else if (is_arm64()) {
        // Check for: mov x0, x0 (explicit identity)
        // This is rare; usually ARM64 identity functions just return
        if (insn.itype == ARM_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == 0 &&
            insn.Op2.type == o_reg && insn.Op2.reg == 0) {
            return true;
        }
    }
    return false;
}

bool is_indirect_jump_via_return_reg(const insn_t &insn) {
    if (is_x86_64()) {
        // Check for: jmp rax or jmpni via rax
        if ((insn.itype == NN_jmpni || insn.itype == NN_jmp) &&
            insn.Op1.type == o_reg && insn.Op1.reg == get_return_reg()) {
            return true;
        }
    }
    else if (is_arm64()) {
        // Check for: br x0 (or any register)
        // For indirect jumps, the target register may vary
        if (insn.itype == ARM_br && insn.Op1.type == o_reg) {
            return true;
        }
    }
    return false;
}

bool is_arg_load_from_mem(const insn_t &insn, ea_t *out_mem_addr) {
    int arg_reg = get_first_arg_reg();

    if (is_x86_64()) {
        // Check for: mov rdi, [mem]
        if (insn.itype == NN_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == arg_reg &&
            insn.Op2.type == o_mem) {
            if (out_mem_addr)
                *out_mem_addr = insn.Op2.addr;
            return true;
        }
    }
    else if (is_arm64()) {
        // Check for: ldr x0, [mem] or ldr x0, =label
        if ((insn.itype == ARM_ldr || insn.itype == ARM_ldur) &&
            insn.Op1.type == o_reg && insn.Op1.reg == arg_reg) {
            // ARM has various addressing modes
            if (insn.Op2.type == o_mem) {
                if (out_mem_addr)
                    *out_mem_addr = insn.Op2.addr;
                return true;
            }
            // Check for PC-relative load (literal pool)
            if (insn.Op2.type == o_displ || insn.Op2.type == o_phrase) {
                // The address calculation is more complex for ARM
                // For now, we'd need additional logic to resolve the address
                return true;
            }
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Identity function analysis
//--------------------------------------------------------------------------

bool analyze_identity_function(ea_t ea) {
    func_t *func = get_func(ea);
    if (!func)
        return false;

    // Identity functions are typically very short (< 32 bytes for x86, < 16 bytes for ARM64)
    size_t max_size = is_arm64() ? 16 : 32;
    if (func->end_ea - func->start_ea > max_size)
        return false;

    ea_t curr = func->start_ea;
    insn_t insn;
    int insn_count = 0;
    bool saw_identity_mov = false;
    bool saw_ret = false;

    while (curr < func->end_ea && insn_count < 10) {
        if (decode_insn(&insn, curr) == 0)
            break;

        insn_count++;

        // Skip NOPs
        if (is_nop_at_ea(curr)) {
            curr = insn.ea + insn.size;
            continue;
        }

        // Check for identity mov pattern
        if (is_identity_mov(insn)) {
            saw_identity_mov = true;
        }

        // Check for return
        if (is_return_insn(insn.itype)) {
            saw_ret = true;
            break;
        }

        // If we see a call, check if it's to another identity function
        // (recursive check for wrapper functions)
        if (is_call_insn(insn.itype)) {
            ea_t call_target = get_first_fcref_from(insn.ea);
            if (call_target != BADADDR && call_target != ea) {
                // Could recurse here, but be careful of infinite loops
                // For now, just note that we saw a call
            }
        }

        curr = insn.ea + insn.size;
    }

    // Determine if this is an identity function
    if (saw_ret) {
        // ARM64 special case: if the function is just "ret", it's identity
        // because X0 already contains the first argument and is the return register
        if (is_arm64() && insn_count <= 2) {
            return true;
        }

        // x86-64: need to see the explicit mov rax, rdi
        if (is_x86_64() && saw_identity_mov) {
            return true;
        }

        // Very short function that just returns might be identity
        if (insn_count <= 3 && (saw_identity_mov || is_arm64())) {
            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Trampoline analysis
//--------------------------------------------------------------------------

bool is_trampoline_code(ea_t addr, ea_t *out_global_ptr) {
    if (addr == BADADDR)
        return false;

    insn_t insn;
    ea_t curr = addr;
    int insn_count = 0;

    ea_t potential_ptr = BADADDR;
    bool saw_identity_call = false;
    bool saw_indirect_jump = false;

    while (insn_count < 30) {
        if (decode_insn(&insn, curr) == 0)
            break;

        insn_count++;

        // Look for argument load from memory
        ea_t mem_addr = BADADDR;
        if (is_arg_load_from_mem(insn, &mem_addr)) {
            potential_ptr = mem_addr;
        }

        // x86-specific: look for mov rdi, [ptr]
        if (is_x86_64() && insn.itype == NN_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == get_first_arg_reg() &&
            insn.Op2.type == o_mem) {
            potential_ptr = insn.Op2.addr;
        }

        // ARM64-specific: look for ldr x0, [ptr] or adrp/add sequence
        if (is_arm64()) {
            if (insn.itype == ARM_ldr &&
                insn.Op1.type == o_reg && insn.Op1.reg == 0) {
                // Try to extract address from operand
                if (insn.Op2.type == o_mem) {
                    potential_ptr = insn.Op2.addr;
                }
            }
            // ADRP loads high bits of address
            if (insn.itype == ARM_adrp) {
                // Would need to track ADRP+ADD/LDR sequence
                // For now, just note we're in a trampoline
            }
        }

        // Look for call to identity function
        if (is_call_insn(insn.itype)) {
            ea_t call_target = get_first_fcref_from(insn.ea);
            if (call_target != BADADDR) {
                if (analyze_identity_function(call_target)) {
                    saw_identity_call = true;
                } else {
                    // Check for HikariFunctionWrapper name pattern
                    qstring fname;
                    if (get_func_name(&fname, call_target) > 0) {
                        if (fname.find("HikariFunctionWrapper") != qstring::npos) {
                            saw_identity_call = true;
                        }
                    }
                }
            }
        }

        // Look for indirect jump via return register
        if (is_indirect_jump_via_return_reg(insn)) {
            saw_indirect_jump = true;
            break;
        }

        // ARM64: br Xn (any register)
        if (is_arm64() && insn.itype == ARM_br) {
            saw_indirect_jump = true;
            break;
        }

        if (is_return_insn(insn.itype)) {
            break;
        }

        curr = insn.ea + insn.size;
    }

    if (saw_identity_call && saw_indirect_jump && potential_ptr != BADADDR) {
        if (out_global_ptr)
            *out_global_ptr = potential_ptr;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Architecture-specific instruction building
//--------------------------------------------------------------------------

size_t build_direct_jump(uint8_t *buf, size_t buf_size, ea_t from_ea, ea_t to_ea) {
    if (is_x86()) {
        // E9 <rel32> - 5 bytes
        if (buf_size < 5)
            return 0;

        ea_t jmp_end = from_ea + 5;
        int32_t rel_offset = (int32_t)(to_ea - jmp_end);

        buf[0] = 0xE9;
        buf[1] = (uint8_t)(rel_offset & 0xFF);
        buf[2] = (uint8_t)((rel_offset >> 8) & 0xFF);
        buf[3] = (uint8_t)((rel_offset >> 16) & 0xFF);
        buf[4] = (uint8_t)((rel_offset >> 24) & 0xFF);
        return 5;
    }
    else if (is_arm64()) {
        // B <imm26> - 4 bytes
        // Encoding: 000101 imm26
        // Range: +/- 128 MB
        if (buf_size < 4)
            return 0;

        int64_t offset = (int64_t)(to_ea - from_ea);
        // Check range (26-bit signed, scaled by 4)
        if (offset < -0x8000000 || offset > 0x7FFFFFC)
            return 0;  // Out of range, would need stub

        int32_t imm26 = (int32_t)(offset >> 2) & 0x03FFFFFF;
        uint32_t insn = 0x14000000 | imm26;

        buf[0] = (uint8_t)(insn & 0xFF);
        buf[1] = (uint8_t)((insn >> 8) & 0xFF);
        buf[2] = (uint8_t)((insn >> 16) & 0xFF);
        buf[3] = (uint8_t)((insn >> 24) & 0xFF);
        return 4;
    }
    return 0;
}

size_t build_direct_call(uint8_t *buf, size_t buf_size, ea_t from_ea, ea_t to_ea) {
    if (is_x86()) {
        // E8 <rel32> - 5 bytes
        if (buf_size < 5)
            return 0;

        ea_t call_end = from_ea + 5;
        int32_t rel_offset = (int32_t)(to_ea - call_end);

        buf[0] = 0xE8;
        buf[1] = (uint8_t)(rel_offset & 0xFF);
        buf[2] = (uint8_t)((rel_offset >> 8) & 0xFF);
        buf[3] = (uint8_t)((rel_offset >> 16) & 0xFF);
        buf[4] = (uint8_t)((rel_offset >> 24) & 0xFF);
        return 5;
    }
    else if (is_arm64()) {
        // BL <imm26> - 4 bytes
        // Encoding: 100101 imm26
        if (buf_size < 4)
            return 0;

        int64_t offset = (int64_t)(to_ea - from_ea);
        if (offset < -0x8000000 || offset > 0x7FFFFFC)
            return 0;

        int32_t imm26 = (int32_t)(offset >> 2) & 0x03FFFFFF;
        uint32_t insn = 0x94000000 | imm26;

        buf[0] = (uint8_t)(insn & 0xFF);
        buf[1] = (uint8_t)((insn >> 8) & 0xFF);
        buf[2] = (uint8_t)((insn >> 16) & 0xFF);
        buf[3] = (uint8_t)((insn >> 24) & 0xFF);
        return 4;
    }
    return 0;
}

size_t get_nop_bytes(uint8_t *buf, size_t buf_size) {
    if (is_x86()) {
        if (buf_size < 1)
            return 0;
        buf[0] = 0x90;
        return 1;
    }
    else if (is_arm64()) {
        // NOP: D503201F
        if (buf_size < 4)
            return 0;
        buf[0] = 0x1F;
        buf[1] = 0x20;
        buf[2] = 0x03;
        buf[3] = 0xD5;
        return 4;
    }
    return 0;
}

size_t get_min_insn_size() {
    if (is_x86()) {
        return 1;  // Variable length, min 1 byte
    }
    else if (is_arm64()) {
        return 4;  // Fixed 4-byte instructions
    }
    else if (is_arm()) {
        return 2;  // Thumb can be 2 bytes, ARM is 4
    }
    return 1;
}

//--------------------------------------------------------------------------
// Pointer size helpers
//--------------------------------------------------------------------------

int get_ptr_size() {
    return is_64bit() ? 8 : 4;
}

ea_t read_ptr(ea_t addr) {
    if (addr == BADADDR)
        return BADADDR;

    ea_t target = BADADDR;
    int ptr_size = get_ptr_size();

    if (ptr_size == 8) {
        uint64_t val = 0;
        if (get_bytes(&val, 8, addr) == 8) {
            target = (ea_t)val;
        }
    } else {
        uint32_t val = 0;
        if (get_bytes(&val, 4, addr) == 4) {
            target = (ea_t)val;
        }
    }

    return target;
}

} // namespace arch
