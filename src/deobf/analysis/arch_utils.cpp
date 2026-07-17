#include "arch_utils.h"
#include "../../common/ida_memory.h"

// IDA's unified instruction enumeration contains both Intel and ARM IDs.
#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

namespace arch {

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
    if ( is_x86_64() ) {
        // PE x64 uses the Microsoft ABI (RCX); ELF and Mach-O use the
        // System V AMD64 ABI (RDI).
        return inf_get_filetype() == f_PE ? 1 : 7;
    }
    else if ( is_arm64() ) {
        return 0;  // X0
    }
    else if ( is_x86() ) {
        // 32-bit x86 typically uses stack, but fastcall uses ECX
        return 1;  // ECX for fastcall
    }
    else if ( is_arm() ) {
        return 0;  // R0
    }
    return -1;
}

int get_return_reg() {
    if ( is_x86() ) {
        return 0;  // (R/E)AX
    }
    else if ( is_arm() ) {
        return 0;  // (X/R)0
    }
    return -1;
}

//--------------------------------------------------------------------------
// Instruction type classification
//--------------------------------------------------------------------------

bool is_direct_call(uint16_t itype) {
    if ( is_x86() ) {
        return itype == NN_call;
    }
    else if ( is_arm() ) {
        return itype == ARM_bl;
    }
    return false;
}

bool is_indirect_call(uint16_t itype) {
    if ( is_x86() ) {
        return itype == NN_callni;
    }
    else if ( is_arm() ) {
        return itype == ARM_blr;
    }
    return false;
}

bool is_call_insn(uint16_t itype) {
    return is_direct_call(itype) || is_indirect_call(itype);
}

bool is_return_insn(uint16_t itype) {
    if ( is_x86() ) {
        return itype == NN_retn || itype == NN_retf;
    }
    else if ( is_arm() ) {
        return itype == ARM_ret;
    }
    return false;
}

bool is_lea_insn(uint16_t itype) {
    if ( is_x86() ) {
        return itype == NN_lea;
    }
    else if ( is_arm() ) {
        // ARM uses ADR/ADRP for PC-relative address computation
        return itype == ARM_adr || itype == ARM_adrp;
    }
    return false;
}

bool is_nop_insn(uint16_t itype) {
    if ( is_x86() ) {
        return itype == NN_nop;
    }
    else if ( is_arm() ) {
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

    return false;
}

bool is_identity_mov(const insn_t &insn) {
    if ( is_x86_64() ) {
        // Check for: mov rax, rdi
        if (insn.itype == NN_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == get_return_reg() &&
            insn.Op2.type == o_reg && insn.Op2.reg == get_first_arg_reg()) {
            return true;
        }
    }
    else if ( is_arm64() ) {
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
    if ( is_x86_64() ) {
        // Check for: jmp rax or jmpni via rax
        if ((insn.itype == NN_jmpni || insn.itype == NN_jmp) &&
            insn.Op1.type == o_reg && insn.Op1.reg == get_return_reg()) {
            return true;
        }
    }
    else if ( is_arm64() ) {
        // The identity result is in X0; a branch through any other register
        // is not data-dependent on that return value.
        if (insn.itype == ARM_br && insn.Op1.type == o_reg &&
            insn.Op1.reg == get_return_reg()) {
            return true;
        }
    }
    return false;
}

bool is_arg_load_from_mem(const insn_t &insn, ea_t *out_mem_addr) {
    int arg_reg = get_first_arg_reg();

    if ( is_x86_64() ) {
        // Check for: mov rdi, [mem]
        if (insn.itype == NN_mov &&
            insn.Op1.type == o_reg && insn.Op1.reg == arg_reg &&
            insn.Op2.type == o_mem ) {
            if (out_mem_addr)
                *out_mem_addr = insn.Op2.addr;
            return true;
        }
    }
    else if ( is_arm64() ) {
        // Check for: ldr x0, [mem] or ldr x0, =label
        if ((insn.itype == ARM_ldr || insn.itype == ARM_ldur) &&
            insn.Op1.type == o_reg && insn.Op1.reg == arg_reg) {
            // ARM has various addressing modes
            if (insn.Op2.type == o_mem) {
                if (out_mem_addr)
                    *out_mem_addr = insn.Op2.addr;
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
    if ( !func )
        return false;

    // Identity functions are typically very short (< 32 bytes for x86, < 16 bytes for ARM64)
    size_t max_size = is_arm64() ? 16 : 32;
    if ( func->end_ea - func->start_ea > max_size )
        return false;

    ea_t curr = func->start_ea;
    insn_t insn;
    int insn_count = 0;
    bool saw_identity_mov = false;

    while ( curr < func->end_ea && insn_count < 10 ) {
        if ( decode_insn(&insn, curr) == 0 )
            return false;

        insn_count++;

        // Skip NOPs
        if ( is_nop_at_ea(curr) ) {
            curr = insn.ea + insn.size;
            continue;
        }

        if ( is_identity_mov(insn) ) {
            if ( saw_identity_mov )
                return false;
            saw_identity_mov = true;
            curr = insn.ea + insn.size;
            continue;
        }

        if ( is_return_insn(insn.itype) ) {
            // AArch64 returns X0 unchanged without an explicit move. AMD64
            // must transfer the ABI's first-argument register into RAX.
            return is_arm64() || (is_x86_64() && saw_identity_mov);
        }

        // Any arithmetic, memory access, call, or control-flow instruction can
        // change the return value or the path and invalidates identity proof.
        return false;
    }
    return false;
}

//--------------------------------------------------------------------------
// Trampoline analysis
//--------------------------------------------------------------------------

bool is_trampoline_code(ea_t addr, ea_t *out_global_ptr) {
    if ( addr == BADADDR )
        return false;

    func_t *func = get_func(addr);
    const ea_t end_ea = func ? func->end_ea : BADADDR;
    insn_t insn;
    ea_t curr = addr;
    int insn_count = 0;
    ea_t potential_ptr = BADADDR;
    enum stage_t { EXPECT_LOAD, EXPECT_CALL, EXPECT_JUMP } stage = EXPECT_LOAD;

    while ( insn_count < 30 && (end_ea == BADADDR || curr < end_ea) ) {
        if ( decode_insn(&insn, curr) == 0 )
            return false;

        insn_count++;
        const ea_t next = insn.ea + insn.size;

        if ( is_nop_at_ea(curr) ) {
            curr = next;
            continue;
        }

        if ( stage == EXPECT_LOAD ) {
            ea_t mem_addr = BADADDR;
            if ( !is_arg_load_from_mem(insn, &mem_addr) || mem_addr == BADADDR )
                return false;
            potential_ptr = mem_addr;
            stage = EXPECT_CALL;
        } else if ( stage == EXPECT_CALL ) {
            if ( !is_call_insn(insn.itype) )
                return false;
            ea_t call_target = get_first_fcref_from(insn.ea);
            if ( call_target == BADADDR || !analyze_identity_function(call_target) )
                return false;
            stage = EXPECT_JUMP;
        } else {
            if ( !is_indirect_jump_via_return_reg(insn) )
                return false;
            if ( out_global_ptr )
                *out_global_ptr = potential_ptr;
            return true;
        }

        curr = next;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pointer size helpers
//--------------------------------------------------------------------------

int get_ptr_size() {
    return is_64bit() ? 8 : 4;
}

ea_t read_ptr(ea_t addr) {
    if ( addr == BADADDR )
        return BADADDR;

    auto value = chernobog::ida_memory::read_integer(addr, get_ptr_size());
    return value ? static_cast<ea_t>(*value) : BADADDR;
}

} // namespace arch
