#include "stack_tracker.h"

// Static members
std::map<sval_t, stack_tracker_t::stack_slot_t> stack_tracker_t::s_slots;
mbl_array_t *stack_tracker_t::s_mba = nullptr;

//--------------------------------------------------------------------------
// Initialize for a function
//--------------------------------------------------------------------------
void stack_tracker_t::init(mbl_array_t *mba) {
    clear();
    s_mba = mba;
}

void stack_tracker_t::clear() {
    s_slots.clear();
    s_mba = nullptr;
}

//--------------------------------------------------------------------------
// Track writes
//--------------------------------------------------------------------------
void stack_tracker_t::track_write(sval_t offset, uint64_t value, int size) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = false;
    slot.is_string = false;
    slot.value = value;
    slot.size = size;
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

void stack_tracker_t::track_write(sval_t offset, ea_t addr) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = true;
    slot.is_string = false;
    slot.address = addr;
    slot.value = addr;
    slot.size = sizeof(ea_t);
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

void stack_tracker_t::track_write_string(sval_t offset, const char *str) {
    stack_slot_t slot;
    slot.has_value = true;
    slot.is_address = false;
    slot.is_string = true;
    slot.string_val = str;
    slot.size = sizeof(ea_t);  // Pointer size
    slot.write_addr = BADADDR;
    s_slots[offset] = slot;
}

//--------------------------------------------------------------------------
// Read from stack
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::read_value(sval_t offset, int size) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.has_value) {
        return it->second.value;
    }
    return std::nullopt;
}

std::optional<ea_t> stack_tracker_t::read_address(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.has_value) {
        if (it->second.is_address) {
            return it->second.address;
        }
        return (ea_t)it->second.value;
    }
    return std::nullopt;
}

std::optional<std::string> stack_tracker_t::read_string(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it != s_slots.end() && it->second.is_string) {
        return it->second.string_val;
    }
    return std::nullopt;
}

bool stack_tracker_t::is_known(sval_t offset) {
    auto it = s_slots.find(offset);
    return it != s_slots.end() && it->second.has_value;
}

//--------------------------------------------------------------------------
// Resolve indirect call through stack
//--------------------------------------------------------------------------
ea_t stack_tracker_t::resolve_stack_call(minsn_t *call_insn, mbl_array_t *mba) {
    if (!call_insn)
        return BADADDR;

    // Check if the call target is through a stack slot
    // Pattern: icall/call where target is loaded from stack

    // For icall, the target is in l operand
    if (call_insn->opcode == m_icall) {
        // Check if target comes from stack
        if (call_insn->l.t == mop_S) {
            sval_t offset = call_insn->l.s ? call_insn->l.s->off : 0;
            auto addr = read_address(offset);
            if (addr.has_value()) {
                return *addr;
            }
        }

        // Target might be in a register loaded from stack
        if (call_insn->l.t == mop_r) {
            // Need to trace back the register
            // This is complex - would need dataflow analysis
        }
    }

    // For call with indirect target
    if (call_insn->opcode == m_call) {
        if (call_insn->l.t == mop_d && call_insn->l.d) {
            // Nested instruction - might be load from stack
            minsn_t *inner = call_insn->l.d;
            if (inner->opcode == m_ldx || inner->opcode == m_mov) {
                sval_t offset;
                if (is_stack_ref(inner->l, &offset)) {
                    auto addr = read_address(offset);
                    if (addr.has_value()) {
                        return *addr;
                    }
                }
            }
        }
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Analyze a block
//--------------------------------------------------------------------------
void stack_tracker_t::analyze_block(mblock_t *blk) {
    if (!blk)
        return;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Look for stores to stack
        if (ins->opcode == m_mov || ins->opcode == m_stx) {
            sval_t offset;
            if (is_stack_ref(ins->d, &offset)) {
                // Destination is stack slot

                // Get the source value
                if (ins->l.t == mop_n) {
                    // Immediate value
                    track_write(offset, ins->l.nnn->value, ins->l.size);
                }
                else if (ins->l.t == mop_v) {
                    // Global address
                    track_write(offset, ins->l.g);

                    // Check if it's a string
                    qstring str;
                    size_t len = get_max_strlit_length(ins->l.g, STRTYPE_C);
                    if (len > 0 && len < 256) {
                        str.resize(len);
                        if (get_strlit_contents(&str, ins->l.g, len, STRTYPE_C) > 0) {
                            track_write_string(offset, str.c_str());
                        }
                    }

                    // Check if it's a function
                    func_t *fn = get_func(ins->l.g);
                    if (fn) {
                        track_write(offset, ins->l.g);
                    }
                }
                else if (ins->l.t == mop_a && ins->l.a) {
                    // Address expression
                    if (ins->l.a->t == mop_v) {
                        track_write(offset, ins->l.a->g);
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Analyze entire function
//--------------------------------------------------------------------------
void stack_tracker_t::analyze_function(mbl_array_t *mba) {
    if (!mba)
        return;

    init(mba);

    // Analyze in execution order (simplified - just linear)
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        analyze_block(blk);
    }
}

//--------------------------------------------------------------------------
// Get slot info for annotation
//--------------------------------------------------------------------------
std::optional<stack_tracker_t::slot_info_t> stack_tracker_t::get_slot_info(sval_t offset) {
    auto it = s_slots.find(offset);
    if (it == s_slots.end() || !it->second.has_value) {
        return std::nullopt;
    }

    slot_info_t info;
    info.offset = offset;

    if (it->second.is_string) {
        info.type = slot_info_t::STRING;
        info.string_val = it->second.string_val;
    } else if (it->second.is_address) {
        info.type = slot_info_t::ADDRESS;
        info.address = it->second.address;
    } else {
        info.type = slot_info_t::VALUE;
        info.value = it->second.value;
    }

    return info;
}

//--------------------------------------------------------------------------
// Extract value from mop
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::get_mop_value(const mop_t &op) {
    if (op.t == mop_n) {
        return op.nnn->value;
    }
    if (op.t == mop_v) {
        return op.g;
    }
    return std::nullopt;
}

//--------------------------------------------------------------------------
// Check if mop is a stack reference
//--------------------------------------------------------------------------
bool stack_tracker_t::is_stack_ref(const mop_t &op, sval_t *out_offset) {
    if (op.t == mop_S) {
        if (out_offset && op.s) {
            *out_offset = op.s->off;
        }
        return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Trace register value back through block
//--------------------------------------------------------------------------
std::optional<uint64_t> stack_tracker_t::trace_register_value(mblock_t *blk, int reg, minsn_t *before) {
    if (!blk)
        return std::nullopt;

    // Search backwards from 'before' for a write to the register
    for (minsn_t *ins = before ? before->prev : blk->tail; ins; ins = ins->prev) {
        if (ins->opcode == m_mov && ins->d.t == mop_r && ins->d.r == reg) {
            // Found a write to the register
            return get_mop_value(ins->l);
        }
        if (ins->opcode == m_ldx && ins->d.t == mop_r && ins->d.r == reg) {
            // Load from memory to register
            // Check if loading from stack
            sval_t offset;
            if (is_stack_ref(ins->l, &offset)) {
                return read_value(offset, ins->d.size);
            }
        }
    }

    return std::nullopt;
}

//==========================================================================
// Frameless Continuation Analyzer Implementation
//==========================================================================

// Static members
std::map<ea_t, ea_t> frameless_continuation_t::s_resolution_cache;
std::map<ea_t, caller_context_t> frameless_continuation_t::s_context_cache;

void frameless_continuation_t::clear_caches() {
    s_resolution_cache.clear();
    s_context_cache.clear();
}

//--------------------------------------------------------------------------
// Check if a function is a frameless continuation
// Frameless continuations:
//   1. Don't set up their own stack frame (no push rbp; mov rbp, rsp)
//   2. Access deep RBP offsets (beyond what they could have allocated)
//   3. Usually very short (< 50 bytes)
//   4. End with an indirect jump
//--------------------------------------------------------------------------
bool frameless_continuation_t::is_frameless_continuation(ea_t func_ea) {
    if (func_ea == BADADDR) {
        deobf::log_verbose("[frameless] is_frameless_continuation: BADADDR\n");
        return false;
    }
    
    func_t *func = get_func(func_ea);
    if (!func) {
        deobf::log_verbose("[frameless] is_frameless_continuation(0x%llx): no func_t\n",
                          (unsigned long long)func_ea);
        return false;
    }
    
    deobf::log("[frameless] Checking function at 0x%llx, size=%lld\n",
              (unsigned long long)func_ea, (long long)func->size());
    
    // Check function size - frameless continuations are typically small
    if (func->size() > 200) {
        deobf::log_verbose("[frameless]   -> too large (%lld bytes)\n", (long long)func->size());
        return false;
    }
    
    // Analyze prologue
    bool has_prologue = analyze_prologue(func_ea);
    deobf::log("[frameless]   -> has_prologue=%d, is_frameless=%d\n", has_prologue, !has_prologue);
    
    if (!has_prologue)
        return true;  // No proper prologue = frameless
    
    return false;
}

//--------------------------------------------------------------------------
// Analyze function prologue to detect frame setup
// Returns true if function has proper prologue, false if frameless
//--------------------------------------------------------------------------
bool frameless_continuation_t::analyze_prologue(ea_t func_ea) {
    if (func_ea == BADADDR)
        return false;
    
    // Read first few instructions
    insn_t insn;
    ea_t ea = func_ea;
    int insn_count = 0;
    int max_prologue_insns = 5;
    
    bool saw_push_rbp = false;
    bool saw_mov_rbp_rsp = false;
    
    // x86-64 prologue: push rbp; mov rbp, rsp
    // ARM64 prologue: stp x29, x30, [sp, #-N]!; mov x29, sp
    
    while (insn_count < max_prologue_insns) {
        if (decode_insn(&insn, ea) == 0)
            break;
        
        // x86-64: Check for push rbp (opcode 0x55)
        uint8_t first_byte = get_byte(ea);
        if (first_byte == 0x55) {
            saw_push_rbp = true;
        }
        
        // x86-64: Check for mov rbp, rsp (various encodings)
        // Common: 48 89 E5 (mov rbp, rsp in 64-bit mode)
        if (first_byte == 0x48) {
            uint8_t second = get_byte(ea + 1);
            uint8_t third = get_byte(ea + 2);
            if (second == 0x89 && third == 0xE5) {
                saw_mov_rbp_rsp = true;
            }
            if (second == 0x8B && third == 0xEC) {
                saw_mov_rbp_rsp = true;
            }
        }
        
        // ARM64: Check for stp x29, x30, [sp, #-N]!
        // This is complex - for now, assume ARM64 functions with frame have this
        
        ea = get_item_end(ea);
        insn_count++;
    }
    
    // For x86-64, a proper frame requires both push rbp and mov rbp, rsp
    // Note: some functions don't use frame pointers (leaf functions with -fomit-frame-pointer)
    // but obfuscated trampolines specifically use the CALLER's frame
    return saw_push_rbp && saw_mov_rbp_rsp;
}

//--------------------------------------------------------------------------
// Build caller context from a function before it jumps to continuation
// Captures stack values, register values, and global values
//--------------------------------------------------------------------------
caller_context_t frameless_continuation_t::build_caller_context(mbl_array_t *mba, mblock_t *jump_block) {
    caller_context_t ctx;
    
    if (!mba || !jump_block)
        return ctx;
    
    ctx.caller_func = mba->entry_ea;
    
    // Analyze all blocks leading up to and including jump_block
    // to capture the full stack and register state
    
    // Track register values as we scan
    std::map<mreg_t, uint64_t> reg_values;
    
    // Scan all blocks in order
    for (int i = 0; i <= jump_block->serial && i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;
        
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Track mov of immediate to register
            if (ins->opcode == m_mov && ins->d.t == mop_r && ins->l.t == mop_n) {
                reg_values[ins->d.r] = ins->l.nnn->value;
            }
            
            // Track mov of global address to register
            if (ins->opcode == m_mov && ins->d.t == mop_r && ins->l.t == mop_v) {
                reg_values[ins->d.r] = ins->l.g;
            }
            
            // Track stores to stack
            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                sval_t offset = 0;
                bool is_stack_write = false;
                
                if (ins->d.t == mop_S && ins->d.s) {
                    offset = ins->d.s->off;
                    is_stack_write = true;
                }
                
                if (is_stack_write) {
                    // Get source value
                    uint64_t value = 0;
                    bool has_value = false;
                    
                    if (ins->l.t == mop_n) {
                        value = ins->l.nnn->value;
                        has_value = true;
                    } else if (ins->l.t == mop_v) {
                        value = ins->l.g;
                        has_value = true;
                    } else if (ins->l.t == mop_r && reg_values.count(ins->l.r)) {
                        value = reg_values[ins->l.r];
                        has_value = true;
                    } else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                        // Address of global
                        value = ins->l.a->g;
                        has_value = true;
                    }
                    
                    if (has_value) {
                        ctx.stack_values[offset] = value;
                        deobf::log_verbose("[frameless] Tracking stack[%lld] = 0x%llx\n",
                                          (long long)offset, (unsigned long long)value);
                    }
                }
            }
            
            // Track LEA to register (address computation)
            if (ins->opcode == m_mov && ins->d.t == mop_r) {
                if (ins->l.t == mop_a && ins->l.a) {
                    if (ins->l.a->t == mop_v) {
                        reg_values[ins->d.r] = ins->l.a->g;
                    }
                }
            }
        }
    }
    
    // Copy final register values to context
    for (const auto &kv : reg_values) {
        ctx.register_values[kv.first] = kv.second;
    }
    
    deobf::log("[frameless] Built caller context: %zu stack values, %zu register values\n",
              ctx.stack_values.size(), ctx.register_values.size());
    
    return ctx;
}

//--------------------------------------------------------------------------
// Read a global variable value
//--------------------------------------------------------------------------
std::optional<uint64_t> frameless_continuation_t::read_global(ea_t addr, int size) {
    if (addr == BADADDR)
        return std::nullopt;
    
    uint64_t value = 0;
    if (get_bytes(&value, size, addr) != size)
        return std::nullopt;
    
    // Sign extend if needed for 32-bit values
    if (size == 4) {
        int32_t signed_val = (int32_t)value;
        value = (uint64_t)(int64_t)signed_val;
    }
    
    return value;
}

//--------------------------------------------------------------------------
// Read a value from RBP-relative offset using caller context
//--------------------------------------------------------------------------
std::optional<uint64_t> frameless_continuation_t::read_rbp_relative(sval_t offset, const caller_context_t &ctx) {
    // First check if we have this offset in the context
    auto val = ctx.get_stack_value(offset);
    if (val.has_value())
        return val;
    
    // Try nearby offsets (sometimes there's alignment differences)
    for (sval_t delta = -8; delta <= 8; delta += 8) {
        if (delta == 0) continue;
        val = ctx.get_stack_value(offset + delta);
        if (val.has_value()) {
            deobf::log_verbose("[frameless] Found stack value at offset %lld (wanted %lld)\n",
                              (long long)(offset + delta), (long long)offset);
            return val;
        }
    }
    
    return std::nullopt;
}

//--------------------------------------------------------------------------
// Resolve indirect jump in continuation using caller's context
// This performs simplified symbolic execution of the continuation code
//--------------------------------------------------------------------------
ea_t frameless_continuation_t::resolve_continuation_jump(ea_t continuation_ea, const caller_context_t &ctx) {
    if (continuation_ea == BADADDR)
        return BADADDR;
    
    // Check cache first
    auto it = s_resolution_cache.find(continuation_ea);
    if (it != s_resolution_cache.end())
        return it->second;
    
    deobf::log("[frameless] Resolving continuation at 0x%llx\n", (unsigned long long)continuation_ea);
    
    // Perform symbolic execution with caller's context
    ea_t result = symbolic_execute(continuation_ea, ctx, 50);
    
    // Cache the result
    s_resolution_cache[continuation_ea] = result;
    
    return result;
}

//--------------------------------------------------------------------------
// Simplified symbolic execution of continuation code
// Tracks register values and resolves indirect jump target
//--------------------------------------------------------------------------
ea_t frameless_continuation_t::symbolic_execute(ea_t start_ea, const caller_context_t &ctx, int max_insns) {
    if (start_ea == BADADDR)
        return BADADDR;
    
    // Register state - 64 registers should cover most architectures
    std::map<int, uint64_t> regs;
    
    // Initialize from caller context
    for (const auto &kv : ctx.register_values) {
        regs[kv.first] = kv.second;
    }
    
    insn_t insn;
    ea_t ea = start_ea;
    int count = 0;
    
    deobf::log_verbose("[frameless] Starting symbolic execution at 0x%llx\n", (unsigned long long)start_ea);
    
    while (count < max_insns) {
        if (decode_insn(&insn, ea) == 0)
            break;
        
        // Check for indirect jump (end of continuation)
        // x86-64: jmp rXX or jmp [mem]
        // We're looking for: jmp rcx (or similar)
        
        // Simplified x86-64 handling
        // This would need to be expanded for ARM64
        
        uint8_t first_byte = get_byte(ea);
        
        // Check for various instruction patterns
        // This is a simplified emulator - in production you'd want a proper one
        
        // mov rax, [rbp+offset] - load from caller's stack
        // Pattern: 48 8B 85 XX XX XX XX (mov rax, [rbp+disp32])
        // or: 48 8B 45 XX (mov rax, [rbp+disp8])
        if (first_byte == 0x48) {
            uint8_t second = get_byte(ea + 1);
            
            // mov r64, [rbp+disp8]
            if (second == 0x8B) {
                uint8_t modrm = get_byte(ea + 2);
                int mod = (modrm >> 6) & 3;
                int reg = (modrm >> 3) & 7;
                int rm = modrm & 7;
                
                // Check for RBP as base (rm=5)
                if (rm == 5 && mod == 1) {
                    // [rbp+disp8]
                    int8_t disp = (int8_t)get_byte(ea + 3);
                    auto val = read_rbp_relative(disp, ctx);
                    if (val.has_value()) {
                        regs[reg] = *val;
                        deobf::log_verbose("[frameless]   mov r%d, [rbp%+d] = 0x%llx\n",
                                          reg, disp, (unsigned long long)*val);
                    }
                } else if (rm == 5 && mod == 2) {
                    // [rbp+disp32]
                    int32_t disp = get_dword(ea + 3);
                    auto val = read_rbp_relative(disp, ctx);
                    if (val.has_value()) {
                        regs[reg] = *val;
                        deobf::log_verbose("[frameless]   mov r%d, [rbp%+d] = 0x%llx\n",
                                          reg, disp, (unsigned long long)*val);
                    }
                }
            }
            
            // movsxd r64, dword [...]
            if (second == 0x63) {
                // Sign-extend dword to qword
                // Handle similar to above
            }
        }
        
        // mov ecx, [global] - load from global
        // Pattern: 8B 0D XX XX XX XX (mov ecx, [rip+disp32])
        if (first_byte == 0x8B) {
            uint8_t modrm = get_byte(ea + 1);
            if ((modrm & 0xC7) == 0x05) {
                // RIP-relative addressing
                int reg = (modrm >> 3) & 7;
                int32_t disp = get_dword(ea + 2);
                ea_t global_addr = ea + 6 + disp;  // Next instruction + displacement
                
                auto val = read_global(global_addr, 4);
                if (val.has_value()) {
                    regs[reg] = *val;
                    deobf::log_verbose("[frameless]   mov r%d, [0x%llx] = 0x%llx\n",
                                      reg, (unsigned long long)global_addr, (unsigned long long)*val);
                }
            }
        }
        
        // xor ecx, edx - XOR registers
        // Pattern: 31 D1 (xor ecx, edx) or 33 CA (xor ecx, edx)
        if (first_byte == 0x31 || first_byte == 0x33) {
            uint8_t modrm = get_byte(ea + 1);
            int reg1 = (modrm >> 3) & 7;  // source
            int reg2 = modrm & 7;          // dest
            
            if (first_byte == 0x31) {
                // xor r/m, r
                if (regs.count(reg1) && regs.count(reg2)) {
                    uint64_t result = regs[reg2] ^ regs[reg1];
                    regs[reg2] = result;
                    deobf::log_verbose("[frameless]   xor r%d, r%d = 0x%llx\n",
                                      reg2, reg1, (unsigned long long)result);
                }
            } else {
                // xor r, r/m
                if (regs.count(reg1) && regs.count(reg2)) {
                    uint64_t result = regs[reg1] ^ regs[reg2];
                    regs[reg1] = result;
                    deobf::log_verbose("[frameless]   xor r%d, r%d = 0x%llx\n",
                                      reg1, reg2, (unsigned long long)result);
                }
            }
        }
        
        // xor ecx, imm32
        // Pattern: 81 F1 XX XX XX XX
        if (first_byte == 0x81) {
            uint8_t modrm = get_byte(ea + 1);
            if ((modrm & 0xF8) == 0xF0) {  // xor r32, imm32
                int reg = modrm & 7;
                uint32_t imm = get_dword(ea + 2);
                if (regs.count(reg)) {
                    uint64_t result = regs[reg] ^ imm;
                    regs[reg] = result;
                    deobf::log_verbose("[frameless]   xor r%d, 0x%x = 0x%llx\n",
                                      reg, imm, (unsigned long long)result);
                }
            }
        }
        
        // neg ecx - negate register
        // Pattern: F7 D9 (neg ecx)
        if (first_byte == 0xF7) {
            uint8_t modrm = get_byte(ea + 1);
            if ((modrm & 0xF8) == 0xD8) {  // neg r32
                int reg = modrm & 7;
                if (regs.count(reg)) {
                    uint64_t result = (uint64_t)(-(int32_t)regs[reg]);
                    regs[reg] = result;
                    deobf::log_verbose("[frameless]   neg r%d = 0x%llx\n",
                                      reg, (unsigned long long)result);
                }
            }
        }
        
        // movsxd rcx, ecx - sign extend 32 to 64
        // Pattern: 48 63 C9
        if (first_byte == 0x48 && get_byte(ea + 1) == 0x63) {
            uint8_t modrm = get_byte(ea + 2);
            int dst = (modrm >> 3) & 7;
            int src = modrm & 7;
            if (regs.count(src)) {
                int32_t signed_val = (int32_t)regs[src];
                regs[dst] = (uint64_t)(int64_t)signed_val;
                deobf::log_verbose("[frameless]   movsxd r%d, r%d = 0x%llx\n",
                                  dst, src, (unsigned long long)regs[dst]);
            }
        }
        
        // add rcx, [rax+rdx*8] - load from table
        // Pattern: 48 03 0C D0
        if (first_byte == 0x48 && get_byte(ea + 1) == 0x03) {
            uint8_t modrm = get_byte(ea + 2);
            // Check for SIB addressing
            if ((modrm & 7) == 4) {
                uint8_t sib = get_byte(ea + 3);
                int scale = 1 << ((sib >> 6) & 3);
                int index_reg = (sib >> 3) & 7;
                int base_reg = sib & 7;
                int dst_reg = (modrm >> 3) & 7;
                
                // add dst, [base + index*scale]
                if (regs.count(base_reg) && regs.count(index_reg) && regs.count(dst_reg)) {
                    ea_t table_addr = (ea_t)regs[base_reg];
                    int64_t index = (int64_t)regs[index_reg];
                    ea_t entry_addr = table_addr + index * scale;
                    
                    uint64_t table_entry = 0;
                    if (get_bytes(&table_entry, sizeof(ea_t), entry_addr) == sizeof(ea_t)) {
                        uint64_t result = regs[dst_reg] + table_entry;
                        regs[dst_reg] = result;
                        deobf::log_verbose("[frameless]   add r%d, [0x%llx + %lld*%d] = 0x%llx + 0x%llx = 0x%llx\n",
                                          dst_reg, (unsigned long long)table_addr, (long long)index, scale,
                                          (unsigned long long)(result - table_entry),
                                          (unsigned long long)table_entry,
                                          (unsigned long long)result);
                    }
                }
            }
        }
        
        // jmp rcx - indirect jump via register
        // Pattern: FF E1 (jmp rcx)
        if (first_byte == 0xFF) {
            uint8_t modrm = get_byte(ea + 1);
            if ((modrm & 0xF8) == 0xE0) {  // jmp r64
                int reg = modrm & 7;
                if (regs.count(reg)) {
                    ea_t target = (ea_t)regs[reg];
                    deobf::log("[frameless] Resolved indirect jump: jmp r%d = 0x%llx\n",
                              reg, (unsigned long long)target);
                    return target;
                }
            }
        }
        
        ea = get_item_end(ea);
        count++;
    }
    
    deobf::log("[frameless] Could not resolve indirect jump after %d instructions\n", count);
    return BADADDR;
}
