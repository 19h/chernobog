#include "ctree_indirect_call.h"

// Include allins.hpp for instruction types (NN_cmp, NN_mov, etc.)
// This header has no include guards, so only include once per translation unit
#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

//--------------------------------------------------------------------------
// File-based debug logging
//--------------------------------------------------------------------------
#include "../../common/compat.h"

static void ctree_icall_debug(const char *fmt, ...) {
#ifndef _WIN32
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/ctree_indirect_call_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
#else
    (void)fmt;
#endif
}

//--------------------------------------------------------------------------
// Dispatcher analysis - for chained indirect call resolution
//--------------------------------------------------------------------------

// Info about a dispatcher function's behavior
struct dispatcher_info_t {
    bool is_dispatcher;       // Is this a dispatcher function?
    ea_t table_addr;          // Table address used
    int64_t offset;           // Offset subtracted
    int cmp_arg_idx;          // Which argument is compared (-1 if none)
    uint64_t cmp_value;       // Value compared against
    int true_index;           // Table index if comparison is true
    int false_index;          // Table index if comparison is false
};

// Visitor to analyze dispatcher functions
struct dispatcher_analyzer_t : public ctree_visitor_t {
    dispatcher_info_t info;
    cfunc_t *cfunc;
    
    dispatcher_analyzer_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {
        memset(&info, 0, sizeof(info));
        info.cmp_arg_idx = -1;
    }
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Look for comparison: arg == constant
        if (e->op == cot_eq || e->op == cot_ne || e->op == cot_slt || 
            e->op == cot_sge || e->op == cot_ult || e->op == cot_uge) {
            // Check if comparing an argument to a constant
            cexpr_t *left = e->x;
            cexpr_t *right = e->y;
            
            // One side should be a number
            if (right && right->op == cot_num) {
                info.cmp_value = right->numval();
                // Left side might be an argument (var with arg index)
                if (left && left->op == cot_var) {
                    lvars_t *lvars = cfunc->get_lvars();
                    if (lvars && left->v.idx < lvars->size()) {
                        lvar_t &lv = (*lvars)[left->v.idx];
                        if (lv.is_arg_var()) {
                            // Simplified: assume first arg for now
                            info.cmp_arg_idx = 0;
                            ctree_icall_debug("[dispatcher] Found cmp: arg%d vs 0x%llx\n",
                                              info.cmp_arg_idx, (unsigned long long)info.cmp_value);
                        }
                    }
                }
            }
        }
        
        // Look for the indirect call pattern (table[idx] - offset)
        if (e->op == cot_sub) {
            cexpr_t *right = e->y;
            if (right && right->op == cot_num) {
                info.offset = right->numval();
                if (info.offset > 0x10000) {
                    info.is_dispatcher = true;
                    ctree_icall_debug("[dispatcher] Found sub with offset 0x%llx\n",
                                      (unsigned long long)info.offset);
                }
            }
        }
        
        return 0;
    }
};

// Analyze a dispatcher function at assembly level to extract comparison and offset
struct asm_dispatcher_info_t {
    bool valid;
    uint32_t cmp_value;     // Value compared with first arg
    bool is_equal_cmp;      // true = setz (==), false = setl (<)
    int64_t offset;         // Computed offset (negated XOR result)
};

static asm_dispatcher_info_t analyze_dispatcher_asm(ea_t func_addr) {
    asm_dispatcher_info_t info = {false, 0, false, 0};
    
    func_t *func = get_func(func_addr);
    if (!func) return info;
    
    ea_t ea = func->start_ea;
    ea_t end = func->end_ea;
    
    uint32_t xor_operand = 0;
    ea_t dword_addr = 0;
    
    while (ea < end) {
        insn_t insn;
        if (decode_insn(&insn, ea) <= 0) break;
        
        // Look for: cmp eax, XXXXXXXX
        if (insn.itype == NN_cmp && insn.ops[0].type == o_reg && 
            insn.ops[0].reg == 0 && insn.ops[1].type == o_imm) {
            info.cmp_value = (uint32_t)insn.ops[1].value;
            ctree_icall_debug("[asm_disp] Found cmp eax, 0x%x\n", info.cmp_value);
        }
        
        // Look for: sete/setl cl (sete = set if equal, setl = set if less)
        if ((insn.itype == NN_sete || insn.itype == NN_setne || 
             insn.itype == NN_setl || insn.itype == NN_setge) && 
            insn.ops[0].type == o_reg && insn.ops[0].reg == 1) {
            info.is_equal_cmp = (insn.itype == NN_sete);
            ctree_icall_debug("[asm_disp] Found %s cl\n", 
                              info.is_equal_cmp ? "setz" : "setl/other");
        }
        
        // Look for: mov esi/ecx, cs:dword_XXXXX (the encrypted offset)
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_mem) {
            dword_addr = insn.ops[1].addr;
            ctree_icall_debug("[asm_disp] Found mov from dword_0x%llx\n", (unsigned long long)dword_addr);
        }
        
        // Look for: mov edi/edx, XXXXXXXX (the XOR operand, right before xor)
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_imm && insn.ops[1].value > 0x10000) {
            xor_operand = (uint32_t)insn.ops[1].value;
            ctree_icall_debug("[asm_disp] Found mov with XOR operand 0x%x\n", xor_operand);
        }
        
        ea = next_head(ea, end);
    }
    
    // Compute the offset if we found the encrypted value
    if (dword_addr != 0 && xor_operand != 0) {
        uint32_t dword_val = get_dword(dword_addr);
        uint32_t xored = dword_val ^ xor_operand;
        // neg = two's complement
        info.offset = -(int32_t)xored;
        info.valid = true;
        ctree_icall_debug("[asm_disp] Computed offset: dword=0x%x ^ 0x%x = 0x%x, neg = %lld\n",
                          dword_val, xor_operand, xored, (long long)info.offset);
    }
    
    return info;
}

// Try to resolve the next level of a chained indirect call using ASM analysis
static ea_t resolve_dispatcher_chain(ea_t initial_target, const carglist_t &args, int max_depth = 3) {
    ea_t current = initial_target;
    
    for (int depth = 0; depth < max_depth; depth++) {
        ctree_icall_debug("[chain] Depth %d: analyzing 0x%llx\n", depth, (unsigned long long)current);
        
        // Ensure it's a function
        if (!get_func(current)) {
            if (!add_func(current)) break;
        }
        
        // Analyze at assembly level
        asm_dispatcher_info_t disp_info = analyze_dispatcher_asm(current);
        if (!disp_info.valid) {
            ctree_icall_debug("[chain] 0x%llx is not a recognized dispatcher\n", (unsigned long long)current);
            break;
        }
        
        // Determine table index from first argument
        int table_index = 0;
        if (args.size() > 0 && args[0].op == cot_num) {
            uint64_t arg_val = args[0].numval();
            bool cmp_result;
            if (disp_info.is_equal_cmp) {
                cmp_result = ((uint32_t)arg_val == disp_info.cmp_value);
            } else {
                cmp_result = ((int32_t)arg_val < (int32_t)disp_info.cmp_value);
            }
            table_index = cmp_result ? 1 : 0;
            ctree_icall_debug("[chain] arg=0x%llx, cmp with 0x%x -> %s, idx=%d\n",
                              (unsigned long long)arg_val, disp_info.cmp_value,
                              cmp_result ? "true" : "false", table_index);
        }
        
        // The dispatcher reads table from stack - we need to find which table
        // For now, try to find a table where table[index] - offset is valid code
        ea_t next_target = BADADDR;
        segment_t *seg = get_first_seg();
        while (seg) {
            if (seg->type == SEG_DATA) {
                ea_t ea = seg->start_ea;
                while (ea < seg->end_ea) {
                    ea_t entry_addr = ea + table_index * 8;
                    if (entry_addr < seg->end_ea) {
                        uint64_t entry_val = 0;
                        if (get_bytes(&entry_val, 8, entry_addr) == 8 && entry_val != 0) {
                            ea_t target = (ea_t)((int64_t)entry_val + disp_info.offset);
                            if (target > 0x100000000LL && target < 0x200000000LL) {
                                if (is_code(get_flags(target)) || get_func(target)) {
                                    next_target = target;
                                    ctree_icall_debug("[chain] Found: table[%d]=0x%llx + %lld = 0x%llx\n",
                                                      table_index, (unsigned long long)entry_val,
                                                      (long long)disp_info.offset,
                                                      (unsigned long long)target);
                                    break;
                                }
                            }
                        }
                    }
                    ea = next_head(ea, seg->end_ea);
                    if (ea == BADADDR) break;
                }
            }
            if (next_target != BADADDR) break;
            seg = get_next_seg(seg->start_ea);
        }
        
        if (next_target == BADADDR) {
            ctree_icall_debug("[chain] Could not resolve next target\n");
            break;
        }
        
        current = next_target;
    }
    
    return current;
}

//--------------------------------------------------------------------------
// Visitor to find indirect call patterns in ctree
//--------------------------------------------------------------------------
struct indirect_call_finder_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    std::vector<cexpr_t*> found_patterns;
    
    indirect_call_finder_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Look for: call(expr) where expr is a cast of (ptr - constant)
        if (e->op == cot_call) {
            cexpr_t *callee = e->x;
            if (!callee) return 0;
            
            ctree_icall_debug("[ctree_icall] Found call, callee op=%d\n", callee->op);
            
            // The callee might be: (func_type*)(table[idx] - offset)
            // Which in ctree is: cast(sub(idx(ptr, idx), const))
            
            // Unwrap cast if present
            while (callee->op == cot_cast) {
                callee = callee->x;
            }
            
            ctree_icall_debug("[ctree_icall]   After unwrap cast: op=%d\n", callee->op);
            
            // Look for subtraction: something - constant
            if (callee->op == cot_sub) {
                cexpr_t *left = callee->x;
                cexpr_t *right = callee->y;
                
                ctree_icall_debug("[ctree_icall]   sub: left op=%d, right op=%d\n", 
                                  left ? left->op : -1, right ? right->op : -1);
                
                // Check if right is a constant
                if (right && right->op == cot_num) {
                    int64_t offset = right->numval();
                    ctree_icall_debug("[ctree_icall]   Offset: %lld (0x%llx)\n", 
                                      (long long)offset, (unsigned long long)offset);
                    
                    // Unwrap casts from left operand
                    while (left && left->op == cot_cast) {
                        left = left->x;
                    }
                    ctree_icall_debug("[ctree_icall]   Left after cast unwrap: op=%d\n", left ? left->op : -1);
                    
                    // Check if left is array indexing: ptr[idx]
                    if (left && left->op == cot_idx) {
                        cexpr_t *base = left->x;
                        cexpr_t *idx_expr = left->y;
                        
                        ctree_icall_debug("[ctree_icall]   idx: base op=%d, idx op=%d\n",
                                          base ? base->op : -1, idx_expr ? idx_expr->op : -1);
                        
                        // Get the base pointer (should be &global or deref of global)
                        // For Hikari, it's often: v3 = &off_XXX; then v3[idx] - offset
                        // So we may need to trace through a local variable
                        ea_t table_addr = BADADDR;
                        
                        if (base && base->op == cot_obj) {
                            table_addr = base->obj_ea;
                            ctree_icall_debug("[ctree_icall]   Base is obj at 0x%llx\n",
                                              (unsigned long long)table_addr);
                        } else if (base && base->op == cot_cast && base->x && base->x->op == cot_obj) {
                            table_addr = base->x->obj_ea;
                            ctree_icall_debug("[ctree_icall]   Base is cast of obj at 0x%llx\n",
                                              (unsigned long long)table_addr);
                        } else if (base && base->op == cot_var) {
                            // Base is a local variable - look for assignment from global
                            ctree_icall_debug("[ctree_icall]   Base is var (idx=%d), looking for table...\n",
                                              base->v.idx);
                            
                            // Strategy: Find a table where table[index] - offset gives valid code
                            // We know the index and offset, so we can validate candidates
                            int64_t search_index = -1;
                            if (idx_expr && idx_expr->op == cot_num) {
                                search_index = idx_expr->numval();
                            }
                            
                            // Scan data segments for code pointer tables
                            segment_t *seg = get_first_seg();
                            while (seg && table_addr == BADADDR) {
                                if (seg->type == SEG_DATA) {
                                    ea_t ea = seg->start_ea;
                                    while (ea < seg->end_ea && table_addr == BADADDR) {
                                        // Check if table[search_index] - offset would be valid code
                                        if (search_index >= 0) {
                                            ea_t entry_addr = ea + search_index * 8;
                                            if (entry_addr < seg->end_ea) {
                                                uint64_t entry_val = 0;
                                                if (get_bytes(&entry_val, 8, entry_addr) == 8 && entry_val != 0) {
                                                    ea_t target = (ea_t)(entry_val - offset);
                                                    if (is_code(get_flags(target)) || get_func(target)) {
                                                        // This looks like a valid table!
                                                        // Verify first entry is also code pointer
                                                        uint64_t first_val = 0;
                                                        if (get_bytes(&first_val, 8, ea) == 8 && first_val != 0) {
                                                            if (is_code(get_flags((ea_t)first_val)) || get_func((ea_t)first_val)) {
                                                                table_addr = ea;
                                                                ctree_icall_debug("[ctree_icall]   Found valid table at 0x%llx (entry[%lld]=0x%llx, target=0x%llx)\n",
                                                                                  (unsigned long long)ea, (long long)search_index,
                                                                                  (unsigned long long)entry_val, (unsigned long long)target);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        ea = next_head(ea, seg->end_ea);
                                        if (ea == BADADDR) break;
                                    }
                                }
                                seg = get_next_seg(seg->start_ea);
                            }
                        }
                        
                        // Get the index
                        int64_t index = -1;
                        if (idx_expr && idx_expr->op == cot_num) {
                            index = idx_expr->numval();
                            ctree_icall_debug("[ctree_icall]   Index: %lld\n", (long long)index);
                        }
                        
                        // If we have table + index + offset, we can resolve!
                        if (table_addr != BADADDR && index >= 0 && offset > 0x10000) {
                            ctree_icall_debug("[ctree_icall]   PATTERN FOUND: table=0x%llx, idx=%lld, off=%lld\n",
                                              (unsigned long long)table_addr, (long long)index, (long long)offset);
                            found_patterns.push_back(e);
                        }
                    }
                }
            }
        }
        return 0;
    }
};

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool ctree_indirect_call_handler_t::detect(cfunc_t *cfunc) {
    if (!cfunc || !cfunc->body.cblock)
        return false;
    
    ctree_icall_debug("[ctree_icall] detect() called for func 0x%llx\n",
                      (unsigned long long)cfunc->entry_ea);
    
    indirect_call_finder_t finder(cfunc);
    finder.apply_to(&cfunc->body, nullptr);
    
    ctree_icall_debug("[ctree_icall] Found %zu patterns\n", finder.found_patterns.size());
    return !finder.found_patterns.empty();
}

//--------------------------------------------------------------------------
// Run resolution
//--------------------------------------------------------------------------
int ctree_indirect_call_handler_t::run(cfunc_t *cfunc, deobf_ctx_t *ctx) {
    if (!cfunc || !cfunc->body.cblock)
        return 0;
    
    ctree_icall_debug("[ctree_icall] run() called for func 0x%llx\n",
                      (unsigned long long)cfunc->entry_ea);
    
    indirect_call_finder_t finder(cfunc);
    finder.apply_to(&cfunc->body, nullptr);
    
    int changes = 0;
    
    ctree_icall_debug("[ctree_icall] Processing %zu found patterns\n", finder.found_patterns.size());
    
    for (cexpr_t *call_expr : finder.found_patterns) {
        ctree_icall_debug("[ctree_icall] Processing pattern at 0x%llx\n", (unsigned long long)call_expr->ea);
        
        // Extract the pattern components
        cexpr_t *callee = call_expr->x;
        while (callee && callee->op == cot_cast)
            callee = callee->x;
        
        ctree_icall_debug("[ctree_icall]   Callee after unwrap: op=%d (cot_sub=%d)\n", callee ? callee->op : -1, cot_sub);
        
        if (!callee || callee->op != cot_sub) {
            ctree_icall_debug("[ctree_icall]   Skipped: callee not sub\n");
            continue;
        }
        
        ctree_icall_debug("[ctree_icall]   Found sub!\n");
        
        cexpr_t *idx_expr = callee->x;  // table[idx]
        cexpr_t *offset_expr = callee->y;  // constant offset
        
        ctree_icall_debug("[ctree_icall]   idx_expr op=%d, offset_expr op=%d\n",
                          idx_expr ? idx_expr->op : -1, offset_expr ? offset_expr->op : -1);
        
        // Unwrap casts from idx_expr
        while (idx_expr && idx_expr->op == cot_cast)
            idx_expr = idx_expr->x;
        
        ctree_icall_debug("[ctree_icall]   idx_expr after unwrap: op=%d (cot_idx=%d)\n",
                          idx_expr ? idx_expr->op : -1, cot_idx);
        
        if (!idx_expr || idx_expr->op != cot_idx) {
            ctree_icall_debug("[ctree_icall]   Skipped: idx_expr not cot_idx\n");
            continue;
        }
        
        // Unwrap casts from idx_expr
        while (idx_expr && idx_expr->op == cot_cast)
            idx_expr = idx_expr->x;
        
        if (!idx_expr || idx_expr->op != cot_idx)
            continue;
        
        cexpr_t *base = idx_expr->x;
        cexpr_t *index = idx_expr->y;
        
        // Get index
        int64_t idx_val = -1;
        if (index && index->op == cot_num)
            idx_val = index->numval();
        
        // Get offset
        int64_t offset_val = offset_expr->numval();
        
        // Get table address
        ea_t table_addr = BADADDR;
        if (base && base->op == cot_obj) {
            table_addr = base->obj_ea;
        } else if (base && base->op == cot_cast && base->x && base->x->op == cot_obj) {
            table_addr = base->x->obj_ea;
        } else if (base && base->op == cot_var && idx_val >= 0 && offset_val > 0x10000) {
            // Variable case - scan for matching table
            segment_t *seg = get_first_seg();
            while (seg && table_addr == BADADDR) {
                if (seg->type == SEG_DATA) {
                    ea_t ea = seg->start_ea;
                    while (ea < seg->end_ea && table_addr == BADADDR) {
                        ea_t entry_addr = ea + idx_val * 8;
                        if (entry_addr < seg->end_ea) {
                            uint64_t entry_val = 0;
                            if (get_bytes(&entry_val, 8, entry_addr) == 8 && entry_val != 0) {
                                ea_t target = (ea_t)(entry_val - offset_val);
                                if (is_code(get_flags(target)) || get_func(target)) {
                                    uint64_t first_val = 0;
                                    if (get_bytes(&first_val, 8, ea) == 8 && first_val != 0) {
                                        if (is_code(get_flags((ea_t)first_val)) || get_func((ea_t)first_val)) {
                                            table_addr = ea;
                                        }
                                    }
                                }
                            }
                        }
                        ea = next_head(ea, seg->end_ea);
                        if (ea == BADADDR) break;
                    }
                }
                seg = get_next_seg(seg->start_ea);
            }
        }
        
        if (table_addr == BADADDR || idx_val < 0)
            continue;
        
        // Compute target
        ea_t target = compute_call_target(table_addr, idx_val, offset_val);
        if (target == BADADDR)
            continue;
        
        // Ensure target is a function - create one if needed
        func_t *target_func = get_func(target);
        if (!target_func) {
            // Target is orphan code - create a function
            if (add_func(target)) {
                ctree_icall_debug("[ctree_icall] Created function at target 0x%llx\n",
                                  (unsigned long long)target);
                target_func = get_func(target);
            } else {
                ctree_icall_debug("[ctree_icall] Failed to create function at 0x%llx\n",
                                  (unsigned long long)target);
            }
        } else if (target_func->start_ea != target) {
            // Target is mid-function - this might be a jump into another function
            ctree_icall_debug("[ctree_icall] Target 0x%llx is inside func 0x%llx (+0x%llx)\n",
                              (unsigned long long)target,
                              (unsigned long long)target_func->start_ea,
                              (unsigned long long)(target - target_func->start_ea));
        }
        
        // Get the target function name
        qstring target_name;
        get_name(&target_name, target);
        
        ctree_icall_debug("[ctree_icall] Initial target: table[%lld] - %lld = 0x%llx (%s)\n",
                          (long long)idx_val, (long long)offset_val, 
                          (unsigned long long)target, target_name.c_str());
        
        // Try to resolve through dispatcher chain if the target is another dispatcher
        // Extract call arguments to pass to chain resolver
        ea_t final_target = target;
        if (call_expr->a && call_expr->a->size() > 0) {
            final_target = resolve_dispatcher_chain(target, *call_expr->a);
            if (final_target != target) {
                // Ensure final target is also a function
                if (!get_func(final_target)) {
                    add_func(final_target);
                }
                get_name(&target_name, final_target);
                ctree_icall_debug("[ctree_icall] Chain resolved to: 0x%llx (%s)\n",
                                  (unsigned long long)final_target, target_name.c_str());
            }
        }
        target = final_target;
        
        // Replace the call target with a direct reference to the resolved function
        // The call expression is: call(complex_expr, args...)
        // We want to change it to: call(target_func, args...)
        
        // Get the original callee to preserve its type info
        cexpr_t *old_callee = call_expr->x;
        tinfo_t callee_type = old_callee->type;
        
        // Create a cot_obj expression that references the target function directly
        // This is the correct way to represent a direct function reference in ctree
        cexpr_t *new_callee = new cexpr_t();
        new_callee->op = cot_obj;
        new_callee->obj_ea = target;
        new_callee->exflags = 0;
        new_callee->ea = call_expr->ea;  // Use call's EA for the callee
        
        // Get the type of the target function if available
        tinfo_t func_type;
        if (get_tinfo(&func_type, target)) {
            // Make it a pointer to the function type for the call expression
            tinfo_t ptr_type;
            ptr_type.create_ptr(func_type);
            new_callee->type = ptr_type;
            ctree_icall_debug("[ctree_icall] Got function type for target\n");
        } else {
            // Fall back to the original callee type
            new_callee->type = callee_type;
            ctree_icall_debug("[ctree_icall] Using original callee type\n");
        }
        
        // Replace the callee in the call expression
        call_expr->x = new_callee;
        
        ctree_icall_debug("[ctree_icall] Replaced callee with cot_obj to 0x%llx (%s)\n", 
                          (unsigned long long)target, target_name.c_str());
        
        // Also add a comment for documentation
        qstring comment;
        comment.sprnt("DEOBF: Resolved indirect call -> %s (0x%llX)", 
                      target_name.c_str(), (unsigned long long)target);
        set_cmt(call_expr->ea, comment.c_str(), false);
        
        changes++;
        if (ctx)
            ctx->indirect_resolved++;
    }
    
    ctree_icall_debug("[ctree_icall] Total changes: %d\n", changes);
    return changes;
}

//--------------------------------------------------------------------------
// Check if expression matches the pattern
//--------------------------------------------------------------------------
bool ctree_indirect_call_handler_t::match_pattern(cexpr_t *expr, ea_t *out_table, 
                                                   int64_t *out_index, int64_t *out_offset) {
    // Implementation in the visitor above
    return false;
}

//--------------------------------------------------------------------------
// Compute call target from table entry
//--------------------------------------------------------------------------
ea_t ctree_indirect_call_handler_t::compute_call_target(ea_t table_addr, int64_t index, int64_t offset) {
    ea_t entry_addr = table_addr + index * 8;  // 64-bit entries
    uint64_t entry_val = 0;
    
    if (get_bytes(&entry_val, 8, entry_addr) != 8) {
        ctree_icall_debug("[ctree_icall] Failed to read table entry at 0x%llx\n",
                          (unsigned long long)entry_addr);
        return BADADDR;
    }
    
    ea_t target = (ea_t)(entry_val - offset);
    
    ctree_icall_debug("[ctree_icall] table[%lld] = 0x%llx, - %lld = 0x%llx\n",
                      (long long)index, (unsigned long long)entry_val, 
                      (long long)offset, (unsigned long long)target);
    
    // Validate target is code
    if (!is_code(get_flags(target))) {
        func_t *func = get_func(target);
        if (!func) {
            ctree_icall_debug("[ctree_icall] Target 0x%llx is not code\n", 
                              (unsigned long long)target);
            return BADADDR;
        }
    }
    
    return target;
}
