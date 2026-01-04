#include "ctree_indirect_call.h"

//--------------------------------------------------------------------------
// File-based debug logging
//--------------------------------------------------------------------------
#include <fcntl.h>
#include <unistd.h>

static void ctree_icall_debug(const char *fmt, ...) {
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
        
        // Get the target function name
        qstring target_name;
        get_name(&target_name, target);
        
        ctree_icall_debug("[ctree_icall] Resolved: table[%lld] - %lld = 0x%llx (%s)\n",
                          (long long)idx_val, (long long)offset_val, 
                          (unsigned long long)target, target_name.c_str());
        
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
