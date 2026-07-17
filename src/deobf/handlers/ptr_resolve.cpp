#include "ptr_resolve.h"
#include "../analysis/arch_utils.h"
#include "../../common/ida_memory.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            ptr_ref_t ref;

            // Check left operand
            if ( is_indirect_ptr_ref(ins->l, &ref) ) 
                return true;

            // Check right operand
            if ( is_indirect_ptr_ref(ins->r, &ref) ) 
                return true;

            // Check address operand for address-of expressions
            if ( ins->l.t == mop_a && ins->l.a ) {
                if ( is_indirect_ptr_ref(*ins->l.a, &ref) ) 
                    return true;
            }
            if ( ins->r.t == mop_a && ins->r.a ) {
                if ( is_indirect_ptr_ref(*ins->r.a, &ref) ) 
                    return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int ptr_resolve_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[ptr_resolve] Starting pointer reference resolution\n");

    int total_changes = 0;

    auto ptr_refs = find_ptr_refs(mba);
    deobf::log("[ptr_resolve] Found %zu pointer references to resolve\n", ptr_refs.size());

    // Track unique addresses we've annotated
    std::set<ea_t> annotated;

    for ( const auto &ref : ptr_refs ) {
        // Annotate the pointer location (only once per address)
        if ( annotated.find(ref.ptr_addr) == annotated.end() ) {
            annotate_ptr_ref(ref);
            annotated.insert(ref.ptr_addr);
            total_changes++;

            if ( ref.is_cfstring ) {
                deobf::log("[ptr_resolve]   %s -> @\"%s\"\n",
                          ref.ptr_name.c_str(),
                          ref.string_value.c_str());
            } else if ( ref.is_objc_class ) {
                deobf::log("[ptr_resolve]   %s -> %s (class: %s)\n",
                          ref.ptr_name.c_str(),
                          ref.target_name.c_str(),
                          ref.class_name.c_str());
            } else {
                deobf::log("[ptr_resolve]   %s -> %s\n",
                          ref.ptr_name.c_str(),
                          ref.target_name.c_str());
            }
        }
    }

    deobf::log("[ptr_resolve] Resolved %d pointer references\n", total_changes);
    // Comments and names update the database, not the current microcode.
    return 0;
}

//--------------------------------------------------------------------------
// Find all indirect pointer references
//--------------------------------------------------------------------------
std::vector<ptr_resolve_handler_t::ptr_ref_t>
ptr_resolve_handler_t::find_ptr_refs(mbl_array_t *mba)
{
    std::vector<ptr_ref_t> result;
    std::set<ea_t> seen_addrs;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            ptr_ref_t ref;
            ref.insn = ins;

            // Check direct global reference
            if ( is_indirect_ptr_ref(ins->l, &ref) ) {
                ref.ptr_mop = &ins->l;
                if ( seen_addrs.find(ref.ptr_addr) == seen_addrs.end() ) {
                    result.push_back(ref);
                    seen_addrs.insert(ref.ptr_addr);
                }
            }

            if ( is_indirect_ptr_ref(ins->r, &ref) ) {
                ref.ptr_mop = &ins->r;
                if ( seen_addrs.find(ref.ptr_addr) == seen_addrs.end() ) {
                    result.push_back(ref);
                    seen_addrs.insert(ref.ptr_addr);
                }
            }

            // Check address-of expressions: &off_XXXX
            if ( ins->l.t == mop_a && ins->l.a ) {
                if ( is_indirect_ptr_ref(*ins->l.a, &ref) ) {
                    ref.ptr_mop = ins->l.a;
                    if ( seen_addrs.find(ref.ptr_addr) == seen_addrs.end() ) {
                        result.push_back(ref);
                        seen_addrs.insert(ref.ptr_addr);
                    }
                }
            }
            if ( ins->r.t == mop_a && ins->r.a ) {
                if ( is_indirect_ptr_ref(*ins->r.a, &ref) ) {
                    ref.ptr_mop = ins->r.a;
                    if ( seen_addrs.find(ref.ptr_addr) == seen_addrs.end() ) {
                        result.push_back(ref);
                        seen_addrs.insert(ref.ptr_addr);
                    }
                }
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if operand is an indirect pointer reference
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::is_indirect_ptr_ref(const mop_t &op, ptr_ref_t *out)
{
    if ( op.t != mop_v ) 
        return false;

    ea_t addr = op.g;
    if ( addr == BADADDR ) 
        return false;

    // Get the name at this address
    qstring name;
    if ( get_name(&name, addr) <= 0 ) 
        return false;

    // Look for patterns that suggest pointer indirection
    // Common patterns: off_XXXX, qword_XXXX, classRef_XXXX, selRef_XXXX
    bool is_indirect = false;

    if ( name.find("off_") == 0 ||
        name.find("qword_") == 0 ||
        name.find("classRef_") == 0 ||
        name.find("selRef_") == 0 ||
        name.find("stru_") == 0)
        {
        is_indirect = true;
    }

    // Also check if it's in an ObjC reference section
    if ( !is_indirect && is_objc_ref_section(addr) ) {
        is_indirect = true;
    }

    if ( !is_indirect ) 
        return false;

    // Try to resolve what this pointer points to
    if ( !resolve_ptr_target(addr, out) ) 
        return false;

    out->ptr_addr = addr;
    out->ptr_name = name;

    return true;
}

//--------------------------------------------------------------------------
// Resolve the target of a pointer
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::resolve_ptr_target(ea_t ptr_addr, ptr_ref_t *out)
{
    if ( !out ) 
        return false;

    // Initialize CFString fields
    out->is_cfstring = false;
    out->string_value.clear();

    // First, try to extract as a CFConstantString struct
    // This takes priority because CFConstantStrings are common in ObjC code
    qstring cf_string;
    if ( try_extract_cfstring(ptr_addr, &cf_string) ) {
        out->is_cfstring = true;
        out->string_value = cf_string;
        out->target_addr = ptr_addr;
        out->target_name.sprnt("@\"%s\"", cf_string.c_str());
        out->is_objc_class = false;
        return true;
    }

    // Read the pointer value
    ea_t target = arch::read_ptr(ptr_addr);
    if ( target == 0 || target == BADADDR ) 
        return false;

    // Get the name of the target
    qstring target_name;
    if ( get_name(&target_name, target) <= 0 ) 
        return false;

    // Skip if target name is also an auto-generated name (off_, qword_, etc)
    // We want to resolve to actual symbols
    if ( target_name.find("off_") == 0 ||
        target_name.find("qword_") == 0 ||
        target_name.find("unk_") == 0 ||
        target_name.find("byte_") == 0 ||
        target_name.find("word_") == 0 ||
        target_name.find("dword_") == 0)
        {
        return false;
    }

    out->target_addr = target;
    out->target_name = target_name;

    // Check if it's an ObjC class
    out->is_objc_class = extract_objc_class_name(target_name.c_str(), &out->class_name);

    return true;
}

//--------------------------------------------------------------------------
// Check if address is in ObjC reference section
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::is_objc_ref_section(ea_t addr)
{
    segment_t *seg = getseg(addr);
    if ( !seg ) 
        return false;

    qstring seg_name;
    get_segm_name(&seg_name, seg);

    // ObjC reference sections
    if ( seg_name == "__objc_classrefs" ||
        seg_name == "__objc_selrefs" ||
        seg_name == "__objc_superrefs" ||
        seg_name == "__objc_protorefs" ||
        seg_name == "__objc_classlist" ||
        seg_name == "__objc_catlist" ||
        seg_name == "__objc_protolist" ||
        seg_name == "__objc_data")
        {
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Extract class name from ObjC symbol
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::extract_objc_class_name(const char *symbol, qstring *out_class)
{
    if ( !symbol || !out_class ) 
        return false;

    // Pattern: _OBJC_CLASS_$_ClassName
    const char *class_prefix = "_OBJC_CLASS_$_";
    size_t prefix_len = strlen(class_prefix);

    if ( strncmp(symbol, class_prefix, prefix_len) == 0 ) {
        *out_class = symbol + prefix_len;
        return true;
    }

    // Pattern: _OBJC_METACLASS_$_ClassName
    const char *meta_prefix = "_OBJC_METACLASS_$_";
    size_t meta_len = strlen(meta_prefix);

    if ( strncmp(symbol, meta_prefix, meta_len) == 0 ) {
        *out_class = symbol + meta_len;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if address is a CFConstantString struct and extract its content
//
// CFConstantString target layout:
//   offset 0 * ptrsize: void *isa
//   offset 1 * ptrsize: flags plus ABI padding where applicable
//   offset 2 * ptrsize: const char *data
//   offset 3 * ptrsize: pointer-sized length
//--------------------------------------------------------------------------
bool ptr_resolve_handler_t::try_extract_cfstring(ea_t struct_addr, qstring *out_string)
{
    if ( struct_addr == BADADDR || !out_string ) 
        return false;

    const int pointer_bytes = arch::get_ptr_size();
    if ( struct_addr > BADADDR - 1
                     - static_cast<ea_t>(3 * pointer_bytes) )
        return false;

    // Read the ISA pointer
    const ea_t isa_ptr = arch::read_ptr(struct_addr);
    if ( isa_ptr == 0 || isa_ptr == BADADDR ) 
        return false;

    // Check if ISA points to ___CFConstantStringClassReference
    qstring isa_name;
    if ( get_name(&isa_name, isa_ptr) <= 0 ) 
        return false;

    // Accept various CFConstantString class reference patterns
    if ( isa_name.find("CFConstantStringClassReference") == qstring::npos &&
        isa_name.find("__CFConstantStringClassReference") == qstring::npos)
        return false;

    // This IS a CFConstantString - now extract the string content
    deobf::log_verbose("[ptr_resolve] CFString struct at %a (isa=%s)\n",
                      struct_addr, isa_name.c_str());

    const ea_t data_ptr = arch::read_ptr(
        struct_addr + static_cast<ea_t>(2 * pointer_bytes));
    const auto length_value = chernobog::ida_memory::read_integer(
        struct_addr + static_cast<ea_t>(3 * pointer_bytes), pointer_bytes);
    if ( !length_value )
        return false;
    const uint64_t length = *length_value;
    deobf::log_verbose("[ptr_resolve]   data_ptr=%a, length=%llu\n",
                      data_ptr, (unsigned long long)length);
    if ( data_ptr == 0 || data_ptr == BADADDR ) {
        deobf::log_verbose("[ptr_resolve] CFString at %a: invalid data_ptr\n", struct_addr);
        return false;
    }

    if ( length > 4096 ) {  // Sanity check - allow 0 for empty strings
        deobf::log_verbose("[ptr_resolve] CFString at %a: length too large (%llu)\n",
                          struct_addr, (unsigned long long)length);
        return false;
    }

    // Handle empty strings
    if ( length == 0 ) {
        *out_string = "";
        return true;
    }

    // Try to read the string content
    size_t str_len = get_max_strlit_length(data_ptr, STRTYPE_C);
    if ( str_len == 0 ) {
        // Fallback: try reading directly using the length from the struct
        const size_t length_bytes = static_cast<size_t>(length);
        out_string->resize(length_bytes + 1);
        if ( chernobog::ida_memory::read_exact(
                out_string->begin(), length_bytes, data_ptr) ) {
            (*out_string)[length_bytes] = '\0';
            out_string->resize(length_bytes);
            return true;
        }
        deobf::log_verbose("[ptr_resolve] CFString at %a: get_max_strlit_length failed for %a\n",
                          struct_addr, data_ptr);
        return false;
    }

    // Use the smaller of the two lengths
    if ( str_len > length + 1 ) 
        str_len = length + 1;

    out_string->resize(str_len);
    if ( get_strlit_contents(out_string, data_ptr, str_len, STRTYPE_C) <= 0 ) {
        deobf::log_verbose("[ptr_resolve] CFString at %a: get_strlit_contents failed\n", struct_addr);
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------
// Annotate the resolved reference
//--------------------------------------------------------------------------
void ptr_resolve_handler_t::annotate_ptr_ref(const ptr_ref_t &ref)
{
    if ( ref.ptr_addr == BADADDR ) 
        return;

    qstring comment;
    qstring new_name;

    if ( ref.is_cfstring ) {
        // For CFConstantStrings, show the string content
        comment.sprnt("@\"%s\"", ref.string_value.c_str());

        // Create a name based on the string content (sanitized)
        qstring sanitized = ref.string_value;
        // Truncate long strings
        if ( sanitized.length() > 20 ) 
            sanitized.resize(20);
        // Replace non-identifier characters with underscores
        for ( size_t i = 0; i < sanitized.length(); ++i ) {
            char c = sanitized[i];
            if ( !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                  {
                sanitized[i] = '_';
            }
        }
        new_name.sprnt("cfstr_%s", sanitized.c_str());
    } else if ( ref.is_objc_class ) {
        comment.sprnt("-> %s (class %s)", ref.target_name.c_str(), ref.class_name.c_str());
        new_name.sprnt("classRef_%s", ref.class_name.c_str());
    } else {
        comment.sprnt("-> %s", ref.target_name.c_str());
        // Create a reasonable name based on target
        qstring target_base = ref.target_name;
        // Remove leading underscore if present
        if ( target_base[0] == '_' ) 
            target_base.remove(0, 1);
        new_name.sprnt("ptr_%s", target_base.c_str());
    }

    // Set a repeatable comment at the pointer location
    set_cmt(ref.ptr_addr, comment.c_str(), true);

    // Rename the pointer if it has an auto-generated name
    if ( ref.ptr_name.find("off_") == 0 || ref.ptr_name.find("qword_") == 0 ||
        ref.ptr_name.find("stru_") == 0)
        {
        // Try to set the name (may fail if name exists)
        set_name(ref.ptr_addr, new_name.c_str(), SN_NOWARN | SN_NOCHECK);
    }
}
