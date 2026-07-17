#include "string_decrypt.h"
#include "../../common/ida_memory.h"
#include "../../common/string_recovery.h"

#include <cstring>

namespace {

constexpr size_t MAX_ENCRYPTED_STRING_BYTES = 1024;

bool is_hikari_encrypted_name(const qstring& raw_name)
{
    const char *name = raw_name.c_str();
    while ( *name == '_' )
        ++name;

    constexpr char prefix[] = "EncryptedString";
    constexpr size_t prefix_length = sizeof(prefix) - 1;
    return std::strncmp(name, prefix, prefix_length) == 0
        && (name[prefix_length] == '\0' || name[prefix_length] == '_');
}

std::set<ea_t> collect_referenced_encrypted_objects(ea_t func_ea)
{
    std::set<ea_t> result;
    func_t *function = get_func(func_ea);
    if ( !function )
        return result;

    func_item_iterator_t iterator(function);
    for ( bool ok = iterator.first(); ok; ok = iterator.next_code() )
    {
        const ea_t from = iterator.current();
        if ( !is_code(get_flags(from)) )
            continue;

        for ( ea_t to = get_first_dref_from(from);
              to != BADADDR;
              to = get_next_dref_from(from, to) )
        {
            const ea_t object = get_item_head(to);
            qstring name;
            if ( get_name(&name, object) > 0
              && is_hikari_encrypted_name(name) )
            {
                result.insert(object);
            }
        }
    }
    return result;
}

bool add_address_offset(ea_t base, uint64_t offset, ea_t *result)
{
    if ( !result || base == BADADDR || offset > uint64_t(BADADDR - base - 1) )
        return false;
    *result = base + static_cast<ea_t>(offset);
    return true;
}

bool static_memory_address(const mop_t& operand, ea_t *address)
{
    if ( !address )
        return false;

    if ( operand.t == mop_v )
    {
        *address = operand.g;
        return *address != BADADDR;
    }
    if ( operand.t == mop_a && operand.a && operand.a->t == mop_v )
    {
        *address = operand.a->g;
        return *address != BADADDR;
    }
    if ( operand.t == mop_n && operand.nnn )
    {
        *address = static_cast<ea_t>(operand.nnn->value);
        return *address != BADADDR;
    }
    if ( operand.t != mop_d || !operand.d )
        return false;

    const minsn_t *instruction = operand.d;
    if ( instruction->opcode != m_add && instruction->opcode != m_sub )
        return false;

    ea_t base = BADADDR;
    uint64_t offset = 0;
    if ( !static_memory_address(instruction->l, &base)
      || instruction->r.t != mop_n || !instruction->r.nnn )
    {
        return false;
    }
    offset = instruction->r.nnn->value;

    if ( instruction->opcode == m_add )
        return add_address_offset(base, offset, address);
    if ( offset > base )
        return false;
    *address = base - static_cast<ea_t>(offset);
    return true;
}

bool loaded_global_byte(const mop_t& operand,
                        const minsn_t *before,
                        ea_t *address)
{
    if ( operand.t == mop_v && operand.size == 1 )
    {
        *address = operand.g;
        return *address != BADADDR;
    }

    if ( operand.t == mop_d && operand.d )
    {
        const minsn_t *nested = operand.d;
        if ( nested->opcode == m_ldx && nested->d.size == 1 )
            return static_memory_address(nested->r, address);
        if ( nested->opcode == m_mov )
            return loaded_global_byte(nested->l, nested, address);
        return false;
    }

    // At MMAT_LOCOPT, a load and its consuming XOR may still be separate.
    // Resolve only the nearest exact-width definition in the same block.
    if ( operand.t == mop_r && before )
    {
        for ( const minsn_t *definition = before->prev;
              definition;
              definition = definition->prev )
        {
            if ( definition->d.t != mop_r || definition->d.r != operand.r )
                continue;
            if ( definition->d.size != operand.size )
                return false;
            if ( definition->opcode == m_ldx && definition->d.size == 1 )
                return static_memory_address(definition->r, address);
            if ( definition->opcode == m_mov )
                return loaded_global_byte(definition->l, definition, address);
            return false;
        }
    }
    return false;
}

bool address_in_object(ea_t address, ea_t object, size_t object_size)
{
    return address >= object
        && static_cast<uint64_t>(address - object) < object_size;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool string_decrypt_handler_t::detect(ea_t func_ea)
{
    return !collect_referenced_encrypted_objects(func_ea).empty();
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int string_decrypt_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[string_decrypt] Starting string decryption\n");

    int total_changes = 0;

    // Find all encrypted strings
    auto encrypted_strings = find_encrypted_strings(ctx->func_ea);
    deobf::log("[string_decrypt] Found %zu potential encrypted strings\n",
              encrypted_strings.size());

    for ( auto &str : encrypted_strings ) {
        // Try to extract XOR keys
        if ( !extract_xor_keys(mba, &str) ) {
            deobf::log_verbose("[string_decrypt] Could not extract keys for %a\n",
                              str.encrypted_addr);
            continue;
        }

        // Decrypt the string
        std::string decrypted = decrypt_string(str);
        if ( decrypted.empty() ) 
            continue;

        deobf::log("[string_decrypt] Decrypted string at %a: \"%s\"\n",
                  str.encrypted_addr, decrypted.c_str());

        // Store in context
        ctx->decrypted_strings[str.encrypted_addr] = decrypted;

        // Annotate in IDA
        annotate_string(str, decrypted);

        ctx->strings_decrypted++;
    }

    deobf::log("[string_decrypt] Decrypted %d strings\n", ctx->strings_decrypted);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find encrypted strings
//--------------------------------------------------------------------------
std::vector<string_decrypt_handler_t::encrypted_string_t>
string_decrypt_handler_t::find_encrypted_strings(ea_t func_ea)
{
    std::vector<encrypted_string_t> result;
    for ( ea_t ea : collect_referenced_encrypted_objects(func_ea) )
    {
        segment_t *segment = getseg(ea);
        if ( !segment || ea >= segment->end_ea )
            continue;

        size_t object_size = static_cast<size_t>(get_item_size(ea));
        tinfo_t type;
        if ( get_tinfo(&type, ea) )
        {
            array_type_data_t array;
            if ( type.get_array_details(&array) )
            {
                const size_t element_size = array.elem_type.get_size();
                if ( element_size != 1 )
                    continue;
            }
            const size_t type_size = type.get_size();
            if ( type_size != BADSIZE && type_size > object_size )
                object_size = type_size;
        }

        const size_t segment_remaining =
            static_cast<size_t>(segment->end_ea - ea);
        object_size = std::min(object_size, segment_remaining);
        object_size = std::min(object_size, MAX_ENCRYPTED_STRING_BYTES);
        if ( object_size == 0 )
            continue;

        encrypted_string_t string;
        string.encrypted_addr = ea;
        string.encrypted_data.resize(object_size);
        if ( !chernobog::ida_memory::read_exact(
                string.encrypted_data.data(), object_size, ea) )
            continue;

        qstring encrypted_name;
        if ( get_name(&encrypted_name, ea) > 0 )
        {
            qstring decrypt_name = encrypted_name;
            decrypt_name.replace("EncryptedString", "DecryptSpace");
            string.decrypt_space_addr =
                get_name_ea(BADADDR, decrypt_name.c_str());
        }
        result.push_back(std::move(string));
    }
    return result;
}

//--------------------------------------------------------------------------
// Extract XOR keys from decryption code
//--------------------------------------------------------------------------
bool string_decrypt_handler_t::extract_xor_keys(mbl_array_t *mba, encrypted_string_t *str)
{
    if ( !mba || !str ) 
        return false;

    // Look for XOR instructions that reference the encrypted address
    // Pattern: load encrypted[i]; xor with key; store to decrypted[i]

    std::map<size_t, uint8_t> key_map;  // offset -> key

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( ins->opcode != m_xor ) 
                continue;

            ea_t ref_addr = BADADDR;
            uint64_t key_val = 0;
            bool found = ins->r.t == mop_n && ins->r.nnn
                && loaded_global_byte(ins->l, ins, &ref_addr);
            if ( found )
                key_val = ins->r.nnn->value;
            else
            {
                found = ins->l.t == mop_n && ins->l.nnn
                    && loaded_global_byte(ins->r, ins, &ref_addr);
                if ( found )
                    key_val = ins->l.nnn->value;
            }

            if ( found && address_in_object(ref_addr, str->encrypted_addr,
                                            str->encrypted_data.size()) )
            {
                if ( key_val > UINT8_MAX )
                    return false;
                const size_t offset = static_cast<size_t>(
                    ref_addr - str->encrypted_addr);
                const uint8_t key_byte = static_cast<uint8_t>(key_val);
                const auto existing = key_map.find(offset);
                if ( existing != key_map.end() )
                {
                    if ( existing->second != key_byte )
                        return false;
                }
                else
                {
                    key_map.emplace(offset, key_byte);
                }
            }
        }
    }

    // A sparse key vector would silently decrypt missing positions with zero.
    // Admit only a contiguous prefix beginning at byte zero.
    str->xor_keys.clear();
    for ( size_t offset = 0; offset < str->encrypted_data.size(); ++offset )
    {
        const auto key = key_map.find(offset);
        if ( key == key_map.end() )
            break;
        str->xor_keys.push_back(key->second);
    }
    return !str->xor_keys.empty();
}

//--------------------------------------------------------------------------
// Decrypt string
//--------------------------------------------------------------------------
std::string string_decrypt_handler_t::decrypt_string(const encrypted_string_t &str)
{
    return chernobog::string_recovery::recover_hikari_xor_ascii(
        str.encrypted_data, str.xor_keys);
}

//--------------------------------------------------------------------------
// Annotate decrypted string in IDA
//--------------------------------------------------------------------------
void string_decrypt_handler_t::annotate_string(const encrypted_string_t &str,
    const std::string &decrypted)
    {

    // Add comment at encrypted string location
    qstring comment;
    comment.sprnt("Decrypted: \"%s\"", decrypted.c_str());
    set_cmt(str.encrypted_addr, comment.c_str(), true);

    // Also comment at decrypt space if available
    if ( str.decrypt_space_addr != BADADDR ) {
        set_cmt(str.decrypt_space_addr, comment.c_str(), true);
    }
}
