#include "string_decrypt.h"
#include "../../common/ida_memory.h"
#include "../../common/string_recovery.h"

#include <cstdarg>
#include <cstring>

namespace {

constexpr size_t MAX_ENCRYPTED_STRING_BYTES = 1024;
constexpr size_t MIN_STATIC_WRITE_COUNT = 2;
constexpr size_t MIN_STATIC_TEXT_CHARACTERS = 1;
constexpr size_t MIN_UNTERMINATED_TEXT_CHARACTERS = 4;

enum class static_write_kind_t {
    xor_immediate,
    bitwise_not,
    identity,
};

struct static_write_t {
    mblock_t *block = nullptr;
    minsn_t *instruction = nullptr;
    ea_t source = BADADDR;
    ea_t destination = BADADDR;
    int width = 0;
    uint64_t value = 0;
    static_write_kind_t kind = static_write_kind_t::identity;
    bool preserve_store_opcode = false;
};

struct recovered_initializer_t {
    std::vector<static_write_t> writes;
    std::vector<uint8_t> output;
    chernobog::string_recovery::recovered_text_t text;
    bool implicit_terminator = false;
};

void xor_string_debug(const char *format, ...)
{
    if ( !deobf::debug_enabled() )
        return;
    va_list arguments;
    va_start(arguments, format);
    deobf::debug_vlog("/tmp/xor_string_debug.log", format, arguments);
    va_end(arguments);
}

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

bool loaded_global_value(const mop_t& operand,
                         const minsn_t *before,
                         int width,
                         ea_t *address)
{
    if ( !address || width < 1 || width > 8 )
        return false;
    if ( width == 1 )
        return loaded_global_byte(operand, before, address);

    if ( operand.t == mop_v && operand.size == width )
    {
        *address = operand.g;
        return *address != BADADDR;
    }
    if ( operand.t == mop_d && operand.d )
    {
        const minsn_t *nested = operand.d;
        if ( nested->opcode == m_ldx && nested->d.size == width )
            return static_memory_address(nested->r, address);
        if ( nested->opcode == m_mov )
            return loaded_global_value(nested->l, nested, width, address);
        return false;
    }
    if ( operand.t == mop_r && before )
    {
        for ( const minsn_t *definition = before->prev;
              definition; definition = definition->prev )
        {
            if ( definition->d.t != mop_r || definition->d.r != operand.r )
                continue;
            if ( definition->d.size != width )
                return false;
            if ( definition->opcode == m_ldx )
                return static_memory_address(definition->r, address);
            if ( definition->opcode == m_mov )
                return loaded_global_value(definition->l, definition,
                                           width, address);
            return false;
        }
    }
    return false;
}

bool direct_static_destination(const mop_t& operand, ea_t *address)
{
    if ( !address || operand.t != mop_v || operand.size < 1
      || operand.size > 8 )
    {
        return false;
    }
    *address = operand.g;
    return *address != BADADDR;
}

const minsn_t *nearest_register_definition(const mop_t& operand,
                                           const minsn_t *before,
                                           int width)
{
    if ( operand.t != mop_r || !before || operand.size != width )
        return nullptr;
    for ( const minsn_t *definition = before->prev;
          definition; definition = definition->prev )
    {
        if ( definition->d.t == mop_r && definition->d.r == operand.r )
            return definition->d.size == width ? definition : nullptr;
    }
    return nullptr;
}

bool evaluate_static_instruction(const minsn_t *instruction, int width,
                                 ea_t *source, uint64_t *value,
                                 static_write_kind_t *kind, int depth);

bool evaluate_static_operand(const mop_t& operand, const minsn_t *before,
                             int width, ea_t *source, uint64_t *value,
                             static_write_kind_t *kind, int depth)
{
    if ( !source || !value || !kind || depth > 8 )
        return false;

    ea_t address = BADADDR;
    if ( loaded_global_value(operand, before, width, &address) )
    {
        const std::optional<uint64_t> memory_value =
            chernobog::ida_memory::read_integer(address, width);
        if ( !memory_value )
            return false;
        *source = address;
        *value = *memory_value;
        *kind = static_write_kind_t::identity;
        return true;
    }
    if ( operand.t == mop_d && operand.d )
        return evaluate_static_instruction(operand.d, width, source, value,
                                           kind, depth + 1);
    const minsn_t *definition = nearest_register_definition(
        operand, before, width);
    return definition != nullptr
        && evaluate_static_instruction(definition, width, source, value,
                                       kind, depth + 1);
}

bool evaluate_static_instruction(const minsn_t *instruction, int width,
                                 ea_t *source, uint64_t *value,
                                 static_write_kind_t *kind, int depth)
{
    if ( !instruction || !source || !value || !kind || depth > 8 )
        return false;

    if ( instruction->opcode == m_xor )
    {
        const mop_t *global = nullptr;
        const mop_t *number = nullptr;
        if ( instruction->r.t == mop_n && instruction->r.nnn )
        {
            global = &instruction->l;
            number = &instruction->r;
        }
        else if ( instruction->l.t == mop_n && instruction->l.nnn )
        {
            global = &instruction->r;
            number = &instruction->l;
        }
        ea_t address = BADADDR;
        if ( !global || !number
          || !loaded_global_value(*global, instruction, width, &address) )
        {
            return false;
        }
        const std::optional<uint64_t> memory_value =
            chernobog::ida_memory::read_integer(address, width);
        if ( !memory_value )
            return false;
        *source = address;
        *value = chernobog::bitvector::truncate(
            *memory_value ^ number->nnn->value, width);
        *kind = static_write_kind_t::xor_immediate;
        return true;
    }
    if ( instruction->opcode == m_bnot )
    {
        ea_t address = BADADDR;
        if ( !loaded_global_value(instruction->l, instruction,
                                  width, &address) )
        {
            return false;
        }
        const std::optional<uint64_t> memory_value =
            chernobog::ida_memory::read_integer(address, width);
        if ( !memory_value )
            return false;
        *source = address;
        *value = chernobog::bitvector::truncate(~*memory_value, width);
        *kind = static_write_kind_t::bitwise_not;
        return true;
    }
    if ( instruction->opcode == m_mov )
        return evaluate_static_operand(instruction->l, instruction, width,
                                       source, value, kind, depth + 1);
    if ( instruction->opcode == m_ldx )
    {
        ea_t address = BADADDR;
        if ( instruction->d.size != width
          || !static_memory_address(instruction->r, &address) )
        {
            return false;
        }
        const std::optional<uint64_t> memory_value =
            chernobog::ida_memory::read_integer(address, width);
        if ( !memory_value )
            return false;
        *source = address;
        *value = *memory_value;
        *kind = static_write_kind_t::identity;
        return true;
    }
    return false;
}

void append_target_bytes(uint64_t value, int width, bool big_endian,
                         std::vector<uint8_t> *output)
{
    if ( !output )
        return;
    for ( int index = 0; index < width; ++index )
    {
        const int shift_index = big_endian ? width - index - 1 : index;
        output->push_back(static_cast<uint8_t>(
            value >> static_cast<unsigned>(shift_index * 8)));
    }
}

bool parse_static_write(mblock_t *block, minsn_t *instruction,
                        static_write_t *result)
{
    if ( !block || !instruction || !result )
        return false;
    const bool extended_store = instruction->opcode == m_stx;
    const int width = extended_store ? instruction->l.size
                                     : instruction->d.size;
    ea_t destination = BADADDR;
    const bool destination_found = extended_store
        ? static_memory_address(instruction->d, &destination)
        : direct_static_destination(instruction->d, &destination);
    if ( width < 1 || width > 8 || !destination_found )
    {
        return false;
    }

    ea_t source = BADADDR;
    uint64_t value = 0;
    static_write_kind_t kind = static_write_kind_t::identity;
    const bool evaluated = extended_store
        ? evaluate_static_operand(instruction->l, instruction, width,
                                  &source, &value, &kind, 0)
        : evaluate_static_instruction(instruction, width, &source,
                                      &value, &kind, 0);
    if ( !evaluated )
        return false;

    segment_t *source_segment = getseg(source);
    segment_t *destination_segment = getseg(destination);
    if ( !source_segment || !destination_segment
      || is_code(get_flags(source)) || is_code(get_flags(destination))
      || (destination_segment->perm & SEGPERM_WRITE) == 0 )
    {
        return false;
    }
    if ( source > BADADDR - static_cast<ea_t>(width)
      || destination > BADADDR - static_cast<ea_t>(width) )
    {
        return false;
    }

    result->block = block;
    result->instruction = instruction;
    result->source = source;
    result->destination = destination;
    result->width = width;
    result->value = value;
    result->kind = kind;
    result->preserve_store_opcode = extended_store;
    return true;
}

bool ranges_overlap(ea_t first, size_t first_size,
                    ea_t second, size_t second_size)
{
    return first < second + second_size && second < first + first_size;
}

bool zero_bytes_at(ea_t address, size_t count)
{
    if ( address == BADADDR || count == 0 )
        return false;
    std::vector<uint8_t> bytes(count, 0xFF);
    return chernobog::ida_memory::read_exact(bytes.data(), count, address)
        && std::all_of(bytes.begin(), bytes.end(),
                       [](uint8_t byte) { return byte == 0; });
}

void finish_static_group(std::vector<static_write_t> *current,
                         std::vector<recovered_initializer_t> *result)
{
    if ( !current || !result || current->empty() )
        return;

    const std::vector<static_write_t> writes = std::move(*current);
    current->clear();
    if ( writes.size() < MIN_STATIC_WRITE_COUNT )
        return;

    const int width = writes.front().width;
    size_t transformed = 0;
    for ( const static_write_t& write : writes )
    {
        if ( write.kind != static_write_kind_t::identity )
            ++transformed;
    }
    // Zero-valued XOR keys are commonly emitted as identity moves.  Require
    // at least two real transforms and a transformed majority/tie; the strict
    // text and terminator gates below provide the remaining admission proof.
    if ( transformed < MIN_STATIC_WRITE_COUNT
      || transformed * 2 < writes.size() )
    {
        return;
    }

    const size_t byte_count = writes.size() * static_cast<size_t>(width);
    if ( ranges_overlap(writes.front().source, byte_count,
                        writes.front().destination, byte_count) )
    {
        return;
    }

    std::vector<uint8_t> output;
    output.reserve(byte_count);
    for ( const static_write_t& write : writes )
        append_target_bytes(write.value, width, inf_is_be(), &output);

    const ea_t after_destination = writes.front().destination
        + static_cast<ea_t>(byte_count);
    const bool implicit_terminator = zero_bytes_at(
        after_destination, static_cast<size_t>(width));
    const bool allow_unterminated = implicit_terminator
        || transformed >= MIN_UNTERMINATED_TEXT_CHARACTERS;
    const auto text = chernobog::string_recovery::recover_static_text(
        output, static_cast<size_t>(width), inf_is_be(), allow_unterminated);
    if ( !text || text->characters < MIN_STATIC_TEXT_CHARACTERS )
        return;
    if ( !text->explicitly_terminated && implicit_terminator
      && text->characters < 2 )
    {
        return;
    }
    if ( !text->explicitly_terminated && !implicit_terminator
      && text->characters < MIN_UNTERMINATED_TEXT_CHARACTERS )
    {
        return;
    }

    recovered_initializer_t recovered;
    recovered.writes = writes;
    recovered.output = std::move(output);
    recovered.text = *text;
    recovered.implicit_terminator = implicit_terminator;
    result->push_back(std::move(recovered));
}

std::vector<recovered_initializer_t> find_static_initializers(mbl_array_t *mba)
{
    std::vector<recovered_initializer_t> result;
    if ( !mba )
        return result;

    for ( int block_index = 0; block_index < mba->qty; ++block_index )
    {
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            continue;
        std::vector<static_write_t> current;
        for ( minsn_t *instruction = block->head;
              instruction; instruction = instruction->next )
        {
            static_write_t write;
            if ( !parse_static_write(block, instruction, &write) )
            {
                const bool deferred_static_definition =
                    instruction->d.t == mop_r
                 && (instruction->opcode == m_xor
                  || instruction->opcode == m_bnot
                  || instruction->opcode == m_mov
                  || is_mcode_set(instruction->opcode));
                if ( deferred_static_definition )
                    continue;
                finish_static_group(&current, &result);
                continue;
            }

            bool contiguous = current.empty();
            if ( !current.empty() )
            {
                const static_write_t& previous = current.back();
                contiguous = write.width == previous.width
                    && write.source == previous.source + previous.width
                    && write.destination == previous.destination + previous.width;
            }
            if ( !contiguous )
            {
                finish_static_group(&current, &result);
            }
            current.push_back(write);
        }
        finish_static_group(&current, &result);
    }
    return result;
}

std::string escaped_comment_text(const std::string& text)
{
    std::string result;
    for ( unsigned char byte : text )
    {
        if ( byte == '\\' || byte == '"' )
        {
            result.push_back('\\');
            result.push_back(static_cast<char>(byte));
        }
        else if ( byte == '\n' )
            result += "\\n";
        else if ( byte == '\r' )
            result += "\\r";
        else if ( byte == '\t' )
            result += "\\t";
        else
            result.push_back(static_cast<char>(byte));
    }
    return result;
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
bool string_decrypt_handler_t::detect(mbl_array_t *mba)
{
    return mba != nullptr
        && (!find_static_initializers(mba).empty()
         || !collect_referenced_encrypted_objects(mba->entry_ea).empty());
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

    const std::vector<recovered_initializer_t> initializers =
        find_static_initializers(mba);
    deobf::log("[string_decrypt] Found %zu static XOR string initializers\n",
               initializers.size());
    std::set<ea_t> recorded_destinations;
    for ( const recovered_initializer_t& initializer : initializers )
    {
        const ea_t source = initializer.writes.front().source;
        const ea_t destination = initializer.writes.front().destination;
        const std::string escaped = escaped_comment_text(initializer.text.utf8);
        qstring comment;
        comment.sprnt("Recovered static XOR string: \"%s\"",
                      escaped.c_str());
        set_cmt(destination, comment.c_str(), true);
        set_cmt(initializer.writes.front().instruction->ea,
                comment.c_str(), false);

        std::vector<uint8_t> current(initializer.output.size());
        const bool readable = chernobog::ida_memory::read_exact(
            current.data(), current.size(), destination);
        if ( !readable || current != initializer.output )
            patch_bytes(destination, initializer.output.data(),
                        initializer.output.size());

        for ( const static_write_t& write : initializer.writes )
        {
            if ( !write.preserve_store_opcode )
                write.instruction->opcode = m_mov;
            write.instruction->l.make_number(write.value, write.width);
            if ( !write.preserve_store_opcode )
                write.instruction->r.erase();
            write.block->mark_lists_dirty();
            ++total_changes;
        }

        if ( recorded_destinations.insert(destination).second )
        {
            ctx->decrypted_strings[destination] = initializer.text.utf8;
            ++ctx->strings_decrypted;
        }
        xor_string_debug(
            "func=%llX src=%llX dst=%llX bytes=%zu chars=%zu term=%s text=\"%s\"\n",
            static_cast<unsigned long long>(mba->entry_ea),
            static_cast<unsigned long long>(source),
            static_cast<unsigned long long>(destination),
            initializer.output.size(), initializer.text.characters,
            initializer.text.explicitly_terminated ? "explicit"
                : initializer.implicit_terminator ? "implicit" : "length",
            escaped.c_str());
        deobf::log("[string_decrypt] Recovered static XOR string at %a: \"%s\"\n",
                   destination, escaped.c_str());
    }

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
