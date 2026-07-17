#include "stack_tracker.h"
#include "arch_utils.h"
#include "../../common/bitvector.h"

namespace {

bool ranges_overlap(sval_t left_offset, int left_size,
                    sval_t right_offset, int right_size)
{
    if ( !chernobog::bitvector::valid_byte_width(left_size)
      || !chernobog::bitvector::valid_byte_width(right_size) )
    {
        return true;
    }

    if ( left_offset <= right_offset )
    {
        return static_cast<uint64_t>(right_offset)
             - static_cast<uint64_t>(left_offset)
             < static_cast<uint64_t>(left_size);
    }
    return static_cast<uint64_t>(left_offset)
         - static_cast<uint64_t>(right_offset)
         < static_cast<uint64_t>(right_size);
}

int write_size(const minsn_t *instruction)
{
    if ( !instruction )
        return 0;
    if ( chernobog::bitvector::valid_byte_width(instruction->d.size) )
        return instruction->d.size;
    return instruction->l.size;
}

} // namespace

std::optional<mop_t> stack_tracker_t::trace_source(mblock_t *block,
                                                    const minsn_t *before,
                                                    sval_t offset,
                                                    int size)
{
    if ( !block || !chernobog::bitvector::valid_byte_width(size) )
        return std::nullopt;

    std::set<int> visited;
    const minsn_t *cursor = before ? before->prev : block->tail;

    while ( block )
    {
        if ( !visited.insert(block->serial).second )
            return std::nullopt;

        for ( const minsn_t *instruction = cursor;
              instruction;
              instruction = instruction->prev )
        {
            const bool direct_stack_write =
                (instruction->opcode == m_mov || instruction->opcode == m_stx)
                && instruction->d.t == mop_S && instruction->d.s;

            if ( direct_stack_write )
            {
                const sval_t write_offset = instruction->d.s->off;
                const int bytes = write_size(instruction);
                if ( ranges_overlap(write_offset, bytes, offset, size) )
                {
                    if ( write_offset != offset || bytes != size )
                        return std::nullopt;
                    return instruction->l;
                }
                continue;
            }

            // Calls and non-direct stores can modify an escaped stack object.
            if ( is_mcode_call(instruction->opcode)
              || instruction->opcode == m_stx )
            {
                return std::nullopt;
            }
        }

        if ( block->npred() != 1 || !block->mba )
            return std::nullopt;
        const int predecessor = block->pred(0);
        if ( predecessor < 0 || predecessor >= block->mba->qty )
            return std::nullopt;
        block = block->mba->get_mblock(predecessor);
        cursor = block ? block->tail : nullptr;
    }

    return std::nullopt;
}

std::optional<ea_t> stack_tracker_t::source_address(const mop_t& source)
{
    ea_t address = BADADDR;
    if ( source.t == mop_a && source.a && source.a->t == mop_v )
        address = source.a->g;
    else if ( source.t == mop_v )
    {
        if ( source.g == BADADDR )
            return std::nullopt;
        // A code symbol or string object is already an address-valued source.
        // For an ordinary data global, mop_v denotes its contents, so load one
        // target pointer before returning the reaching value.
        const flags64_t flags = get_flags(source.g);
        const size_t string_length =
            get_max_strlit_length(source.g, STRTYPE_C);
        if ( is_code(flags) || get_func(source.g)
          || (string_length > 0 && string_length < 1024) )
        {
            address = source.g;
        }
        else
        {
            address = arch::read_ptr(source.g);
        }
    }
    else if ( source.t == mop_n && source.nnn )
        address = static_cast<ea_t>(source.nnn->value);
    else
        return std::nullopt;

    if ( address == BADADDR || !getseg(address) )
        return std::nullopt;
    return address;
}

std::optional<ea_t> stack_tracker_t::trace_address(mblock_t *block,
                                                   const minsn_t *before,
                                                   sval_t offset,
                                                   int size)
{
    auto source = trace_source(block, before, offset, size);
    return source ? source_address(*source) : std::nullopt;
}
