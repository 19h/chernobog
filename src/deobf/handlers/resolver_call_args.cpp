#include "resolver_call_args.h"
#include "../analysis/dependency_liveness.hpp"
#include "../../common/bitvector.h"

#include <intel.hpp>
#include <nalt.hpp>
#include <segment.hpp>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace {

constexpr size_t minimum_recurrent_calls = 8;
constexpr size_t minimum_entry_instructions = 12;
constexpr size_t maximum_entry_instructions = 64;
constexpr size_t minimum_dispatch_targets = 4;
constexpr size_t minimum_direct_dispatch_targets = 2;
constexpr size_t maximum_dispatch_targets = 256;
constexpr size_t maximum_dispatch_block_instructions = 512;
constexpr size_t maximum_linear_function_instructions = 512;
constexpr size_t maximum_direct_table_padding = 16;
constexpr size_t maximum_dispatch_block_padding = 32;
constexpr ea_t maximum_dispatch_span = 0x10000;

struct call_site_t
{
    minsn_t *instruction = nullptr;
    mblock_t *block = nullptr;
};

struct direct_call_collector_t final : public minsn_visitor_t
{
    std::map<ea_t, std::vector<call_site_t>> calls;

    int idaapi visit_minsn() override
    {
        if ( curins == nullptr || curins->opcode != m_call
          || curins->l.t != mop_v || curins->d.t != mop_f
          || curins->d.f == nullptr )
        {
            return 0;
        }

        const ea_t operand_target = curins->l.g;
        const ea_t metadata_target = curins->d.f->callee;
        if ( operand_target == BADADDR
          || (metadata_target != BADADDR
           && metadata_target != operand_target) )
        {
            return 0;
        }
        calls[operand_target].push_back({curins, blk});
        return 0;
    }
};

struct decoded_block_t
{
    ea_t start = BADADDR;
    ea_t end = BADADDR;
    std::vector<insn_t> instructions;
};

struct indexed_memory_t
{
    int base = -1;
    int index = -1;
    int scale = 0;
    sval_t displacement = 0;
};

struct split_dispatch_t
{
    ea_t encoded_table = BADADDR;
    ea_t subtract_table = BADADDR;
    int index_register = -1;
    size_t load_instruction = 0;
};

struct dispatcher_proof_t
{
    ea_t entry = BADADDR;
    split_dispatch_t split;
    std::vector<ea_t> targets;
    std::vector<decoded_block_t> blocks;
    std::map<int, ea_t> static_bases;
    std::map<int, std::set<int64_t>> entry_constants;
};

bool executable_target(ea_t target, const segment_t *code_segment)
{
    const segment_t *segment = getseg(target);
    if ( target == BADADDR || segment == nullptr || segment != code_segment
      || (segment->perm & SEGPERM_EXEC) == 0 )
    {
        return false;
    }
    insn_t decoded;
    return decode_insn(&decoded, target) > 0;
}

bool mapped_range(ea_t address, size_t size)
{
    if ( address == BADADDR || size == 0 )
        return false;
    const segment_t *segment = getseg(address);
    return segment != nullptr && address <= segment->end_ea
        && size <= static_cast<size_t>(segment->end_ea - address);
}

bool indexed_memory_operand(
    const insn_t &instruction,
    const op_t &operand,
    indexed_memory_t *out)
{
    if ( out == nullptr
      || (operand.type != o_phrase && operand.type != o_displ) )
    {
        return false;
    }
    const int index = x86_index_reg(instruction, operand);
    if ( index == R_none || index < 0 )
        return false;
    out->base = x86_base_reg(instruction, operand);
    out->index = index;
    out->scale = 1 << x86_scale(operand);
    out->displacement = operand.type == o_displ
                      ? static_cast<sval_t>(operand.addr) : 0;
    return out->base != R_none && out->base >= 0;
}

bool full_register_destination(
    const insn_t &instruction,
    int register_id)
{
    if ( instruction.Op1.type != o_reg
      || instruction.Op1.reg != register_id )
    {
        return false;
    }
    const size_t width = get_dtype_size(instruction.Op1.dtype);
    // In x86-64, a 32-bit GPR write also clears the upper 32 bits.
    return width == 4 || width == 8;
}

bool zero_idiom(const insn_t &instruction, int register_id)
{
    return (instruction.itype == NN_xor || instruction.itype == NN_sub)
        && instruction.Op1.type == o_reg
        && instruction.Op2.type == o_reg
        && instruction.Op1.reg == register_id
        && instruction.Op2.reg == register_id
        && full_register_destination(instruction, register_id);
}

bool x86_unconditional_jump(const insn_t &instruction)
{
    return instruction.itype == NN_jmp
        || instruction.itype == NN_jmpfi
        || instruction.itype == NN_jmpni
        || instruction.itype == NN_jmpshort;
}

bool operand_is_read(const insn_t &instruction, int operand_index)
{
    // IDA's canonical feature for IMUL covers both the two-operand and
    // three-operand encodings. In the latter, operand 0 is a pure destination
    // even though CF_USE1 is set on the shared instruction descriptor.
    if ( operand_index == 0 && instruction.itype == NN_imul
      && instruction.Op3.type != o_void )
    {
        return false;
    }
    return has_cf_use(
        instruction.get_canon_feature(PH), operand_index);
}

bool x86_setcc(const insn_t &instruction)
{
    return instruction.itype >= NN_seta
        && instruction.itype <= NN_setz;
}

bool x86_implicit_system_transfer(const insn_t &instruction)
{
    return instruction.itype == NN_syscall
        || instruction.itype == NN_sysenter
        || instruction.itype == NN_int
        || instruction.itype == NN_into;
}

bool full_x86_gpr_write(const reg_access_t &access)
{
    // The processor module reports whole-register accesses with an empty
    // range. A low 32-bit GPR write also defines all 64 bits in x86-64.
    return access.range.empty()
        || (access.range.bitoff() == 0 && access.range.bitsize() >= 32);
}

uint64_t register_access_mask(const reg_access_t &access)
{
    if ( access.range.empty() )
        return ~uint64_t{0};
    const unsigned offset = access.range.bitoff();
    if ( offset >= 64 )
        return 0;
    const unsigned width = std::min<unsigned>(
        access.range.bitsize(), 64 - offset);
    if ( width == 0 )
        return 0;
    const uint64_t low_mask = width == 64
                            ? ~uint64_t{0}
                            : (uint64_t{1} << width) - 1;
    return low_mask << offset;
}

uint64_t register_write_mask(const reg_access_t &access)
{
    if ( full_x86_gpr_write(access) )
        return ~uint64_t{0};
    return register_access_mask(access);
}

bool processor_access_reads_incoming_value(
    const insn_t &instruction,
    const reg_access_t &access)
{
    if ( (access.access_type & READ_ACCESS) == 0 )
        return false;
    // The x86 module can report the shared two-operand IMUL descriptor's
    // USE1 bit for a three-operand encoding. Reuse the encoding-aware feature
    // correction for explicit accesses; implicit accesses remain reads.
    if ( access.opnum < UA_MAXOP
      && instruction.ops[access.opnum].type != o_void )
    {
        return operand_is_read(instruction, access.opnum);
    }
    return true;
}

std::optional<ea_t> static_operand_address(const op_t &operand)
{
    if ( operand.type == o_mem && is_mapped(operand.addr) )
        return operand.addr;
    return std::nullopt;
}

std::optional<int64_t> read_static_integer(
    ea_t address,
    size_t width,
    bool sign_extend)
{
    if ( !mapped_range(address, width) )
        return std::nullopt;
    switch ( width )
    {
        case 1:
            return sign_extend ? int64_t(int8_t(get_byte(address)))
                               : int64_t(get_byte(address));
        case 2:
            return sign_extend ? int64_t(int16_t(get_word(address)))
                               : int64_t(get_word(address));
        case 4:
            return sign_extend ? int64_t(int32_t(get_dword(address)))
                               : int64_t(get_dword(address));
        case 8:
            return int64_t(get_qword(address));
        default:
            return std::nullopt;
    }
}

void update_entry_facts(
    const insn_t &instruction,
    std::map<int, ea_t> &bases,
    std::map<int, std::set<int64_t>> &constants)
{
    if ( instruction.Op1.type != o_reg
      || !full_register_destination(instruction, instruction.Op1.reg) )
    {
        return;
    }
    const int destination = instruction.Op1.reg;
    bases.erase(destination);
    constants.erase(destination);

    if ( instruction.itype == NN_lea )
    {
        const auto address = static_operand_address(instruction.Op2);
        if ( address )
            bases[destination] = *address;
        return;
    }
    if ( instruction.itype == NN_mov && instruction.Op2.type == o_imm )
    {
        constants[destination] = {int64_t(instruction.Op2.value)};
        return;
    }
    if ( instruction.itype != NN_mov && instruction.itype != NN_movsx
      && instruction.itype != NN_movzx && instruction.itype != NN_movsxd )
    {
        return;
    }
    const auto address = static_operand_address(instruction.Op2);
    if ( !address )
        return;
    const size_t width = get_dtype_size(instruction.Op2.dtype);
    const bool sign_extend = instruction.itype == NN_movsx
                          || instruction.itype == NN_movsxd;
    const auto value = read_static_integer(*address, width, sign_extend);
    if ( value )
        constants[destination] = {*value};
}

std::optional<decoded_block_t> decode_entry_block(
    ea_t entry,
    const func_t *function)
{
    decoded_block_t result;
    result.start = entry;
    ea_t address = entry;
    while ( result.instructions.size() < maximum_entry_instructions
         && address < function->end_ea
         && function_contains(function->start_ea, address) )
    {
        insn_t instruction;
        if ( decode_insn(&instruction, address) <= 0 )
            return std::nullopt;
        result.instructions.push_back(instruction);
        address += instruction.size;
        if ( x86_unconditional_jump(instruction) )
        {
            const bool indirect = instruction.Op1.type != o_near
                               && instruction.Op1.type != o_far;
            if ( !indirect || address != function->end_ea
              || result.instructions.size() < minimum_entry_instructions )
                return std::nullopt;
            result.end = address;
            return result;
        }
        const uint32_t features = instruction.get_canon_feature(PH);
        if ( is_call_insn(instruction) || is_ret_insn(instruction)
          || (features & (CF_JUMP | CF_STOP)) != 0 )
            return std::nullopt;
    }
    return std::nullopt;
}

std::optional<split_dispatch_t> find_split_dispatch(
    const decoded_block_t &block,
    const std::map<int, ea_t> &initial_bases)
{
    if ( block.instructions.empty() )
        return std::nullopt;
    const insn_t &jump = block.instructions.back();
    if ( !x86_unconditional_jump(jump) || jump.Op1.type != o_reg )
        return std::nullopt;
    const int target_register = jump.Op1.reg;

    std::vector<std::map<int, ea_t>> bases_before;
    bases_before.reserve(block.instructions.size() + 1);
    std::map<int, ea_t> bases = initial_bases;
    std::map<int, std::set<int64_t>> constants;
    bases_before.push_back(bases);
    for ( const insn_t &instruction : block.instructions )
    {
        update_entry_facts(instruction, bases, constants);
        bases_before.push_back(bases);
    }

    for ( size_t sub_pos = block.instructions.size() - 1;
          sub_pos-- > 0; )
    {
        const insn_t &sub = block.instructions[sub_pos];
        indexed_memory_t subtract_memory;
        if ( sub.itype != NN_sub || sub.Op1.type != o_reg
          || sub.Op1.reg != target_register
          || !indexed_memory_operand(sub, sub.Op2, &subtract_memory)
          || subtract_memory.scale != 8 )
        {
            continue;
        }
        for ( size_t load_pos = sub_pos; load_pos-- > 0; )
        {
            const insn_t &load = block.instructions[load_pos];
            indexed_memory_t encoded_memory;
            if ( load.itype != NN_mov || load.Op1.type != o_reg
              || load.Op1.reg != target_register
              || !indexed_memory_operand(load, load.Op2, &encoded_memory)
              || encoded_memory.scale != 8
              || encoded_memory.index != subtract_memory.index )
            {
                continue;
            }
            bool clobbered = false;
            for ( size_t index = load_pos + 1; index < sub_pos; ++index )
            {
                if ( full_register_destination(
                        block.instructions[index], target_register) )
                {
                    clobbered = true;
                    break;
                }
            }
            const auto &load_bases = bases_before[load_pos];
            const auto &sub_bases = bases_before[sub_pos];
            const auto encoded = load_bases.find(encoded_memory.base);
            const auto subtract = sub_bases.find(subtract_memory.base);
            if ( clobbered || encoded == load_bases.end()
              || subtract == sub_bases.end()
              || encoded_memory.displacement != 0
              || subtract_memory.displacement != 0 )
            {
                continue;
            }
            return split_dispatch_t{
                encoded->second, subtract->second,
                encoded_memory.index, load_pos};
        }
    }
    return std::nullopt;
}

std::vector<ea_t> enumerate_split_targets(
    const split_dispatch_t &dispatch,
    const segment_t *code_segment)
{
    std::vector<ea_t> targets;
    for ( size_t index = 0; index < maximum_dispatch_targets; ++index )
    {
        const ea_t encoded_address = dispatch.encoded_table + index * 8;
        const ea_t subtract_address = dispatch.subtract_table + index * 8;
        if ( !mapped_range(encoded_address, 8)
          || !mapped_range(subtract_address, 8) )
        {
            break;
        }
        const ea_t target = ea_t(
            get_qword(encoded_address) - get_qword(subtract_address));
        if ( !executable_target(target, code_segment) )
            break;
        targets.push_back(target);
    }
    if ( targets.size() < minimum_dispatch_targets
      || targets.size() == maximum_dispatch_targets )
    {
        targets.clear();
    }
    return targets;
}

std::optional<std::set<int64_t>> memory_values(
    const insn_t &instruction,
    const op_t &source,
    const std::map<int, ea_t> &bases,
    const std::map<int, std::set<int64_t>> &constants)
{
    std::vector<ea_t> addresses;
    const auto direct = static_operand_address(source);
    if ( direct )
    {
        addresses.push_back(*direct);
    }
    else
    {
        indexed_memory_t memory;
        if ( !indexed_memory_operand(instruction, source, &memory) )
            return std::nullopt;
        const auto base = bases.find(memory.base);
        const auto indexes = constants.find(memory.index);
        if ( base == bases.end() || indexes == constants.end()
          || indexes->second.empty() || indexes->second.size() > 2 )
            return std::nullopt;
        for ( int64_t index : indexes->second )
        {
            const int64_t signed_address = int64_t(base->second)
                + memory.displacement + index * memory.scale;
            if ( signed_address < 0 )
                return std::nullopt;
            addresses.push_back(ea_t(signed_address));
        }
    }

    const size_t width = get_dtype_size(source.dtype);
    const bool sign_extend = instruction.itype == NN_movsx
                          || instruction.itype == NN_movsxd;
    std::set<int64_t> values;
    for ( ea_t address : addresses )
    {
        const auto value = read_static_integer(address, width, sign_extend);
        if ( !value )
            return std::nullopt;
        values.insert(*value);
    }
    return values;
}

std::map<int, std::set<int64_t>> constants_before(
    const decoded_block_t &block,
    size_t stop,
    const dispatcher_proof_t &proof)
{
    std::map<int, std::set<int64_t>> constants;
    if ( block.start != proof.entry )
        constants = proof.entry_constants;
    for ( size_t index = 0; index < stop; ++index )
    {
        const insn_t &instruction = block.instructions[index];
        if ( instruction.Op1.type != o_reg )
            continue;
        const int destination = instruction.Op1.reg;
        if ( zero_idiom(instruction, destination) )
        {
            constants[destination] = {0};
            continue;
        }
        if ( !full_register_destination(instruction, destination) )
        {
            // A SETcc following a known full-register zero produces exactly
            // {0,1}; other partial writes invalidate the fact.
            const uint32_t features = instruction.get_canon_feature(PH);
            if ( x86_setcc(instruction) && has_cf_chg(features, 0)
              && constants.count(destination) != 0
              && constants[destination] == std::set<int64_t>{0} )
            {
                constants[destination] = {0, 1};
            }
            else if ( has_cf_chg(features, 0) )
            {
                constants.erase(destination);
            }
            continue;
        }

        std::optional<std::set<int64_t>> loaded_values;
        if ( (instruction.itype == NN_mov
           || instruction.itype == NN_movsx
           || instruction.itype == NN_movzx
           || instruction.itype == NN_movsxd)
          && (instruction.Op2.type == o_mem
           || instruction.Op2.type == o_phrase
           || instruction.Op2.type == o_displ) )
        {
            // Resolve the source before killing DESTINATION: indexed loads
            // such as `movsxd r13, table[r13]` consume the old value of the
            // same architectural register.
            loaded_values = memory_values(
                instruction, instruction.Op2, proof.static_bases, constants);
        }
        constants.erase(destination);
        if ( instruction.itype == NN_mov && instruction.Op2.type == o_imm )
        {
            constants[destination] = {int64_t(instruction.Op2.value)};
            continue;
        }
        if ( loaded_values )
            constants[destination] = *loaded_values;
    }
    return constants;
}

std::optional<std::vector<ea_t>> split_jump_targets(
    const decoded_block_t &block,
    const dispatcher_proof_t &proof)
{
    const std::map<int, ea_t> no_bases;
    const auto dispatch = find_split_dispatch(
        block, block.start == proof.entry ? no_bases : proof.static_bases);
    if ( !dispatch
      || dispatch->encoded_table != proof.split.encoded_table
      || dispatch->subtract_table != proof.split.subtract_table )
        return std::nullopt;
    const auto constants = constants_before(
        block, dispatch->load_instruction, proof);
    const auto found = constants.find(dispatch->index_register);
    if ( found == constants.end() || found->second.empty() )
        return std::nullopt;
    std::vector<ea_t> targets;
    for ( int64_t index : found->second )
    {
        if ( index < 0 || size_t(index) >= proof.targets.size() )
            return std::nullopt;
        const ea_t target = ea_t(
            get_qword(proof.split.encoded_table + size_t(index) * 8)
          - get_qword(proof.split.subtract_table + size_t(index) * 8));
        if ( std::find(proof.targets.begin(), proof.targets.end(), target)
          == proof.targets.end() )
            return std::nullopt;
        if ( std::find(targets.begin(), targets.end(), target)
          == targets.end() )
        {
            targets.push_back(target);
        }
    }
    return targets;
}

std::optional<std::vector<ea_t>> direct_table_targets(
    const decoded_block_t &block,
    const dispatcher_proof_t &proof,
    const segment_t *code_segment)
{
    if ( block.instructions.empty() )
        return std::nullopt;
    const insn_t &jump = block.instructions.back();
    indexed_memory_t memory;
    if ( jump.Op1.type != o_phrase && jump.Op1.type != o_displ )
        return std::nullopt;
    if ( !indexed_memory_operand(jump, jump.Op1, &memory)
      || memory.scale != 8 || memory.displacement != 0 )
        return std::nullopt;
    std::map<int, ea_t> bases;
    std::map<int, std::set<int64_t>> constants;
    if ( block.start != proof.entry )
    {
        bases = proof.static_bases;
        constants = proof.entry_constants;
    }
    for ( size_t index = 0; index + 1 < block.instructions.size(); ++index )
        update_entry_facts(block.instructions[index], bases, constants);
    const auto base = bases.find(memory.base);
    if ( base == bases.end() )
        return std::nullopt;

    std::vector<ea_t> direct_targets;
    for ( size_t index = 0; index < maximum_dispatch_targets; ++index )
    {
        const ea_t slot = base->second + index * 8;
        if ( !mapped_range(slot, 8) )
            return std::nullopt;
        const ea_t target = ea_t(get_qword(slot));
        if ( !executable_target(target, code_segment) )
            break;
        direct_targets.push_back(target);
    }
    const ea_t direct_end = base->second + direct_targets.size() * 8;
    bool adjacent = direct_end <= proof.split.encoded_table
                 && proof.split.encoded_table - direct_end
                        <= maximum_direct_table_padding;
    for ( ea_t padding = direct_end;
          adjacent && padding < proof.split.encoded_table; padding += 8 )
    {
        adjacent = mapped_range(padding, 8) && get_qword(padding) == 0;
    }
    if ( direct_targets.size() < minimum_direct_dispatch_targets
      || !adjacent )
        return std::nullopt;
    for ( ea_t target : direct_targets )
    {
        if ( std::find(proof.targets.begin(), proof.targets.end(), target)
          == proof.targets.end() )
            return std::nullopt;
    }
    return direct_targets;
}

bool nop_padding_to(ea_t address, ea_t limit)
{
    if ( address > limit || limit - address > maximum_dispatch_block_padding )
        return false;
    while ( address < limit )
    {
        insn_t instruction;
        if ( decode_insn(&instruction, address) <= 0
          || instruction.itype != NN_nop
          || address + instruction.size > limit )
        {
            return false;
        }
        address += instruction.size;
    }
    return true;
}

bool decode_dispatch_blocks(
    dispatcher_proof_t &proof,
    const segment_t *code_segment)
{
    std::vector<ea_t> starts = proof.targets;
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    if ( starts.size() < minimum_dispatch_targets
      || starts.back() - starts.front() > maximum_dispatch_span )
        return false;

    proof.blocks.clear();
    for ( size_t block_index = 0; block_index < starts.size(); ++block_index )
    {
        decoded_block_t block;
        block.start = starts[block_index];
        const ea_t hard_limit = block_index + 1 < starts.size()
                              ? starts[block_index + 1]
                              : starts[block_index] + 0x1000;
        ea_t address = block.start;
        bool terminated = false;
        while ( address < hard_limit
             && block.instructions.size()
                  < maximum_dispatch_block_instructions )
        {
            insn_t instruction;
            if ( decode_insn(&instruction, address) <= 0 )
                return false;
            block.instructions.push_back(instruction);
            address += instruction.size;

            if ( is_ret_insn(instruction) )
            {
                terminated = true;
                break;
            }
            if ( x86_unconditional_jump(instruction) )
            {
                if ( instruction.Op1.type == o_near
                  || instruction.Op1.type == o_far )
                    return false;
                terminated = true;
                break;
            }
            if ( !is_call_insn(instruction)
              && (instruction.get_canon_feature(PH)
                & (CF_JUMP | CF_STOP)) != 0 )
            {
                deobf::log_verbose(
                    "[resolver_args] %a: unsupported internal flow at %a\n",
                    block.start, instruction.ea);
                return false;
            }
        }
        block.end = address;
        const bool boundary_valid = block_index + 1 >= starts.size()
            || block.end == starts[block_index + 1]
            || nop_padding_to(block.end, starts[block_index + 1]);
        if ( !terminated || !boundary_valid )
        {
            deobf::log_verbose(
                "[resolver_args] %a: target boundary rejected at %a\n",
                block.start, block.end);
            return false;
        }

        const insn_t &terminator = block.instructions.back();
        bool closed_dispatch = true;
        if ( x86_unconditional_jump(terminator) )
        {
            closed_dispatch = split_jump_targets(block, proof).has_value();
            if ( !closed_dispatch )
            {
                closed_dispatch = direct_table_targets(
                    block, proof, code_segment).has_value();
            }
        }
        if ( !closed_dispatch )
        {
            deobf::log_verbose(
                "[resolver_args] %a: terminal dispatch rejected at %a\n",
                block.start, terminator.ea);
            return false;
        }
        proof.blocks.push_back(std::move(block));
    }
    return !proof.blocks.empty()
        && is_ret_insn(proof.blocks.back().instructions.back());
}

std::optional<dispatcher_proof_t> prove_split_dispatcher(
    ea_t entry,
    const func_t *function)
{
    const segment_t *code_segment = getseg(entry);
    const auto entry_block = decode_entry_block(entry, function);
    if ( code_segment == nullptr || !entry_block )
        return std::nullopt;

    dispatcher_proof_t proof;
    proof.entry = entry;
    for ( const insn_t &instruction : entry_block->instructions )
        update_entry_facts(
            instruction, proof.static_bases, proof.entry_constants);
    const auto split = find_split_dispatch(*entry_block, {});
    if ( !split )
    {
        deobf::log_verbose("[resolver_args] %a: no entry split\n", entry);
        return std::nullopt;
    }
    proof.split = *split;
    proof.targets = enumerate_split_targets(*split, code_segment);
    if ( proof.targets.empty() )
    {
        deobf::log_verbose("[resolver_args] %a: no split targets\n", entry);
        return std::nullopt;
    }
    if ( !split_jump_targets(*entry_block, proof) )
    {
        deobf::log_verbose("[resolver_args] %a: entry split not closed\n", entry);
        return std::nullopt;
    }
    if ( !decode_dispatch_blocks(proof, code_segment) )
    {
        deobf::log_verbose("[resolver_args] %a: target blocks not closed\n", entry);
        return std::nullopt;
    }
    proof.blocks.insert(proof.blocks.begin(), *entry_block);
    return proof;
}

std::vector<int> abi_argument_registers()
{
    static constexpr std::array<const char *, 6> sysv_names =
        {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static constexpr std::array<const char *, 4> win_names =
        {"rcx", "rdx", "r8", "r9"};
    const bool windows = inf_get_filetype() == f_PE;
    const char *const *names = windows ? win_names.data() : sysv_names.data();
    const size_t count = windows ? win_names.size() : sysv_names.size();
    std::vector<int> result;
    result.reserve(count);
    for ( size_t index = 0; index < count; ++index )
    {
        const int reg = str2reg(names[index]);
        if ( reg < 0 )
            return {};
        result.push_back(reg);
    }
    return result;
}

ea_t direct_transfer_target(const insn_t &instruction)
{
    if ( !is_call_insn(instruction)
      && !x86_unconditional_jump(instruction) )
    {
        return BADADDR;
    }
    for ( int index = 0; index < UA_MAXOP; ++index )
    {
        const op_t &operand = instruction.ops[index];
        if ( operand.type == o_void )
            break;
        if ( operand.type == o_near || operand.type == o_far )
            return operand.addr;
    }
    return BADADDR;
}

struct argument_usage_t
{
    std::vector<int> registers;
    std::vector<uint8_t> used;
};

struct argument_inference_t
{
    std::map<ea_t, std::optional<argument_usage_t>> cache;
    std::set<ea_t> active;
};

std::optional<argument_usage_t> infer_native_argument_usage(
    ea_t entry,
    argument_inference_t &inference);

bool call_observes_argument(
    const insn_t &instruction,
    int register_id,
    size_t argument_index,
    argument_inference_t &inference)
{
    const ea_t target = direct_transfer_target(instruction);
    if ( target == BADADDR )
        return true;

    if ( is_userti(target) )
    {
        tinfo_t user_type;
        func_type_data_t user_details;
        if ( !get_tinfo(&user_type, target)
          || !user_type.get_func_details(&user_details)
          || user_details.is_vararg_cc() )
        {
            return true;
        }
        for ( const funcarg_t &argument : user_details )
        {
            const argloc_t &location = argument.argloc;
            if ( location.is_reg1() && location.reg1() == register_id )
                return true;
            if ( location.is_reg2()
              && (location.reg1() == register_id
               || location.reg2() == register_id) )
            {
                return true;
            }
            if ( location.is_scattered() )
            {
                for ( const argpart_t &part : location.scattered() )
                {
                    if ( (part.is_reg1() && part.reg1() == register_id)
                      || (part.is_reg2()
                       && (part.reg1() == register_id
                        || part.reg2() == register_id)) )
                    {
                        return true;
                    }
                    if ( part.is_badloc() || part.is_custom() )
                        return true;
                }
            }
            else if ( location.is_badloc() || location.is_custom() )
            {
                // Without concrete locations a user prototype cannot prove
                // that this architectural register is unobserved.
                return true;
            }
        }
        return false;
    }

    const auto inferred = infer_native_argument_usage(target, inference);
    if ( inferred && argument_index < inferred->used.size() )
        return inferred->used[argument_index] != 0;

    return true;
}

bool block_observes_incoming_register(
    const decoded_block_t &block,
    int register_id,
    size_t argument_index,
    uint64_t incoming_bits,
    uint64_t *live_after,
    argument_inference_t &inference)
{
    uint64_t live_bits = incoming_bits;
    for ( const insn_t &instruction : block.instructions )
    {
        const ea_t transfer_target = direct_transfer_target(instruction);
        if ( live_bits != 0
          && (is_call_insn(instruction) || transfer_target != BADADDR)
          && call_observes_argument(
                instruction, register_id, argument_index, inference) )
        {
            return true;
        }
        if ( zero_idiom(instruction, register_id) )
        {
            live_bits = 0;
            continue;
        }

        // System-transfer instructions consume architectural registers that
        // are not represented as explicit operands on every processor-module
        // version. Preserve every still-live ABI input at this boundary.
        if ( live_bits != 0 && x86_implicit_system_transfer(instruction) )
            return true;

        // Supplement canonical operand features with processor-provided
        // register accesses. This covers implicit consumers such as string
        // operations while retaining the explicit-operand fallback below.
        reg_accesses_t accesses;
        if ( PH.get_reg_accesses(&accesses, instruction, 0) > 0 )
        {
            uint64_t read_bits = 0;
            uint64_t written_bits = 0;
            for ( const reg_access_t &access : accesses )
            {
                if ( access.regnum != register_id )
                    continue;
                if ( processor_access_reads_incoming_value(
                        instruction, access) )
                    read_bits |= register_access_mask(access);
                if ( (access.access_type & WRITE_ACCESS) != 0 )
                    written_bits |= register_write_mask(access);
            }
            const auto transfer =
                chernobog::analysis::transfer_bit_liveness(
                    live_bits, read_bits, written_bits);
            if ( transfer.observed )
                return true;
            live_bits = transfer.live_after;
            continue;
        }

        const uint32_t features = instruction.get_canon_feature(PH);
        for ( int operand_index = 0;
              operand_index < UA_MAXOP; ++operand_index )
        {
            const op_t &operand = instruction.ops[operand_index];
            if ( operand.type == o_void )
                break;
            if ( operand.type == o_reg && operand.reg == register_id )
            {
                if ( live_bits != 0
                  && operand_is_read(instruction, operand_index) )
                    return true;
                if ( has_cf_chg(features, operand_index)
                  && operand_index == 0
                  && full_register_destination(instruction, register_id) )
                {
                    live_bits = 0;
                }
            }
            else if ( live_bits != 0
                   && (operand.type == o_phrase
                    || operand.type == o_displ) )
            {
                if ( x86_base_reg(instruction, operand) == register_id
                  || x86_index_reg(instruction, operand) == register_id )
                {
                    return true;
                }
            }
        }
    }
    if ( live_after != nullptr )
        *live_after = live_bits;
    return false;
}

std::optional<decoded_block_t> decode_linear_function(
    ea_t entry,
    const func_t *function)
{
    if ( function == nullptr || function->end_ea <= entry )
    {
        return std::nullopt;
    }

    decoded_block_t block;
    block.start = entry;
    ea_t address = entry;
    while ( address < function->end_ea
         && block.instructions.size() < maximum_linear_function_instructions )
    {
        if ( !function_contains(function->start_ea, address) )
            return std::nullopt;
        insn_t instruction;
        if ( decode_insn(&instruction, address) <= 0 )
            return std::nullopt;
        block.instructions.push_back(instruction);
        address += instruction.size;

        if ( is_ret_insn(instruction) )
        {
            block.end = address;
            return block;
        }
        if ( x86_unconditional_jump(instruction) )
        {
            if ( direct_transfer_target(instruction) == BADADDR )
            {
                return std::nullopt;
            }
            block.end = address;
            return block;
        }

        const uint32_t features = instruction.get_canon_feature(PH);
        if ( (features & (CF_JUMP | CF_STOP)) != 0 )
            return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::vector<ea_t>> dispatcher_successors(
    const decoded_block_t &block,
    const dispatcher_proof_t &proof)
{
    if ( block.instructions.empty() )
        return std::nullopt;
    const insn_t &terminator = block.instructions.back();
    if ( is_ret_insn(terminator) )
        return std::vector<ea_t>{};
    if ( !x86_unconditional_jump(terminator) )
        return std::nullopt;
    if ( auto targets = split_jump_targets(block, proof) )
        return targets;
    const segment_t *code_segment = getseg(proof.entry);
    if ( code_segment == nullptr )
        return std::nullopt;
    return direct_table_targets(block, proof, code_segment);
}

std::optional<argument_usage_t> infer_argument_usage_from_blocks(
    const std::vector<decoded_block_t> &blocks,
    const dispatcher_proof_t *proof,
    argument_inference_t &inference)
{
    const std::vector<int> arguments = abi_argument_registers();
    if ( arguments.empty() || blocks.empty() )
        return std::nullopt;

    std::map<ea_t, size_t> block_by_start;
    if ( proof != nullptr )
    {
        for ( size_t index = 0; index < blocks.size(); ++index )
        {
            if ( !block_by_start.emplace(blocks[index].start, index).second )
                return std::nullopt;
        }
    }

    argument_usage_t result;
    result.registers = arguments;
    result.used.assign(arguments.size(), 0);
    for ( size_t argument_index = 0;
          argument_index < arguments.size(); ++argument_index )
    {
        if ( proof == nullptr )
        {
            if ( block_observes_incoming_register(
                    blocks.front(), arguments[argument_index],
                    argument_index, ~uint64_t{0}, nullptr, inference) )
            {
                result.used[argument_index] = 1;
            }
            continue;
        }

        std::vector<uint64_t> incoming_bits(blocks.size(), 0);
        std::vector<size_t> worklist = {0};
        incoming_bits[0] = ~uint64_t{0};
        while ( !worklist.empty() )
        {
            const size_t block_index = worklist.back();
            worklist.pop_back();
            uint64_t live_after = incoming_bits[block_index];
            if ( block_observes_incoming_register(
                    blocks[block_index], arguments[argument_index],
                    argument_index, live_after, &live_after, inference) )
            {
                result.used[argument_index] = 1;
                break;
            }
            if ( live_after == 0 )
                continue;

            const auto successors =
                dispatcher_successors(blocks[block_index], *proof);
            if ( !successors )
                return std::nullopt;
            for ( ea_t successor : *successors )
            {
                const auto found = block_by_start.find(successor);
                if ( found == block_by_start.end() )
                    return std::nullopt;
                const uint64_t merged =
                    incoming_bits[found->second] | live_after;
                if ( merged != incoming_bits[found->second] )
                {
                    incoming_bits[found->second] = merged;
                    worklist.push_back(found->second);
                }
            }
        }
    }

    return result;
}

std::optional<argument_usage_t> infer_native_argument_usage(
    ea_t entry,
    argument_inference_t &inference)
{
    const auto cached = inference.cache.find(entry);
    if ( cached != inference.cache.end() )
        return cached->second;
    if ( PH.id != PLFM_386 || !inf_is_64bit()
      || inference.active.count(entry) != 0 )
    {
        return std::nullopt;
    }

    const func_t *function = get_func(entry);
    if ( function == nullptr || (function->flags & FUNC_LIB) != 0
      || is_userti(entry) )
    {
        inference.cache[entry] = std::nullopt;
        return std::nullopt;
    }

    inference.active.insert(entry);
    std::optional<argument_usage_t> result;
    if ( auto proof = prove_split_dispatcher(entry, function) )
    {
        result = infer_argument_usage_from_blocks(
            proof->blocks, &*proof, inference);
    }
    else if ( auto linear = decode_linear_function(entry, function) )
    {
        result = infer_argument_usage_from_blocks(
            {*linear}, nullptr, inference);
    }
    inference.active.erase(entry);

    if ( result )
    {
        tinfo_t guessed;
        func_type_data_t details;
        if ( guess_tinfo(&guessed, entry) != GUESS_FUNC_FAILED
          && guessed.get_func_details(&details) )
        {
            if ( details.is_vararg_cc() )
                result = std::nullopt;
            else
            {
                const size_t typed_register_arguments =
                    std::min(details.size(), result->used.size());
                for ( size_t index = 0;
                      index < typed_register_arguments; ++index )
                {
                    result->used[index] = 1;
                }
            }
        }
    }
    inference.cache[entry] = result;
    return result;
}

std::optional<argument_usage_t> unresolved_argument_usage(ea_t entry)
{
    if ( PH.id != PLFM_386 || !inf_is_64bit() || is_userti(entry) )
        return std::nullopt;

    const func_t *function = get_func(entry);
    if ( function == nullptr || function->start_ea != entry
      || (function->flags & FUNC_LIB) != 0 )
    {
        return std::nullopt;
    }

    const auto proof = prove_split_dispatcher(entry, function);
    if ( !proof )
        return std::nullopt;

    argument_inference_t inference;
    inference.active.insert(entry);
    const auto usage =
        infer_argument_usage_from_blocks(
            proof->blocks, &*proof, inference);
    inference.active.erase(entry);
    if ( !usage || usage->used.empty() || usage->used[0] == 0 )
        return std::nullopt;

    tinfo_t guessed;
    func_type_data_t details;
    if ( guess_tinfo(&guessed, entry) == GUESS_FUNC_FAILED
      || !guessed.get_func_details(&details) || details.is_vararg_cc() )
    {
        deobf::log_verbose(
            "[resolver_args] %a: guessed prototype rejected: args=%zu "
            "vararg=%d\n",
            entry, details.size(),
            details.is_vararg_cc() ? 1 : 0);
        return std::nullopt;
    }
    deobf::log_verbose(
        "[resolver_args] Proven closed split dispatcher at %a: "
        "%zu targets, register-use mask=%d%d%d%d%d%d\n",
        entry, proof->targets.size(),
        usage->used.size() > 0 ? usage->used[0] : 0,
        usage->used.size() > 1 ? usage->used[1] : 0,
        usage->used.size() > 2 ? usage->used[2] : 0,
        usage->used.size() > 3 ? usage->used[3] : 0,
        usage->used.size() > 4 ? usage->used[4] : 0,
        usage->used.size() > 5 ? usage->used[5] : 0);
    return usage;
}

int argument_usage_index(
    const argument_usage_t &usage,
    int register_id)
{
    const auto found = std::find(
        usage.registers.begin(), usage.registers.end(), register_id);
    return found == usage.registers.end()
         ? -1 : static_cast<int>(found - usage.registers.begin());
}

bool neutralizable_call_argument(
    const mcallarg_t &argument,
    const argument_usage_t &usage)
{
    if ( !argument.argloc.is_reg1()
      || !chernobog::bitvector::valid_byte_width(argument.size)
      || argument.has_side_effects(true) )
        return false;
    const int index = argument_usage_index(usage, argument.argloc.reg1());
    return index >= 0 && usage.used[static_cast<size_t>(index)] == 0;
}

size_t neutralizable_register_arguments(
    const mcallinfo_t &info,
    const argument_usage_t &usage)
{
    if ( (info.flags & FCI_FINAL) != 0 || info.args.empty()
      || info.solid_args < 0
      || static_cast<size_t>(info.solid_args) < info.args.size() )
        return 0;

    size_t neutralizable = 0;
    for ( const mcallarg_t &argument : info.args )
    {
        if ( neutralizable_call_argument(argument, usage) )
            ++neutralizable;
    }
    return neutralizable;
}

} // namespace

int resolver_call_args_handler_t::run(
    mbl_array_t *mba,
    deobf_ctx_t *ctx)
{
    if ( mba == nullptr || mba->maturity != MMAT_CALLS )
        return 0;

    direct_call_collector_t collector;
    mba->for_all_insns(collector);

    int changes = 0;
    for ( auto &cohort : collector.calls )
    {
        std::vector<call_site_t> &sites = cohort.second;
        if ( sites.size() < minimum_recurrent_calls )
            continue;
        deobf::log_verbose(
            "[resolver_args] Checking %zu recurrent calls to %a\n",
            sites.size(), cohort.first);
        const std::optional<argument_usage_t> usage =
            unresolved_argument_usage(cohort.first);
        if ( !usage )
            continue;

        size_t neutralizable_sites = 0;
        for ( const call_site_t &site : sites )
        {
            if ( site.instruction != nullptr
              && site.instruction->d.t == mop_f
              && site.instruction->d.f != nullptr
              && neutralizable_register_arguments(
                    *site.instruction->d.f, *usage) != 0 )
            {
                ++neutralizable_sites;
            }
        }
        // Require a coherent recurrent-call cohort rather than specializing a
        // target from a few anomalous call sites.
        if ( neutralizable_sites < minimum_recurrent_calls
          || neutralizable_sites * 4 < sites.size() * 3 )
        {
            continue;
        }

        size_t cohort_removed = 0;
        size_t changed_sites = 0;
        for ( const call_site_t &site : sites )
        {
            if ( site.instruction == nullptr
              || site.instruction->d.t != mop_f
              || site.instruction->d.f == nullptr )
            {
                continue;
            }
            mcallinfo_t &info = *site.instruction->d.f;
            if ( neutralizable_register_arguments(info, *usage) == 0 )
                continue;

            size_t removed_here = 0;
            for ( mcallarg_t &argument : info.args )
            {
                if ( neutralizable_call_argument(argument, *usage) )
                {
                    // Preserve the physical ABI slot and its register location.
                    // A compacted prototype would incorrectly shift a later
                    // register argument left. The callee cannot observe this
                    // pure value, so replace it with zero and let ordinary DCE
                    // remove the now-unreferenced mixer chain.
                    argument.make_number(
                        0, argument.size, argument.ea);
                    ++removed_here;
                }
            }
            if ( removed_here == 0 )
                continue;

            info.flags |= FCI_FINAL;
            if ( site.block != nullptr )
                site.block->mark_lists_dirty();
            cohort_removed += removed_here;
            ++changed_sites;
            changes += static_cast<int>(removed_here);
        }
        if ( cohort_removed != 0 )
        {
            deobf::log(
                "[resolver_args] Neutralized %zu proven-unused register "
                "argument(s) across %zu recurrent calls to %a\n",
                cohort_removed, changed_sites, cohort.first);
        }
    }

    if ( changes > 0 )
    {
        mba->mark_chains_dirty();
        if ( ctx != nullptr )
            ctx->expressions_simplified += changes;
    }
    return changes;
}
