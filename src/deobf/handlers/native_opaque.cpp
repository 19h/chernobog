#include "native_opaque.h"

#include "global_const.h"
#include "../analysis/arch_utils.h"
#include "../../common/arm64_branch.h"
#include "../../common/arm64_predicate.h"
#include "../../common/bitvector.h"
#include "../../common/warn_off.h"
#include <gdl.hpp>
#include "../../common/warn_on.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

#include <map>
#include <set>

namespace {

constexpr uint32_t ARM64_NOP = 0xD503201FU;

struct predicate_proof_t
{
    ea_t function_ea = BADADDR;
    ea_t branch_ea = BADADDR;
    ea_t taken_target = BADADDR;
    bool taken = false;
    uint32_t original_word = 0;
    std::set<ea_t> scalar_evidence;
};

struct stack_slot_t
{
    int64_t offset = 0;
    int size = 0;

    bool operator<(const stack_slot_t &other) const
    {
        return std::tie(offset, size) < std::tie(other.offset, other.size);
    }
};

bool stack_slots_overlap(const stack_slot_t &left, const stack_slot_t &right)
{
    const int64_t left_end = left.offset + left.size;
    const int64_t right_end = right.offset + right.size;
    return left.size <= 0 || right.size <= 0
        || (left.offset < right_end && right.offset < left_end);
}

struct block_evaluator_t
{
    std::map<int, uint64_t> registers;
    std::map<int, int64_t> frame_offsets;
    std::map<stack_slot_t, uint64_t> stack_values;
    std::optional<chernobog::arm64_predicate::nzcv_t> flags;
    std::set<ea_t> scalar_evidence;
    int frame_register = -1;

    block_evaluator_t()
        : frame_register(str2reg("X29"))
    {
        if ( frame_register >= 0 )
            frame_offsets[frame_register] = 0;
    }

    static int operand_bytes(const op_t &operand)
    {
        const size_t size = get_dtype_size(operand.dtype);
        return chernobog::bitvector::valid_byte_width(static_cast<int>(size))
            ? static_cast<int>(size) : 0;
    }

    static uint64_t truncate(uint64_t value, int bytes)
    {
        return chernobog::bitvector::truncate(value, bytes);
    }

    static bool plain_memory_operand(const op_t &operand)
    {
        return (operand.type == o_mem || operand.type == o_displ
             || operand.type == o_phrase)
            && operand.specflag1 == 0 && operand.specflag2 == 0
            && operand.specflag3 == 0 && operand.specflag4 == 0;
    }

    static bool is_zero_register(const op_t &operand)
    {
        if ( operand.type != o_reg )
            return false;
        qstring name;
        const int bytes = operand_bytes(operand);
        if ( bytes == 0 || get_reg_name(&name, operand.reg, bytes) <= 0 )
            return false;
        return name == "WZR" || name == "XZR";
    }

    std::optional<uint64_t> register_value(const op_t &operand) const
    {
        if ( operand.type != o_reg )
            return std::nullopt;
        const int bytes = operand_bytes(operand);
        if ( bytes == 0 )
            return std::nullopt;
        if ( is_zero_register(operand) )
            return uint64_t{0};
        const auto found = registers.find(operand.reg);
        return found == registers.end()
            ? std::nullopt
            : std::optional<uint64_t>(truncate(found->second, bytes));
    }

    std::optional<uint64_t> value(const op_t &operand) const
    {
        const int bytes = operand_bytes(operand);
        if ( bytes == 0 )
            return std::nullopt;

        uint64_t result = 0;
        if ( operand.type == o_imm )
        {
            result = operand.value;
            if ( operand.specval != 0 )
            {
                if ( operand.specval >= static_cast<ea_t>(bytes * 8) )
                    return std::nullopt;
                result <<= static_cast<unsigned>(operand.specval);
            }
        }
        else if ( operand.type == o_reg )
        {
            const auto known = register_value(operand);
            if ( !known )
                return std::nullopt;
            result = *known;
        }
        else if ( operand.type == o_idpspec0 )
        {
            // The ARM64 processor module represents a register shifted left
            // by an immediate as o_idpspec0(reg, value=shift). No other
            // processor-specific operand form is admitted here.
            if ( operand.specflag1 != 0 || operand.specflag2 != 0
              || operand.specflag3 != 0 || operand.specflag4 != 0 )
            {
                return std::nullopt;
            }
            op_t source = operand;
            source.type = o_reg;
            const auto known = register_value(source);
            if ( !known || operand.value >= static_cast<uval_t>(bytes * 8) )
                return std::nullopt;
            result = *known << static_cast<unsigned>(operand.value);
        }
        else
        {
            return std::nullopt;
        }
        return truncate(result, bytes);
    }

    void invalidate_register(const op_t &operand)
    {
        if ( operand.type == o_reg && !is_zero_register(operand) )
        {
            registers.erase(operand.reg);
            frame_offsets.erase(operand.reg);
        }
    }

    void write_register(const op_t &destination,
                        const std::optional<uint64_t> &known)
    {
        if ( destination.type != o_reg || is_zero_register(destination) )
            return;
        frame_offsets.erase(destination.reg);
        const int bytes = operand_bytes(destination);
        if ( !known || bytes == 0 )
            registers.erase(destination.reg);
        else
            registers[destination.reg] = truncate(*known, bytes);
    }

    void write_frame_register(const op_t &destination, int64_t offset)
    {
        if ( destination.type != o_reg || is_zero_register(destination)
          || operand_bytes(destination) != 8 )
        {
            invalidate_register(destination);
            return;
        }
        registers.erase(destination.reg);
        frame_offsets[destination.reg] = offset;
    }

    std::optional<ea_t> memory_address(const op_t &operand) const
    {
        if ( !plain_memory_operand(operand) )
            return std::nullopt;
        if ( operand.type == o_mem )
            return operand.addr;

        op_t base = operand;
        base.type = o_reg;
        base.dtype = dt_qword;
        const auto known_base = register_value(base);
        if ( !known_base )
            return std::nullopt;
        const adiff_t displacement = static_cast<adiff_t>(operand.addr);
        return static_cast<ea_t>(*known_base + displacement);
    }

    std::optional<int64_t> frame_address(const op_t &operand) const
    {
        if ( !plain_memory_operand(operand) || operand.type == o_mem )
            return std::nullopt;
        const auto found = frame_offsets.find(operand.reg);
        if ( found == frame_offsets.end() )
            return std::nullopt;
        return found->second + static_cast<adiff_t>(operand.addr);
    }

    void invalidate_stack_slot(const stack_slot_t &written)
    {
        for ( auto iterator = stack_values.begin();
              iterator != stack_values.end(); )
        {
            iterator = stack_slots_overlap(iterator->first, written)
                ? stack_values.erase(iterator) : std::next(iterator);
        }
    }

    bool load(const insn_t &instruction)
    {
        if ( instruction.Op1.type != o_reg )
            return false;
        const int bytes = operand_bytes(instruction.Op2);
        const int destination_bytes = operand_bytes(instruction.Op1);
        const auto stack_address = frame_address(instruction.Op2);
        if ( bytes != 0 && destination_bytes != 0 && stack_address )
        {
            const auto found = stack_values.find({*stack_address, bytes});
            write_register(
                instruction.Op1,
                found == stack_values.end()
                    ? std::nullopt
                    : std::optional<uint64_t>(found->second));
            return true;
        }
        const auto address = memory_address(instruction.Op2);
        if ( bytes == 0 || destination_bytes == 0 || !address )
        {
            invalidate_register(instruction.Op1);
            return true;
        }
        const auto loaded = global_const_handler_t::read_admitted_scalar(
            *address, bytes);
        write_register(instruction.Op1, loaded);
        if ( loaded )
            scalar_evidence.insert(*address);
        return true;
    }

    bool store(const insn_t &instruction)
    {
        if ( !plain_memory_operand(instruction.Op2) )
        {
            return false;
        }
        const int bytes = operand_bytes(instruction.Op2);
        if ( bytes == 0 )
        {
            stack_values.clear();
            return true;
        }
        const auto stack_address = frame_address(instruction.Op2);
        if ( stack_address )
        {
            const stack_slot_t slot{*stack_address, bytes};
            invalidate_stack_slot(slot);
            const auto source = value(instruction.Op1);
            if ( source )
                stack_values[slot] = truncate(*source, bytes);
            return true;
        }
        if ( memory_address(instruction.Op2) )
            return true; // Exact non-stack address cannot alias a frame slot.

        // An unresolved store base can alias any tracked stack slot.
        stack_values.clear();
        return true;
    }

    static bool sets_flags(const insn_t &instruction)
    {
        return (instruction.auxpref & 1U) != 0
            || instruction.itype == ARM_cmp
            || instruction.itype == ARM_cmn
            || instruction.itype == ARM_tst
            || instruction.itype == ARM_teq;
    }

    bool binary(const insn_t &instruction)
    {
        if ( instruction.Op1.type != o_reg )
            return false;
        switch ( instruction.itype )
        {
            case ARM_add:
            case ARM_sub:
            case ARM_mul:
            case ARM_and:
            case ARM_eor:
            case ARM_orr:
            case ARM_bic:
            case ARM_orn:
            case ARM_eon:
            case ARM_udiv:
                break;
            default:
                return false;
        }
        const int bytes = operand_bytes(instruction.Op1);
        const auto left = value(instruction.Op2);
        const auto right = value(instruction.Op3);
        std::optional<uint64_t> result;
        if ( bytes != 0 && left && right )
        {
            const uint64_t mask = chernobog::bitvector::mask(bytes);
            switch ( instruction.itype )
            {
                case ARM_add: result = (*left + *right) & mask; break;
                case ARM_sub: result = (*left - *right) & mask; break;
                case ARM_mul: result = (*left * *right) & mask; break;
                case ARM_and: result = *left & *right; break;
                case ARM_eor: result = *left ^ *right; break;
                case ARM_orr: result = *left | *right; break;
                case ARM_bic: result = *left & ~*right; break;
                case ARM_orn: result = *left | ~*right; break;
                case ARM_eon: result = *left ^ ~*right; break;
                case ARM_udiv: result = *right == 0 ? 0 : *left / *right; break;
                default: break;
            }
            result = truncate(*result, bytes);
        }
        write_register(instruction.Op1, result);

        if ( sets_flags(instruction) )
        {
            if ( !left || !right || bytes == 0 )
            {
                flags.reset();
            }
            else if ( instruction.itype == ARM_add )
            {
                flags = chernobog::arm64_predicate::add_flags(
                    *left, *right, bytes);
            }
            else if ( instruction.itype == ARM_sub )
            {
                flags = chernobog::arm64_predicate::sub_flags(
                    *left, *right, bytes);
            }
            else
            {
                const uint64_t known_result = result.value_or(0);
                const uint64_t sign = uint64_t{1} << (bytes * 8 - 1);
                flags = chernobog::arm64_predicate::nzcv_t{
                    (known_result & sign) != 0,
                    known_result == 0,
                    false,
                    false,
                };
            }
        }
        return true;
    }

    void process(const insn_t &instruction)
    {
        if ( is_call_insn(instruction) )
        {
            registers.clear();
            frame_offsets.clear();
            stack_values.clear();
            if ( frame_register >= 0 )
                frame_offsets[frame_register] = 0;
            flags.reset();
            return;
        }

        if ( instruction.itype == ARM_adrp
          || instruction.itype == ARM_adrl
          || instruction.itype == ARM_adr )
        {
            const std::optional<uint64_t> address =
                instruction.Op2.type == o_imm
                ? std::optional<uint64_t>(instruction.Op2.value)
                : std::nullopt;
            write_register(instruction.Op1, address);
            return;
        }

        if ( instruction.itype == ARM_ldr
          || instruction.itype == ARM_ldur
          || instruction.itype == ARM_ldapr )
        {
            (void)load(instruction);
            return;
        }

        if ( instruction.itype == ARM_str
          || instruction.itype == ARM_stur
          || instruction.itype == ARM_stlr )
        {
            if ( !store(instruction) )
                stack_values.clear();
            return;
        }

        if ( instruction.itype == ARM_mov
          || instruction.itype == ARM_movl )
        {
            if ( instruction.Op2.type == o_reg )
            {
                const auto frame = frame_offsets.find(instruction.Op2.reg);
                if ( frame != frame_offsets.end() )
                {
                    write_frame_register(instruction.Op1, frame->second);
                    return;
                }
            }
            write_register(instruction.Op1, value(instruction.Op2));
            return;
        }
        if ( instruction.itype == ARM_mvn || instruction.itype == ARM_neg )
        {
            const int bytes = operand_bytes(instruction.Op1);
            const auto source = value(instruction.Op2);
            std::optional<uint64_t> result;
            if ( source && bytes != 0 )
            {
                result = instruction.itype == ARM_mvn
                    ? truncate(~*source, bytes)
                    : truncate(uint64_t{0} - *source, bytes);
            }
            write_register(instruction.Op1, result);
            if ( sets_flags(instruction) )
                flags.reset();
            return;
        }

        if ( (instruction.itype == ARM_add || instruction.itype == ARM_sub)
          && instruction.Op1.type == o_reg
          && instruction.Op2.type == o_reg )
        {
            const auto frame = frame_offsets.find(instruction.Op2.reg);
            const auto delta = value(instruction.Op3);
            if ( frame != frame_offsets.end() && delta
              && operand_bytes(instruction.Op1) == 8
              && !sets_flags(instruction) )
            {
                const int64_t signed_delta = static_cast<int64_t>(*delta);
                write_frame_register(
                    instruction.Op1,
                    instruction.itype == ARM_add
                        ? frame->second + signed_delta
                        : frame->second - signed_delta);
                return;
            }
        }

        if ( binary(instruction) )
            return;

        if ( instruction.itype == ARM_cmp || instruction.itype == ARM_cmn )
        {
            const auto left = value(instruction.Op1);
            const auto right = value(instruction.Op2);
            const int bytes = operand_bytes(instruction.Op1);
            if ( !left || !right || bytes == 0 )
                flags.reset();
            else if ( instruction.itype == ARM_cmp )
                flags = chernobog::arm64_predicate::sub_flags(
                    *left, *right, bytes);
            else
                flags = chernobog::arm64_predicate::add_flags(
                    *left, *right, bytes);
            return;
        }

        const uint32_t feature = instruction.get_canon_feature(PH);
        for ( uint index = 0; index < UA_MAXOP; ++index )
        {
            const op_t &operand = instruction.ops[index];
            if ( operand.type == o_void )
                break;
            if ( operand.type != o_reg && has_cf_chg(feature, index) )
            {
                // Unsupported memory writes (for example STP or indexed
                // addressing) may alias any tracked frame slot.
                stack_values.clear();
                break;
            }
        }
        for ( uint index = 0; index < UA_MAXOP; ++index )
        {
            const op_t &operand = instruction.ops[index];
            if ( operand.type == o_void )
                break;
            if ( has_cf_chg(feature, index) )
                invalidate_register(operand);
        }
        if ( sets_flags(instruction) )
            flags.reset();
    }

    std::optional<bool> evaluate_branch(const insn_t &instruction) const
    {
        if ( instruction.itype == ARM_b
          && instruction.Op1.type == o_near
          && instruction.segpref <= 0xD )
        {
            return flags
                ? chernobog::arm64_predicate::evaluate(
                      static_cast<uint8_t>(instruction.segpref), *flags)
                : std::nullopt;
        }
        if ( (instruction.itype == ARM_cbz || instruction.itype == ARM_cbnz)
          && instruction.Op1.type == o_reg
          && instruction.Op2.type == o_near )
        {
            const auto known = register_value(instruction.Op1);
            if ( !known )
                return std::nullopt;
            const bool zero = *known == 0;
            return instruction.itype == ARM_cbz ? zero : !zero;
        }
        return std::nullopt;
    }
};

bool conditional_branch(const insn_t &instruction, ea_t *target)
{
    if ( instruction.itype == ARM_b
      && instruction.Op1.type == o_near
      && instruction.segpref <= 0xD )
    {
        if ( target )
            *target = instruction.Op1.addr;
        return true;
    }
    if ( (instruction.itype == ARM_cbz || instruction.itype == ARM_cbnz)
      && instruction.Op1.type == o_reg
      && instruction.Op2.type == o_near )
    {
        if ( target )
            *target = instruction.Op2.addr;
        return true;
    }
    return false;
}

std::optional<predicate_proof_t> analyze_block(
    ea_t function_ea, const qbasic_block_t &block)
{
    ea_t tail_ea = prev_head(block.end_ea, block.start_ea);
    if ( tail_ea == BADADDR || !is_code(get_flags(tail_ea)) )
        return std::nullopt;

    insn_t branch;
    ea_t target = BADADDR;
    if ( decode_insn(&branch, tail_ea) != 4
      || !conditional_branch(branch, &target)
      || target == BADADDR || !is_code(get_flags(target))
      || get_func(target) != get_func(function_ea) )
    {
        return std::nullopt;
    }

    block_evaluator_t evaluator;
    for ( ea_t ea = block.start_ea; ea < tail_ea; ea = next_head(ea, tail_ea) )
    {
        if ( !is_code(get_flags(ea)) )
            continue;
        insn_t instruction;
        if ( decode_insn(&instruction, ea) <= 0 )
            return std::nullopt;
        evaluator.process(instruction);
    }
    const auto result = evaluator.evaluate_branch(branch);
    if ( !result )
        return std::nullopt;

    predicate_proof_t proof;
    proof.function_ea = function_ea;
    proof.branch_ea = tail_ea;
    proof.taken_target = target;
    proof.taken = *result;
    proof.original_word = static_cast<uint32_t>(get_dword(tail_ea));
    proof.scalar_evidence = evaluator.scalar_evidence;
    return proof;
}

bool apply_proof(const predicate_proof_t &proof)
{
    if ( proof.branch_ea == BADADDR || proof.taken_target == BADADDR
      || static_cast<uint32_t>(get_dword(proof.branch_ea))
          != proof.original_word )
    {
        return false;
    }

    std::optional<uint32_t> replacement;
    if ( proof.taken )
        replacement = chernobog::arm64_branch::encode_b(
            proof.branch_ea, proof.taken_target);
    else
        replacement = ARM64_NOP;
    if ( !replacement )
        return false;
    if ( !patch_dword(proof.branch_ea, *replacement)
      && static_cast<uint32_t>(get_dword(proof.branch_ea)) != *replacement )
    {
        return false;
    }

    std::vector<ea_t> stale_targets;
    xrefblk_t xref;
    for ( bool ok = xref.first_from(proof.branch_ea, XREF_FAR);
          ok;
          ok = xref.next_from() )
    {
        if ( xref.iscode && (!proof.taken || xref.to != proof.taken_target) )
            stale_targets.push_back(xref.to);
    }
    for ( ea_t target : stale_targets )
        del_cref(proof.branch_ea, target, false);
    if ( proof.taken )
        add_cref(proof.branch_ea, proof.taken_target, fl_JN);

    qstring comment;
    comment.sprnt(
        "DEOBF: reversible native constant predicate; original=0x%08X; "
        "result=%s; scalar_proofs=%zu",
        proof.original_word, proof.taken ? "taken" : "fallthrough",
        proof.scalar_evidence.size());
    set_cmt(proof.branch_ea, comment.c_str(), false);
    plan_range(proof.branch_ea, proof.branch_ea + 4);
    deobf::log(
        "[native_opaque] Patched ARM64 conditional at %a to %s "
        "(%zu admitted scalars)\n",
        proof.branch_ea, proof.taken ? "taken B" : "fallthrough NOP",
        proof.scalar_evidence.size());
    return true;
}

} // namespace

int native_opaque_handler_t::mode()
{
    qstring value;
    return qgetenv("CHERNOBOG_NATIVE_OPAQUE", &value)
        && !value.empty() && value[0] == '1' ? 1 : 0;
}

native_opaque_stats_t native_opaque_handler_t::run()
{
    native_opaque_stats_t stats;
    if ( mode() == 0 || !arch::is_arm64() )
        return stats;

    std::vector<predicate_proof_t> proofs;
    const size_t function_count = get_func_qty();
    for ( size_t function_index = 0;
          function_index < function_count;
          ++function_index )
    {
        func_t *function = getn_func(function_index);
        if ( function == nullptr || (function->flags & FUNC_TAIL) != 0 )
            continue;
        ++stats.functions_scanned;
        qflow_chart_t flowchart(
            "", function, BADADDR, BADADDR, FC_NOEXT);
        for ( const qbasic_block_t &block : flowchart.blocks )
        {
            ++stats.blocks_scanned;
            const ea_t tail_ea = prev_head(block.end_ea, block.start_ea);
            insn_t tail;
            if ( tail_ea == BADADDR || decode_insn(&tail, tail_ea) <= 0
              || !conditional_branch(tail, nullptr) )
            {
                continue;
            }
            ++stats.conditional_branches;
            const auto proof = analyze_block(function->start_ea, block);
            if ( proof )
            {
                ++stats.predicates_proved;
                proofs.push_back(*proof);
            }
        }
    }

    for ( const predicate_proof_t &proof : proofs )
    {
        if ( apply_proof(proof) )
            ++stats.branches_patched;
    }
    deobf::log(
        "[native_opaque] functions=%d blocks=%d conditional=%d "
        "proved=%d patched=%d\n",
        stats.functions_scanned, stats.blocks_scanned,
        stats.conditional_branches, stats.predicates_proved,
        stats.branches_patched);
    return stats;
}
