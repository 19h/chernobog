#include "hikari_cfg.h"

#include "../analysis/arch_utils.h"
#include "../../common/arm64_branch.h"
#include "../../common/ida_memory.h"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include "../../common/warn_on.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

#include <array>
#include <deque>
#include <limits>
#include <tuple>

namespace {

constexpr size_t TAIL_WINDOW = 256;
constexpr uint32_t ARM64_NOP = 0xD503201FU;

struct state_slot_t {
    int base_reg = -1;
    int64_t offset = 0;

    bool operator<(const state_slot_t &other) const
    {
        return std::tie(base_reg, offset)
             < std::tie(other.base_reg, other.offset);
    }
};

struct native_insn_t {
    ea_t ea = BADADDR;
    insn_t insn;
};

struct dispatcher_proof_t {
    ea_t function_ea = BADADDR;
    ea_t function_end = BADADDR;
    ea_t branch_ea = BADADDR;
    ea_t cset_ea = BADADDR;
    size_t cset_index = 0;
    int index_reg = -1;
    uint8_t condition = 0;
    ea_t table = BADADDR;
    int32_t bias = 0;
    uint32_t key = 0;
    std::array<ea_t, 2> targets = {BADADDR, BADADDR};
    std::vector<native_insn_t> tail;
};

using state_map_t = std::map<state_slot_t, ea_t>;
using immediate_map_t = std::map<int, std::set<uint32_t>>;

bool is_full_immediate_move(const insn_t &instruction)
{
    return (instruction.itype == ARM_mov
         || instruction.itype == ARM_movl)
        && instruction.Op1.type == o_reg
        && instruction.Op2.type == o_imm;
}

void cfg_debug(ea_t function_ea, const char *reason)
{
    if ( !deobf::debug_enabled() )
        return;
    qstring line;
    line.sprnt("function=%a reject=%s\n", function_ea, reason);
    FILE *file = qfopen("/tmp/chernobog_hikari_cfg.log", "a");
    if ( file )
    {
        qfwrite(file, line.c_str(), line.length());
        qfclose(file);
    }
}

bool is_changed_register(const insn_t &instruction, int *out)
{
    if ( instruction.Op1.type != o_reg )
        return false;
    const uint32 feature = instruction.get_canon_feature(PH);
    if ( !has_cf_chg(feature, 0) )
        return false;
    if ( out )
        *out = instruction.Op1.reg;
    return true;
}

std::vector<native_insn_t> function_instructions(
    func_t *function, size_t retain_last = std::numeric_limits<size_t>::max())
{
    std::vector<native_insn_t> result;
    if ( !function )
        return result;

    func_item_iterator_t iterator(function);
    for ( bool ok = iterator.first(); ok; ok = iterator.next_code() )
    {
        const ea_t ea = iterator.current();
        if ( !is_code(get_flags(ea)) )
            continue;
        native_insn_t item;
        item.ea = ea;
        if ( decode_insn(&item.insn, ea) <= 0 )
            continue;
        result.push_back(item);
        if ( result.size() > retain_last )
            result.erase(result.begin());
    }
    return result;
}

bool is_state_base(int reg, int x19, int x29)
{
    return reg == x19 || reg == x29;
}

state_map_t collect_state_tables(func_t *function, int x19, int x29)
{
    state_map_t result;
    std::map<int, ea_t> register_constants;
    for ( const native_insn_t &item : function_instructions(function) )
    {
        const insn_t &instruction = item.insn;
        if ( (instruction.itype == ARM_str || instruction.itype == ARM_stur)
          && instruction.Op1.type == o_reg
          && (instruction.Op2.type == o_displ
           || instruction.Op2.type == o_phrase) )
        {
            const int source = instruction.Op1.reg;
            const int base = instruction.Op2.reg;
            const int64_t offset = static_cast<int64_t>(instruction.Op2.addr);
            const auto constant = register_constants.find(source);
            if ( constant != register_constants.end()
              && is_state_base(base, x19, x29) )
            {
                result[{base, offset}] = constant->second;
            }
        }
        else if ( instruction.itype == ARM_stp
               && instruction.Op1.type == o_reg
               && instruction.Op2.type == o_reg
               && (instruction.Op3.type == o_displ
                || instruction.Op3.type == o_phrase) )
        {
            const int base = instruction.Op3.reg;
            const int64_t offset = static_cast<int64_t>(instruction.Op3.addr);
            if ( is_state_base(base, x19, x29) )
            {
                const auto first = register_constants.find(instruction.Op1.reg);
                const auto second = register_constants.find(instruction.Op2.reg);
                if ( first != register_constants.end() )
                    result[{base, offset}] = first->second;
                if ( second != register_constants.end() )
                    result[{base, offset + 8}] = second->second;
            }
        }

        int changed = -1;
        if ( is_changed_register(instruction, &changed) )
            register_constants.erase(changed);
        if ( instruction.itype == ARM_adrl
          && instruction.Op1.type == o_reg
          && instruction.Op2.type == o_imm )
        {
            register_constants[instruction.Op1.reg] =
                static_cast<ea_t>(instruction.Op2.value);
        }
    }
    return result;
}

bool exact_function_entry(ea_t ea)
{
    const segment_t *segment = getseg(ea);
    const func_t *function = get_func(ea);
    return segment && (segment->perm & SEGPERM_EXEC) != 0
        && function && (function->flags & FUNC_TAIL) == 0
        && function->start_ea == ea;
}

bool exact_fixup(ea_t ea)
{
    fixup_data_t fixup;
    return get_fixup(&fixup, ea) && !fixup.is_unused();
}

std::optional<std::tuple<int32_t, ea_t, ea_t, uint32_t>> infer_targets(
    ea_t table,
    int key_reg,
    const std::optional<uint32_t> &local_key,
    const immediate_map_t &immediates,
    const std::vector<ea_t> &function_starts)
{
    const segment_t *segment = getseg(table);
    if ( !segment || (segment->perm & SEGPERM_EXEC) != 0
      || !exact_fixup(table) || !exact_fixup(table + 8)
      || !is_loaded(table + 16) )
    {
        return std::nullopt;
    }

    const std::optional<uint64_t> entry0 =
        chernobog::ida_memory::read_integer(table, 8);
    const std::optional<uint64_t> entry1 =
        chernobog::ida_memory::read_integer(table + 8, 8);
    const std::optional<uint64_t> encoded =
        chernobog::ida_memory::read_integer(table + 16, 4);
    if ( !entry0 || !entry1 || !encoded )
        return std::nullopt;

    std::set<std::tuple<int32_t, ea_t, ea_t, uint32_t>> candidates;
    for ( ea_t target0 : function_starts )
    {
        const int64_t wide_bias = static_cast<int64_t>(target0)
                                - static_cast<int64_t>(*entry0);
        if ( wide_bias < std::numeric_limits<int32_t>::min()
          || wide_bias > std::numeric_limits<int32_t>::max() )
        {
            continue;
        }
        const int32_t bias = static_cast<int32_t>(wide_bias);
        const ea_t target1 = static_cast<ea_t>(
            static_cast<uint64_t>(*entry1) + static_cast<int64_t>(bias));
        if ( !exact_function_entry(target0) || !exact_function_entry(target1) )
            continue;

        const uint32_t required_key = static_cast<uint32_t>(*encoded)
            ^ (uint32_t{0} - static_cast<uint32_t>(bias));
        bool key_matches = local_key && *local_key == required_key;
        if ( !local_key )
        {
            const auto observed = immediates.find(key_reg);
            key_matches = observed != immediates.end()
                       && observed->second.count(required_key) != 0;
        }
        if ( key_matches )
            candidates.emplace(bias, target0, target1, required_key);
    }
    if ( candidates.size() != 1 )
    {
        if ( deobf::debug_enabled() )
        {
            qstring detail;
            detail.sprnt(
                "infer table=%a candidates=%zu key_reg=%d local=%X\n",
                table, candidates.size(), key_reg,
                local_key ? *local_key : uint32_t{0});
            FILE *file = qfopen("/tmp/chernobog_hikari_cfg.log", "a");
            if ( file )
            {
                qfwrite(file, detail.c_str(), detail.length());
                qfclose(file);
            }
        }
        return std::nullopt;
    }
    return *candidates.begin();
}

int find_previous_definition(
    const std::vector<native_insn_t> &items, size_t before, int reg)
{
    for ( size_t cursor = before; cursor > 0; )
    {
        --cursor;
        int changed = -1;
        if ( is_changed_register(items[cursor].insn, &changed)
          && changed == reg )
        {
            return static_cast<int>(cursor);
        }
    }
    return -1;
}

std::optional<dispatcher_proof_t> analyze_dispatcher(
    func_t *function,
    const state_map_t &state_tables,
    const immediate_map_t &immediates,
    const std::vector<ea_t> &function_starts)
{
    if ( !function )
        return std::nullopt;
    std::vector<native_insn_t> items =
        function_instructions(function, TAIL_WINDOW);
    if ( items.empty() || items.back().insn.itype != ARM_br
      || items.back().insn.Op1.type != o_reg )
    {
        return std::nullopt;
    }

    dispatcher_proof_t proof;
    proof.function_ea = function->start_ea;
    proof.function_end = function->end_ea;
    proof.branch_ea = items.back().ea;
    const int branch_reg = items.back().insn.Op1.reg;

    const int add_index = find_previous_definition(
        items, items.size() - 1, branch_reg);
    if ( add_index < 0 )
    {
        cfg_debug(function->start_ea, "no terminal ADD definition");
        return std::nullopt;
    }
    const native_insn_t &add = items[static_cast<size_t>(add_index)];
    const uint32_t add_word = get_dword(add.ea);
    if ( add.insn.itype != ARM_add
      || add.insn.Op1.type != o_reg || add.insn.Op1.reg != branch_reg
      || add.insn.Op2.type != o_reg
      || (add_word & 0xFFE0FC00U) != 0x8B20C000U )
    {
        cfg_debug(function->start_ea, "terminal ADD encoding mismatch");
        return std::nullopt;
    }
    const int entry_reg = add.insn.Op2.reg;
    qstring offset_name;
    offset_name.sprnt("X%d", static_cast<int>((add_word >> 16) & 0x1FU));
    const int offset_reg = str2reg(offset_name.c_str());
    if ( offset_reg < 0 )
    {
        cfg_debug(function->start_ea, "terminal ADD register decode failed");
        return std::nullopt;
    }

    const int neg_index = find_previous_definition(
        items, static_cast<size_t>(add_index), offset_reg);
    if ( neg_index < 0 )
    {
        cfg_debug(function->start_ea, "no bias NEG definition");
        return std::nullopt;
    }
    const insn_t &neg = items[static_cast<size_t>(neg_index)].insn;
    if ( neg.itype != ARM_neg || neg.Op1.type != o_reg
      || neg.Op1.reg != offset_reg || neg.Op2.type != o_reg )
    {
        cfg_debug(function->start_ea, "bias NEG encoding mismatch");
        return std::nullopt;
    }
    const int encoded_reg = neg.Op2.reg;

    const int eor_index = find_previous_definition(
        items, static_cast<size_t>(neg_index), encoded_reg);
    if ( eor_index < 0 )
    {
        cfg_debug(function->start_ea, "no bias EOR definition");
        return std::nullopt;
    }
    const insn_t &eor = items[static_cast<size_t>(eor_index)].insn;
    if ( eor.itype != ARM_eor || eor.Op1.type != o_reg
      || eor.Op1.reg != encoded_reg
      || eor.Op2.type != o_reg || eor.Op3.type != o_reg )
    {
        cfg_debug(function->start_ea, "bias EOR encoding mismatch");
        return std::nullopt;
    }
    int key_reg = -1;
    if ( eor.Op2.reg == encoded_reg && eor.Op3.reg != encoded_reg )
        key_reg = eor.Op3.reg;
    else if ( eor.Op3.reg == encoded_reg && eor.Op2.reg != encoded_reg )
        key_reg = eor.Op2.reg;
    if ( key_reg < 0 )
    {
        cfg_debug(function->start_ea, "bias EOR has no distinct key register");
        return std::nullopt;
    }

    std::optional<uint32_t> local_key;
    const int key_definition = find_previous_definition(
        items, static_cast<size_t>(eor_index), key_reg);
    if ( key_definition >= 0 )
    {
        const insn_t &definition = items[static_cast<size_t>(key_definition)].insn;
        if ( is_full_immediate_move(definition) )
            local_key = static_cast<uint32_t>(definition.Op2.value);
    }

    const int indexed_index = find_previous_definition(
        items, static_cast<size_t>(add_index), entry_reg);
    if ( indexed_index < 0 )
    {
        cfg_debug(function->start_ea, "no indexed LDR definition");
        return std::nullopt;
    }
    const native_insn_t &indexed = items[static_cast<size_t>(indexed_index)];
    const uint32_t indexed_word = get_dword(indexed.ea);
    if ( indexed.insn.itype != ARM_ldr
      || indexed.insn.Op1.type != o_reg || indexed.insn.Op1.reg != entry_reg
      || (indexed_word & 0xFFE0FC00U) != 0xF8605800U )
    {
        cfg_debug(function->start_ea, "indexed LDR encoding mismatch");
        return std::nullopt;
    }
    const int raw_index_reg = static_cast<int>((indexed_word >> 16) & 0x1FU);
    qstring index_name;
    index_name.sprnt("X%d", raw_index_reg);
    const int index_reg = str2reg(index_name.c_str());
    const int base_reg = indexed.insn.Op2.reg;
    if ( index_reg < 0 || base_reg < 0 )
    {
        cfg_debug(function->start_ea, "indexed LDR register decode failed");
        return std::nullopt;
    }

    const int base_definition = find_previous_definition(
        items, static_cast<size_t>(indexed_index), base_reg);
    if ( base_definition < 0 )
    {
        cfg_debug(function->start_ea, "no table base definition");
        return std::nullopt;
    }
    const insn_t &base = items[static_cast<size_t>(base_definition)].insn;
    if ( (base.itype != ARM_ldr && base.itype != ARM_ldur)
      || base.Op1.type != o_reg || base.Op1.reg != base_reg
      || (base.Op2.type != o_displ && base.Op2.type != o_phrase) )
    {
        cfg_debug(function->start_ea, "table base load mismatch");
        return std::nullopt;
    }
    const state_slot_t slot = {
        base.Op2.reg,
        static_cast<int64_t>(base.Op2.addr),
    };
    const auto table = state_tables.find(slot);
    if ( table == state_tables.end() )
    {
        cfg_debug(function->start_ea, "table state slot absent from root map");
        return std::nullopt;
    }

    const int cset_index = find_previous_definition(
        items, static_cast<size_t>(indexed_index), index_reg);
    if ( cset_index < 0 )
    {
        cfg_debug(function->start_ea, "no CSET index definition");
        return std::nullopt;
    }
    const insn_t &cset = items[static_cast<size_t>(cset_index)].insn;
    if ( cset.itype != ARM_cset || cset.Op1.type != o_reg
      || cset.Op1.reg != index_reg || cset.Op2.value > 0xDU )
    {
        cfg_debug(function->start_ea, "CSET definition mismatch");
        return std::nullopt;
    }

    const auto targets = infer_targets(
        table->second, key_reg, local_key, immediates, function_starts);
    if ( !targets )
    {
        if ( deobf::debug_enabled() )
        {
            qstring detail;
            detail.sprnt(
                "function=%a detail table=%a key_reg=%d local_key=%llX "
                "entry0=%llX entry1=%llX encoded=%X\n",
                function->start_ea, table->second, key_reg,
                static_cast<unsigned long long>(
                    local_key ? *local_key : uint32_t{0}),
                static_cast<unsigned long long>(get_qword(table->second)),
                static_cast<unsigned long long>(get_qword(table->second + 8)),
                get_dword(table->second + 16));
            FILE *file = qfopen("/tmp/chernobog_hikari_cfg.log", "a");
            if ( file )
            {
                qfwrite(file, detail.c_str(), detail.length());
                qfclose(file);
            }
        }
        cfg_debug(function->start_ea, "target/key inference not unique");
        return std::nullopt;
    }
    proof.bias = std::get<0>(*targets);
    proof.targets = {std::get<1>(*targets), std::get<2>(*targets)};
    proof.key = std::get<3>(*targets);
    proof.table = table->second;
    proof.index_reg = index_reg;
    proof.condition = static_cast<uint8_t>(cset.Op2.value);
    proof.cset_index = static_cast<size_t>(cset_index);
    proof.cset_ea = items[proof.cset_index].ea;
    proof.tail = std::move(items);
    return proof;
}

const char *condition_name(uint8_t condition)
{
    static const char *names[] = {
        "EQ", "NE", "CS", "CC", "MI", "PL", "VS",
        "VC", "HI", "LS", "GE", "LT", "GT", "LE",
    };
    return condition < qnumber(names) ? names[condition] : "?";
}

void annotate_dispatcher(const dispatcher_proof_t &proof)
{
    add_cref(proof.branch_ea, proof.targets[0], fl_JN);
    add_cref(proof.branch_ea, proof.targets[1], fl_JN);
    qstring comment;
    comment.sprnt(
        "DEOBF: Hikari two-way %s: false=%a, true=%a; table=%a, bias=%d",
        condition_name(proof.condition), proof.targets[0], proof.targets[1],
        proof.table, proof.bias);
    set_cmt(proof.branch_ea, comment.c_str(), false);
}

bool has_external_incoming_edge(ea_t ea, ea_t range_start, ea_t range_end)
{
    xrefblk_t xref;
    for ( bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to() )
    {
        if ( xref.iscode
          && (xref.from < range_start || xref.from > range_end) )
        {
            return true;
        }
    }
    return false;
}

bool patchable_dispatch_instruction(const insn_t &instruction)
{
    switch ( instruction.itype )
    {
        case ARM_ldr:
        case ARM_ldur:
        case ARM_adr:
        case ARM_adrp:
        case ARM_adrl:
        case ARM_mov:
        case ARM_movl:
        case ARM_neg:
        case ARM_eor:
        case ARM_add:
            return true;
        default:
            return false;
    }
}

bool patch_compact_dispatcher(const dispatcher_proof_t &proof)
{
    if ( proof.cset_index == 0
      || proof.tail[proof.cset_index - 1].insn.itype != ARM_cmp )
    {
        return false;
    }

    size_t patch_index = proof.cset_index + 1;
    if ( patch_index >= proof.tail.size() )
        return false;
    const insn_t &possible_store = proof.tail[patch_index].insn;
    const int x19 = str2reg("X19");
    const int x29 = str2reg("X29");
    if ( (possible_store.itype == ARM_str
       || possible_store.itype == ARM_stur)
      && possible_store.Op1.type == o_reg
      && possible_store.Op1.reg == proof.index_reg
      && (possible_store.Op2.type == o_displ
       || possible_store.Op2.type == o_phrase)
      && is_state_base(possible_store.Op2.reg, x19, x29) )
    {
        ++patch_index;
    }
    if ( patch_index >= proof.tail.size() - 1 )
        return false;

    const ea_t patch_start = proof.tail[patch_index].ea;
    const asize_t region_size = proof.branch_ea + 4 - patch_start;
    if ( region_size < 12 || (region_size & 3U) != 0 )
        return false;

    for ( size_t index = patch_index; index + 1 < proof.tail.size(); ++index )
    {
        if ( !patchable_dispatch_instruction(proof.tail[index].insn)
          || has_external_incoming_edge(
                proof.tail[index].ea, proof.cset_ea, proof.branch_ea) )
        {
            return false;
        }
    }

    const std::optional<uint32_t> conditional =
        chernobog::arm64_branch::encode_b_cond(
            patch_start, patch_start + 8, proof.condition ^ 1U);
    const std::optional<uint32_t> true_branch =
        chernobog::arm64_branch::encode_b(
            patch_start + 4, proof.targets[1]);
    const std::optional<uint32_t> false_branch =
        chernobog::arm64_branch::encode_b(
            patch_start + 8, proof.targets[0]);
    if ( !conditional || !true_branch || !false_branch )
        return false;

    if ( !del_items(patch_start, DELIT_SIMPLE, region_size) )
        return false;
    for ( ea_t ea = patch_start; ea <= proof.branch_ea; ea += 4 )
        patch_dword(ea, ARM64_NOP);
    patch_dword(patch_start, *conditional);
    patch_dword(patch_start + 4, *true_branch);
    patch_dword(patch_start + 8, *false_branch);
    for ( ea_t ea = patch_start; ea <= proof.branch_ea; ea += 4 )
    {
        if ( create_insn(ea) <= 0 )
            return false;
    }
    if ( !set_func_end(proof.function_ea, proof.function_end) )
        return false;

    add_cref(patch_start, patch_start + 8, fl_JN);
    add_cref(patch_start + 4, proof.targets[1], fl_JN);
    add_cref(patch_start + 8, proof.targets[0], fl_JN);
    qstring comment;
    comment.sprnt(
        "DEOBF: reversible Hikari dispatch rewrite; %s->%a, else->%a",
        condition_name(proof.condition), proof.targets[1], proof.targets[0]);
    set_cmt(patch_start, comment.c_str(), false);
    plan_range(patch_start, proof.branch_ea + 4);
    return true;
}

} // namespace

int hikari_cfg_handler_t::mode()
{
    qstring value;
    if ( !qgetenv("CHERNOBOG_HIKARI_CFG", &value) || value.empty() )
        return 0;
    if ( value[0] == '2' )
        return 2;
    if ( value[0] == '1' )
        return 1;
    return 0;
}

hikari_cfg_stats_t hikari_cfg_handler_t::run()
{
    hikari_cfg_stats_t stats;
    const int recovery_mode = mode();
    if ( recovery_mode == 0 || !arch::is_arm64() )
        return stats;

    const int x19 = str2reg("X19");
    const int x29 = str2reg("X29");
    if ( x19 < 0 || x29 < 0 )
        return stats;

    std::vector<ea_t> function_starts;
    immediate_map_t immediates;
    func_t *root = nullptr;
    state_map_t root_tables;
    bool root_ambiguous = false;
    const size_t function_count = get_func_qty();
    for ( size_t index = 0; index < function_count; ++index )
    {
        func_t *function = getn_func(index);
        if ( !function || (function->flags & FUNC_TAIL) != 0 )
            continue;
        function_starts.push_back(function->start_ea);

        for ( const native_insn_t &item : function_instructions(function) )
        {
            const insn_t &instruction = item.insn;
            if ( is_full_immediate_move(instruction) )
            {
                immediates[instruction.Op1.reg].insert(
                    static_cast<uint32_t>(instruction.Op2.value));
            }
        }

        const state_map_t candidate = collect_state_tables(function, x19, x29);
        if ( candidate.size() > root_tables.size() )
        {
            root = function;
            root_tables = candidate;
            root_ambiguous = false;
        }
        else if ( !candidate.empty()
               && candidate.size() == root_tables.size() )
        {
            root_ambiguous = true;
        }
    }
    stats.root_state_slots = static_cast<int>(root_tables.size());
    if ( !root || root_tables.size() < 4 || root_ambiguous )
    {
        deobf::log(
            "[hikari_cfg] No unique root state-table initializer found\n");
        return stats;
    }
    const ea_t root_ea = root->start_ea;

    std::vector<dispatcher_proof_t> proofs;
    for ( ea_t function_ea : function_starts )
    {
        func_t *function = get_func(function_ea);
        if ( !function )
            continue;
        const std::vector<native_insn_t> tail =
            function_instructions(function, 1);
        if ( !tail.empty() && tail.back().insn.itype == ARM_br )
            ++stats.terminal_indirect_branches;

        const auto proof = analyze_dispatcher(
            function, root_tables, immediates, function_starts);
        if ( proof )
            proofs.push_back(*proof);
    }
    stats.recovered_dispatchers = static_cast<int>(proofs.size());

    std::map<ea_t, std::array<ea_t, 2>> graph;
    for ( const dispatcher_proof_t &proof : proofs )
    {
        graph[proof.function_ea] = proof.targets;
        annotate_dispatcher(proof);
        if ( recovery_mode >= 2 && patch_compact_dispatcher(proof) )
            ++stats.patched_dispatchers;
    }

    std::set<ea_t> reachable = {root_ea};
    std::deque<ea_t> queue = {root_ea};
    while ( !queue.empty() )
    {
        const ea_t source = queue.front();
        queue.pop_front();
        const auto edges = graph.find(source);
        if ( edges == graph.end() )
            continue;
        for ( ea_t target : edges->second )
        {
            if ( reachable.insert(target).second )
                queue.push_back(target);
        }
    }
    stats.reachable_functions = static_cast<int>(reachable.size());
    deobf::log(
        "[hikari_cfg] root=%a slots=%d indirect=%d recovered=%d "
        "patched=%d reachable=%d\n",
        root_ea, stats.root_state_slots,
        stats.terminal_indirect_branches, stats.recovered_dispatchers,
        stats.patched_dispatchers, stats.reachable_functions);
    return stats;
}
