/*
 * Native IDA analysis-quality additions.
 *
 * The pattern set is derived from viy's IDA-native/structural providers.
 * This implementation is per-IDB, preserves existing annotations, and
 * validates a complete candidate before changing item boundaries or function
 * metadata.
 */
#include "native_engine.hpp"

#include "analysis_config.hpp"
#include "get_pc_ida.hpp"
#include "ida_sdk_compat.hpp"
#include "x86_analysis.hpp"
#include "proof_receipt.hpp"

#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <netnode.hpp>
#include <auto.hpp>
#include <range.hpp>
#include <regfinder.hpp>
#include <typeinf.hpp>
#include <kernwin.hpp>
#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif
#include "../common/warn_on.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace chernobog::ida_analysis
{
namespace
{

constexpr const char *kCommentPrefix = "[chernobog][ida-analysis] ";

enum class Architecture : uint8_t
{
    Unsupported = 0,
    X86,
    Arm,
};

enum class BranchDecision : uint8_t
{
    Unknown = 0,
    Taken,
    NotTaken,
};

ea_t branch_target(const insn_t &instruction)
{
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const op_t &operand = instruction.ops[index];
        if (operand.type == o_void)
            break;
        if (operand.type == o_near || operand.type == o_far)
            return operand.addr;
    }
    return BADADDR;
}

bool target_is_executable(ea_t target)
{
    const segment_t *segment = getseg(target);
    return target != BADADDR && is_mapped(target) && segment != nullptr &&
           (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0) &&
           !is_tail(get_flags(target));
}

bool target_is_mapped_executable(ea_t target)
{
    const segment_t *segment = getseg(target);
    return target != BADADDR && is_mapped(target) && segment != nullptr &&
           (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0);
}

// Packers commonly place executable instructions in a PE section whose
// loader permissions are RW.  For an already-proven control transfer, accept
// such a target only when IDA can decode it and either IDA has classified the
// segment/item as code or the transfer remains within the source segment.
// This deliberately does not make arbitrary non-executable data branchable.
bool target_is_proven_code_candidate(ea_t from, ea_t target)
{
    if (target_is_mapped_executable(target))
        return true;
    if (from == BADADDR || target == BADADDR || !is_mapped(target))
        return false;
    const segment_t *source_segment = getseg(from);
    const segment_t *target_segment = getseg(target);
    if (source_segment == nullptr || target_segment == nullptr)
        return false;
    const flags64_t flags = get_flags(target);
    if (source_segment != target_segment && target_segment->type != SEG_CODE && !is_code(flags))
    {
        return false;
    }
    insn_t decoded;
    return decode_insn(&decoded, target) > 0;
}

bool add_user_cref(ea_t from, ea_t to, cref_t type, bool persistent = true,
                   bool require_code_target = true)
{
    if (from == BADADDR ||
        (require_code_target ? !target_is_executable(to) : !target_is_mapped_executable(to)) ||
        !is_code(get_flags(from)) || !is_head(get_flags(from)))
    {
        return false;
    }
    xrefblk_t xref;
    for (bool ok = xref.first_from(from, XREF_CODE); ok; ok = xref.next_from())
    {
        if (xref.to != to)
            continue;
        if ((int(xref.type) & XREF_MASK) == int(type))
            return false;
        // Preserve a user-selected edge type. IDA-generated call edges are safe
        // to replace after the get-PC gadget has been proven.
        if (xref.user)
            return false;
        del_cref(from, to, false);
        break;
    }
    // A call/pop classification must replace IDA's initial fl_CN edge with
    // fl_JN. fl_F cannot carry XREF_USER and is handled as ordinary flow.
    const cref_t stored_type = type == fl_F || !persistent ? type : cref_t(int(type) | XREF_USER);
    return add_cref(from, to, stored_type);
}

struct desired_code_edge_t
{
    ea_t target = BADADDR;
    cref_t type = fl_U;
    bool persistent = true;
};

bool edge_matches(ea_t target, int type, const desired_code_edge_t &desired)
{
    return target == desired.target && (int(type) & XREF_MASK) == (int(desired.type) & XREF_MASK);
}

bool exact_code_edge_exists(ea_t from, const desired_code_edge_t &desired)
{
    xrefblk_t xref;
    for (bool ok = xref.first_from(from, XREF_CODE); ok; ok = xref.next_from())
    {
        if (edge_matches(xref.to, xref.type, desired))
            return true;
    }
    return false;
}

struct existing_code_edge_t
{
    ea_t target = BADADDR;
    cref_t type = fl_U;
    bool user = false;
};

std::vector<existing_code_edge_t> collect_code_edges(ea_t from)
{
    std::vector<existing_code_edge_t> result;
    xrefblk_t xref;
    for (bool ok = xref.first_from(from, XREF_CODE); ok; ok = xref.next_from())
    {
        result.push_back(existing_code_edge_t{
            xref.to,
            cref_t(int(xref.type) & XREF_MASK),
            xref.user,
        });
    }
    return result;
}

bool desired_edge_set_is_exact(ea_t from, const std::vector<desired_code_edge_t> &desired)
{
    const std::vector<existing_code_edge_t> current = collect_code_edges(from);
    if (current.size() != desired.size())
        return false;
    for (const existing_code_edge_t &edge : current)
    {
        const auto found =
            std::find_if(desired.begin(), desired.end(), [&](const desired_code_edge_t &candidate)
                         { return edge_matches(edge.target, edge.type, candidate); });
        if (found == desired.end())
            return false;
        if (found->persistent && found->type != fl_F && !edge.user)
            return false;
    }
    return true;
}

void remove_generated_code_edges(ea_t from)
{
    std::vector<ea_t> targets;
    for (const existing_code_edge_t &edge : collect_code_edges(from))
    {
        if (!edge.user)
            targets.push_back(edge.target);
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    for (ea_t target : targets)
        del_cref(from, target, false);
}

// Replace only IDA-generated edges. A conflicting user edge is an explicit
// boundary and makes an exclusive branch proof inapplicable.
bool replace_generated_code_edges(ea_t from, const std::vector<desired_code_edge_t> &desired)
{
    qstring trace_value;
    const bool trace = qgetenv("CHERNOBOG_IDA_GET_PC_TRACE", &trace_value) &&
                       !trace_value.empty() && trace_value[0] != '0';
    if (trace)
        msg("[chernobog][ida-analysis][edge-trace] enter from=%a desired=%zu\n", from,
            desired.size());
    if (from == BADADDR || desired.empty())
    {
        if (trace)
            msg("[chernobog][ida-analysis][edge-trace] reject invalid source/set\n");
        return false;
    }
    for (const desired_code_edge_t &edge : desired)
    {
        if (edge.target == BADADDR || !target_is_proven_code_candidate(from, edge.target))
        {
            if (trace)
            {
                const segment_t *segment = getseg(edge.target);
                msg("[chernobog][ida-analysis][edge-trace] reject target=%a "
                    "mapped=%d segment=%p perm=%d\n",
                    edge.target, is_mapped(edge.target) ? 1 : 0, segment,
                    segment != nullptr ? segment->perm : -1);
            }
            return false;
        }
    }
    for (size_t index = 0; index < desired.size(); ++index)
    {
        for (size_t other = index + 1; other < desired.size(); ++other)
        {
            if (desired[index].target == desired[other].target)
            {
                if (trace)
                    msg("[chernobog][ida-analysis][edge-trace] reject duplicate=%a\n",
                        desired[index].target);
                return false;
            }
        }
    }

    const std::vector<existing_code_edge_t> original = collect_code_edges(from);
    if (trace)
    {
        msg("[chernobog][ida-analysis][edge-trace] from=%a original=%zu "
            "desired=%zu\n",
            from, original.size(), desired.size());
        for (const existing_code_edge_t &edge : original)
            msg("[chernobog][ida-analysis][edge-trace]   old to=%a type=%d "
                "user=%d\n",
                edge.target, int(edge.type), edge.user ? 1 : 0);
    }
    for (const existing_code_edge_t &edge : original)
    {
        if (edge.user &&
            std::none_of(desired.begin(), desired.end(), [&](const desired_code_edge_t &candidate)
                         { return edge_matches(edge.target, edge.type, candidate); }))
        {
            if (trace)
                msg("[chernobog][ida-analysis][edge-trace] reject conflicting "
                    "user edge to=%a type=%d\n",
                    edge.target, int(edge.type));
            return false;
        }
    }
    if (desired_edge_set_is_exact(from, desired))
        return true;

    // Rebuild the generated portion as a transaction. User edges that agree
    // with the proof remain untouched; every generated edge can be restored
    // exactly if an insertion fails.
    remove_generated_code_edges(from);
    bool success = true;
    std::vector<ea_t> inserted_targets;
    for (const desired_code_edge_t &edge : desired)
    {
        if (exact_code_edge_exists(from, edge))
            continue;
        const cref_t stored_type =
            edge.type == fl_F || !edge.persistent ? edge.type : cref_t(int(edge.type) | XREF_USER);
        const bool inserted = add_cref(from, edge.target, stored_type);
        if (trace)
            msg("[chernobog][ida-analysis][edge-trace]   add to=%a type=%d "
                "inserted=%d exact=%d\n",
                edge.target, int(stored_type), inserted ? 1 : 0,
                exact_code_edge_exists(from, edge) ? 1 : 0);
        if (inserted || exact_code_edge_exists(from, edge))
            inserted_targets.push_back(edge.target);
        if (!inserted && !exact_code_edge_exists(from, edge))
        {
            success = false;
            break;
        }
    }
    success = success && desired_edge_set_is_exact(from, desired);
    if (trace)
    {
        const std::vector<existing_code_edge_t> current = collect_code_edges(from);
        msg("[chernobog][ida-analysis][edge-trace] final success=%d count=%zu\n", success ? 1 : 0,
            current.size());
        for (const existing_code_edge_t &edge : current)
            msg("[chernobog][ida-analysis][edge-trace]   now to=%a type=%d "
                "user=%d\n",
                edge.target, int(edge.type), edge.user ? 1 : 0);
    }
    if (success)
        return true;

    for (ea_t target : inserted_targets)
        del_cref(from, target, false);
    remove_generated_code_edges(from);
    for (const existing_code_edge_t &edge : original)
    {
        if (edge.user)
            continue;
        add_cref(from, edge.target, edge.type);
    }
    return false;
}

bool flow_xref_exists(ea_t address, bool outgoing, ea_t excluded = BADADDR,
                      cref_t required_type = cref_t(-1))
{
    xrefblk_t xref;
    bool ok = outgoing ? xref.first_from(address, XREF_FLOW) : xref.first_to(address, XREF_FLOW);
    while (ok)
    {
        if (xref.from != excluded &&
            (required_type == cref_t(-1) || (int(xref.type) & XREF_MASK) == int(required_type)))
        {
            return true;
        }
        ok = outgoing ? xref.next_from() : xref.next_to();
    }
    return false;
}

bool append_analysis_comment(ea_t address, const char *text)
{
    qstring tagged = kCommentPrefix;
    tagged.append(text);
    qstring current;
    get_cmt(&current, address, true);
    if (current.find(tagged.c_str()) != qstring::npos)
        return false;
    if (!current.empty())
        current.append("\n");
    current.append(tagged);
    return set_cmt(address, current.c_str(), true);
}

// Remove only the exact line we inserted. User edits to that line, and all
// other repeatable/non-repeatable annotations, remain user-owned.
void remove_owned_comment(ea_t address, const std::string &line)
{
    if (line.empty())
        return;
    qstring current;
    get_cmt(&current, address, true);
    const std::string original(current.c_str());
    std::string remaining;
    bool removed = false;
    bool have_line = false;
    for (size_t first = 0; first <= original.size();)
    {
        const size_t end = original.find('\n', first);
        const auto part = original.substr(first, end == std::string::npos ? end : end - first);
        if (part == line && !removed)
            removed = true;
        else
        {
            if (have_line)
                remaining += '\n';
            remaining += part;
            have_line = true;
        }
        if (end == std::string::npos)
            break;
        first = end + 1;
    }
    if (removed)
        set_cmt(address, remaining.c_str(), true);
}

struct NativeProofDependency
{
    ea_t first = BADADDR;
    std::vector<uint8_t> bytes;
    ea_t owner = BADADDR;
    int permissions = 0;
    int bitness = 0;
    bool code = false;
};

struct NativeProof
{
    enum class Kind
    {
        Unknown,
        Call,
        Return,
        Materialization,
        StackTransfer,
        Condition
    };
    Kind kind = Kind::Unknown;
    uint64_t publication = 0;
    ea_t context_call = BADADDR;
    std::optional<uint64_t> value;
    ea_t source = BADADDR; // PUSH or condition, used for bounded reanalysis
    ea_t site = BADADDR;   // RET or condition, owns annotations/outgoing edges
    std::optional<desired_code_edge_t> intended_edge;
    std::vector<NativeProofDependency> dependencies;
    std::vector<existing_code_edge_t> owned_edges;
    std::string owned_comment;
    std::string conclusion;
};

// Main-thread publication identity across all engines in this loaded plugin.
uint64_t native_inspection_publication = 0;
uint64_t native_region_context = 0;

struct NativeMutationGuard
{
    unsigned &depth;
    explicit NativeMutationGuard(unsigned &value) : depth(value) { ++depth; }
    ~NativeMutationGuard() { --depth; }
};

bool has_inbound_reference(ea_t address, ea_t allowed_source = BADADDR)
{
    xrefblk_t xref;
    for (bool ok = xref.first_to(address, XREF_ALL); ok; ok = xref.next_to())
    {
        // A proven always-transfer instruction can leave an IDA-generated
        // fallthrough into the skipped bytes from an earlier analysis wave. That
        // edge is precisely the stale state being repaired. User-selected edges
        // and every reference from another source remain a hard barrier.
        if (xref.from != allowed_source || xref.user)
            return true;
    }
    return false;
}

bool has_protected_metadata(ea_t address, flags64_t flags)
{
    if (has_any_name(flags) || has_cmt(flags) || has_extra_cmts(flags) || is_manual_insn(address))
    {
        return true;
    }
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        if (is_defarg(flags, index))
            return true;
    }
    if (is_head(flags))
    {
        tinfo_t type;
        if (get_tinfo(&type, address))
            return true;
    }
    return false;
}

bool safe_gap_candidate(ea_t start, ea_t end, uint64_t maximum_gap, ea_t allowed_source)
{
    if (start >= end || uint64_t(end - start) > maximum_gap)
        return false;
    const func_t *owner = get_func(start);
    for (ea_t address = start; address < end; ++address)
    {
        const flags64_t flags = get_flags(address);
        if (!is_mapped(address) || !is_loaded(address) || has_protected_metadata(address, flags) ||
            has_inbound_reference(address, allowed_source))
        {
            return false;
        }
        const func_t *function = get_func(address);
        if (function != nullptr && function->start_ea == address)
            return false;
        if (owner == nullptr && function != nullptr)
            return false;
        if (owner != nullptr && function != nullptr && function != owner)
            return false;
    }
    return true;
}

size_t retype_gap_as_bytes(ea_t start, ea_t end, uint64_t maximum_gap, ea_t allowed_source)
{
    // The operation is idempotent: existing one-byte data items are retained.
    // Re-run the safety proof even on a revisited instruction because a plugin
    // loaded during an active autoanalysis wave can first observe the source
    // after IDA has already decoded the skipped byte as overlapping code.
    if (!safe_gap_candidate(start, end, maximum_gap, allowed_source))
        return 0;
    size_t changed = 0;
    for (ea_t address = start; address < end; ++address)
    {
        const flags64_t flags = get_flags(address);
        if (is_byte(flags) && get_item_size(address) == 1)
            continue;
        if (!del_items(address, DELIT_SIMPLE, 1))
            continue;
        if (create_byte(address, 1))
            ++changed;
    }
    return changed;
}

bool operands_equivalent(const op_t &left, const op_t &right)
{
    if (left.type != right.type || left.dtype != right.dtype || left.flags != right.flags)
    {
        return false;
    }
    if (left.type == o_void)
        return true;
    return left.reg == right.reg && left.value == right.value && left.addr == right.addr &&
           left.specval == right.specval && left.specflag1 == right.specflag1 &&
           left.specflag2 == right.specflag2 && left.specflag3 == right.specflag3 &&
           left.specflag4 == right.specflag4;
}

bool instructions_equivalent_without_prefix(const insn_t &prefixed, const insn_t &plain)
{
    if (prefixed.itype != plain.itype || prefixed.size != plain.size + 1 ||
        prefixed.get_canon_feature(PH) != plain.get_canon_feature(PH))
    {
        return false;
    }
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        if (!operands_equivalent(prefixed.ops[index], plain.ops[index]))
            return false;
        if (prefixed.ops[index].type == o_void)
            break;
    }
    return true;
}

bool prefix_candidate_is_semantically_eligible(ea_t address, const insn_t &prefixed)
{
    if (!is_loaded(address) || !is_loaded(address + 1))
        return false;
    const uint8_t prefix = get_byte(address);
    if (prefix != 0xF2 && prefix != 0xF3)
        return false;
    const uint8_t opcode = get_byte(address + 1);
    // Any second prefix byte makes this a prefix train. Conservatively retain
    // it; the following byte, not this one, determines REP semantics.
    if (opcode == 0x0F || opcode == 0x26 || opcode == 0x2E || opcode == 0x36 || opcode == 0x3E ||
        opcode == 0x64 || opcode == 0x65 || opcode == 0x66 || opcode == 0x67 || opcode == 0xF0 ||
        opcode == 0xF2 || opcode == 0xF3 || (inf_is_64bit() && opcode >= 0x40 && opcode <= 0x4F) ||
        (prefix == 0xF3 && opcode == 0x90))
    {
        return false;
    }
    if (prefix == 0xF3 && (opcode == 0xC2 || opcode == 0xC3 || opcode == 0xCA || opcode == 0xCB))
    {
        return false;
    }
    if ((opcode >= 0xA4 && opcode <= 0xA7) || (opcode >= 0xAA && opcode <= 0xAF) ||
        (opcode >= 0x6C && opcode <= 0x6F) || is_call_insn(prefixed) ||
        is_basic_block_end(prefixed, false))
    {
        return false;
    }
    return true;
}

constexpr std::array<std::array<uint16_t, 2>, 8> kX86Opposites = {{
    {{NN_jz, NN_jnz}},
    {{NN_jo, NN_jno}},
    {{NN_js, NN_jns}},
    {{NN_jp, NN_jnp}},
    {{NN_jb, NN_jnb}},
    {{NN_jbe, NN_ja}},
    {{NN_jl, NN_jnl}},
    {{NN_jle, NN_jnle}},
}};

uint16_t opposite_x86_condition(uint16_t type)
{
    for (const auto &pair : kX86Opposites)
    {
        if (type == pair[0])
            return pair[1];
        if (type == pair[1])
            return pair[0];
    }
    return 0;
}

bool instruction_modifies_x86_flags(uint16_t type)
{
    static constexpr std::array<uint16_t, 18> preserving = {{
        NN_mov,
        NN_lea,
        NN_nop,
        NN_push,
        NN_pop,
        NN_pusha,
        NN_popa,
        NN_pushf,
        NN_pushfd,
        NN_pushfq,
        NN_xchg,
        NN_bswap,
        NN_jmp,
        NN_jmpni,
        NN_jmpfi,
        NN_jcxz,
        NN_jecxz,
        NN_jrcxz,
    }};
    return std::find(preserving.begin(), preserving.end(), type) == preserving.end() &&
           opposite_x86_condition(type) == 0;
}

bool zero_register_operand(const op_t &operand)
{
    if (operand.type != o_reg)
        return false;
    size_t width = get_dtype_size(operand.dtype);
    if (width == 0)
        width = inf_is_64bit() ? 8 : 4;
    qstring name;
    return get_reg_name(&name, operand.reg, width) > 0 && (name == "XZR" || name == "WZR");
}

bool exact_register_operand(const op_t &left, const op_t &right)
{
    if (left.type != o_reg || right.type != o_reg || left.dtype != right.dtype)
    {
        return false;
    }
    const size_t width = get_dtype_size(left.dtype);
    if (width == 0 || width != get_dtype_size(right.dtype))
        return false;
    qstring left_name;
    qstring right_name;
    if (get_reg_name(&left_name, left.reg, width) <= 0 ||
        get_reg_name(&right_name, right.reg, width) <= 0)
    {
        return false;
    }
    bitrange_t left_range;
    bitrange_t right_range;
    const char *left_main = PH.get_reg_info(left_name.c_str(), &left_range);
    const char *right_main = PH.get_reg_info(right_name.c_str(), &right_range);
    if (left_main == nullptr || right_main == nullptr || str2reg(left_main) != str2reg(right_main))
    {
        return false;
    }
    const size_t left_offset = left_range.empty() ? 0 : left_range.bitoff();
    const size_t right_offset = right_range.empty() ? 0 : right_range.bitoff();
    const size_t left_bits = left_range.empty() ? width * 8 : left_range.bitsize();
    const size_t right_bits = right_range.empty() ? width * 8 : right_range.bitsize();
    return left_offset == right_offset && left_bits == right_bits;
}

std::string normalized_mnemonic(ea_t address)
{
    qstring raw;
    if (!print_insn_mnem(&raw, address))
        return {};
    std::string result;
    for (char value : std::string(raw.c_str()))
    {
        const unsigned char byte = static_cast<unsigned char>(value);
        if (std::isalnum(byte))
            result.push_back(char(std::tolower(byte)));
    }
    return result;
}

bool opposite_arm_branch(const insn_t &left, const insn_t &right)
{
    if ((left.itype == ARM_cbz && right.itype == ARM_cbnz) ||
        (left.itype == ARM_cbnz && right.itype == ARM_cbz))
    {
        return exact_register_operand(left.Op1, right.Op1);
    }
    if ((left.itype == ARM_tbz && right.itype == ARM_tbnz) ||
        (left.itype == ARM_tbnz && right.itype == ARM_tbz))
    {
        if (!exact_register_operand(left.Op1, right.Op1) || left.Op2.type != o_imm ||
            right.Op2.type != o_imm || left.Op2.value != right.Op2.value)
        {
            return false;
        }
        const size_t width = get_dtype_size(left.Op1.dtype);
        return width != 0 && left.Op2.value < width * 8;
    }
    if (left.itype != ARM_b || right.itype != ARM_b)
        return false;
    static const std::map<std::string, std::string> opposites = {
        {"beq", "bne"}, {"bne", "beq"}, {"bcs", "bcc"}, {"bcc", "bcs"},
        {"bhs", "blo"}, {"blo", "bhs"}, {"bmi", "bpl"}, {"bpl", "bmi"},
        {"bvs", "bvc"}, {"bvc", "bvs"}, {"bhi", "bls"}, {"bls", "bhi"},
        {"bge", "blt"}, {"blt", "bge"}, {"bgt", "ble"}, {"ble", "bgt"},
    };
    const std::string first = normalized_mnemonic(left.ea);
    const std::string second = normalized_mnemonic(right.ea);
    const auto found = opposites.find(first);
    return found != opposites.end() && found->second == second;
}

bool direct_transfer(const insn_t &instruction)
{
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const optype_t type = instruction.ops[index].type;
        if (type == o_void)
            break;
        if (type == o_near || type == o_far)
            return true;
    }
    return false;
}

bool writes_global_memory(const insn_t &instruction)
{
    const uint32_t features = instruction.get_canon_feature(PH);
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const op_t &operand = instruction.ops[index];
        if (operand.type == o_void)
            break;
        if (operand.type == o_mem && has_cf_chg(features, index))
            return true;
    }
    return false;
}

bool name_contains_hikari_wrapper(ea_t address)
{
    qstring name;
    return get_short_name(&name, address) > 0 &&
           name.find("HikariFunctionWrapper") != qstring::npos;
}

bool wrapper_shape(const func_t *function, const NativeAnalysisConfig &config)
{
    if (function == nullptr)
        return false;
    const uint32_t excluded = FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN | FUNC_OUTLINE;
    if ((function->flags & excluded) != 0 || function->tailqty > 0 ||
        function->start_ea < inf_get_min_ea() || function->end_ea >= inf_get_max_ea())
    {
        return false;
    }

    int instruction_count = 0;
    int calls = 0;
    int returns = 0;
    int other_terminators = 0;
    ea_t call_target = BADADDR;
    bool final_instruction_is_return = false;
    for (ea_t address = function->start_ea; address < function->end_ea;)
    {
        insn_t instruction;
        if (decode_insn(&instruction, address) <= 0 ||
            ++instruction_count > config.wrapper_max_instructions)
        {
            return false;
        }
        if (writes_global_memory(instruction))
            return false;
        const bool call = is_call_insn(instruction);
        const bool ret = is_ret_insn(instruction);
        if (call)
        {
            if (!direct_transfer(instruction))
                return false;
            call_target = branch_target(instruction);
            ++calls;
        }
        if (ret)
            ++returns;
        if (!call && !ret && is_basic_block_end(instruction, false))
            ++other_terminators;
        const ea_t next = address + instruction.size;
        final_instruction_is_return = ret && next == function->end_ea;
        address = next;
    }
    if (calls != 1 || other_terminators != 0 || call_target == BADADDR ||
        call_target == function->start_ea || !target_is_mapped_executable(call_target))
        return false;
    const func_t *callee = get_func(call_target);
    const bool callee_returns = callee == nullptr || callee->does_return();
    if (callee_returns)
    {
        if (returns != 1 || !final_instruction_is_return)
            return false;
    }
    else if (returns != 0)
    {
        return false;
    }

    int callers = 0;
    xrefblk_t xref;
    for (bool ok = xref.first_to(function->start_ea, XREF_CODE); ok; ok = xref.next_to())
    {
        if (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF))
            ++callers;
    }
    return config.wrapper_max_callers == 0 || callers <= config.wrapper_max_callers;
}

ea_t bounded_function_end(ea_t start, int maximum_instructions)
{
    ea_t address = start;
    for (int index = 0; index < maximum_instructions; ++index)
    {
        if (!is_code(get_flags(address)))
            return BADADDR;
        const func_t *owner = get_func(address);
        if (address != start && owner != nullptr && owner->start_ea == address)
            return BADADDR;
        insn_t instruction;
        if (decode_insn(&instruction, address) <= 0)
            return BADADDR;
        if (is_ret_insn(instruction))
            return address + instruction.size;
        // This is deliberately a linear item-boundary scan, matching IDA's
        // orphan-callee recovery heuristic. A legitimate function may contain
        // direct jumps before its natural return; CF_STOP is therefore not a
        // rejection criterion here. Existing function entries still terminate
        // the scan above, and the configured instruction bound prevents runaway.
        address += instruction.size;
    }
    return BADADDR;
}

} // namespace

struct NativeAnalysisEngine::Impl final : event_listener_t
{
    const ssize_t owner_database = get_dbctx_id();
    const uint64_t region_context =
        native_region_context == UINT64_MAX ? 0 : ++native_region_context;
    NativeAnalysisConfig config = load_native_analysis_config();
    NativeAnalysisStats statistics;
    Architecture architecture = Architecture::Unsupported;
    bool hooked = false;
    bool post_analysis_running = false;
    bool post_metadata_scanned = false;
    bool prefix_decode_probe = false;
    rangeset_t emulated;
    rangeset_t prefix_seen;
    std::set<std::pair<int, ea_t>> findings_seen;
    std::set<ea_t> get_pc_function_roots;
    std::set<ea_t> observed_direct_call_targets;
    std::set<std::pair<ea_t, ea_t>> pending_direct_jump_decodes;
    std::vector<std::pair<ea_t, ea_t>> pending_cfg_edges;
    std::set<ea_t> pending_call_returns;
    std::set<ea_t> pending_flag_fallthroughs;
    // Conclusions/dependencies are session-local. Persisted receipts authorize
    // cleanup only; every reopen recomputes proofs from the current database.
    static constexpr size_t maximum_native_proofs = 4096;
    std::map<ea_t, NativeProof> native_proofs;
    netnode ownership_node;
    bool ownership_ready = false;
    bool ownership_publication_disabled = false;
    bool closing_database = false;
    bool replaying_undo = false;
    bool pending_ownership_recovery = false;
    std::vector<ea_t> moving_proof_sources;
    unsigned native_mutation_depth = 0;
    size_t reported_orphan_functions = 0;
    size_t reported_outlined_wrappers = 0;
    size_t reported_get_pc_tail_extensions = 0;

    Impl()
    {
        if (PH.id == PLFM_386)
            architecture = Architecture::X86;
        else if (PH.id == PLFM_ARM)
            architecture = Architecture::Arm;
        ownership_node.create("$ chernobog.native_proof_ownership.v1");
        ownership_ready = ownership_node != BADNODE;
        recover_ownership_receipts();
        if (config.enabled && architecture != Architecture::Unsupported)
            hooked = hook_event_listener(HT_IDP, this, this);
        if (config.enabled)
        {
            msg("[chernobog][ida-analysis] native engine %s (%s)\n",
                hooked ? "enabled" : "unavailable",
                architecture == Architecture::X86   ? "x86"
                : architecture == Architecture::Arm ? "ARM"
                                                    : "unsupported");
        }
    }

    ~Impl() override
    {
        if (hooked)
            unhook_event_listener(HT_IDP, this);
        if (get_dbctx_id() == owner_database && !closing_database)
        {
            if (pending_ownership_recovery)
                recover_ownership_receipts();
            invalidate_proofs(0, BADADDR);
        }
    }

    void reset()
    {
        if (closing_database)
            native_proofs.clear();
        else
            invalidate_proofs(0, BADADDR);
        post_analysis_running = false;
        prefix_decode_probe = false;
        emulated.clear();
        prefix_seen.clear();
        findings_seen.clear();
        get_pc_function_roots.clear();
        observed_direct_call_targets.clear();
        pending_direct_jump_decodes.clear();
        pending_cfg_edges.clear();
        pending_call_returns.clear();
        pending_flag_fallthroughs.clear();
        statistics = NativeAnalysisStats{};
        post_metadata_scanned = false;
        reported_orphan_functions = 0;
        reported_outlined_wrappers = 0;
        reported_get_pc_tail_extensions = 0;
    }

    bool persist_ownership(const NativeProof &proof)
    {
        if (!ownership_ready)
            return false;
        proof_receipt::Receipt receipt;
        receipt.source_node = ea2node(proof.source);
        receipt.site_node = ea2node(proof.site);
        receipt.comment = proof.owned_comment;
        for (const auto &edge : proof.owned_edges)
            receipt.edges.push_back(
                {uint64_t(ea2node(edge.target)), uint8_t(edge.type), edge.user});
        const auto encoded = proof_receipt::encode(receipt);
        static_assert(proof_receipt::maximum_size <= MAXSPECSIZE);
        return encoded && ownership_node.supset(nodeidx_t(receipt.source_node), encoded->data(),
                                                encoded->size());
    }

    void recover_ownership_receipts(ea_t preserved_from = BADADDR, ea_t preserved_to = BADADDR,
                                    int preserved_type = -1)
    {
        pending_ownership_recovery = false;
        if (!ownership_ready)
            return;
        NativeMutationGuard guard(native_mutation_depth);
        // Do not treat cached proof state as authoritative after reopen or undo.
        native_proofs.clear();
        pending_flag_fallthroughs.clear();
        size_t recovered = 0;
        nodeidx_t key = ownership_node.supfirst();
        for (; key != BADNODE && recovered < maximum_native_proofs; ++recovered)
        {
            const nodeidx_t next = ownership_node.supnext(key);
            std::array<uint8_t, proof_receipt::maximum_size> bytes{};
            const ssize_t size = ownership_node.supval(key, bytes.data(), bytes.size());
            const auto receipt = size >= 0 && size_t(size) <= bytes.size()
                                     ? proof_receipt::decode(bytes.data(), size_t(size))
                                     : std::nullopt;
            bool valid = receipt && receipt->source_node == uint64_t(key) &&
                         receipt->source_node != BADNODE && receipt->site_node != BADNODE &&
                         (receipt->comment.empty() || receipt->comment.find(kCommentPrefix) == 0);
            NativeProof proof;
            if (valid)
            {
                proof.source = node2ea(nodeidx_t(receipt->source_node));
                proof.site = node2ea(nodeidx_t(receipt->site_node));
                proof.owned_comment = receipt->comment;
                valid = proof.source != BADADDR && proof.site != BADADDR;
                for (const auto &edge : receipt->edges)
                {
                    const ea_t target = node2ea(nodeidx_t(edge.target_node));
                    if (target == BADADDR || (edge.type != fl_JN && edge.type != fl_F) ||
                        (edge.type == fl_F && edge.user))
                        valid = false;
                    if (proof.site != preserved_from || target != preserved_to ||
                        int(edge.type) != preserved_type)
                        proof.owned_edges.push_back({target, cref_t(edge.type), edge.user});
                }
            }
            if (!valid)
            {
                // Malformed receipts cannot establish ownership of arbitrary metadata.
                // Retain the record for diagnosis and disable new proof publication.
                ownership_ready = false;
                msg("[chernobog][ida-analysis] invalid native ownership receipt; "
                    "new proof publication disabled\n");
                return;
            }
            revoke_proof(std::move(proof), true);
            key = next;
        }
        if (key != BADNODE)
        {
            ownership_ready = false;
            msg("[chernobog][ida-analysis] native ownership receipt limit exceeded; "
                "new proof publication disabled\n");
        }
        if (recovered != 0)
            msg("[chernobog][ida-analysis] recovered %zu native ownership receipts; "
                "proofs queued for recomputation\n",
                recovered);
    }

    bool add_dependency(NativeProof &proof, ea_t address, size_t size, bool code)
    {
        if (size == 0 || size > 16 || address > BADADDR - size)
            return false;
        const segment_t *segment = getseg(address);
        if (segment == nullptr || address + size > segment->end_ea)
            return false;
        NativeProofDependency dependency;
        dependency.first = address;
        dependency.bytes.resize(size);
        dependency.code = code;
        dependency.permissions = segment->perm;
        dependency.bitness = segment->bitness;
        const func_t *owner = get_func(address);
        dependency.owner = owner != nullptr ? owner->start_ea : BADADDR;
        for (size_t i = 0; i < size; ++i)
        {
            if (!is_loaded(address + i))
                return false;
            dependency.bytes[i] = get_byte(address + i);
        }
        proof.dependencies.push_back(std::move(dependency));
        return true;
    }

    bool add_instruction_dependency(NativeProof &proof, ea_t address)
    {
        insn_t decoded;
        return decode_insn(&decoded, address) > 0 &&
               add_dependency(proof, address, decoded.size, true);
    }

    bool proof_is_fresh(const NativeProof &proof) const
    {
        for (const auto &dependency : proof.dependencies)
        {
            const segment_t *segment = getseg(dependency.first);
            const func_t *owner = get_func(dependency.first);
            if (segment == nullptr || segment->perm != dependency.permissions ||
                segment->bitness != dependency.bitness ||
                dependency.first + dependency.bytes.size() > segment->end_ea ||
                (dependency.code &&
                 (!is_code(get_flags(dependency.first)) ||
                  (owner != nullptr ? owner->start_ea : BADADDR) != dependency.owner)))
                return false;
            for (size_t i = 0; i < dependency.bytes.size(); ++i)
                if (!is_loaded(dependency.first + i) ||
                    get_byte(dependency.first + i) != dependency.bytes[i])
                    return false;
        }
        return true;
    }

    bool current_proof_conclusion(const NativeProof &proof,
                                  std::map<std::string, std::string> *details = nullptr) const
    {
        std::map<std::string, std::string> ignored;
        auto &row = details != nullptr ? *details : ignored;
        const auto covered = [&](const std::vector<uint64_t> &support)
        {
            return std::all_of(support.begin(), support.end(),
                               [&](uint64_t address)
                               {
                                   return std::any_of(
                                       proof.dependencies.begin(), proof.dependencies.end(),
                                       [&](const NativeProofDependency &dependency)
                                       { return dependency.code && dependency.first == address; });
                               });
        };
        const auto hex = [](uint64_t value)
        {
            std::ostringstream out;
            out << "0x" << std::hex << value;
            return out.str();
        };
        insn_t instruction;
        const ea_t root =
            proof.kind == NativeProof::Kind::Return ? proof.context_call : proof.source;
        bool current = decode_insn(&instruction, root) > 0;
        // Re-run the read-only recognizer as well as checking stored bytes. This
        // covers current entry topology and alias/write-reference restrictions.
        if (current)
            switch (proof.kind)
            {
            case NativeProof::Kind::StackTransfer:
            {
                row["kind"] = "stack-transfer";
                const auto candidate =
                    classify_ida_push_return(instruction, config.register_scan_depth);
                current = candidate && candidate->transfer == proof.site &&
                          covered(candidate->target.definitions);
                if (!current)
                    break;
                for (const auto &memory : candidate->target.memory)
                    current =
                        current && std::any_of(proof.dependencies.begin(), proof.dependencies.end(),
                                               [&](const NativeProofDependency &dependency)
                                               {
                                                   return !dependency.code &&
                                                          dependency.first == memory.address &&
                                                          dependency.bytes == memory.bytes;
                                               });
                if (!current)
                    break;
                current = proof.intended_edge
                              ? candidate->target.value &&
                                    *candidate->target.value == proof.intended_edge->target
                              : !candidate->target.value;
                row["width_bits"] = std::to_string(candidate->width_bits);
                row["stack_delta_bytes"] = std::to_string(candidate->stack_delta_bytes);
                row["stack_write_bytes"] = std::to_string(candidate->stack_write_bytes);
                switch (candidate->target.kind)
                {
                case classifier::target_proof_kind_t::immediate:
                    row["target_basis"] = "immediate";
                    break;
                case classifier::target_proof_kind_t::register_definition:
                    row["target_basis"] = "register-definition";
                    break;
                case classifier::target_proof_kind_t::immutable_memory:
                    row["target_basis"] = "immutable-memory";
                    break;
                default:
                    row["target_basis"] = "unresolved";
                    break;
                }
                row["register_scan_depth"] = std::to_string(config.register_scan_depth);
                row["memory_model"] =
                    "IDA loaded immutable bytes and current write-reference checks; external runtime mutations unmodeled";
                if (!proof.intended_edge)
                    row["truth"] = "candidate";
                break;
            }
            case NativeProof::Kind::Call:
            case NativeProof::Kind::Return:
            {
                const bool returning = proof.kind == NativeProof::Kind::Return;
                row["kind"] = returning ? "call-context-return" : "get-pc-call";
                const auto candidate =
                    classify_ida_get_pc_call(instruction, size_t(config.pop_ret_depth), true);
                current = candidate && proof.intended_edge && covered(candidate->support);
                if (!current)
                    break;
                current = returning ? candidate->return_instruction == proof.site &&
                                          candidate->resumed_at &&
                                          *candidate->resumed_at == proof.intended_edge->target
                                    : candidate->gadget == proof.intended_edge->target;
                row["context_call"] = hex(candidate->call);
                row["scan_depth"] = std::to_string(config.pop_ret_depth);
                row["width_bits"] = std::to_string(candidate->width_bits);
                row["stack_delta_bytes"] = std::to_string(candidate->stack_delta_bytes);
                row["stack_access_count"] = std::to_string(candidate->stack_accesses.size());
                row["effect_scope"] = "complete recognized CALL sequence; not the isolated edge";
                if (returning)
                    row["assumption"] =
                        "recognized CALL entry context and return-address provenance; native stack accesses retained";
                break;
            }
            case NativeProof::Kind::Materialization:
            {
                row["kind"] = "stack-address-materialization";
                const auto candidate = classify_ida_push_get_pc(instruction);
                current = candidate && proof.value && candidate->address_value == *proof.value &&
                          covered(candidate->support);
                if (!current)
                    break;
                row["value"] = hex(candidate->address_value);
                row["width_bits"] = std::to_string(candidate->width_bits);
                row["stack_delta_bytes"] = std::to_string(candidate->stack_delta_bytes);
                row["stack_access_count"] = std::to_string(candidate->stack_accesses.size());
                row["flags_preserved"] = candidate->flags_preserved ? "true" : "false";
                break;
            }
            case NativeProof::Kind::Condition:
            {
                const auto condition = x86_condition(instruction.itype);
                current = condition.has_value();
                if (!current)
                    break;
                const auto fact =
                    analyze_x86_flag_fact_before(instruction, size_t(config.flag_scan_depth));
                const auto outcome = x86_abstract::evaluate(condition->condition, fact.flags);
                current = outcome && proof.value && uint64_t(*outcome ? 1 : 0) == *proof.value &&
                          covered(fact.support);
                row["kind"] = condition->use == X86ConditionUse::branch     ? "local-flag-branch"
                              : condition->use == X86ConditionUse::set_byte ? "setcc-value"
                                                                            : "cmov-condition";
                if (!current)
                    break;
                row["condition_value"] = *outcome ? "true" : "false";
                row["scan_depth"] = std::to_string(config.flag_scan_depth);
                if (condition->use == X86ConditionUse::branch)
                    current =
                        proof.intended_edge && proof.intended_edge->target ==
                                                   (*outcome ? branch_target(instruction)
                                                             : instruction.ea + instruction.size);
                if (condition->use == X86ConditionUse::set_byte)
                {
                    row["value"] = *outcome ? "0x1" : "0x0";
                    row["width_bits"] = "8";
                }
                row["assumption"] =
                    "bounded owned-graph or single-entry flag analysis; SETcc byte writes and CMOV memory/partial-register effects retained";
                break;
            }
            default:
                current = false;
                break;
            }
        return current;
    }

    NativeInspection inspect(uint64_t function_start) const
    {
        NativeInspection result;
        result.database = int64_t(get_dbctx_id());
        result.function = function_start;
        func_t *function = get_func(ea_t(function_start));
        if (result.database != owner_database || closing_database || replaying_undo ||
            pending_ownership_recovery || native_mutation_depth != 0 || !config.enabled ||
            function == nullptr || function->start_ea != function_start)
            return result;
        result.available = true;
        const auto hex = [](uint64_t value)
        {
            std::ostringstream out;
            out << "0x" << std::hex << value;
            return out.str();
        };
        for (const auto &[source, proof] : native_proofs)
        {
            if (!func_contains(function, source) && !func_contains(function, proof.site) &&
                (proof.context_call == BADADDR || !func_contains(function, proof.context_call)))
                continue;
            if (result.records.size() >= NativeInspection::proof_limit)
            {
                ++result.omitted;
                continue;
            }
            std::map<std::string, std::string> row{
                {"publication", hex(proof.publication)},
                {"source", hex(source)},
                {"site", hex(proof.site)},
                {"truth", "native-proof"},
                {"conclusion", proof.conclusion},
                {"kind", "unknown"},
                {"edge", proof.intended_edge ? "true" : "false"},
                {"assumption",
                 "bounded local x86 model; native memory/stack effects retained; not whole-program reachability"}};
            if (proof.intended_edge)
                row["target"] = hex(proof.intended_edge->target);
            bool current = proof.publication != 0 && proof_is_fresh(proof);
            const bool dependencies_current = current;
            current = current && current_proof_conclusion(proof, &row);
            row["fresh"] = current ? "true" : "false";
            row["validation"] = current                ? "current"
                                : dependencies_current ? "current-recognizer-rejected"
                                                       : "stored-dependency-or-publication-invalid";
            row["dependency_count"] = std::to_string(proof.dependencies.size());
            row["dependencies_omitted"] =
                std::to_string(proof.dependencies.size() > NativeInspection::dependency_limit
                                   ? proof.dependencies.size() - NativeInspection::dependency_limit
                                   : 0);
            static const char digits[] = "0123456789abcdef";
            for (size_t i = 0;
                 i < std::min(proof.dependencies.size(), NativeInspection::dependency_limit); ++i)
            {
                const auto &dependency = proof.dependencies[i];
                std::string bytes;
                for (uint8_t value : dependency.bytes)
                {
                    bytes += digits[value >> 4];
                    bytes += digits[value & 15];
                }
                row["dependency_" + std::to_string(i)] =
                    hex(dependency.first) + ":" + bytes + (dependency.code ? ";code" : ";data") +
                    ";owner=" + hex(dependency.owner) +
                    ";permissions=" + std::to_string(dependency.permissions) +
                    ";segment_bitness=" + std::to_string(dependency.bitness);
            }
            result.records.push_back(std::move(row));
        }
        return result;
    }

    X86RegionInspection inspect_region(uint64_t root) const
    {
        X86RegionInspection result;
        result.database = int64_t(get_dbctx_id());
        result.root = root;
        result.context = region_context;
        if (result.database != owner_database || closing_database || replaying_undo ||
            pending_ownership_recovery || native_mutation_depth != 0 || !config.enabled ||
            region_context == 0)
        {
            result.reason = "native analysis context unavailable";
            return result;
        }
        result = analyze_x86_region(root);
        result.database = int64_t(get_dbctx_id());
        result.context = region_context;
        return result;
    }

    bool dependency_intersects(const NativeProof &proof, ea_t first, ea_t end) const
    {
        return std::any_of(proof.dependencies.begin(), proof.dependencies.end(),
                           [&](const NativeProofDependency &dependency)
                           {
                               return dependency.first < end &&
                                      first < dependency.first + dependency.bytes.size();
                           });
    }

    void revoke_proof(NativeProof proof, bool schedule)
    {
        NativeMutationGuard guard(native_mutation_depth);
        for (const auto &owned : proof.owned_edges)
            for (const auto &current : collect_code_edges(proof.site))
                if (current.target == owned.target && current.type == owned.type &&
                    current.user == owned.user)
                {
                    del_cref(proof.site, owned.target, false);
                    break;
                }
        remove_owned_comment(proof.site, proof.owned_comment);
        if (ownership_ready)
            ownership_node.supdel(ea2node(proof.source));
        pending_flag_fallthroughs.erase(proof.source);
        emulated.sub(proof.source);
        if (schedule)
        {
            plan_ea(proof.source);
            plan_ea(proof.site);
        }
    }

    void invalidate_proofs(ea_t first, ea_t end, bool schedule = true)
    {
        for (auto it = native_proofs.begin(); it != native_proofs.end();)
        {
            if (!dependency_intersects(it->second, first, end))
            {
                ++it;
                continue;
            }
            NativeProof proof = std::move(it->second);
            it = native_proofs.erase(it); // Remove before callbacks can reenter.
            revoke_proof(std::move(proof), schedule);
        }
    }

    void revalidate_proofs()
    {
        for (auto it = native_proofs.begin(); it != native_proofs.end();)
        {
            if (proof_is_fresh(it->second) && current_proof_conclusion(it->second))
            {
                ++it;
                continue;
            }
            NativeProof proof = std::move(it->second);
            it = native_proofs.erase(it);
            revoke_proof(std::move(proof), true);
        }
    }

    void invalidate_new_fallthrough(ea_t from, ea_t to)
    {
        insn_t source;
        const bool ordinary = decode_insn(&source, from) > 0 && source.ea + source.size == to &&
                              source.itype != NN_jmp && !is_ret_insn(source) &&
                              !is_call_insn(source) && !is_indirect_jump_insn(source);
        for (auto it = native_proofs.begin(); it != native_proofs.end();)
        {
            const auto &proof = it->second;
            const auto covered = [&](ea_t address)
            {
                return std::any_of(proof.dependencies.begin(), proof.dependencies.end(),
                                   [&](const NativeProofDependency &dependency)
                                   { return dependency.code && dependency.first == address; });
            };
            // The register/flag analysis already reconstructs this architectural
            // successor from bytes. Its ordinary emulation does not add an entry
            // if both endpoints were included in the proof. External adjacent
            // instructions, including those before a tail, do add an entry.
            const bool modeled = ordinary &&
                                 (proof.kind == NativeProof::Kind::Condition ||
                                  proof.kind == NativeProof::Kind::StackTransfer) &&
                                 covered(from) && covered(to);
            if (!dependency_intersects(proof, to, to + 1) || modeled)
            {
                ++it;
                continue;
            }
            NativeProof stale = std::move(it->second);
            it = native_proofs.erase(it);
            revoke_proof(std::move(stale), true);
        }
    }

    bool can_record_proof(ea_t source) const
    {
        return ownership_ready && !ownership_publication_disabled &&
               (native_proofs.count(source) != 0 || native_proofs.size() < maximum_native_proofs);
    }

    bool record_proof(NativeProof proof, const std::vector<existing_code_edge_t> &before,
                      const char *comment)
    {
        const auto old = native_proofs.find(proof.source);
        if (old != native_proofs.end())
        {
            proof.owned_edges = old->second.owned_edges;
            proof.owned_comment = old->second.owned_comment;
        }
        if (!proof.owned_comment.empty() &&
            proof.owned_comment != std::string(kCommentPrefix) + comment)
        {
            remove_owned_comment(proof.site, proof.owned_comment);
            proof.owned_comment.clear();
        }
        for (const auto &edge : collect_code_edges(proof.site))
        {
            // Other listeners may create additional references during our callback.
            // A before/after difference alone cannot assign those edges to us.
            if (!proof.intended_edge || !edge_matches(edge.target, edge.type, *proof.intended_edge))
                continue;
            const auto same = [&](const existing_code_edge_t &candidate)
            {
                return candidate.target == edge.target && candidate.type == edge.type &&
                       candidate.user == edge.user;
            };
            if (std::none_of(before.begin(), before.end(), same) &&
                std::none_of(proof.owned_edges.begin(), proof.owned_edges.end(), same))
                proof.owned_edges.push_back(edge);
        }
        if (append_analysis_comment(proof.site, comment))
            proof.owned_comment = std::string(kCommentPrefix) + comment;
        if (!persist_ownership(proof))
        {
            // Do not create an infinite reanalysis/retry wave on storage failure.
            // Existing ownership still needs cleanup, so keep the node accessible.
            ownership_publication_disabled = true;
            native_proofs.erase(proof.source);
            revoke_proof(std::move(proof), true);
            msg("[chernobog][ida-analysis] native ownership receipt write failed; "
                "new proof publication disabled\n");
            return false;
        }
        proof.conclusion = comment;
        proof.publication =
            native_inspection_publication == UINT64_MAX ? 0 : ++native_inspection_publication;
        native_proofs[proof.source] = std::move(proof);
        return true;
    }

    void on_database_event(int event, va_list arguments)
    {
        if (get_dbctx_id() != owner_database || native_mutation_depth != 0 || replaying_undo)
            return;
        const bool topology_changing =
            event == idb_event::set_func_start || event == idb_event::set_func_end ||
            event == idb_event::deleting_func || event == idb_event::deleting_func_tail
#if IDA_SDK_VERSION >= 940
            || event == idb_event::set_function_start || event == idb_event::set_function_end ||
            event == idb_event::deleting_function || event == idb_event::deleting_function_tail
#endif
            ;
        const bool topology_changed =
            event == idb_event::func_added || event == idb_event::func_updated ||
            event == idb_event::func_tail_appended || event == idb_event::func_tail_deleted ||
            event == idb_event::tail_owner_changed
#if IDA_SDK_VERSION >= 940
            || event == idb_event::function_added || event == idb_event::function_updated ||
            event == idb_event::function_tail_appended ||
            event == idb_event::function_tail_deleted ||
            event == idb_event::function_tail_owner_changed
#endif
            ;
        if (pending_ownership_recovery &&
            (topology_changing || topology_changed || event == idb_event::byte_patched ||
             event == idb_event::destroyed_items || event == idb_event::deleting_segm ||
             event == idb_event::savebase || event == idb_event::segm_attrs_updated
#if IDA_SDK_VERSION >= 940
             || event == idb_event::segment_attrs_updated
#endif
             ))
            recover_ownership_receipts();
        if (topology_changing)
        {
            // These notifications precede the ownership mutation. Invalidate
            // conservatively while receipts still refer to the original sites.
            invalidate_proofs(0, BADADDR);
            return;
        }
        if (topology_changed)
        {
            // Recompute conclusions after a topology update, including support
            // coverage; equal values with newly introduced dependencies are stale.
            revalidate_proofs();
            return;
        }
        if (event == idb_event::closebase)
        {
            closing_database = true;
        }
        else if (event == idb_event::savebase)
        {
            revalidate_proofs();
        }
        else if (event == idb_event::segm_moved)
        {
            const ea_t from = va_arg(arguments, ea_t);
            const ea_t to = va_arg(arguments, ea_t);
            const asize_t size = va_arg(arguments, asize_t);
            for (ea_t &source : moving_proof_sources)
            {
                if (source >= from && source - from < size)
                    source = to + (source - from);
                plan_ea(source);
            }
        }
        else if (event == idb_event::allsegs_moved)
        {
            for (ea_t source : moving_proof_sources)
                plan_ea(source);
            moving_proof_sources.clear();
        }
        else if (event == idb_event::byte_patched)
        {
            const ea_t address = va_arg(arguments, ea_t);
            invalidate_proofs(address, address + 1);
        }
        else if (event == idb_event::destroyed_items)
        {
            const ea_t first = va_arg(arguments, ea_t);
            const ea_t end = va_arg(arguments, ea_t);
            invalidate_proofs(first, end);
        }
        else if (event == idb_event::segm_attrs_updated)
        {
            revalidate_proofs();
        }
#if IDA_SDK_VERSION >= 940
        else if (event == idb_event::segment_attrs_updated)
        {
            revalidate_proofs();
        }
#endif
        else if (event == idb_event::deleting_segm)
        {
            const segment_t *segment = getseg(va_arg(arguments, ea_t));
            if (segment != nullptr)
                invalidate_proofs(segment->start_ea, segment->end_ea);
        }
    }

    void on_reference_event(ssize_t event, va_list arguments)
    {
        if (native_mutation_depth != 0)
            return;
        const ea_t from = va_arg(arguments, ea_t);
        const ea_t to = va_arg(arguments, ea_t);
        const int type = va_arg(arguments, int);
        if (pending_ownership_recovery)
        {
            if (event == processor_t::ev_add_cref && (type & XREF_USER) != 0)
                recover_ownership_receipts(from, to, type & XREF_MASK);
            else
                recover_ownership_receipts();
        }
        if (event == processor_t::ev_add_cref)
        {
            if ((type & XREF_USER) != 0)
            {
                // An explicit external reassertion transfers ownership to its author.
                for (auto &[source, proof] : native_proofs)
                {
                    (void)source;
                    if (proof.site != from)
                        continue;
                    auto &edges = proof.owned_edges;
                    edges.erase(
                        std::remove_if(
                            edges.begin(), edges.end(), [&](const existing_code_edge_t &edge)
                            { return edge.target == to && int(edge.type) == (type & XREF_MASK); }),
                        edges.end());
                }
                invalidate_proofs(from, from + 1);
            }
            if (exact_code_edge_exists(from,
                                       desired_code_edge_t{to, cref_t(type & XREF_MASK), false}))
                return;
            if ((type & XREF_MASK) == fl_F)
                invalidate_new_fallthrough(from, to);
            else
                invalidate_proofs(to, to + 1);
        }
        else if ((type & XREF_MASK) == dr_W)
        {
            invalidate_proofs(to, to + 1);
        }
    }

    bool mark_once(int category, ea_t address)
    {
        return findings_seen.insert({category, address}).second;
    }

    void remember_direct_call_target(ea_t target, ea_t fallthrough)
    {
        if (target == BADADDR || target == fallthrough ||
            observed_direct_call_targets.count(target) != 0)
        {
            return;
        }
        if (observed_direct_call_targets.size() >= config.maximum_post_scan_heads)
        {
            statistics.post_scan_truncated = true;
            return;
        }
        observed_direct_call_targets.insert(target);
    }

    bool redundant_rep_prefix(ea_t address)
    {
        if (prefix_decode_probe || !is_loaded(address))
            return false;
        // The same first-byte condition is required by the semantic eligibility
        // check below. Reject ordinary opcodes before the recursive raw decode.
        const uint8_t prefix = get_byte(address);
        if ((prefix != 0xF2 && prefix != 0xF3) || !is_loaded(address + 1))
        {
            return false;
        }
        struct probe_scope_t
        {
            bool &active;
            explicit probe_scope_t(bool &value) : active(value) { active = true; }
            ~probe_scope_t() { active = false; }
        } probe(prefix_decode_probe);

        insn_t prefixed;
        insn_t plain;
        return decode_insn(&prefixed, address) > 0 &&
               prefix_candidate_is_semantically_eligible(address, prefixed) &&
               decode_insn(&plain, address + 1) > 0 &&
               instructions_equivalent_without_prefix(prefixed, plain);
    }

    ssize_t handle_analysis(insn_t &instruction)
    {
        if (prefix_decode_probe || architecture != Architecture::X86 ||
            !config.redundant_prefixes || !redundant_rep_prefix(instruction.ea))
        {
            return 0;
        }
        if (!prefix_seen.contains(instruction.ea))
        {
            prefix_seen.add(instruction.ea, instruction.ea + 1);
            ++statistics.redundant_prefixes;
        }
        instruction.size = 1;
        instruction.itype = NN_nop;
        return 1;
    }

    ssize_t handle_output_mnemonic(outctx_t &context)
    {
        if (architecture != Architecture::X86 || !config.redundant_prefixes ||
            !redundant_rep_prefix(context.insn.ea))
        {
            return 0;
        }
        context.out_custom_mnem(get_byte(context.insn.ea) == 0xF2 ? "repne" : "rep");
        return 1;
    }

    bool handle_call_pop(const insn_t &instruction, bool revisiting)
    {
        if (architecture != Architecture::X86 || !config.call_pop_get_pc ||
            instruction.itype != NN_call || instruction.Op1.type != o_near)
        {
            return false;
        }
        const ea_t target = instruction.Op1.addr;
        const ea_t call_end = instruction.ea + instruction.size;
        if (target > call_end && uint64_t(target - call_end) > config.maximum_gap)
        {
            return false;
        }
        const auto gadget =
            classify_ida_get_pc_call(instruction, size_t(config.pop_ret_depth), true);
        if (!gadget)
            return false;
        if (!can_record_proof(instruction.ea))
            return false;
        NativeProof call_proof;
        call_proof.kind = NativeProof::Kind::Call;
        call_proof.source = call_proof.site = instruction.ea;
        call_proof.intended_edge = desired_code_edge_t{target, fl_JN, true};
        for (uint64_t address : gadget->support)
            if (!add_instruction_dependency(call_proof, ea_t(address)))
                return false;
        const auto before_call = collect_code_edges(instruction.ea);
        qstring trace;
        if (qgetenv("CHERNOBOG_IDA_GET_PC_TRACE", &trace) && !trace.empty() && trace[0] != '0')
        {
            msg("[chernobog][ida-analysis][get-pc-trace] native accepted call=%a "
                "target=%a owner=%p revisiting=%d\n",
                instruction.ea, target, get_func(instruction.ea), revisiting ? 1 : 0);
        }

        // This handler owns processor emulation for the reclassified CALL. Install
        // the one exact outgoing transfer and remove stale IDA-generated call and
        // fallthrough edges. Conflicting user edges make the proof inapplicable.
        if (!replace_generated_code_edges(instruction.ea,
                                          {desired_code_edge_t{target, fl_JN, true}}))
            return false;
        set_notproc(target);
        if (is_unknown(get_flags(target)))
            create_insn(target);
        auto_make_code(target);
        plan_ea(target);
        // Every accepted get-PC form is an intra-function transfer. In
        // particular, add-sp/discard gadgets continue in the target body and have
        // no later return edge that could otherwise pull that range into the
        // caller. Admit the proven gadget target before queuing it so nested
        // get-PC chains are traversed rather than truncated at an auto-created
        // tail boundary.
        func_t *call_owner = get_func(instruction.ea);
        if (call_owner != nullptr)
            get_pc_function_roots.insert(call_owner->start_ea);
        if (call_owner != nullptr && !func_contains(call_owner, target))
        {
            const bool appended = append_func_tail_ea(call_owner->start_ea, target, BADADDR);
            if (!trace.empty() && trace[0] != '0')
                msg("[chernobog][ida-analysis][get-pc-trace] target-tail owner=%a "
                    "target=%a appended=%d\n",
                    call_owner->start_ea, target, appended ? 1 : 0);
        }
        statistics.gaps_retyped +=
            retype_gap_as_bytes(call_end, target, config.maximum_gap, instruction.ea);
        add_user_stkpnt(target, -sval_t(gadget->width_bits / 8));

        qstring summary;
        summary.sprnt("%s; summary end=%a; width=%u bits; net SP delta=%lld bytes; "
                      "%zu modeled stack accesses retained; flags %s",
                      gadget->mode == classifier::get_pc_mode_t::discard_return_address
                          ? "call+discard get-PC idiom"
                          : "call+pop get-PC idiom",
                      ea_t(gadget->summary_end), gadget->width_bits,
                      static_cast<long long>(gadget->stack_delta_bytes),
                      gadget->stack_accesses.size(),
                      gadget->flags_preserved ? "preserved" : "effects retained");
        if (gadget->resumed_at.has_value())
        {
            const ea_t resumed = ea_t(*gadget->resumed_at);
            if (target_is_proven_code_candidate(instruction.ea, resumed))
            {
                if (!revisiting && resumed >= call_end && resumed < target &&
                    is_unknown(get_flags(resumed)))
                {
                    create_insn(resumed);
                }
                if (is_unknown(get_flags(resumed)))
                    create_insn(resumed);
                auto_make_code(resumed);
                plan_ea(resumed);
                func_t *owner = get_func(instruction.ea);
                // The effective return can already belong to a small auto-created
                // function or range while still being outside the caller. Test
                // containment in the caller, not merely whether some function owns
                // the address; that distinction lets chained gadgets become one
                // traversable CFG.
                if (owner != nullptr && !func_contains(owner, resumed))
                {
                    const bool appended = append_func_tail_ea(owner->start_ea, resumed, BADADDR);
                    if (!trace.empty() && trace[0] != '0')
                        msg("[chernobog][ida-analysis][get-pc-trace] resumed-tail owner=%a "
                            "resumed=%a appended=%d\n",
                            owner->start_ea, resumed, appended ? 1 : 0);
                }
            }
        }
        // Function-tail admission above can change the owner of supporting code.
        // It does not change these bytes or their instruction-level effects.
        for (auto &dependency : call_proof.dependencies)
        {
            const func_t *owner = get_func(dependency.first);
            dependency.owner = owner != nullptr ? owner->start_ea : BADADDR;
        }
        if (!record_proof(std::move(call_proof), before_call, summary.c_str()))
            return false;
        if (gadget->return_instruction != classifier::k_bad_address && gadget->resumed_at)
            install_call_return_fact(*gadget);
        if (mark_once(1, instruction.ea))
            ++statistics.get_pc_gadgets;
        return true;
    }

    void install_call_return_fact(const classifier::get_pc_candidate_t &gadget, bool defer = true)
    {
        const ea_t site = ea_t(gadget.return_instruction), target = ea_t(*gadget.resumed_at);
        if (!can_record_proof(site) || !target_is_proven_code_candidate(site, target))
            return;
        NativeProof proof;
        proof.source = proof.site = site;
        proof.kind = NativeProof::Kind::Return;
        proof.context_call = ea_t(gadget.call);
        for (uint64_t address : gadget.support)
            if (!add_instruction_dependency(proof, ea_t(address)))
                return;
        if (!add_dependency(proof, target, 1, false))
            return;
        if (is_unknown(get_flags(site)))
            create_insn(site);
        const auto before = collect_code_edges(site);
        const cref_t type = get_item_end(site) == target ? fl_F : fl_JN;
        proof.intended_edge = desired_code_edge_t{target, type, type != fl_F};
        if (!replace_generated_code_edges(site, {*proof.intended_edge}))
            return;
        qstring comment;
        comment.sprnt("exact call-context return target %a; CALL at %a; net SP delta=%lld bytes; "
                      "native stack accesses retained",
                      target, ea_t(gadget.call), static_cast<long long>(gadget.stack_delta_bytes));
        if (record_proof(std::move(proof), before, comment.c_str()))
        {
            plan_ea(target);
            if (defer && type == fl_F)
                pending_call_returns.insert(ea_t(gadget.call));
        }
    }

    bool handle_push_get_pc(const insn_t &instruction)
    {
        if (architecture != Architecture::X86 || !config.call_pop_get_pc ||
            instruction.itype != NN_push || !can_record_proof(instruction.ea))
            return false;
        const auto materialization = classify_ida_push_get_pc(instruction);
        if (!materialization)
            return false;
        NativeProof proof;
        proof.source = proof.site = instruction.ea;
        proof.kind = NativeProof::Kind::Materialization;
        proof.value = materialization->address_value;
        for (uint64_t address : materialization->support)
            if (!add_instruction_dependency(proof, ea_t(address)))
                return false;
        const auto before = collect_code_edges(instruction.ea);
        qstring comment;
        comment.sprnt("stack address materialization %a; width=%u bits; net SP delta=%lld bytes; "
                      "flags preserved; %s",
                      ea_t(materialization->address_value), materialization->width_bits,
                      static_cast<long long>(materialization->stack_delta_bytes),
                      materialization->restored_register.valid()
                          ? "saved register restored; both stack writes and locked XCHG retained"
                          : "stack write retained");
        return record_proof(std::move(proof), before, comment.c_str());
    }

    bool handle_push_return(const insn_t &instruction)
    {
        if (architecture != Architecture::X86 || !config.push_return ||
            instruction.itype != NN_push)
        {
            return false;
        }
        const auto transfer = classify_ida_push_return(instruction, config.register_scan_depth);
        if (!transfer)
            return false;
        const ea_t return_ea = ea_t(transfer->transfer);
        if (!can_record_proof(instruction.ea))
            return false;
        NativeProof proof;
        proof.source = instruction.ea;
        proof.site = return_ea;
        proof.kind = NativeProof::Kind::StackTransfer;
        if (!add_instruction_dependency(proof, instruction.ea) ||
            !add_instruction_dependency(proof, return_ea))
            return false;
        for (uint64_t address : transfer->target.definitions)
            if (!add_instruction_dependency(proof, ea_t(address)))
                return false;
        for (const auto &memory : transfer->target.memory)
            if (!add_dependency(proof, ea_t(memory.address), memory.bytes.size(), false))
                return false;
        const auto before = collect_code_edges(return_ea);
        if (!transfer->target.value)
        {
            record_proof(
                std::move(proof), before,
                "stack-mediated transfer candidate; unresolved target; stack write retained");
            return false;
        }
        const ea_t target = ea_t(*transfer->target.value);
        if (!target_is_executable(target))
            return false;
        if (!add_dependency(proof, target, 1, false))
            return false;
        proof.intended_edge = desired_code_edge_t{target, fl_JN, true};
        // The RET may not yet be an instruction head during the PUSH callback.
        // Decode it without changing either instruction's native bytes or SP effect.
        if (is_unknown(get_flags(return_ea)))
            create_insn(return_ea);
        if (!add_user_cref(return_ea, target, fl_JN) &&
            !exact_code_edge_exists(return_ea, desired_code_edge_t{target, fl_JN, true}))
            return false;
        if (is_unknown(get_flags(target)))
        {
            auto_make_code(target);
            plan_ea(target);
        }
        qstring comment;
        comment.sprnt("exact push/return target %a; width=%u bits; net SP delta=0; "
                      "stack write=%u bytes retained",
                      target, transfer->width_bits, transfer->stack_write_bytes);
        if (!record_proof(std::move(proof), before, comment.c_str()))
            return false;
        if (mark_once(2, return_ea))
            ++statistics.push_return_targets;
        return true;
    }

    bool handle_zero_register(const insn_t &instruction)
    {
        if (architecture != Architecture::Arm || !config.zero_register_branches)
            return false;
        BranchDecision decision = BranchDecision::Unknown;
        switch (instruction.itype)
        {
        case ARM_cbz:
        case ARM_tbz:
            if (zero_register_operand(instruction.Op1))
                decision = BranchDecision::Taken;
            break;
        case ARM_cbnz:
        case ARM_tbnz:
            if (zero_register_operand(instruction.Op1))
                decision = BranchDecision::NotTaken;
            break;
        default:
            break;
        }
        if (decision == BranchDecision::Unknown)
            return false;
        const ea_t target = branch_target(instruction);
        if (target == BADADDR)
            return false;
        const ea_t selected =
            decision == BranchDecision::Taken ? target : instruction.ea + instruction.size;
        const cref_t selected_type = decision == BranchDecision::Taken ? fl_JN : fl_F;
        if (!replace_generated_code_edges(
                instruction.ea,
                {desired_code_edge_t{selected, selected_type, selected_type != fl_F}}))
        {
            return false;
        }
        auto_make_code(selected);
        plan_ea(selected);
        append_analysis_comment(instruction.ea, decision == BranchDecision::Taken
                                                    ? "always taken (architectural zero register)"
                                                    : "never taken (architectural zero register)");
        if (mark_once(3, instruction.ea))
            ++statistics.zero_register_branches;
        return true;
    }

    bool handle_opposite_pair(const insn_t &instruction, bool revisiting)
    {
        if (!config.opposite_branches)
            return false;
        insn_t next;
        if (decode_insn(&next, instruction.ea + instruction.size) <= 0)
            return false;
        const ea_t target = branch_target(instruction);
        if (target == BADADDR || branch_target(next) != target)
            return false;
        bool opposite = false;
        if (architecture == Architecture::X86)
            opposite = opposite_x86_condition(instruction.itype) == next.itype;
        else if (architecture == Architecture::Arm)
            opposite = opposite_arm_branch(instruction, next);
        if (!opposite)
            return false;

        statistics.gaps_retyped +=
            retype_gap_as_bytes(next.ea + next.size, target, config.maximum_gap, next.ea);
        if (is_unknown(get_flags(target)))
            create_insn(target);
        add_user_cref(instruction.ea, target, fl_JN, true, false);
        add_user_cref(instruction.ea, instruction.ea + instruction.size, fl_F);
        add_user_cref(next.ea, target, fl_JN, false, false);
        // Reinstall the first predicate's adjacent fallthrough after the processor
        // has finalized its own branch xrefs. fl_F cannot be made user-persistent,
        // and the paired-branch reclassification can otherwise leave the second
        // predicate as an orphan block.
        const auto fallthrough_edge =
            std::make_pair(instruction.ea, instruction.ea + instruction.size);
        if (std::find(pending_cfg_edges.begin(), pending_cfg_edges.end(), fallthrough_edge) ==
            pending_cfg_edges.end())
        {
            pending_cfg_edges.push_back(fallthrough_edge);
        }
        append_analysis_comment(instruction.ea, "adjacent opposite predicates cover both outcomes");
        if (mark_once(4, instruction.ea))
            ++statistics.opposite_branch_pairs;
        return true;
    }

    bool handle_entry_predicate(const insn_t &instruction)
    {
        if (architecture != Architecture::X86 || !config.entry_predicates ||
            opposite_x86_condition(instruction.itype) == 0)
        {
            return false;
        }
        const func_t *function = get_func(instruction.ea);
        if (function == nullptr || instruction.ea < function->start_ea ||
            uint64_t(instruction.ea - function->start_ea) > config.entry_predicate_window)
        {
            return false;
        }
        for (ea_t scan = function->start_ea; scan < instruction.ea;)
        {
            insn_t prior;
            if (decode_insn(&prior, scan) <= 0)
                return false;
            if (instruction_modifies_x86_flags(prior.itype))
                return false;
            scan += prior.size;
        }
        if (append_analysis_comment(instruction.ea,
                                    "entry predicate consumes ABI-unspecified flags") &&
            mark_once(5, instruction.ea))
        {
            ++statistics.entry_predicates;
        }
        return true;
    }

    bool handle_known_x86_flag(const insn_t &instruction, bool revisiting)
    {
        if (architecture != Architecture::X86 || !config.known_x86_flags)
            return false;
        const auto condition = x86_condition(instruction.itype);
        if (!condition)
            return false;
        const auto fact = analyze_x86_flag_fact_before(instruction, size_t(config.flag_scan_depth));
        const auto flags = fact.flags;
        const auto outcome = x86_abstract::evaluate(condition->condition, flags);
        if (!outcome)
        {
            const auto old = native_proofs.find(instruction.ea);
            if (old != native_proofs.end() && old->second.kind == NativeProof::Kind::Condition)
            {
                NativeProof stale = std::move(old->second);
                native_proofs.erase(old);
                // This instruction is already being emulated. Revoke its old
                // publication without scheduling another identical unknown query.
                revoke_proof(std::move(stale), false);
            }
            return false;
        }
        if (!can_record_proof(instruction.ea))
            return false;
        NativeProof proof;
        proof.source = proof.site = instruction.ea;
        proof.kind = NativeProof::Kind::Condition;
        proof.value = *outcome ? 1 : 0;
        if (!add_instruction_dependency(proof, instruction.ea))
            return false;
        for (uint64_t address : fact.support)
            if (!add_instruction_dependency(proof, ea_t(address)))
                return false;
        const auto before = collect_code_edges(instruction.ea);
        if (condition->use != X86ConditionUse::branch)
        {
            record_proof(std::move(proof), before,
                         condition->use == X86ConditionUse::set_byte
                             ? (*outcome ? "SETcc byte result 1 (locally proven flags)"
                                         : "SETcc byte result 0 (locally proven flags)")
                             : (*outcome ? "CMOVcc condition true (locally proven flags)"
                                         : "CMOVcc condition false (locally proven flags)"));
            // Facts alone do not authorize deletion of memory access, partial
            // register writes, or the processor module's normal emulation.
            return false;
        }
        const BranchDecision decision = *outcome ? BranchDecision::Taken : BranchDecision::NotTaken;
        const ea_t target = branch_target(instruction);
        if (target == BADADDR)
            return false;
        const ea_t fallthrough = instruction.ea + instruction.size;
        const ea_t selected = decision == BranchDecision::Taken ? target : fallthrough;
        const cref_t selected_type = decision == BranchDecision::Taken ? fl_JN : fl_F;
        if (!add_dependency(proof, selected, 1, false))
            return false;
        proof.intended_edge = desired_code_edge_t{selected, selected_type, selected_type != fl_F};
        if (!replace_generated_code_edges(
                instruction.ea,
                {desired_code_edge_t{selected, selected_type, selected_type != fl_F}}))
        {
            return false;
        }
        if (decision == BranchDecision::Taken)
        {
            // Keep instruction/data ownership intact so revoking this proof needs
            // no speculative reconstruction of the skipped interval.
            if (is_unknown(get_flags(target)))
                create_insn(target);
        }
        else
        {
            auto_make_code(fallthrough);
            // Normal flow cannot carry XREF_USER. The processor's initial analysis
            // can erase fl_F after our ev_emu_insn callback, just as with get-PC.
            // Revalidate the proof after that wave before restoring it once.
            if (!revisiting || native_proofs.count(instruction.ea) == 0)
                pending_flag_fallthroughs.insert(instruction.ea);
        }
        plan_ea(selected);
        qstring comment;
        comment.sprnt("%s (locally proven x86 flags; known=%02X value=%02X)",
                      decision == BranchDecision::Taken ? "always taken" : "never taken",
                      unsigned(flags.known), unsigned(flags.value));
        if (!record_proof(std::move(proof), before, comment.c_str()))
            return false;
        if (mark_once(6, instruction.ea))
            ++statistics.known_flag_branches;
        return true;
    }

    bool handle_indirect_branch(const insn_t &instruction)
    {
        if (!config.indirect_branches)
            return false;
        const bool call = is_call_insn(instruction);
        const bool jump = is_indirect_jump_insn(instruction);
        if ((!call && !jump) || is_ret_insn(instruction))
            return false;
        const uint32_t features = instruction.get_canon_feature(PH);
        int reg = -1;
        for (int index = 0; index < UA_MAXOP; ++index)
        {
            const op_t &operand = instruction.ops[index];
            if (operand.type == o_void)
                break;
            if (operand.type != o_reg)
                continue;
            if (has_cf_chg(features, index) && !has_cf_use(features, index))
                continue;
            reg = operand.reg;
            break;
        }
        if (reg < 0)
            return false;
        reg_value_info_t value;
        ea_t target = BADADDR;
        if (!find_reg_value_info(&value, instruction.ea, reg, config.register_scan_depth) ||
            !reg_value_address_compat(value, &target) || !target_is_executable(target))
        {
            return false;
        }
        const cref_t type = call ? fl_CN : fl_JN;
        if (flow_xref_exists(instruction.ea, true, BADADDR, type))
            return false;
        add_user_cref(instruction.ea, target, type);
        qstring comment;
        comment.sprnt("resolved to %a (IDA register tracker)", target);
        append_analysis_comment(instruction.ea, comment.c_str());
        if (mark_once(7, instruction.ea))
            ++statistics.indirect_targets;
        return true;
    }

    bool handle_jump_gap(const insn_t &instruction, bool revisiting)
    {
        if (architecture != Architecture::X86 || !config.jump_gaps || instruction.itype != NN_jmp ||
            instruction.Op1.type == o_far)
        {
            return false;
        }
        const ea_t target = branch_target(instruction);
        const ea_t fallthrough = instruction.ea + instruction.size;
        if (target == BADADDR || target <= fallthrough)
            return false;
        const size_t changed =
            retype_gap_as_bytes(fallthrough, target, config.maximum_gap, instruction.ea);
        if (changed > 0 && is_unknown(get_flags(target)))
            create_insn(target);
        statistics.gaps_retyped += changed;
        return changed != 0;
    }

    ssize_t handle_emulation(const insn_t &instruction)
    {
        if (pending_ownership_recovery)
            recover_ownership_receipts();
        NativeMutationGuard guard(native_mutation_depth);
        const bool revisiting = emulated.contains(instruction.ea);
        if (!revisiting)
            emulated.add(instruction.ea, instruction.ea + instruction.size);
        const bool call_pop = handle_call_pop(instruction, revisiting);
        remember_direct_jump_decode(instruction);
        if (!call_pop && config.orphan_functions && is_call_insn(instruction) &&
            direct_transfer(instruction))
        {
            const ea_t target = branch_target(instruction);
            remember_direct_call_target(target, instruction.ea + instruction.size);
        }
        // Additive mutations must not claim ev_emu_insn: returning 1 suppresses
        // the processor module's normal emulation. Only handlers that installed a
        // complete exclusive edge set own the event.
        // A PUSH-next/RET pair has a control-transfer fact at RET. Do not replace
        // its ownership record with the less specific address-materialization fact.
        if (!handle_push_return(instruction))
            (void)handle_push_get_pc(instruction);
        const bool zero_register = handle_zero_register(instruction);
        (void)handle_opposite_pair(instruction, revisiting);
        (void)handle_entry_predicate(instruction);
        const bool known_flag = handle_known_x86_flag(instruction, revisiting);
        (void)handle_indirect_branch(instruction);
        (void)handle_jump_gap(instruction, revisiting);
        return call_pop || zero_register || known_flag ? 1 : 0;
    }

    ssize_t idaapi on_event(ssize_t code, va_list arguments) override
    {
        if (get_dbctx_id() != owner_database || !config.enabled)
            return 0;
        if (code == processor_t::ev_replaying_undo)
        {
            replaying_undo = true;
            return 0;
        }
        if (code == processor_t::ev_ending_undo)
        {
            replaying_undo = false;
            // IDA is still replaying its internal transaction at this notification.
            // Mutating xrefs/comments here can corrupt the undo event sequence.
            // Reload receipts at the next ordinary analysis/database interaction.
            native_proofs.clear();
            pending_flag_fallthroughs.clear();
            pending_ownership_recovery = true;
            return 0;
        }
        if (replaying_undo)
            return 0;
        if (code == processor_t::ev_moving_segm
#if IDA_SDK_VERSION >= 940
            || code == processor_t::ev_moving_segment
#endif
        )
        {
            if (pending_ownership_recovery)
                recover_ownership_receipts();
            for (const auto &[source, proof] : native_proofs)
            {
                (void)proof;
                if (moving_proof_sources.size() < maximum_native_proofs &&
                    std::find(moving_proof_sources.begin(), moving_proof_sources.end(), source) ==
                        moving_proof_sources.end())
                    moving_proof_sources.push_back(source);
            }
            // Revoke while EAs still identify the original metadata. A vetoed move
            // merely causes recomputation at unchanged addresses.
            invalidate_proofs(0, BADADDR);
            return 0;
        }
        if (code == processor_t::ev_add_cref || code == processor_t::ev_add_dref)
        {
            on_reference_event(code, arguments);
            return 0;
        }
        if (code == processor_t::ev_ana_insn)
            return handle_analysis(*va_arg(arguments, insn_t *));
        if (code == processor_t::ev_emu_insn)
            return handle_emulation(*va_arg(arguments, const insn_t *));
        if (code == processor_t::ev_out_mnem)
            return handle_output_mnemonic(*va_arg(arguments, outctx_t *));
        return 0;
    }

    void fix_pending_cfg_edges()
    {
        // A queued CALL-context return must be rederived from current instructions;
        // a stale (RET,target) pair cannot justify reinstating an edge after edits.
        const auto pending_calls = std::move(pending_call_returns);
        pending_call_returns.clear();
        for (ea_t source : pending_calls)
        {
            insn_t call;
            if (!is_code(get_flags(source)) || decode_insn(&call, source) <= 0)
                continue;
            const auto gadget = classify_ida_get_pc_call(call, size_t(config.pop_ret_depth), true);
            if (gadget && gadget->resumed_at &&
                gadget->return_instruction != classifier::k_bad_address)
                install_call_return_fact(*gadget, false);
        }
        for (const auto &edge : pending_cfg_edges)
        {
            if (is_code(get_flags(edge.first)) && get_item_end(edge.first) == edge.second)
            {
                add_user_cref(edge.first, edge.second, fl_F);
                // The edge is installed from auto_empty_finally, after the original
                // traversal stopped at the return. Explicitly queue its continuation
                // so chained call/pop gadgets are discovered in the next bounded
                // autoanalysis wave instead of remaining unreachable until a manual
                // reanalysis.
                if (is_unknown(get_flags(edge.second)))
                    create_insn(edge.second);
                auto_make_code(edge.second);
                plan_ea(edge.first);
                plan_ea(edge.second);
            }
        }
        pending_cfg_edges.clear();
        const auto pending_flags = std::move(pending_flag_fallthroughs);
        pending_flag_fallthroughs.clear();
        for (ea_t address : pending_flags)
        {
            insn_t instruction;
            if (!is_code(get_flags(address)) || decode_insn(&instruction, address) <= 0)
                continue;
            const auto condition = x86_condition(instruction.itype);
            if (!condition || condition->use != X86ConditionUse::branch)
                continue;
            const auto flags =
                analyze_x86_flags_before(instruction, size_t(config.flag_scan_depth));
            const auto outcome = x86_abstract::evaluate(condition->condition, flags);
            if (!outcome || *outcome)
                continue;
            const ea_t continuation = instruction.ea + instruction.size;
            if (is_unknown(get_flags(continuation)))
                create_insn(continuation);
            if (replace_generated_code_edges(address,
                                             {desired_code_edge_t{continuation, fl_F, false}}))
            {
                auto_make_code(continuation);
                plan_ea(continuation);
            }
        }
    }

    size_t expand_get_pc_function_tails()
    {
        size_t appended_count = 0;
        size_t inspected = 0;
        bool limit_hit = false;
        std::set<ea_t> completed_roots;
        for (ea_t root : get_pc_function_roots)
        {
            func_t *function = get_func(root);
            if (function == nullptr || function->start_ea != root)
            {
                completed_roots.insert(root);
                continue;
            }

            std::vector<std::pair<ea_t, ea_t>> worklist;
            std::set<ea_t> queued;
            auto queue_noncall_successors = [&](ea_t source)
            {
                xrefblk_t xref;
                for (bool ok = xref.first_from(source, XREF_CODE); ok; ok = xref.next_from())
                {
                    const int type = int(xref.type) & XREF_MASK;
                    if (type != fl_F && type != fl_JF && type != fl_JN)
                        continue;
                    if (queued.insert(xref.to).second)
                        worklist.emplace_back(source, xref.to);
                }
            };

            function_item_iterator_t item(root);
            for (bool ok = item.first(); ok; ok = item.next_code())
            {
                if (++inspected > config.maximum_post_scan_heads)
                {
                    limit_hit = true;
                    completed_roots.insert(root);
                    break;
                }
                queue_noncall_successors(item.current());
            }
            if (limit_hit)
                break;

            for (size_t cursor = 0; cursor < worklist.size(); ++cursor)
            {
                if (++inspected > config.maximum_post_scan_heads)
                {
                    limit_hit = true;
                    completed_roots.insert(root);
                    break;
                }
                const ea_t source = worklist[cursor].first;
                const ea_t target = worklist[cursor].second;
                func_t *owner = get_func(target);
                if (owner != nullptr)
                {
                    if (owner->start_ea == root)
                        queue_noncall_successors(target);
                    continue;
                }
                const flags64_t flags = get_flags(target);
                if (!is_code(flags) || !is_head(flags) || has_user_name(flags) ||
                    !target_is_proven_code_candidate(source, target))
                {
                    continue;
                }
                const ea_t end = get_item_end(target);
                if (end == BADADDR || end <= target || !append_func_tail_ea(root, target, end))
                {
                    continue;
                }
                ++appended_count;
                queue_noncall_successors(target);
            }
            if (limit_hit)
                break;
            completed_roots.insert(root);
        }
        for (ea_t root : completed_roots)
            get_pc_function_roots.erase(root);
        statistics.post_scan_truncated |= limit_hit;
        statistics.get_pc_tail_extensions += appended_count;
        return appended_count;
    }

    size_t direct_jump_decode_limit() const
    {
        return std::min<size_t>(config.maximum_direct_jump_targets, 4096);
    }

    void remember_direct_jump_decode(const insn_t &instruction)
    {
        if (!config.direct_jump_decode || architecture != Architecture::X86 ||
            instruction.itype != NN_jmp || instruction.Op1.type != o_near)
            return;
        const ea_t target = instruction.Op1.addr;
        const segment_t *segment = getseg(target);
        // Sectionless executable Mach-O segments can be classified SEG_DATA by
        // the loader. Follow an existing exact jump without retyping that segment.
        if (segment == nullptr || segment->type != SEG_DATA ||
            (segment->perm & SEGPERM_EXEC) == 0 || !is_unknown(get_flags(target)))
            return;
        const std::pair<ea_t, ea_t> edge{instruction.ea, target};
        if (pending_direct_jump_decodes.count(edge) != 0)
            return;
        if (statistics.direct_jump_decode_attempts + pending_direct_jump_decodes.size() >=
            direct_jump_decode_limit())
        {
            statistics.direct_jump_decode_truncated = true;
            return;
        }
        pending_direct_jump_decodes.insert(edge);
    }

    void decode_pending_direct_jump_targets()
    {
        auto pending = std::move(pending_direct_jump_decodes);
        pending_direct_jump_decodes.clear();
        for (const auto &edge : pending)
        {
            if (statistics.direct_jump_decode_attempts >= direct_jump_decode_limit())
            {
                statistics.direct_jump_decode_truncated = true;
                break;
            }
            ++statistics.direct_jump_decode_attempts;
            const ea_t source = edge.first, target = edge.second;
            const segment_t *source_segment = getseg(source);
            const segment_t *target_segment = getseg(target);
            insn_t jump, decoded;
            if (!is_code(get_flags(source)) || !is_head(get_flags(source)) ||
                decode_insn(&jump, source) <= 0 || jump.itype != NN_jmp ||
                jump.Op1.type != o_near || jump.Op1.addr != target ||
                !exact_code_edge_exists(source, {target, fl_JN, false}) ||
                source_segment == nullptr || target_segment == nullptr ||
                source_segment->bitness == 0 ||
                source_segment->bitness != target_segment->bitness ||
                target_segment->type != SEG_DATA || (target_segment->perm & SEGPERM_EXEC) == 0 ||
                !is_unknown(get_flags(target)) || get_func(target) != nullptr ||
                decode_insn(&decoded, target) <= 0 ||
                target_segment->end_ea - target < ea_t(decoded.size))
                continue;
            bool admissible = true;
            for (ea_t byte = target; byte < target + decoded.size; ++byte)
            {
                const flags64_t flags = get_flags(byte);
                // Never overwrite defined data/tails, interior labels, or unloaded
                // storage. A label at the exact jump target is retained by create_insn;
                // relocated symbol names are common on these protected entry points.
                if (!is_unknown(flags) || !is_loaded(byte) ||
                    (byte != target && has_user_name(flags)))
                {
                    admissible = false;
                    break;
                }
            }
            if (admissible && create_insn(target) > 0)
                ++statistics.direct_jump_targets_decoded;
            // IDA owns subsequent ordinary decoding and function-tail decisions.
            // No bytes, permissions, user xrefs, or inferred proof edges are changed.
        }
    }

    size_t recover_orphan_functions(bool discover_database_targets)
    {
        if (!config.orphan_functions && !config.direct_jump_decode)
            return 0;
        size_t scanned_heads = 0;
        bool limit_hit = false;
        if (discover_database_targets)
        {
            const int segment_count = get_segm_qty();
            for (int segment_index = 0; segment_index < segment_count && !limit_hit;
                 ++segment_index)
            {
                const segment_t *segment = getnseg(segment_index);
                if (segment == nullptr || (segment->perm & SEGPERM_EXEC) == 0)
                    continue;
                ea_t address = segment->start_ea;
                while (address != BADADDR && address < segment->end_ea)
                {
                    if (scanned_heads >= config.maximum_post_scan_heads)
                    {
                        limit_hit = true;
                        break;
                    }
                    ++scanned_heads;
                    if (is_code(get_flags(address)) && is_head(get_flags(address)))
                    {
                        insn_t instruction;
                        if (decode_insn(&instruction, address) > 0)
                        {
                            remember_direct_jump_decode(instruction);
                            if (config.orphan_functions && is_call_insn(instruction) &&
                                direct_transfer(instruction))
                            {
                                const ea_t target = branch_target(instruction);
                                remember_direct_call_target(target,
                                                            instruction.ea + instruction.size);
                            }
                        }
                    }
                    const ea_t next = next_head(address, segment->end_ea);
                    if (next == BADADDR || next <= address)
                        break;
                    address = next;
                }
            }
            statistics.post_scan_heads += scanned_heads;
            statistics.post_scan_truncated |= limit_hit;
        }

        if (!config.orphan_functions)
            return 0;
        size_t promoted = 0;
        for (auto iterator = observed_direct_call_targets.begin();
             iterator != observed_direct_call_targets.end();)
        {
            const ea_t target = *iterator;
            func_t *owner = get_func(target);
            if (owner != nullptr)
            {
                // A proper entry is resolved and can leave the candidate set. Retain
                // interior targets so a later IDA function-boundary correction can
                // make them eligible without another whole-database scan; do not split
                // the current owner automatically.
                if (owner->start_ea == target)
                    iterator = observed_direct_call_targets.erase(iterator);
                else
                    ++iterator;
                continue;
            }
            if (!target_is_executable(target))
            {
                ++iterator;
                continue;
            }
            if (is_unknown(get_flags(target)))
            {
                insn_t decoded;
                if (decode_insn(&decoded, target) <= 0 || create_insn(target) <= 0)
                {
                    ++iterator;
                    continue;
                }
            }
            bool created = false;
            if (add_func(target))
            {
                created = true;
            }
            else
            {
                const ea_t end = bounded_function_end(target, config.orphan_scan_instructions);
                if (end != BADADDR && get_func(target) == nullptr && add_func(target, end))
                {
                    created = true;
                }
            }
            if (!created)
            {
                ++iterator;
                continue;
            }
            ++promoted;
            iterator = observed_direct_call_targets.erase(iterator);
        }
        statistics.orphan_functions += promoted;
        return promoted;
    }

    void outline_wrapper_functions()
    {
        if (!config.outline_wrappers)
            return;
        size_t marked = 0;
        const size_t count = get_func_qty();
        const size_t scan_count = qmin(count, config.maximum_post_scan_functions);
        for (size_t index = 0; index < scan_count; ++index)
        {
            func_t *function = getn_func(index);
            if (function == nullptr || (function->flags & FUNC_OUTLINE) != 0)
                continue;
            // FUNC_OUTLINE changes decompiler structure. Require both independent
            // signals: an explicit Hikari wrapper name and the complete bounded
            // one-call forwarding shape. Neither a name nor a ubiquitous short
            // one-call function is sufficient alone.
            if (!name_contains_hikari_wrapper(function->start_ea) ||
                !wrapper_shape(function, config))
            {
                continue;
            }
            const uint32_t old_flags = function->flags;
            function->flags |= FUNC_OUTLINE;
            if (update_func(function))
                ++marked;
            else
                function->flags = old_flags;
        }
        statistics.post_scan_functions += scan_count;
        statistics.post_scan_truncated |= scan_count < count;
        statistics.outlined_wrappers += marked;
    }

    void on_autoanalysis_complete()
    {
        if (get_dbctx_id() != owner_database || !config.enabled || post_analysis_running)
            return;
        if (pending_ownership_recovery)
            recover_ownership_receipts();
        revalidate_proofs();
        NativeMutationGuard guard(native_mutation_depth);
        post_analysis_running = true;
        fix_pending_cfg_edges();
        (void)expand_get_pc_function_tails();
        const bool initial_metadata_scan = !post_metadata_scanned;
        size_t promoted = 0;
        if (!post_metadata_scanned)
        {
            // This is a bounded IDA decoder/xref metadata pass, not emulation.
            // Discover the baseline direct-call set once between per-database
            // resets. ev_emu_insn adds later call targets incrementally, so future
            // autoanalysis completions need not rescan the whole database.
            post_metadata_scanned = true;
            promoted = recover_orphan_functions(true);
        }
        else if (!observed_direct_call_targets.empty())
        {
            promoted = recover_orphan_functions(false);
        }
        decode_pending_direct_jump_targets();
        if (initial_metadata_scan || promoted > 0)
        {
            outline_wrapper_functions();
            if (statistics.post_scan_truncated)
            {
                msg("[chernobog][ida-analysis] post-analysis scan reached its "
                    "configured bound (%zu heads, %zu functions)\n",
                    statistics.post_scan_heads, statistics.post_scan_functions);
            }
        }
        if (statistics.orphan_functions != reported_orphan_functions ||
            statistics.outlined_wrappers != reported_outlined_wrappers ||
            statistics.get_pc_tail_extensions != reported_get_pc_tail_extensions)
        {
            msg("[chernobog][ida-analysis] post-analysis: %zu get-PC tail "
                "extensions, %zu orphan functions, %zu outlined wrappers\n",
                statistics.get_pc_tail_extensions, statistics.orphan_functions,
                statistics.outlined_wrappers);
            reported_get_pc_tail_extensions = statistics.get_pc_tail_extensions;
            reported_orphan_functions = statistics.orphan_functions;
            reported_outlined_wrappers = statistics.outlined_wrappers;
        }
        post_analysis_running = false;
    }
};

NativeAnalysisEngine::NativeAnalysisEngine() : impl_(new Impl) {}

NativeAnalysisEngine::~NativeAnalysisEngine() = default;

bool NativeAnalysisEngine::enabled() const
{
    return impl_ != nullptr && impl_->config.enabled && impl_->hooked;
}

void NativeAnalysisEngine::reset()
{
    if (impl_ != nullptr)
        impl_->reset();
}

void NativeAnalysisEngine::on_autoanalysis_complete()
{
    if (impl_ != nullptr)
        impl_->on_autoanalysis_complete();
}

void NativeAnalysisEngine::on_database_event(int event, va_list arguments)
{
    if (impl_ != nullptr)
        impl_->on_database_event(event, arguments);
}

const NativeAnalysisStats &NativeAnalysisEngine::stats() const
{
    static const NativeAnalysisStats empty;
    return impl_ != nullptr ? impl_->statistics : empty;
}

NativeInspection NativeAnalysisEngine::inspect(uint64_t function_start) const
{
    return impl_ != nullptr ? impl_->inspect(function_start) : NativeInspection{};
}

X86RegionInspection NativeAnalysisEngine::inspect_region(uint64_t root) const
{
    return impl_ != nullptr ? impl_->inspect_region(root) : X86RegionInspection{};
}

} // namespace chernobog::ida_analysis
