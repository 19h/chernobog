#include "recurrent_switch.h"

#include "../analysis/z3_solver.h"
#include "../../common/compat.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace recurrent_switch {
namespace {

constexpr std::size_t k_max_path_blocks = 32;
constexpr std::size_t k_max_paths_per_case = 256;
constexpr std::size_t k_max_total_paths = 4096;
constexpr std::size_t k_max_work_items_per_case = 4096;
constexpr std::size_t k_max_entry_work_items = 4096;
// A few converged/type-refined paths in the reference recurrent dispatcher
// require slightly more than 100 ms for Z3's uniqueness counterexample check.
// Keep both a per-query bound and a hard wall-clock bound so those paths are
// deterministic without allowing decompilation-time solver runaway.
constexpr unsigned k_solver_query_budget_ms = 1000;
constexpr unsigned k_solver_total_budget_ms = 30000;

class scoped_solver_timeout_t {
public:
    scoped_solver_timeout_t()
      : previous_(z3_solver::get_global_timeout()) {}
    ~scoped_solver_timeout_t()
    {
        z3_solver::set_global_timeout(previous_);
    }

private:
    unsigned previous_;
};

bool apply_remaining_solver_budget(
    const std::chrono::steady_clock::time_point &deadline)
{
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    if ( remaining <= 0 )
        return false;
    z3_solver::set_global_timeout(static_cast<unsigned>(std::min<int64_t>(
        remaining, k_solver_query_budget_ms)));
    return true;
}

struct storage_key_t {
    mopt_t type = mop_z;
    uint64_t id = 0;
    int size = 0;

    bool operator<(const storage_key_t &other) const
    {
        if ( type != other.type )
            return type < other.type;
        if ( id != other.id )
            return id < other.id;
        return size < other.size;
    }
};

struct edge_key_t {
    int source = -1;
    int destination = -1;

    bool operator<(const edge_key_t &other) const
    {
        return source < other.source
            || (source == other.source && destination < other.destination);
    }
};

struct case_path_t {
    uint64_t state = 0;
    std::vector<int> blocks;
    std::vector<edge_key_t> edges;
    std::optional<int> resolved_target;
    bool infeasible = false;
};

enum class selector_resolution_kind_t {
    resolved,
    infeasible,
    unresolved,
};

struct selector_resolution_t {
    selector_resolution_kind_t kind = selector_resolution_kind_t::unresolved;
    int target = -1;
};

struct edge_proof_t {
    std::set<int> targets;
    bool unresolved = false;
    bool suffix_safe = true;
};

// A branch-selecting case can converge through a shared block that performs
// real program updates as well as assigning the next encoded state.  Such a
// block cannot be skipped.  Preserve it on both arms by retaining the
// original for the direct arm and cloning it into the one-way arm.
struct split_rewrite_t {
    uint64_t state = 0;
    int branch = -1;
    int alternate = -1;
    std::vector<int> suffix;
    int direct_target = -1;
    int alternate_target = -1;
};

struct specialization_rewrite_t {
    uint64_t state = 0;
    int predecessor = -1;
    int frontier = -1;
    int target = -1;
};

std::optional<storage_key_t> storage_key(const mop_t &operand)
{
    switch ( operand.t ) {
        case mop_S:
            if ( operand.s )
                return storage_key_t{
                    mop_S, static_cast<uint64_t>(operand.s->off),
                    operand.size};
            break;
        case mop_l:
            if ( operand.l )
                return storage_key_t{
                    mop_l, static_cast<uint64_t>(operand.l->idx),
                    operand.size};
            break;
        case mop_v:
            return storage_key_t{mop_v, operand.g, operand.size};
        default:
            break;
    }
    return std::nullopt;
}

bool same_storage(const storage_key_t &left, const storage_key_t &right)
{
    if ( left.type != right.type )
        return false;
    if ( left.type == mop_l )
        return left.id == right.id;
    if ( left.size <= 0 || right.size <= 0 )
        return left.id == right.id;
    if ( left.type == mop_S ) {
        const int64_t left_offset = static_cast<int64_t>(left.id);
        const int64_t right_offset = static_cast<int64_t>(right.id);
        if ( left_offset > INT64_MAX - left.size
          || right_offset > INT64_MAX - right.size )
            return true;
        return left_offset < right_offset + right.size
            && right_offset < left_offset + left.size;
    }
    if ( left.id > UINT64_MAX - static_cast<uint64_t>(left.size)
      || right.id > UINT64_MAX - static_cast<uint64_t>(right.size) )
        return true;
    return left.id < right.id + static_cast<uint64_t>(right.size)
        && right.id < left.id + static_cast<uint64_t>(left.size);
}

uint64_t normalize_scalar(uint64_t value, int size)
{
    if ( size <= 0 || size >= 8 )
        return value;
    return value & ((uint64_t(1) << (size * 8)) - 1);
}

bool is_state_storage(const mop_t &operand,
                      const std::set<storage_key_t> &state_storage)
{
    const std::optional<storage_key_t> key = storage_key(operand);
    if ( !key )
        return false;
    return std::any_of(
        state_storage.begin(), state_storage.end(),
        [&](const storage_key_t &candidate) {
            return same_storage(*key, candidate);
        });
}

struct operand_collector_t : public mop_visitor_t {
    std::vector<mop_t> source_registers;
    std::vector<mop_t> target_registers;
    std::set<storage_key_t> source_storage;
    std::vector<mop_t> source_storage_operands;

    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool is_target) override
    {
        if ( !operand )
            return 0;
        if ( operand->t == mop_r ) {
            (is_target ? target_registers : source_registers).push_back(
                *operand);
        } else if ( !is_target ) {
            const std::optional<storage_key_t> key = storage_key(*operand);
            if ( key ) {
                source_storage.insert(*key);
                source_storage_operands.push_back(*operand);
            }
        }
        return 0;
    }
};

bool register_aliases(const mop_t &left, const mop_t &right)
{
    if ( left.t != mop_r || right.t != mop_r )
        return false;
    const int left_size = std::max(left.size, 1);
    const int right_size = std::max(right.size, 1);
    return left.r < right.r + right_size
        && right.r < left.r + left_size;
}

bool register_is_defined(const mop_t &operand,
                         const std::vector<mop_t> &definitions)
{
    return std::any_of(
        definitions.begin(), definitions.end(),
        [&](const mop_t &defined) {
            return register_aliases(operand, defined);
        });
}

std::string register_name(const mop_t &operand)
{
    if ( operand.t != mop_r || operand.size <= 0 )
        return {};
    qstring name;
    if ( get_mreg_name(&name, operand.r, operand.size) <= 0 )
        return {};
    std::string result = name.c_str();
    std::transform(
        result.begin(), result.end(), result.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return result;
}

bool is_stack_pointer_name(const std::string &name)
{
    return name == "sp" || name == "esp" || name == "rsp";
}

void add_register_unique(std::vector<mop_t> *registers,
                         const mop_t &candidate)
{
    if ( !registers || candidate.t != mop_r )
        return;
    auto existing = std::find_if(
        registers->begin(), registers->end(),
        [&](const mop_t &value) { return value.r == candidate.r; });
    if ( existing == registers->end() ) {
        registers->push_back(candidate);
    } else if ( candidate.size > existing->size ) {
        *existing = candidate;
    }
}

bool build_dispatcher_path(
    mbl_array_t *mba,
    const pattern_match::flatten_info_t &pattern,
    std::vector<int> *path)
{
    if ( !mba || !path || pattern.dispatcher_block < 0
      || pattern.switch_block < 0 )
        return false;
    path->clear();
    std::set<int> seen;
    int current = pattern.dispatcher_block;
    while ( current != pattern.switch_block ) {
        if ( current < 0 || current >= mba->qty
          || !seen.insert(current).second )
            return false;
        path->push_back(current);
        const mblock_t *block = mba->get_mblock(current);
        if ( !block || block->nsucc() != 1 )
            return false;
        current = block->succ(0);
        if ( pattern.dispatcher_blocks.count(current) == 0 )
            return false;
    }
    return !path->empty();
}

bool collect_selector_inputs(
    mbl_array_t *mba,
    const std::vector<int> &dispatcher_path,
    std::vector<mop_t> *live_registers,
    std::vector<mop_t> *state_operands,
    std::set<storage_key_t> *state_storage)
{
    if ( !mba || !live_registers || !state_operands || !state_storage )
        return false;
    std::vector<mop_t> definitions;
    for ( int block_index : dispatcher_path ) {
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            return false;
        for ( minsn_t *instruction = block->head;
              instruction; instruction = instruction->next ) {
            operand_collector_t collector;
            instruction->for_all_ops(collector);
            state_storage->insert(
                collector.source_storage.begin(),
                collector.source_storage.end());
            for ( const mop_t &operand : collector.source_storage_operands ) {
                const std::optional<storage_key_t> candidate =
                    storage_key(operand);
                if ( !candidate )
                    continue;
                const bool duplicate = std::any_of(
                    state_operands->begin(), state_operands->end(),
                    [&](const mop_t &existing) {
                        const std::optional<storage_key_t> key =
                            storage_key(existing);
                        return key && same_storage(*key, *candidate);
                    });
                if ( !duplicate )
                    state_operands->push_back(operand);
            }
            for ( const mop_t &source : collector.source_registers ) {
                if ( !register_is_defined(source, definitions) )
                    add_register_unique(live_registers, source);
            }
            for ( const mop_t &target : collector.target_registers )
                add_register_unique(&definitions, target);
        }
    }
    return !state_storage->empty();
}

struct escaped_state_visitor_t : public mop_visitor_t {
    const std::set<storage_key_t> &state_storage;
    bool escaped = false;

    explicit escaped_state_visitor_t(
        const std::set<storage_key_t> &storage)
        : state_storage(storage) {}

    int idaapi visit_mop(mop_t *operand, const tinfo_t *, bool) override
    {
        if ( operand && operand->t == mop_a && operand->a
          && is_state_storage(*operand->a, state_storage) ) {
            escaped = true;
            return 1;
        }
        return 0;
    }
};

bool state_storage_is_private(
    mbl_array_t *mba, const std::set<storage_key_t> &state_storage)
{
    if ( !mba || state_storage.empty() )
        return false;
    for ( const storage_key_t &key : state_storage ) {
        if ( key.type != mop_S && key.type != mop_l )
            return false;
    }
    escaped_state_visitor_t visitor(state_storage);
    mba->for_all_ops(visitor);
    return !visitor.escaped;
}

bool is_pure_rotate_call(const minsn_t *instruction)
{
    if ( !instruction || instruction->opcode != m_call
      || instruction->d.t != mop_f || !instruction->d.f )
        return false;
    if ( instruction->d.f->role == ROLE_ROL
      || instruction->d.f->role == ROLE_ROR )
        return true;
    const char *helper = instruction->l.t == mop_h
        ? instruction->l.helper : nullptr;
    if ( !helper )
        return false;
    const std::string name(helper);
    return name.find("ROL") != std::string::npos
        || name.find("ROR") != std::string::npos;
}

bool is_supported_proof_opcode(const minsn_t *instruction)
{
    if ( !instruction )
        return false;
    if ( is_mcode_call(instruction->opcode) )
    {
        // Pure rotate helpers have an exact bit-vector model. Every other call
        // is a proof barrier: the executor applies explicit Hex-Rays spoils or,
        // when callinfo is absent, invalidates all register and memory state.
        // A selector proved unique after that over-approximation is safe.
        return true;
    }
    switch ( instruction->opcode ) {
        case m_nop:
        case m_und:
        case m_ldc:
        case m_mov:
        case m_ldx:
        case m_stx:
        case m_neg:
        case m_lnot:
        case m_bnot:
        case m_xds:
        case m_xdu:
        case m_low:
        case m_high:
        case m_add:
        case m_sub:
        case m_mul:
        case m_udiv:
        case m_sdiv:
        case m_umod:
        case m_smod:
        case m_or:
        case m_and:
        case m_xor:
        case m_shl:
        case m_shr:
        case m_sar:
        // Pure flag-result instructions are admitted with the translator's
        // conservative fresh-bitvector semantics.  This is an over-
        // approximation: a uniqueness proof that survives an unconstrained
        // result also holds for the instruction's concrete flag value.
        case m_cfadd:
        case m_ofadd:
        case m_cfshl:
        case m_cfshr:
        case m_sets:
        case m_seto:
        case m_setp:
        case m_setnz:
        case m_setz:
        case m_setae:
        case m_setb:
        case m_seta:
        case m_setbe:
        case m_setg:
        case m_setge:
        case m_setl:
        case m_setle:
        case m_jcnd:
        case m_jnz:
        case m_jz:
        case m_jae:
        case m_jb:
        case m_ja:
        case m_jbe:
        case m_jg:
        case m_jge:
        case m_jl:
        case m_jle:
        case m_goto:
        case m_jtbl:
        // Floating conversion/arithmetic instructions expose a single
        // explicit destination. The translator models them as fresh values,
        // an over-approximation that is sufficient for uniqueness proofs.
        case m_f2i:
        case m_f2u:
        case m_i2f:
        case m_u2f:
        case m_f2f:
        case m_fneg:
        case m_fadd:
        case m_fsub:
        case m_fmul:
        case m_fdiv:
            return true;
        default:
            return false;
    }
}

struct proof_semantics_visitor_t : public minsn_visitor_t {
    bool supported = true;
    mcode_t rejected_opcode = m_nop;

    int idaapi visit_minsn() override
    {
        if ( !is_supported_proof_opcode(curins) ) {
            supported = false;
            rejected_opcode = curins ? curins->opcode : m_nop;
            return 1;
        }
        return 0;
    }
};

bool validate_proof_semantics(
    mbl_array_t *mba,
    const std::set<int> &blocks,
    int *rejected_block,
    mcode_t *rejected_opcode)
{
    if ( !mba )
        return false;
    for ( int block_index : blocks ) {
        if ( block_index < 0 || block_index >= mba->qty )
            return false;
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            return false;
        proof_semantics_visitor_t visitor;
        block->for_all_insns(visitor);
        if ( !visitor.supported ) {
            if ( rejected_block )
                *rejected_block = block_index;
            if ( rejected_opcode )
                *rejected_opcode = visitor.rejected_opcode;
            return false;
        }
    }
    return true;
}

struct suffix_effect_visitor_t : public minsn_visitor_t {
    const std::set<storage_key_t> &state_storage;
    bool safe = true;

    explicit suffix_effect_visitor_t(
        const std::set<storage_key_t> &storage)
        : state_storage(storage) {}

    int idaapi visit_minsn() override
    {
        if ( !curins )
            return 0;
        switch ( curins->opcode ) {
            case m_nop:
            case m_ldc:
            case m_mov:
            case m_neg:
            case m_lnot:
            case m_bnot:
            case m_xds:
            case m_xdu:
            case m_low:
            case m_high:
            case m_add:
            case m_sub:
            case m_mul:
            case m_or:
            case m_and:
            case m_xor:
            case m_shl:
            case m_shr:
            case m_sar:
            case m_setnz:
            case m_setz:
            case m_setae:
            case m_setb:
            case m_seta:
            case m_setbe:
            case m_setg:
            case m_setge:
            case m_setl:
            case m_setle:
            case m_jcnd:
            case m_jnz:
            case m_jz:
            case m_jae:
            case m_jb:
            case m_ja:
            case m_jbe:
            case m_jg:
            case m_jge:
            case m_jl:
            case m_jle:
            case m_goto:
            case m_und:
                break;
            case m_call:
                if ( is_pure_rotate_call(curins) )
                    break;
                [[fallthrough]];
            default:
                safe = false;
                return 1;
        }

        const std::optional<storage_key_t> destination =
            storage_key(curins->d);
        if ( destination
          && !is_state_storage(curins->d, state_storage) ) {
            safe = false;
            return 1;
        }
        return 0;
    }
};

bool block_is_safe_suffix(
    mblock_t *block, const std::set<storage_key_t> &state_storage)
{
    if ( !block )
        return false;
    suffix_effect_visitor_t visitor(state_storage);
    block->for_all_insns(visitor);
    return visitor.safe;
}

bool decode_microcode_switch(
    mbl_array_t *mba,
    int switch_block_index,
    std::map<uint64_t, int> *state_to_block,
    mop_t *selector)
{
    if ( !mba || !state_to_block || !selector
      || switch_block_index < 0 || switch_block_index >= mba->qty )
        return false;
    const mblock_t *block = mba->get_mblock(switch_block_index);
    const minsn_t *tail = block ? block->tail : nullptr;
    if ( !tail || tail->opcode != m_jtbl || tail->r.t != mop_c
      || !tail->r.c || tail->l.empty() )
        return false;
    const mcases_t &cases = *tail->r.c;
    if ( cases.values.size() != cases.targets.size() )
        return false;
    *selector = tail->l;
    if ( selector->size != 1 && selector->size != 2
      && selector->size != 4 && selector->size != 8 )
        return false;
    state_to_block->clear();
    for ( std::size_t index = 0; index < cases.targets.size(); ++index ) {
        const int target = cases.targets[index];
        if ( target < 0 || target >= mba->qty )
            return false;
        for ( sval_t value : cases.values[index] ) {
            const uint64_t normalized = normalize_scalar(
                static_cast<uint64_t>(value), selector->size);
            const auto inserted = state_to_block->emplace(normalized, target);
            if ( !inserted.second && inserted.first->second != target )
                return false;
        }
    }
    return state_to_block->size() >= 8;
}

void append_edge(std::vector<edge_key_t> *edges, int source, int destination)
{
    if ( edges )
        edges->push_back(edge_key_t{source, destination});
}

bool enumerate_case_paths(
    mbl_array_t *mba,
    uint64_t state,
    int origin,
    const std::set<int> &case_targets,
    const std::set<int> &dispatcher_blocks,
    std::vector<case_path_t> *paths,
    bool *terminated_without_dispatch)
{
    if ( !mba || !paths || !terminated_without_dispatch )
        return false;
    struct work_t {
        std::vector<int> blocks;
    };
    std::vector<work_t> worklist{{std::vector<int>{origin}}};
    std::size_t completed = 0;
    std::size_t explored = 0;
    *terminated_without_dispatch = false;

    while ( !worklist.empty() ) {
        if ( ++explored > k_max_work_items_per_case
          || worklist.size() > k_max_work_items_per_case )
            return false;
        work_t work = std::move(worklist.back());
        worklist.pop_back();
        if ( work.blocks.empty() || work.blocks.size() > k_max_path_blocks )
            return false;
        const int current = work.blocks.back();
        const mblock_t *block = mba->get_mblock(current);
        if ( !block )
            return false;
        if ( block->nsucc() == 0 ) {
            *terminated_without_dispatch = true;
            continue;
        }
        for ( int successor : block->succset ) {
            if ( dispatcher_blocks.count(successor) != 0 ) {
                case_path_t path;
                path.state = state;
                path.blocks = work.blocks;
                for ( std::size_t index = 1; index < path.blocks.size(); ++index )
                    append_edge(&path.edges, path.blocks[index - 1], path.blocks[index]);
                append_edge(&path.edges, current, successor);
                paths->push_back(std::move(path));
                if ( ++completed > k_max_paths_per_case
                  || paths->size() > k_max_total_paths )
                    return false;
                continue;
            }
            if ( successor < 0 || successor >= mba->qty
              || (case_targets.count(successor) != 0 && successor != origin)
              || std::find(work.blocks.begin(), work.blocks.end(), successor)
                   != work.blocks.end() )
                return false;
            work_t next = work;
            next.blocks.push_back(successor);
            worklist.push_back(std::move(next));
        }
    }
    return true;
}

bool find_unique_entry_path(
    mbl_array_t *mba,
    int destination,
    const std::set<int> &case_targets,
    const std::set<int> &dispatcher_blocks,
    std::vector<int> *result)
{
    if ( !mba || !result || destination < 0 || destination >= mba->qty )
        return false;
    std::vector<std::vector<int>> worklist{{0}};
    std::vector<std::vector<int>> matches;
    std::size_t explored = 0;
    while ( !worklist.empty() ) {
        if ( ++explored > k_max_entry_work_items
          || worklist.size() > k_max_entry_work_items )
            return false;
        std::vector<int> path = std::move(worklist.back());
        worklist.pop_back();
        if ( path.size() > k_max_path_blocks )
            return false;
        const int current = path.back();
        if ( current == destination ) {
            matches.push_back(std::move(path));
            if ( matches.size() > 1 )
                return false;
            continue;
        }
        const mblock_t *block = mba->get_mblock(current);
        if ( !block )
            return false;
        for ( int successor : block->succset ) {
            if ( successor < 0 || successor >= mba->qty
              || dispatcher_blocks.count(successor) != 0
              || case_targets.count(successor) != 0
              || std::find(path.begin(), path.end(), successor) != path.end() )
                continue;
            std::vector<int> next = path;
            next.push_back(successor);
            worklist.push_back(std::move(next));
        }
    }
    if ( matches.size() != 1 )
        return false;
    *result = std::move(matches.front());
    return true;
}

void collect_stack_pointer_operands(
    mbl_array_t *mba,
    const std::vector<int> &blocks,
    std::vector<mop_t> *stack_pointers)
{
    for ( int block_index : blocks ) {
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            continue;
        for ( minsn_t *instruction = block->head;
              instruction; instruction = instruction->next ) {
            operand_collector_t collector;
            instruction->for_all_ops(collector);
            for ( const mop_t &operand : collector.source_registers ) {
                if ( is_stack_pointer_name(register_name(operand)) )
                    add_register_unique(stack_pointers, operand);
            }
        }
    }
}

void collect_register_operands(
    mbl_array_t *mba,
    const std::set<int> &blocks,
    std::vector<mop_t> *registers)
{
    if ( !mba || !registers )
        return;
    for ( int block_index : blocks ) {
        if ( block_index < 0 || block_index >= mba->qty )
            continue;
        mblock_t *block = mba->get_mblock(block_index);
        for ( minsn_t *instruction = block ? block->head : nullptr;
              instruction; instruction = instruction->next ) {
            operand_collector_t collector;
            instruction->for_all_ops(collector);
            for ( const mop_t &operand : collector.source_registers )
                add_register_unique(registers, operand);
            for ( const mop_t &operand : collector.target_registers )
                add_register_unique(registers, operand);
        }
    }
}

struct call_preservation_visitor_t : public minsn_visitor_t {
    mbl_array_t *mba;
    const mop_t &candidate;
    bool preserved = true;

    call_preservation_visitor_t(mbl_array_t *array, const mop_t &operand)
      : mba(array), candidate(operand) {}

    bool inferred_spoils(const minsn_t *call, mlist_t *spoiled) const
    {
        if ( !mba || !call || !spoiled )
            return false;

        tinfo_t type;
        bool have_type = false;
        if ( call->l.t == mop_v && call->l.g != BADADDR ) {
            have_type = get_tinfo(&type, call->l.g)
                     || guess_tinfo(&type, call->l.g) > GUESS_FUNC_FAILED;
            if ( have_type && type.is_funcptr() )
                type = type.get_pointed_object();
            have_type = have_type && type.is_func();
        }
        if ( !have_type ) {
            // A call with no mcallinfo_t is represented at this maturity using
            // the database's effective calling convention. Ask Hex-Rays to
            // derive the standard return/spoil lists instead of naming ABI
            // registers in the plugin.
            func_type_data_t details;
            details.rettype.create_simple_type(BT_VOID);
            details.set_cc(CM_CC_UNKNOWN);
            if ( !type.create_func(details) )
                return false;
        }

        mlist_t return_registers;
        mba->get_func_output_lists(
            &return_registers, spoiled, type, call->ea, false);
        return true;
    }

    int idaapi visit_minsn() override
    {
        if ( !curins || !is_mcode_call(curins->opcode)
          || is_pure_rotate_call(curins) )
            return 0;
        const mcallinfo_t *call_info = curins->d.t == mop_f
            ? curins->d.f : nullptr;
        if ( candidate.t != mop_r || candidate.size <= 0 ) {
            preserved = false;
            return 1;
        }
        if ( call_info ) {
            if ( !call_info->spoiled.reg.has_any(
                    candidate.r, candidate.size) )
                return 0;
        } else {
            mlist_t spoiled;
            if ( inferred_spoils(curins, &spoiled)
              && !spoiled.reg.has_any(candidate.r, candidate.size) )
                return 0;
        }
        preserved = false;
        return 1;
    }
};

bool register_preserved_across_calls(
    mbl_array_t *mba,
    const std::set<int> &blocks,
    const mop_t &candidate)
{
    if ( !mba || candidate.t != mop_r || candidate.size <= 0 )
        return false;
    if ( is_stack_pointer_name(register_name(candidate)) )
        return true;
    for ( int block_index : blocks ) {
        if ( block_index < 0 || block_index >= mba->qty )
            return false;
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            return false;
        call_preservation_visitor_t visitor(mba, candidate);
        block->for_all_insns(visitor);
        if ( !visitor.preserved )
            return false;
    }
    return true;
}

bool constrain_selected_edge(
    const mblock_t *block,
    int destination,
    z3_solver::symbolic_executor_t *executor)
{
    if ( !block || !executor || destination < 0
      || !block->succset.has(destination) )
        return false;
    if ( block->nsucc() == 1 )
        return true;
    const minsn_t *tail = block->tail;
    if ( block->nsucc() != 2 || !tail || !is_mcode_jcond(tail->opcode)
      || tail->d.t != mop_b )
        return false;
    const z3::expr condition = executor->evaluate_jcc_condition(tail);
    return executor->assume(
        tail->d.b == destination ? condition : !condition);
}

bool execute_path(
    mbl_array_t *mba,
    const std::vector<int> &blocks,
    std::optional<int> final_destination,
    z3_solver::symbolic_executor_t *executor)
{
    if ( !mba || !executor )
        return false;
    for ( std::size_t index = 0; index < blocks.size(); ++index ) {
        const int block_index = blocks[index];
        if ( block_index < 0 || block_index >= mba->qty )
            return false;
        const mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            return false;
        executor->execute_block(block);
        const std::optional<int> destination = index + 1 < blocks.size()
            ? std::optional<int>(blocks[index + 1])
            : final_destination;
        if ( destination && !constrain_selected_edge(
                block, *destination, executor) )
            return false;
    }
    return true;
}

std::optional<uint64_t> prove_unique_value(
    z3_solver::symbolic_executor_t *executor, const z3::expr &expression)
{
    if ( !executor )
        return std::nullopt;
    const z3::expr simplified = expression.simplify();
    uint64_t value = 0;
    if ( simplified.is_numeral_u64(value) )
        return value;
    return executor->solve_for_value(simplified);
}

selector_resolution_t resolve_selector_target(
    mbl_array_t *mba,
    const std::vector<int> &entry_path,
    int entry_destination,
    const std::vector<int> &dispatcher_path,
    int switch_block,
    const case_path_t *case_path,
    const std::vector<mop_t> &preserved_registers,
    const std::vector<mop_t> &private_state_operands,
    const mop_t &selector,
    const std::map<uint64_t, int> &state_to_block,
    bool clear_memory)
{
    z3_solver::symbolic_executor_t executor(
        z3_solver::get_global_context());
    for ( const mop_t &operand : private_state_operands )
        executor.preserve_across_calls(operand);
    if ( !execute_path(
            mba, entry_path, entry_destination, &executor) )
        return {};
    for ( const mop_t &operand : preserved_registers ) {
        const z3::expr value = executor.evaluate_operand(operand);
        executor.set_value(operand, value, true);
    }
    if ( clear_memory )
        executor.invalidate_memory_values();
    for ( const mop_t &operand : private_state_operands ) {
        const z3::expr value = executor.evaluate_operand(operand);
        executor.set_value(operand, value, true);
    }

    if ( clear_memory ) {
        if ( !execute_path(
                mba, dispatcher_path, switch_block,
                &executor) )
            return {};
        const z3::expr incoming_selector =
            executor.evaluate_operand(selector);
        const uint64_t normalized = normalize_scalar(
            case_path ? case_path->state : 0, selector.size);
        if ( !case_path || !executor.assume(
                incoming_selector == incoming_selector.ctx().bv_val(
                    normalized, selector.size * 8)) )
            return {};
    }
    if ( case_path ) {
        const int final_destination = case_path->edges.empty()
            ? -1 : case_path->edges.back().destination;
        if ( final_destination < 0 || !execute_path(
                mba, case_path->blocks, final_destination,
                &executor) )
            return {};
    }
    if ( !execute_path(
            mba, dispatcher_path, switch_block,
            &executor) )
        return {};

    const auto feasibility = executor.check_feasibility();
    if ( feasibility == z3_solver::symbolic_executor_t::feasibility_t::infeasible )
        return {selector_resolution_kind_t::infeasible, -1};
    if ( feasibility != z3_solver::symbolic_executor_t::feasibility_t::feasible )
        return {};
    const std::optional<uint64_t> state = prove_unique_value(
        &executor, executor.evaluate_operand(selector));
    if ( !state )
        return {};
    const auto target = state_to_block.find(
        normalize_scalar(*state, selector.size));
    return target == state_to_block.end()
        ? selector_resolution_t{}
        : selector_resolution_t{
            selector_resolution_kind_t::resolved, target->second};
}

bool edge_is_rewriteable(mbl_array_t *mba, const edge_key_t &edge)
{
    if ( !mba || edge.source < 0 || edge.source >= mba->qty
      || edge.destination < 0 || edge.destination >= mba->qty )
        return false;
    const mblock_t *source = mba->get_mblock(edge.source);
    if ( !source || !source->tail )
        return false;
    if ( source->nsucc() == 1 && source->succ(0) == edge.destination ) {
        if ( source->tail->opcode == m_goto )
            return source->tail->l.t == mop_b;
        return !must_mcode_close_block(source->tail->opcode, true);
    }
    return source->tail->d.t == mop_b
        && is_mcode_jcond(source->tail->opcode)
        && source->tail->d.b == edge.destination;
}

void append_goto(mblock_t *block, int destination)
{
    minsn_t *instruction = block->tail
        ? new minsn_t(*block->tail)
        : new minsn_t(block->start);
    instruction->opcode = m_goto;
    instruction->clr_fpinsn();
    instruction->clr_assert();
    instruction->l.make_blkref(destination);
    instruction->r.erase();
    instruction->d.erase();
    block->insert_into_block(instruction, block->tail);
}

bool apply_edge_rewrite(
    mbl_array_t *mba, const edge_key_t &edge, int target)
{
    if ( !edge_is_rewriteable(mba, edge) || target < 0 || target >= mba->qty )
        return false;
    mblock_t *source = mba->get_mblock(edge.source);
    mblock_t *old_destination = mba->get_mblock(edge.destination);
    mblock_t *new_destination = mba->get_mblock(target);
    if ( !source || !old_destination || !new_destination )
        return false;

    if ( source->nsucc() == 1 ) {
        if ( source->tail->opcode == m_goto )
            source->tail->l.make_blkref(target);
        else
            append_goto(source, target);
    } else {
        source->tail->d.make_blkref(target);
    }

    source->succset.del(edge.destination);
    source->succset.add(target);
    old_destination->predset.del(edge.source);
    new_destination->predset.add(edge.source);
    source->mark_lists_dirty();
    old_destination->mark_lists_dirty();
    new_destination->mark_lists_dirty();
    return true;
}

bool path_uses_edge(const case_path_t &path, const edge_key_t &edge)
{
    return std::find_if(
        path.edges.begin(), path.edges.end(),
        [&](const edge_key_t &candidate) {
            return candidate.source == edge.source
                && candidate.destination == edge.destination;
        }) != path.edges.end();
}

void log_cut_diagnostics(
    mbl_array_t *mba,
    uint64_t state,
    const std::vector<const case_path_t *> &state_paths,
    const std::map<edge_key_t, edge_proof_t> &proofs)
{
    for ( const case_path_t *path : state_paths ) {
        if ( !path )
            continue;
        qstring route;
        for ( int block : path->blocks ) {
            if ( !route.empty() )
                route.append(',');
            route.cat_sprnt("%d", block);
        }
        deobf::log_verbose(
            "[deflatten][cff-switch] no-cut path state=0x%llx "
            "target=%d blocks=%s\n",
            static_cast<unsigned long long>(state),
            path->resolved_target.value_or(-1), route.c_str());
        for ( auto edge = path->edges.rbegin();
              edge != path->edges.rend(); ++edge ) {
            const auto proof = proofs.find(*edge);
            deobf::log_verbose(
                "[deflatten][cff-switch] no-cut edge=%d->%d proof=%s "
                "targets=%zu unresolved=%d suffix-safe=%d rewriteable=%d\n",
                edge->source, edge->destination,
                proof == proofs.end() ? "missing" : "present",
                proof == proofs.end() ? 0U : proof->second.targets.size(),
                proof != proofs.end() && proof->second.unresolved ? 1 : 0,
                proof != proofs.end() && proof->second.suffix_safe ? 1 : 0,
                edge_is_rewriteable(mba, *edge) ? 1 : 0);
        }
    }
}

bool try_build_frontier_specializations(
    mbl_array_t *mba,
    const std::vector<const case_path_t *> &state_paths,
    const std::map<edge_key_t, edge_proof_t> &proofs,
    const std::set<int> &dispatcher_blocks,
    std::vector<specialization_rewrite_t> *result)
{
    if ( !mba || !result || state_paths.empty() )
        return false;
    result->clear();

    const case_path_t *first_path = state_paths.front();
    if ( !first_path || first_path->blocks.size() < 2 )
        return false;
    const int frontier_index = first_path->blocks.back();
    mblock_t *frontier = mba->get_mblock(frontier_index);
    if ( !frontier || frontier->nsucc() != 1
      || dispatcher_blocks.count(frontier->succ(0)) == 0
      || !edge_is_rewriteable(
            mba, edge_key_t{frontier_index, frontier->succ(0)}) )
        return false;

    std::map<edge_key_t, int> incoming_targets;
    for ( const case_path_t *path : state_paths ) {
        if ( !path || path->blocks.size() < 2
          || path->blocks.back() != frontier_index
          || !path->resolved_target )
            return false;
        const int predecessor_index = path->blocks[path->blocks.size() - 2];
        const edge_key_t incoming{predecessor_index, frontier_index};
        mblock_t *predecessor = mba->get_mblock(predecessor_index);
        const auto proof = proofs.find(incoming);
        if ( !predecessor || predecessor->nsucc() != 1
          || predecessor->succ(0) != frontier_index
          || (predecessor->tail
              && predecessor->tail->opcode != m_goto
              && must_mcode_close_block(predecessor->tail->opcode, true))
          || proof == proofs.end() || proof->second.unresolved
          || proof->second.targets.size() != 1 )
            return false;
        const int target = *proof->second.targets.begin();
        const auto inserted = incoming_targets.emplace(incoming, target);
        if ( !inserted.second && inserted.first->second != target )
            return false;
    }

    for ( const auto &incoming : incoming_targets ) {
        result->push_back(specialization_rewrite_t{
            first_path->state, incoming.first.source,
            frontier_index, incoming.second});
    }
    return !result->empty();
}

bool try_build_split_rewrite(
    mbl_array_t *mba,
    const std::vector<const case_path_t *> &state_paths,
    const std::set<int> &dispatcher_blocks,
    split_rewrite_t *result)
{
    if ( !mba || !result || state_paths.empty() )
        return false;

    const case_path_t *first_path = state_paths.front();
    if ( !first_path || first_path->blocks.empty()
      || !first_path->resolved_target )
        return false;

    std::size_t common_suffix_size = 0;
    while ( common_suffix_size < first_path->blocks.size() ) {
        const int candidate = first_path->blocks[
            first_path->blocks.size() - common_suffix_size - 1];
        bool common = true;
        for ( const case_path_t *path : state_paths ) {
            if ( !path || path->blocks.size() <= common_suffix_size
              || path->blocks[path->blocks.size() - common_suffix_size - 1]
                   != candidate ) {
                common = false;
                break;
            }
        }
        if ( !common )
            break;
        ++common_suffix_size;
    }
    if ( common_suffix_size == 0 )
        return false;

    std::vector<int> suffix(
        first_path->blocks.end() - common_suffix_size,
        first_path->blocks.end());
    for ( const case_path_t *path : state_paths ) {
        if ( !path || path->blocks.empty() || !path->resolved_target
          || path->blocks.size() <= suffix.size() )
            return false;
    }

    for ( std::size_t index = 0; index < suffix.size(); ++index ) {
        mblock_t *block = mba->get_mblock(suffix[index]);
        if ( !block || block->nsucc() != 1 )
            return false;
        if ( index + 1 < suffix.size() ) {
            if ( block->succ(0) != suffix[index + 1] )
                return false;
            if ( block->tail && block->tail->opcode != m_goto
              && must_mcode_close_block(block->tail->opcode, true) )
                return false;
        } else if ( dispatcher_blocks.count(block->succ(0)) == 0
                 || !edge_is_rewriteable(
                        mba, edge_key_t{block->serial, block->succ(0)}) ) {
            return false;
        }
    }

    const int suffix_entry = suffix.front();
    mblock_t *entry = mba->get_mblock(suffix_entry);
    if ( !entry || entry->npred() < 2 )
        return false;

    mblock_t *branch = nullptr;
    mblock_t *alternate = nullptr;
    const auto classify = [&](mblock_t *conditional, mblock_t *one_way) {
        if ( !conditional || !one_way || !conditional->tail
          || !is_mcode_jcond(conditional->tail->opcode)
          || conditional->tail->d.t != mop_b
          || conditional->nsucc() != 2
          || !conditional->succset.has(suffix_entry)
          || !conditional->succset.has(one_way->serial)
          || one_way->npred() != 1
          || one_way->pred(0) != conditional->serial
          || one_way->nsucc() != 1
          || one_way->succ(0) != suffix_entry )
            return false;
        // A closing instruction cannot be followed by the cloned frontier.
        // A goto is handled separately by retaining it as the final branch.
        if ( one_way->tail
          && one_way->tail->opcode != m_goto
          && must_mcode_close_block(one_way->tail->opcode, true) )
            return false;
        return true;
    };
    std::vector<std::pair<mblock_t *, mblock_t *>> candidates;
    for ( int conditional_index : entry->predset ) {
        for ( int one_way_index : entry->predset ) {
            if ( conditional_index == one_way_index )
                continue;
            mblock_t *conditional = mba->get_mblock(conditional_index);
            mblock_t *one_way = mba->get_mblock(one_way_index);
            if ( classify(conditional, one_way) )
                candidates.emplace_back(conditional, one_way);
        }
    }
    if ( candidates.size() != 1 )
        return false;
    branch = candidates.front().first;
    alternate = candidates.front().second;

    const edge_key_t direct_edge{branch->serial, suffix_entry};
    const edge_key_t alternate_edge{alternate->serial, suffix_entry};
    std::set<int> direct_targets;
    std::set<int> alternate_targets;
    for ( const case_path_t *path : state_paths ) {
        const bool direct = path_uses_edge(*path, direct_edge);
        const bool indirect = path_uses_edge(*path, alternate_edge);
        if ( direct == indirect )
            return false;
        (direct ? direct_targets : alternate_targets)
            .insert(*path->resolved_target);
    }
    if ( direct_targets.size() != 1 || alternate_targets.size() != 1 )
        return false;

    // The original frontier edge is retained for the direct arm.  The
    // alternate edge becomes rewriteable after the frontier is cloned into
    // the alternate block, even when that block is currently empty.
    mblock_t *terminal = mba->get_mblock(suffix.back());
    const edge_key_t frontier_edge{suffix.back(), terminal->succ(0)};
    if ( !edge_is_rewriteable(mba, frontier_edge) )
        return false;

    result->state = first_path->state;
    result->branch = branch->serial;
    result->alternate = alternate->serial;
    result->suffix = std::move(suffix);
    result->direct_target = *direct_targets.begin();
    result->alternate_target = *alternate_targets.begin();
    return true;
}

bool validate_split_rewrite(
    mbl_array_t *mba,
    const split_rewrite_t &rewrite,
    const std::set<int> &dispatcher_blocks,
    const std::set<edge_key_t> &bypassed_inputs)
{
    if ( !mba || rewrite.branch < 0 || rewrite.branch >= mba->qty
      || rewrite.alternate < 0 || rewrite.alternate >= mba->qty
      || rewrite.suffix.empty()
      || rewrite.direct_target < 0 || rewrite.direct_target >= mba->qty
      || rewrite.alternate_target < 0
      || rewrite.alternate_target >= mba->qty )
        return false;
    const mblock_t *branch = mba->get_mblock(rewrite.branch);
    const mblock_t *alternate = mba->get_mblock(rewrite.alternate);
    const int suffix_entry = rewrite.suffix.front();
    if ( suffix_entry < 0 || suffix_entry >= mba->qty )
        return false;
    const mblock_t *entry = mba->get_mblock(suffix_entry);
    if ( !branch || !alternate || !entry || !branch->tail
      || !is_mcode_jcond(branch->tail->opcode)
      || !branch->succset.has(suffix_entry)
      || !branch->succset.has(rewrite.alternate)
      || alternate->npred() != 1 || alternate->pred(0) != rewrite.branch
      || alternate->nsucc() != 1
      || alternate->succ(0) != suffix_entry
      || entry->npred() < 2 )
        return false;
    if ( alternate->tail && alternate->tail->opcode != m_goto
      && must_mcode_close_block(alternate->tail->opcode, true) )
        return false;
    for ( std::size_t index = 0; index < rewrite.suffix.size(); ++index ) {
        const int block_index = rewrite.suffix[index];
        if ( block_index < 0 || block_index >= mba->qty )
            return false;
        const mblock_t *block = mba->get_mblock(block_index);
        if ( !block || block->nsucc() != 1 )
            return false;
        if ( index + 1 < rewrite.suffix.size() ) {
            if ( block->succ(0) != rewrite.suffix[index + 1] )
                return false;
        } else if ( dispatcher_blocks.count(block->succ(0)) == 0
                 || !edge_is_rewriteable(
                        mba, edge_key_t{block_index, block->succ(0)}) ) {
            return false;
        }

        // Only the suffix entry is specialized in-place. Remaining suffix
        // blocks stay untouched for unrelated predecessors: their bodies are
        // copied into the entry/alternate arms before those arms bypass them.
        if ( index != 0 )
            continue;
        for ( int predecessor : block->predset ) {
            const bool expected_entry = index == 0
                && (predecessor == rewrite.branch
                    || predecessor == rewrite.alternate);
            const bool expected_chain = index > 0
                && predecessor == rewrite.suffix[index - 1];
            if ( !expected_entry && !expected_chain
              && bypassed_inputs.count(
                    edge_key_t{predecessor, block_index}) == 0 )
                return false;
        }
    }
    return true;
}

bool clone_block_chain_into(
    mbl_array_t *mba,
    const std::vector<int> &suffix,
    mblock_t *destination,
    const std::set<storage_key_t> *omitted_storage = nullptr)
{
    if ( !mba || !destination || suffix.empty() )
        return false;
    mblock_t *terminal_block = mba->get_mblock(suffix.back());
    if ( !terminal_block || terminal_block->nsucc() != 1
      || !edge_is_rewriteable(
            mba, edge_key_t{
                terminal_block->serial, terminal_block->succ(0)}) )
        return false;

    // If the alternate already has an explicit goto to the frontier, retain
    // it as the terminal instruction and insert the frontier body before it.
    // Otherwise append the entire frontier, including its dispatcher goto.
    minsn_t *anchor = destination->tail;
    const bool retain_existing_goto = anchor && anchor->opcode == m_goto;
    if ( retain_existing_goto )
        anchor = anchor->prev;

    for ( int block_index : suffix ) {
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            return false;
        // We are merging the copied instructions into an existing block, so
        // carry over the same stack-range metadata that Hex-Rays updates in
        // mba_t::copy_block(CPBLK_MINREF) and block combination.
        destination->maxbsp = std::max(destination->maxbsp, block->maxbsp);
        destination->minbstkref = std::min(
            destination->minbstkref, block->minbstkref);
        destination->minbargref = std::min(
            destination->minbargref, block->minbargref);
        for ( const minsn_t *instruction = block->head;
              instruction; instruction = instruction->next ) {
            if ( instruction == block->tail
              && instruction->opcode == m_goto )
                continue;
            if ( omitted_storage
              && is_state_storage(instruction->d, *omitted_storage) )
                continue;
            minsn_t *copy = new minsn_t(*instruction);
            // These properties are invalid on copied non-FPU/control-flow
            // instructions and cause Hex-Rays INTERR 50801/52123 if retained.
            if ( !is_mcode_fpu(copy->opcode) )
                copy->clr_fpinsn();
            copy->clr_assert();
            destination->insert_into_block(copy, anchor);
            anchor = copy;
        }
    }
    if ( !retain_existing_goto ) {
        if ( terminal_block->tail
          && terminal_block->tail->opcode == m_goto ) {
            minsn_t *terminal = new minsn_t(*terminal_block->tail);
            terminal->clr_fpinsn();
            terminal->clr_assert();
            destination->insert_into_block(terminal, anchor);
        } else {
            append_goto(destination, terminal_block->succ(0));
        }
    }
    destination->mark_lists_dirty();
    return destination->tail && destination->tail->opcode == m_goto;
}

bool validate_specialization_rewrite(
    mbl_array_t *mba,
    const specialization_rewrite_t &rewrite,
    const std::set<int> &dispatcher_blocks)
{
    if ( !mba || rewrite.predecessor < 0
      || rewrite.predecessor >= mba->qty || rewrite.frontier < 0
      || rewrite.frontier >= mba->qty || rewrite.target < 0
      || rewrite.target >= mba->qty )
        return false;
    const mblock_t *predecessor = mba->get_mblock(rewrite.predecessor);
    const mblock_t *frontier = mba->get_mblock(rewrite.frontier);
    return predecessor && frontier && predecessor->nsucc() == 1
        && predecessor->succ(0) == rewrite.frontier
        && (!predecessor->tail || predecessor->tail->opcode == m_goto
            || !must_mcode_close_block(predecessor->tail->opcode, true))
        && frontier->nsucc() == 1
        && dispatcher_blocks.count(frontier->succ(0)) != 0
        && edge_is_rewriteable(
            mba, edge_key_t{rewrite.frontier, frontier->succ(0)});
}

bool apply_specialization_rewrite(
    mbl_array_t *mba, const specialization_rewrite_t &rewrite)
{
    mblock_t *predecessor = mba->get_mblock(rewrite.predecessor);
    mblock_t *frontier = mba->get_mblock(rewrite.frontier);
    if ( !predecessor || !frontier
      || !clone_block_chain_into(
            mba, std::vector<int>{rewrite.frontier}, predecessor) )
        return false;
    return apply_edge_rewrite(
        mba, edge_key_t{rewrite.predecessor, rewrite.frontier},
        rewrite.target);
}

bool apply_split_rewrite(
    mbl_array_t *mba,
    const split_rewrite_t &rewrite,
    const std::set<storage_key_t> &state_storage)
{
    mblock_t *alternate = mba->get_mblock(rewrite.alternate);
    mblock_t *direct = rewrite.suffix.empty()
        ? nullptr : mba->get_mblock(rewrite.suffix.front());
    if ( !alternate || !direct
      || !clone_block_chain_into(
            mba, rewrite.suffix, alternate, &state_storage) )
        return false;

    edge_key_t direct_edge;
    if ( rewrite.suffix.size() == 1 ) {
        if ( direct->nsucc() != 1 )
            return false;
        direct_edge = edge_key_t{direct->serial, direct->succ(0)};
    } else {
        const std::vector<int> tail(
            rewrite.suffix.begin() + 1, rewrite.suffix.end());
        if ( !clone_block_chain_into(
                mba, tail, direct, &state_storage) )
            return false;
        direct_edge = edge_key_t{direct->serial, rewrite.suffix[1]};
    }
    if ( !apply_edge_rewrite(mba, direct_edge, rewrite.direct_target) )
        return false;
    if ( !apply_edge_rewrite(
            mba, edge_key_t{rewrite.alternate, rewrite.suffix.front()},
            rewrite.alternate_target) )
        return false;
    return true;
}

bool collect_split_state_erasures(
    mbl_array_t *mba,
    const std::vector<split_rewrite_t> &split_plan,
    const std::set<storage_key_t> &state_storage,
    std::set<std::pair<int, minsn_t *>> *erasures)
{
    if ( !mba || !erasures )
        return false;
    for ( const split_rewrite_t &rewrite : split_plan ) {
        std::set<storage_key_t> erased_storage;
        // The suffix tail may be shared by unrelated inputs. It is copied
        // into both selected arms and remains unmodified in its original
        // location. Only the specialized suffix entry is made state-free.
        const std::vector<int> specialized_blocks = rewrite.suffix.empty()
            ? std::vector<int>{}
            : std::vector<int>{rewrite.suffix.front()};
        for ( int block_index : specialized_blocks ) {
            mblock_t *block = mba->get_mblock(block_index);
            if ( !block )
                return false;
            for ( minsn_t *instruction = block->head;
                  instruction; instruction = instruction->next ) {
                if ( !is_state_storage(instruction->d, state_storage) ) {
                    // Once a synthetic state definition is removed, a later
                    // retained instruction must not observe that definition.
                    // Reject instead of attempting register/data-flow slicing
                    // at this microcode maturity.
                    operand_collector_t collector;
                    instruction->for_all_ops(collector);
                    for ( const storage_key_t &source
                          : collector.source_storage ) {
                        if ( std::any_of(
                                erased_storage.begin(),
                                erased_storage.end(),
                                [&](const storage_key_t &erased) {
                                    return same_storage(source, erased);
                                }) )
                            return false;
                    }
                    continue;
                }
                // The destination store is synthetic and its successor has
                // been proven directly.  Nested side effects would make
                // deleting the store unsafe, so reject such a topology.
                if ( instruction->l.has_side_effects()
                  || instruction->r.has_side_effects() )
                    return false;
                const std::optional<storage_key_t> destination =
                    storage_key(instruction->d);
                if ( destination )
                    erased_storage.insert(*destination);
                erasures->insert({block_index, instruction});
            }
        }
    }
    return true;
}

void apply_state_erasures(
    mbl_array_t *mba,
    const std::set<std::pair<int, minsn_t *>> &erasures)
{
    for ( const auto &erasure : erasures ) {
        minsn_t *instruction = erasure.second;
        instruction->clr_fpinsn();
        instruction->clr_assert();
        mba->get_mblock(erasure.first)->make_nop(instruction);
    }
}

struct block_snapshot_t {
    int serial = -1;
    uint32 flags = 0;
    ea_t start = BADADDR;
    ea_t end = BADADDR;
    mblock_type_t type = BLT_NONE;
    sval_t maxbsp = 0;
    sval_t minbstkref = 0;
    sval_t minbargref = 0;
    intvec_t predecessors;
    intvec_t successors;
    std::vector<std::unique_ptr<minsn_t>> instructions;
};

class mba_rewrite_transaction_t {
public:
    mba_rewrite_transaction_t(mbl_array_t *mba, const std::set<int> &blocks)
      : mba_(mba)
    {
        if ( !mba_ )
            return;
        snapshots_.reserve(blocks.size());
        for ( int serial : blocks ) {
            if ( serial < 0 || serial >= mba_->qty )
                continue;
            const mblock_t *block = mba_->get_mblock(serial);
            if ( !block )
                continue;
            block_snapshot_t snapshot;
            snapshot.serial = serial;
            snapshot.flags = block->flags;
            snapshot.start = block->start;
            snapshot.end = block->end;
            snapshot.type = block->type;
            snapshot.maxbsp = block->maxbsp;
            snapshot.minbstkref = block->minbstkref;
            snapshot.minbargref = block->minbargref;
            snapshot.predecessors = block->predset;
            snapshot.successors = block->succset;
            for ( const minsn_t *instruction = block->head;
                  instruction; instruction = instruction->next ) {
                snapshot.instructions.emplace_back(
                    new minsn_t(*instruction));
            }
            snapshots_.push_back(std::move(snapshot));
        }
    }

    ~mba_rewrite_transaction_t()
    {
        if ( !committed_ )
            rollback();
    }

    void commit()
    {
        committed_ = true;
    }

private:
    void rollback()
    {
        if ( !mba_ )
            return;
        for ( const block_snapshot_t &snapshot : snapshots_ ) {
            if ( snapshot.serial < 0 || snapshot.serial >= mba_->qty )
                continue;
            mblock_t *block = mba_->get_mblock(snapshot.serial);
            if ( !block )
                continue;
            for ( minsn_t *instruction = block->head;
                  instruction != nullptr; ) {
                minsn_t *next = block->remove_from_block(instruction);
                delete instruction;
                instruction = next;
            }
            minsn_t *anchor = nullptr;
            for ( const auto &instruction : snapshot.instructions ) {
                anchor = block->insert_into_block(
                    new minsn_t(*instruction), anchor);
            }
            block->start = snapshot.start;
            block->end = snapshot.end;
            block->type = snapshot.type;
            block->maxbsp = snapshot.maxbsp;
            block->minbstkref = snapshot.minbstkref;
            block->minbargref = snapshot.minbargref;
            block->predset = snapshot.predecessors;
            block->succset = snapshot.successors;
            block->flags = snapshot.flags;
        }
        mba_->mark_chains_dirty();
    }

    mbl_array_t *mba_ = nullptr;
    std::vector<block_snapshot_t> snapshots_;
    bool committed_ = false;
};

} // namespace

int run(mbl_array_t *mba,
        const pattern_match::flatten_info_t &pattern,
        deobf_ctx_t *ctx)
{
    if ( !mba || !ctx || mba->maturity != MMAT_LOCOPT
      || pattern.kind != pattern_match::flatten_pattern_kind_t::recurrent_switch )
        return 0;

    std::vector<int> dispatcher_path;
    if ( !build_dispatcher_path(mba, pattern, &dispatcher_path) ) {
        deobf::log("[deflatten][cff-switch] rejected: dispatcher chain is not linear\n");
        return 0;
    }

    std::map<uint64_t, int> state_to_block;
    mop_t selector;
    if ( !decode_microcode_switch(
            mba, pattern.switch_block, &state_to_block, &selector) ) {
        deobf::log("[deflatten][cff-switch] rejected: no stable microcode switch map\n");
        return 0;
    }

    std::vector<mop_t> selector_live_registers;
    std::vector<mop_t> private_state_operands;
    std::set<storage_key_t> state_storage;
    if ( !collect_selector_inputs(
            mba, dispatcher_path, &selector_live_registers,
            &private_state_operands, &state_storage)
      || !state_storage_is_private(mba, state_storage) ) {
        deobf::log("[deflatten][cff-switch] rejected: selector state storage is not private\n");
        return 0;
    }

    std::set<int> dispatcher_blocks = pattern.dispatcher_blocks;
    dispatcher_blocks.insert(pattern.dispatcher_block);
    dispatcher_blocks.insert(pattern.switch_block);
    std::set<int> case_targets;
    for ( const auto &mapping : state_to_block )
        case_targets.insert(mapping.second);

    std::vector<case_path_t> paths;
    std::set<edge_key_t> terminal_case_edges;
    std::size_t terminal_cases = 0;
    for ( const auto &mapping : state_to_block ) {
        const std::size_t before = paths.size();
        bool terminated_without_dispatch = false;
        if ( !enumerate_case_paths(
                mba, mapping.first, mapping.second, case_targets,
                dispatcher_blocks, &paths, &terminated_without_dispatch) ) {
            deobf::log(
                "[deflatten][cff-switch] rejected: path enumeration exceeded proof bounds\n");
            return 0;
        }
        if ( paths.size() == before ) {
            if ( !terminated_without_dispatch ) {
                deobf::log(
                    "[deflatten][cff-switch] rejected: state 0x%llx has no complete exit\n",
                    static_cast<unsigned long long>(mapping.first));
                return 0;
            }
            ++terminal_cases;
        }
        for ( std::size_t index = before; index < paths.size(); ++index )
            terminal_case_edges.insert(paths[index].edges.back());
    }

    // The non-case incoming edge seeds invariant selector registers and the
    // initial encoded state. It must be unique before any transformation.
    std::set<edge_key_t> entry_edges;
    for ( int dispatcher_block : dispatcher_blocks ) {
        const mblock_t *block = mba->get_mblock(dispatcher_block);
        for ( int predecessor : block->predset ) {
            const edge_key_t edge{predecessor, dispatcher_block};
            if ( dispatcher_blocks.count(predecessor) == 0
              && terminal_case_edges.count(edge) == 0 )
                entry_edges.insert(edge);
        }
    }
    if ( entry_edges.size() != 1 ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: expected one entry edge, found %zu\n",
            entry_edges.size());
        return 0;
    }
    const edge_key_t entry_edge = *entry_edges.begin();
    std::vector<int> entry_path;
    if ( !find_unique_entry_path(
            mba, entry_edge.source, case_targets,
            dispatcher_blocks, &entry_path) ) {
        deobf::log("[deflatten][cff-switch] rejected: entry provenance is ambiguous\n");
        return 0;
    }

    std::vector<mop_t> stack_pointers;
    collect_stack_pointer_operands(mba, entry_path, &stack_pointers);
    for ( case_path_t &path : paths )
        collect_stack_pointer_operands(mba, path.blocks, &stack_pointers);

    std::set<int> executed_blocks(
        entry_path.begin(), entry_path.end());
    executed_blocks.insert(
        dispatcher_path.begin(), dispatcher_path.end());
    for ( const case_path_t &path : paths )
        executed_blocks.insert(path.blocks.begin(), path.blocks.end());

    int rejected_block = -1;
    mcode_t rejected_opcode = m_nop;
    if ( !validate_proof_semantics(
            mba, executed_blocks, &rejected_block, &rejected_opcode) ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: unsupported proof semantics "
            "opcode=%d block=%d\n",
            static_cast<int>(rejected_opcode), rejected_block);
        return 0;
    }

    std::vector<mop_t> preservation_candidates = selector_live_registers;
    collect_register_operands(
        mba, executed_blocks, &preservation_candidates);
    for ( const mop_t &operand : stack_pointers )
        add_register_unique(&preservation_candidates, operand);
    std::vector<mop_t> preserved_registers;
    for ( const mop_t &operand : preservation_candidates ) {
        if ( register_preserved_across_calls(
                mba, executed_blocks, operand) )
            add_register_unique(&preserved_registers, operand);
    }

    scoped_solver_timeout_t restore_solver_timeout;
    z3_solver::reset_global_context();
    const auto solver_deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(k_solver_total_budget_ms);

    if ( !apply_remaining_solver_budget(solver_deadline) ) {
        deobf::log("[deflatten][cff-switch] rejected: solver budget exhausted before initial proof\n");
        return 0;
    }
    const selector_resolution_t initial_resolution = resolve_selector_target(
        mba, entry_path, entry_edge.destination, dispatcher_path,
        pattern.switch_block, nullptr, preserved_registers,
        private_state_operands, selector, state_to_block, false);
    if ( std::chrono::steady_clock::now() >= solver_deadline ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: total solver deadline exceeded "
            "during initial proof\n");
        return 0;
    }
    if ( initial_resolution.kind != selector_resolution_kind_t::resolved ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: initial selector is %s\n",
            initial_resolution.kind == selector_resolution_kind_t::infeasible
                ? "infeasible" : "not unique");
        return 0;
    }

    std::map<edge_key_t, edge_proof_t> proofs;
    using transition_key_t =
        std::pair<uint64_t, std::vector<edge_key_t>>;
    std::map<transition_key_t, selector_resolution_t> transition_cache;
    std::map<uint64_t, std::size_t> syntactic_paths_by_state;
    std::map<uint64_t, std::size_t> feasible_paths_by_state;
    std::size_t resolved_paths = 0;
    std::size_t infeasible_paths = 0;
    std::size_t unresolved_paths = 0;
    std::size_t cache_hits = 0;
    for ( case_path_t &path : paths ) {
        ++syntactic_paths_by_state[path.state];
        const transition_key_t cache_key{path.state, path.edges};
        const auto cached = transition_cache.find(cache_key);
        selector_resolution_t resolution;
        if ( cached != transition_cache.end() ) {
            resolution = cached->second;
            ++cache_hits;
        } else {
            if ( !apply_remaining_solver_budget(solver_deadline) ) {
                deobf::log(
                    "[deflatten][cff-switch] rejected: total solver deadline "
                    "exceeded after %zu/%zu paths\n",
                    resolved_paths, paths.size());
                return 0;
            }
            resolution = resolve_selector_target(
                mba, entry_path, entry_edge.destination, dispatcher_path,
                pattern.switch_block, &path, preserved_registers,
                private_state_operands, selector, state_to_block, true);
            transition_cache.emplace(cache_key, resolution);
            if ( std::chrono::steady_clock::now() >= solver_deadline ) {
                deobf::log(
                    "[deflatten][cff-switch] rejected: total solver deadline "
                    "exceeded while proving path %zu/%zu\n",
                    resolved_paths + 1, paths.size());
                return 0;
            }
        }
        if ( resolution.kind == selector_resolution_kind_t::resolved ) {
            path.resolved_target = resolution.target;
            ++resolved_paths;
            ++feasible_paths_by_state[path.state];
        } else if ( resolution.kind == selector_resolution_kind_t::infeasible ) {
            path.infeasible = true;
            ++infeasible_paths;
            deobf::log_verbose(
                "[deflatten][cff-switch] excluded infeasible path "
                "state=0x%llx\n",
                static_cast<unsigned long long>(path.state));
            continue;
        } else {
            ++unresolved_paths;
            ++feasible_paths_by_state[path.state];
            qstring route;
            for ( int block_index : path.blocks ) {
                if ( !route.empty() )
                    route.append(',');
                route.cat_sprnt("%d", block_index);
            }
            deobf::log(
                "[deflatten][cff-switch] unresolved path state=0x%llx blocks=%s\n",
                static_cast<unsigned long long>(path.state), route.c_str());
        }

        for ( std::size_t edge_index = 0;
              edge_index < path.edges.size(); ++edge_index ) {
            edge_proof_t &proof = proofs[path.edges[edge_index]];
            if ( path.resolved_target )
                proof.targets.insert(*path.resolved_target);
            else
                proof.unresolved = true;
            for ( std::size_t block_index = edge_index + 1;
                  block_index < path.blocks.size(); ++block_index ) {
                if ( !block_is_safe_suffix(
                        mba->get_mblock(path.blocks[block_index]),
                        state_storage) ) {
                    proof.suffix_safe = false;
                    break;
                }
            }
        }
    }

    if ( unresolved_paths != 0 ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: proved %zu/%zu feasible "
            "transition paths (%zu infeasible excluded)\n",
            resolved_paths, resolved_paths + unresolved_paths,
            infeasible_paths);
        return 0;
    }
    for ( const auto &state_paths : syntactic_paths_by_state ) {
        if ( state_paths.second != 0
          && feasible_paths_by_state[state_paths.first] == 0 ) {
            deobf::log(
                "[deflatten][cff-switch] rejected: state 0x%llx has no "
                "feasible transition path\n",
                static_cast<unsigned long long>(state_paths.first));
            return 0;
        }
    }
    deobf::log_verbose(
        "[deflatten][cff-switch] transition paths=%zu feasible=%zu "
        "infeasible=%zu unique-proofs=%zu cache-hits=%zu\n",
        paths.size(), resolved_paths, infeasible_paths,
        transition_cache.size(), cache_hits);

    std::map<edge_key_t, int> rewrite_plan;
    std::map<edge_key_t, specialization_rewrite_t> specialization_plan;
    std::vector<split_rewrite_t> split_plan;
    rewrite_plan[entry_edge] = initial_resolution.target;
    std::map<uint64_t, std::vector<const case_path_t *>> paths_by_state;
    for ( const case_path_t &path : paths ) {
        if ( !path.infeasible )
            paths_by_state[path.state].push_back(&path);
    }

    for ( const auto &state_group : paths_by_state ) {
        std::map<edge_key_t, int> state_rewrites;
        bool all_paths_have_safe_cut = true;
        for ( const case_path_t *path : state_group.second ) {
            bool selected = false;
            for ( auto edge = path->edges.rbegin();
                  edge != path->edges.rend(); ++edge ) {
                const auto proof = proofs.find(*edge);
                if ( proof == proofs.end() || proof->second.unresolved
                  || !proof->second.suffix_safe
                  || proof->second.targets.size() != 1
                  || !edge_is_rewriteable(mba, *edge) )
                    continue;
                state_rewrites[*edge] = *proof->second.targets.begin();
                selected = true;
                break;
            }
            if ( !selected ) {
                all_paths_have_safe_cut = false;
                break;
            }
        }
        if ( all_paths_have_safe_cut ) {
            rewrite_plan.insert(state_rewrites.begin(), state_rewrites.end());
            continue;
        }

        std::vector<specialization_rewrite_t> specializations;
        if ( try_build_frontier_specializations(
                mba, state_group.second, proofs,
                dispatcher_blocks, &specializations) ) {
            for ( const specialization_rewrite_t &specialization
                  : specializations ) {
                const edge_key_t edge{
                    specialization.predecessor, specialization.frontier};
                const auto inserted = specialization_plan.emplace(
                    edge, specialization);
                if ( !inserted.second
                  && inserted.first->second.target != specialization.target ) {
                    deobf::log(
                        "[deflatten][cff-switch] rejected: conflicting "
                        "specializations at edge %d->%d\n",
                        edge.source, edge.destination);
                    return 0;
                }
            }
            continue;
        }

        split_rewrite_t split;
        if ( !try_build_split_rewrite(
                mba, state_group.second, dispatcher_blocks, &split) ) {
            log_cut_diagnostics(
                mba, state_group.first, state_group.second, proofs);
            deobf::log(
                "[deflatten][cff-switch] rejected: no semantics-preserving cut "
                "for state 0x%llx\n",
                static_cast<unsigned long long>(state_group.first));
            return 0;
        }
        split_plan.push_back(split);
    }

    std::set<std::pair<int, minsn_t *>> state_erasures;
    if ( !collect_split_state_erasures(
            mba, split_plan, state_storage, &state_erasures) ) {
        deobf::log(
            "[deflatten][cff-switch] rejected: split state assignment has "
            "nested side effects\n");
        return 0;
    }

    // Validate the complete plan against the unmodified graph. No partial
    // mutation is allowed if any planned edge is no longer representable.
    for ( const auto &rewrite : rewrite_plan ) {
        if ( !edge_is_rewriteable(mba, rewrite.first) ) {
            deobf::log("[deflatten][cff-switch] rejected: rewrite plan became stale\n");
            return 0;
        }
    }
    std::set<edge_key_t> bypassed_inputs;
    for ( const auto &rewrite : rewrite_plan )
        bypassed_inputs.insert(rewrite.first);
    for ( const auto &planned : specialization_plan )
        bypassed_inputs.insert(planned.first);
    for ( const split_rewrite_t &rewrite : split_plan ) {
        if ( !validate_split_rewrite(
                mba, rewrite, dispatcher_blocks, bypassed_inputs) ) {
            deobf::log("[deflatten][cff-switch] rejected: split plan became stale\n");
            return 0;
        }
    }
    for ( const auto &planned : specialization_plan ) {
        if ( !validate_specialization_rewrite(
                mba, planned.second, dispatcher_blocks) ) {
            deobf::log(
                "[deflatten][cff-switch] rejected: specialization plan became stale\n");
            return 0;
        }
    }

    std::set<int> transaction_blocks;
    const auto include_edge = [&](const edge_key_t &edge, int target) {
        transaction_blocks.insert(edge.source);
        transaction_blocks.insert(edge.destination);
        transaction_blocks.insert(target);
    };
    for ( const auto &rewrite : rewrite_plan )
        include_edge(rewrite.first, rewrite.second);
    for ( const auto &planned : specialization_plan ) {
        const specialization_rewrite_t &rewrite = planned.second;
        include_edge(
            edge_key_t{rewrite.predecessor, rewrite.frontier},
            rewrite.target);
        transaction_blocks.insert(rewrite.frontier);
    }
    for ( const split_rewrite_t &rewrite : split_plan ) {
        transaction_blocks.insert(rewrite.branch);
        transaction_blocks.insert(rewrite.alternate);
        transaction_blocks.insert(rewrite.direct_target);
        transaction_blocks.insert(rewrite.alternate_target);
        transaction_blocks.insert(
            rewrite.suffix.begin(), rewrite.suffix.end());
        if ( !rewrite.suffix.empty() ) {
            const mblock_t *terminal = mba->get_mblock(rewrite.suffix.back());
            if ( terminal && terminal->nsucc() == 1 )
                transaction_blocks.insert(terminal->succ(0));
        }
    }
    for ( const auto &erasure : state_erasures )
        transaction_blocks.insert(erasure.first);

    mba_rewrite_transaction_t transaction(mba, transaction_blocks);
    int changes = 0;
    for ( const auto &planned : specialization_plan ) {
        const specialization_rewrite_t &rewrite = planned.second;
        if ( !apply_specialization_rewrite(mba, rewrite) ) {
            deobf::log(
                "[deflatten][cff-switch] internal rejection while specializing "
                "state 0x%llx at edge %d->%d\n",
                static_cast<unsigned long long>(rewrite.state),
                rewrite.predecessor, rewrite.frontier);
            return 0;
        }
        ++changes;
    }
    for ( const split_rewrite_t &rewrite : split_plan ) {
        if ( !apply_split_rewrite(mba, rewrite, state_storage) ) {
            deobf::log(
                "[deflatten][cff-switch] internal rejection while splitting "
                "state 0x%llx\n",
                static_cast<unsigned long long>(rewrite.state));
            return 0;
        }
        changes += 2;
    }
    apply_state_erasures(mba, state_erasures);
    for ( const auto &rewrite : rewrite_plan ) {
        if ( !apply_edge_rewrite(mba, rewrite.first, rewrite.second) ) {
            deobf::log(
                "[deflatten][cff-switch] internal rejection while applying edge %d->%d\n",
                rewrite.first.source, rewrite.first.destination);
            return 0;
        }
        ++changes;
    }

    if ( changes > 0 ) {
        mba->mark_chains_dirty();
        mba->verify(true);
        ctx->branches_simplified += changes;
        transaction.commit();
        // Return the exact mutation count to the owning optblock pass. Hex-
        // Rays will rebuild chains and prune unreachable blocks in its normal
        // optimizer lifecycle. Calling optimize_local/remove-unreachable from
        // inside this callback is re-entrant and was a source of fast INTERRs.
        deobf::log(
            "[deflatten][cff-switch] rewrote %d proven edges across %zu paths "
            "(%zu specialized edges, %zu split frontiers, %zu terminal cases); "
            "dispatcher cleanup=deferred\n",
            changes, paths.size(), specialization_plan.size(),
            split_plan.size(), terminal_cases);
    }
    return changes;
}

} // namespace recurrent_switch
