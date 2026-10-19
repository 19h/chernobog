#include "mba_smt.h"
#include "../../common/bitvector.h"
#include <chrono>
#include <stdexcept>
#include <tuple>

namespace chernobog::mba_smt
{
namespace
{
struct Register
{
    mreg_t start;
    int bytes;
    uint64_t value_number;
};

bool has_volatile_inputs(ea_t entry)
{
    tinfo_t function_type;
    func_type_data_t details;
    if (!get_tinfo(&function_type, entry) || !function_type.get_func_details(&details))
    {
        return false;
    }
    for (const auto &argument : details)
    {
        tinfo_t type = argument.type;
        for (unsigned depth = 0; depth < limits::expression_depth; ++depth)
        {
            if (type.is_volatile())
            {
                return true;
            }
            if (type.is_ptr())
            {
                type = type.get_pointed_object();
            }
            else if (type.is_array())
            {
                type = type.get_array_element();
            }
            else
            {
                break;
            }
        }
    }
    return false;
}

class MicrocodeAdapter
{
  public:
    mbl_array_t *mba;
    Program program;
    std::vector<Register> registers;
    std::vector<std::pair<Term, mop_t>> available;
    std::map<std::pair<size_t, size_t>, minsn_t *> originals;
    std::map<int64_t, size_t> frames;
    std::map<std::pair<uintptr_t, int>, size_t> locals;
    std::map<std::tuple<int, int, int64_t, uint64_t, int>, size_t> local_values;
    size_t visits = 0;
    mblock_t *local_block = nullptr;
    minsn_t *local_instruction = nullptr;

    explicit MicrocodeAdapter(mbl_array_t *value, mblock_t *block = nullptr,
                              minsn_t *instruction = nullptr)
        : mba(value), local_block(block), local_instruction(instruction)
    {
        program.address_bits = inf_is_64bit() ? 64 : 32;
        program.big_endian = inf_is_be();
    }

    static bool has_supported_properties(const minsn_t *ins)
    {
        return ins && !ins->is_fpinsn() && !ins->is_mbarrier() && !ins->is_persistent() &&
               !ins->is_assert() && ins->is_combinable() && ins->is_propagatable();
    }

    static bool has_observable_read(const mop_t &operand)
    {
        if (operand.t == mop_v)
        {
            return true;
        }
        if (operand.t != mop_d || operand.d == nullptr)
        {
            return false;
        }
        return operand.d->opcode == m_ldx || has_observable_read(operand.d->l) ||
               has_observable_read(operand.d->r);
    }

    void collect_register_views(const mop_t &op, unsigned depth = 0)
    {
        if (++visits > 4096 || depth > 64)
        {
            throw std::invalid_argument("tree budget");
        }
        if (op.t == mop_d && op.d)
        {
            collect_register_views(op.d->l, depth + 1);
            collect_register_views(op.d->r, depth + 1);
        }
        else if (op.t == mop_r && op.r >= 8 && bitvector::valid_byte_width(op.size))
        {
            registers.push_back({op.r, op.size, uint64_t(op.valnum)});
        }
    }

    Term register_view(size_t id, unsigned offset, unsigned bits)
    {
        auto result = variable(id, program.widths[id]);
        if (offset)
        {
            result = expression(Op::High, result, {}, result->bits - offset);
        }
        if (result->bits != bits)
        {
            result = expression(Op::Low, result, {}, bits);
        }
        return result;
    }

    std::pair<size_t, unsigned> locate_register_view(const mop_t &op)
    {
        for (size_t i = 0; i < registers.size(); ++i)
        {
            if (uint64_t(op.valnum) == registers[i].value_number && op.r >= registers[i].start &&
                op.r + op.size <= registers[i].start + registers[i].bytes)
            {
                return {i, unsigned(op.r - registers[i].start) * 8};
            }
        }
        throw std::invalid_argument("untracked register");
    }

    size_t frame_base(int64_t owner)
    {
        const auto found = frames.find(owner);
        if (found != frames.end())
        {
            return found->second;
        }
        auto id = program.widths.size();
        program.widths.push_back(program.address_bits);
        program.readonly.push_back(id);
        frames.emplace(owner, id);
        return id;
    }

    Term translate_address(const mop_t &op)
    {
        if (op.t == mop_v)
        {
            return constant(uint64_t(op.g), program.address_bits);
        }
        if (op.t == mop_S && op.s && op.s->mba == mba)
        {
            return expression(Op::Add,
                              variable(frame_base(int64_t(reinterpret_cast<uintptr_t>(op.s->mba))),
                                       program.address_bits),
                              constant(uint64_t(op.s->off), program.address_bits));
        }
        if (op.t == mop_l && op.l && op.l->mba == mba)
        {
            auto identifier = std::make_pair(reinterpret_cast<uintptr_t>(op.l->mba), op.l->idx);
            auto it = locals.find(identifier);
            if (it == locals.end())
            {
                auto id = program.widths.size();
                program.widths.push_back(program.address_bits);
                program.readonly.push_back(id);
                it = locals.emplace(identifier, id).first;
            }
            return expression(Op::Add, variable(it->second, program.address_bits),
                              constant(uint64_t(op.l->off), program.address_bits));
        }
        throw std::invalid_argument("unresolved address");
    }

    Term translate_local_value(const mop_t &operand)
    {
        const bool stack_value = operand.t == mop_S;
        const int index = stack_value ? 0 : operand.l->idx;
        const int64_t offset = stack_value ? operand.s->off : operand.l->off;
        const auto identity =
            std::make_tuple(int(operand.t), index, offset, uint64_t(operand.valnum), operand.size);
        const auto found = local_values.find(identity);
        if (found != local_values.end())
        {
            return variable(found->second, unsigned(operand.size * 8));
        }
        if (program.widths.size() >= limits::storage_regions)
        {
            throw std::invalid_argument("local value budget");
        }

        const size_t id = program.widths.size();
        program.widths.push_back(unsigned(operand.size * 8));
        local_values.emplace(identity, id);
        const Term value = variable(id, unsigned(operand.size * 8));
        available.emplace_back(value, operand);
        program.available.push_back(value);
        return value;
    }

    Term translate_operand(const mop_t &op, unsigned depth = 0)
    {
        if (depth > 64 || !bitvector::valid_byte_width(op.size) || op.oprops ||
            op.probably_floating() || op.is_udt() || op.is_undef_val())
        {
            throw std::invalid_argument("unsupported operand");
        }
        auto bits = unsigned(op.size * 8);
        if (op.t == mop_n && op.nnn)
        {
            return constant(uint64_t(op.nnn->value), bits);
        }
        if (op.t == mop_r && op.r >= 8 && (local_instruction || op.valnum == 0))
        {
            auto [id, offset] = locate_register_view(op);
            auto term = register_view(id, offset, bits);
            if (available.size() < 64)
            {
                available.emplace_back(term, op);
                program.available.push_back(term);
            }
            return term;
        }
        if (op.t == mop_d && op.d && op.d->d.size == op.size)
        {
            return translate_instruction(op.d, depth + 1);
        }
        if (local_instruction && ((op.t == mop_S && op.s && op.s->mba == mba) ||
                                  (op.t == mop_l && op.l && op.l->mba == mba)))
        {
            // A pure expression cannot write between these implicit reads.
            // Different value numbers and overlapping views remain independent
            // symbols; this loses possible equalities rather than inventing them.
            return translate_local_value(op);
        }
        if (op.t == mop_v || op.t == mop_S || op.t == mop_l)
        {
            if (op.valnum != 0)
            {
                throw std::invalid_argument(
                    "numbered memory snapshot requires a reaching definition");
            }
            return load(translate_address(op), bits);
        }
        if (op.t == mop_a && op.a && bits == program.address_bits)
        {
            return translate_address(*op.a);
        }
        throw std::invalid_argument("unsupported operand identity");
    }

    static Op opcode(mcode_t code)
    {
        switch (code)
        {
        case m_add:
            return Op::Add;
        case m_sub:
            return Op::Sub;
        case m_mul:
            return Op::Mul;
        case m_udiv:
            return Op::UnsignedDivide;
        case m_and:
            return Op::And;
        case m_or:
            return Op::Or;
        case m_xor:
            return Op::Xor;
        case m_bnot:
            return Op::Not;
        case m_neg:
            return Op::Neg;
        case m_xdu:
            return Op::ZeroExtend;
        case m_xds:
            return Op::SignExtend;
        case m_low:
            return Op::Low;
        case m_high:
            return Op::High;
        case m_shl:
            return Op::Shl;
        case m_shr:
            return Op::Shr;
        case m_sar:
            return Op::Sar;
        case m_setz:
        case m_jz:
            return Op::Equal;
        case m_setnz:
        case m_jnz:
            return Op::NotEqual;
        case m_setb:
        case m_jb:
            return Op::UnsignedLess;
        case m_setl:
        case m_jl:
            return Op::SignedLess;
        default:
            throw std::invalid_argument("unsupported opcode");
        }
    }

    Term translate_instruction(const minsn_t *ins, unsigned depth = 0)
    {
        if (!has_supported_properties(ins) || depth > 64 ||
            !bitvector::valid_byte_width(ins->d.size))
        {
            throw std::invalid_argument("unsupported effects");
        }
        if (ins->opcode == m_mov || ins->opcode == m_ldc)
        {
            if (ins->r.t != mop_z)
            {
                throw std::invalid_argument("unexpected move operand");
            }
            auto term = translate_operand(ins->l, depth + 1);
            if (term->bits != unsigned(ins->d.size * 8))
            {
                throw std::invalid_argument("implicit conversion");
            }
            return term;
        }
        auto code = opcode(ins->opcode);
        auto left = translate_operand(ins->l, depth + 1);
        const bool unary = code == Op::Not || code == Op::Neg || code == Op::ZeroExtend ||
                           code == Op::SignExtend || code == Op::Low || code == Op::High;
        if (unary && ins->r.t != mop_z)
        {
            throw std::invalid_argument("unexpected unary operand");
        }
        return expression(code, left, unary ? Term{} : translate_operand(ins->r, depth + 1),
                          unsigned(ins->d.size * 8));
    }

    bool has_flat_selector(const mop_t &op)
    {
        if (op.t == mop_n && op.nnn && op.nnn->value == 0)
        {
            return true;
        }
        // Only flat architectural data selectors are admitted. FS/GS and all
        // 32-bit segmentation remain unmodeled and invalidate memory facts.
        if (!inf_is_64bit() || op.t != mop_r)
        {
            return false;
        }
        qstring name;
        get_mreg_name(&name, op.r, op.size);
        return name == "ds" || name == "ss" || name == "es";
    }

    void build_register_regions()
    {
        if (!local_instruction && mba->qty > 64)
        {
            throw std::invalid_argument("block budget");
        }
        if (local_instruction)
        {
            collect_register_views(local_instruction->l);
            collect_register_views(local_instruction->r);
        }
        else
        {
            for (int b = 0; b < mba->qty; ++b)
            {
                for (auto *ins = mba->get_mblock(b)->head; ins; ins = ins->next)
                {
                    collect_register_views(ins->l);
                    collect_register_views(ins->r);
                    collect_register_views(ins->d);
                }
            }
        }
        std::sort(registers.begin(), registers.end(),
                  [](const Register &left, const Register &right)
                  {
                      return std::tie(left.value_number, left.start) <
                             std::tie(right.value_number, right.start);
                  });
        std::vector<Register> merged;
        for (const auto &r : registers)
        {
            if (!merged.empty() && r.value_number == merged.back().value_number &&
                r.start < merged.back().start + merged.back().bytes)
            {
                merged.back().bytes =
                    std::max(merged.back().bytes, int(r.start - merged.back().start) + r.bytes);
            }
            else
            {
                merged.push_back(r);
            }
        }
        registers = std::move(merged);
        for (const auto &r : registers)
        {
            if (r.bytes > 8)
            {
                throw std::invalid_argument("wide register overlap");
            }
            program.widths.push_back(unsigned(r.bytes * 8));
        }
    }

    void translate_statement(minsn_t *ins, size_t block_index, Block &output)
    {
        if (ins->opcode == m_nop || ins->opcode == m_goto || is_mcode_jcond(ins->opcode) ||
            ins->opcode == m_ret || ins->opcode == m_jtbl)
        {
            return;
        }

        if (ins->d.t == mop_r && ins->d.r < 8 && has_supported_properties(ins))
        {
            const bool flag_copy = ins->opcode == m_mov && (ins->l.t == mop_n || ins->l.t == mop_r);
            if (flag_copy)
            {
                return;
            }
            if (is_mcode_set(ins->opcode))
            {
                try
                {
                    // Validate nested inputs so a propagated call cannot be
                    // mistaken for a pure write to an unmodeled flag.
                    translate_operand(ins->l);
                    if (ins->r.t != mop_z)
                    {
                        translate_operand(ins->r);
                    }
                    return;
                }
                catch (const std::invalid_argument &)
                {
                    output.statements.push_back(Statement::havoc());
                    return;
                }
            }
        }

        if (ins->opcode == m_ijmp)
        {
            throw std::invalid_argument("unresolved indirect control flow");
        }

        try
        {
            const bool memory_instruction = ins->opcode == m_stx || ins->opcode == m_ldx;
            const bool ordinary_memory =
                memory_instruction && ins->iprops == 0 && !ins->is_fpinsn() &&
                !ins->is_mbarrier() && !ins->is_persistent() && !ins->is_assert() &&
                ins->l.oprops == 0 && ins->r.oprops == 0 && ins->d.oprops == 0;
            const bool supported =
                memory_instruction ? ordinary_memory : has_supported_properties(ins);
            if (!supported)
            {
                throw std::invalid_argument("unsupported instruction effects");
            }

            if (ins->opcode == m_stx)
            {
                if (!has_flat_selector(ins->r))
                {
                    throw std::invalid_argument("segmented store");
                }

                output.statements.push_back(
                    Statement::store(translate_operand(ins->d), translate_operand(ins->l)));
                return;
            }

            Term value;
            if (ins->opcode == m_ldx)
            {
                if (!has_flat_selector(ins->l))
                {
                    throw std::invalid_argument("segmented load");
                }

                value = load(translate_operand(ins->r), static_cast<unsigned>(ins->d.size * 8));
            }
            else
            {
                value = translate_instruction(ins);
            }

            if (ins->d.t == mop_r && ins->d.r >= 8 && ins->d.valnum == 0)
            {
                const auto [register_index, bit_offset] = locate_register_view(ins->d);
                auto statement = Statement::assign(register_index, value);
                statement.offset = bit_offset;

                const bool pure_candidate = ins->opcode != m_ldx && !has_observable_read(ins->l) &&
                                            !has_observable_read(ins->r);
                const bool has_computation = ins->opcode != m_mov || ins->l.t == mop_d;
                if (pure_candidate && has_computation)
                {
                    originals[{block_index, output.statements.size()}] = ins;
                }

                output.statements.push_back(std::move(statement));
                return;
            }

            if (ins->d.t == mop_v || ins->d.t == mop_S || ins->d.t == mop_l)
            {
                output.statements.push_back(Statement::store(translate_address(ins->d), value));
                return;
            }

            throw std::invalid_argument("unsupported destination");
        }
        catch (const std::invalid_argument &)
        {
            // Unknown effects may invalidate both register and memory facts.
            output.statements.push_back(Statement::havoc());
        }
    }

    void translate_successors(const mblock_t *block, Block &output)
    {
        Term condition;
        const minsn_t *tail = block->tail;
        const bool conditional_branch = tail && is_mcode_jcond(tail->opcode);

        if (conditional_branch && (tail->d.t != mop_b || block->nsucc() != 2))
        {
            output.statements.push_back(Statement::havoc());
        }
        if (tail && tail->opcode == m_jtbl)
        {
            // Table dispatch can contain unmodeled selector evaluation.
            // Keep every CFG successor, but do not carry facts through it.
            output.statements.push_back(Statement::havoc());
        }

        if (conditional_branch && tail->d.t == mop_b && block->nsucc() == 2)
        {
            try
            {
                if (tail->is_fpinsn() || tail->is_mbarrier())
                {
                    throw std::invalid_argument("unsupported branch semantics");
                }
                if (tail->opcode == m_jcnd)
                {
                    condition = translate_operand(tail->l);
                }
                else
                {
                    condition = expression(opcode(tail->opcode), translate_operand(tail->l),
                                           translate_operand(tail->r), 8);
                }
            }
            catch (const std::invalid_argument &)
            {
                // A rejected nested predicate can contain a call. Retaining
                // its old register or memory facts would be unsound.
                output.statements.push_back(Statement::havoc());
            }
        }

        for (int successor = 0; successor < block->nsucc(); ++successor)
        {
            const int target = block->succ(successor);
            const bool inverted = condition && target != tail->d.b;
            output.edges.push_back({static_cast<size_t>(target), condition, inverted});
        }
    }

    void build()
    {
        build_register_regions();

        if (local_instruction)
        {
            const Term value = translate_instruction(local_instruction);
            if (contains_load(value))
            {
                throw std::invalid_argument("local expression contains memory reads");
            }

            const size_t result = program.widths.size();
            program.widths.push_back(value->bits);
            program.blocks.resize(1);
            program.blocks[0].statements.push_back(Statement::assign(result, value));
            originals[{0, 0}] = local_instruction;
            program.targets.push_back({0, 0});
            return;
        }

        program.blocks.resize(static_cast<size_t>(mba->qty));

        for (int block_index = 0; block_index < mba->qty; ++block_index)
        {
            auto *block = mba->get_mblock(block_index);
            auto &output = program.blocks[static_cast<size_t>(block_index)];
            for (auto *ins = block->head; ins; ins = ins->next)
            {
                translate_statement(ins, static_cast<size_t>(block_index), output);
            }
            translate_successors(block, output);
        }

        for (const auto &site : originals)
        {
            program.targets.push_back(site.first);
        }
    }

    static bool contains_load(const Term &term)
    {
        return term &&
               (term->op == Op::Load || contains_load(term->left) || contains_load(term->right));
    }

    static size_t expression_cost(const minsn_t *ins)
    {
        if (!ins)
        {
            return 0;
        }
        const size_t weight =
            ins->opcode == m_udiv ? limits::division_cost : size_t(ins->opcode != m_mov);
        return weight + (ins->l.t == mop_d ? expression_cost(ins->l.d) : 0) +
               (ins->r.t == mop_d ? expression_cost(ins->r.d) : 0);
    }

    mop_t emit_operand(const Term &term, ea_t ea)
    {
        mop_t result;
        for (const auto &leaf : available)
        {
            if (key(leaf.first) == key(term))
            {
                return leaf.second;
            }
        }
        if (term->op == Op::Constant)
        {
            result.make_number(term->value, int(term->bits / 8));
            return result;
        }
        minsn_t node(ea);
        node.d.size = int(term->bits / 8);
        switch (term->op)
        {
        case Op::Add:
            node.opcode = m_add;
            break;
        case Op::Sub:
            node.opcode = m_sub;
            break;
        case Op::Mul:
            node.opcode = m_mul;
            break;
        case Op::UnsignedDivide:
            node.opcode = m_udiv;
            break;
        case Op::And:
            node.opcode = m_and;
            break;
        case Op::Or:
            node.opcode = m_or;
            break;
        case Op::Xor:
            node.opcode = m_xor;
            break;
        case Op::Not:
            node.opcode = m_bnot;
            break;
        case Op::Neg:
            node.opcode = m_neg;
            break;
        case Op::Low:
            node.opcode = m_low;
            break;
        case Op::High:
            node.opcode = m_high;
            break;
        case Op::ZeroExtend:
            node.opcode = m_xdu;
            break;
        case Op::SignExtend:
            node.opcode = m_xds;
            break;
        case Op::Shl:
            node.opcode = m_shl;
            break;
        case Op::Shr:
            node.opcode = m_shr;
            break;
        case Op::Sar:
            node.opcode = m_sar;
            break;
        case Op::Equal:
            node.opcode = m_setz;
            break;
        case Op::NotEqual:
            node.opcode = m_setnz;
            break;
        case Op::UnsignedLess:
            node.opcode = m_setb;
            break;
        case Op::SignedLess:
            node.opcode = m_setl;
            break;
        default:
            throw std::invalid_argument("unavailable operand");
        }
        node.l = emit_operand(term->left, ea);
        if (term->right)
        {
            node.r = emit_operand(term->right, ea);
        }
        result.create_from_insn(&node);
        result.size = int(term->bits / 8);
        return result;
    }
};

void accumulate_statistics(Statistics &total, const Statistics &attempt)
{
    total.candidates += attempt.candidates;
    total.verified += attempt.verified;
    total.disproved += attempt.disproved;
    total.unsupported += attempt.unsupported;
    total.unknown += attempt.unknown;
    total.invariant_candidates += attempt.invariant_candidates;
    total.invariants += attempt.invariants;
    total.invariants_rejected += attempt.invariants_rejected;
    total.exhausted += attempt.exhausted;
}

class BudgetCharge
{
  public:
    explicit BudgetCharge(FunctionBudget &budget)
        : budget_(budget), started_(std::chrono::steady_clock::now())
    {
    }

    ~BudgetCharge() { budget_.spent_ns += elapsed_ns(); }

    uint64_t elapsed_ns() const
    {
        const auto elapsed = std::chrono::steady_clock::now() - started_;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

  private:
    FunctionBudget &budget_;
    std::chrono::steady_clock::time_point started_;
};

bool apply_verified_proposal(MicrocodeAdapter &adapter, Analysis &analysis,
                             const Proposal &proposal)
{
    const auto site = std::make_pair(proposal.block, proposal.statement);
    const auto found = adapter.originals.find(site);
    if (found == adapter.originals.end())
    {
        return false;
    }

    minsn_t *original = found->second;
    minsn_t replacement(*original);
    const mop_t value = adapter.emit_operand(proposal.replacement, original->ea);

    if (value.t == mop_d && value.d != nullptr)
    {
        replacement.opcode = value.d->opcode;
        replacement.l = value.d->l;
        replacement.r = value.d->r;
    }
    else
    {
        replacement.opcode = m_mov;
        replacement.l = value;
        replacement.r.erase();
    }

    if (MicrocodeAdapter::expression_cost(&replacement) >=
        MicrocodeAdapter::expression_cost(original))
    {
        return false;
    }

    // Emission is an independent boundary: verify the actual SDK operands,
    // not the synthesizer's expression or its textual representation.
    const Term emitted = adapter.translate_instruction(&replacement);
    if (analysis.verify(proposal.block, proposal.statement, emitted) != Verdict::Verified)
    {
        return false;
    }

    original->swap(replacement);
    mblock_t *owner = adapter.local_block;
    if (!owner)
    {
        owner = adapter.mba->get_mblock(static_cast<int>(proposal.block));
    }
    owner->mark_lists_dirty();
    return true;
}

int simplify_once(mbl_array_t *mba, FunctionBudget &budget, mblock_t *local_block = nullptr,
                  minsn_t *local_instruction = nullptr)
{
    BudgetCharge charge(budget);

    try
    {
        MicrocodeAdapter adapter(mba, local_block, local_instruction);
        adapter.build();
        if (adapter.originals.empty())
        {
            return 0;
        }

        const uint64_t used_ms = (budget.spent_ns + charge.elapsed_ns()) / 1000000;
        if (used_ms >= budget.limit_ms)
        {
            ++budget.totals.exhausted;
            return 0;
        }

        Options options = budget.limit_ms > 1000 ? Options::deep() : Options{};
        options.budget_ms = budget.limit_ms - static_cast<unsigned>(used_ms);
        options.cancelled = [] { return user_cancelled(); };

        Analysis analysis(adapter.program, options);
        const auto proposals = analysis.run();
        bool applied = false;
        for (const Proposal &proposal : proposals)
        {
            if (apply_verified_proposal(adapter, analysis, proposal))
            {
                applied = true;
                ++budget.totals.applied;
                break;
            }
        }
        accumulate_statistics(budget.totals, analysis.statistics());

        if (applied)
        {
            mba->verify(false);
            return 1;
        }
    }
    catch (const std::exception &error)
    {
        ++budget.totals.unsupported;
        deobf::log_verbose("[MBA SMT] Retained original microcode: %s\n", error.what());
    }

    return 0;
}

struct LocalCandidate
{
    mblock_t *block;
    minsn_t *instruction;
    size_t cost;
};

bool collect_local_candidates(mblock_t *block, minsn_t *instruction, unsigned depth,
                              std::set<minsn_t *> &visited, std::vector<LocalCandidate> &candidates)
{
    if (!instruction || depth > limits::expression_depth || visited.size() >= limits::statements ||
        !visited.insert(instruction).second)
    {
        return false;
    }

    for (mop_t *operand : {&instruction->l, &instruction->r})
    {
        if (operand->t == mop_d &&
            !collect_local_candidates(block, operand->d, depth + 1, visited, candidates))
        {
            return false;
        }
    }

    switch (instruction->opcode)
    {
    case m_add:
    case m_sub:
    case m_mul:
    case m_udiv:
    case m_and:
    case m_or:
    case m_xor:
    case m_bnot:
    case m_neg:
    case m_shl:
    case m_shr:
    case m_sar:
    case m_setz:
    case m_setnz:
    case m_setb:
    case m_setl:
    {
        const size_t cost = MicrocodeAdapter::expression_cost(instruction);
        if (cost >= 2)
        {
            candidates.push_back({block, instruction, cost});
        }
        break;
    }
    default:
        break;
    }
    return true;
}

int simplify_local_trees(mbl_array_t *mba, FunctionBudget &budget)
{
    std::vector<LocalCandidate> candidates;
    std::set<minsn_t *> visited;
    for (int index = 0; index < mba->qty && visited.size() < limits::statements; ++index)
    {
        mblock_t *block = mba->get_mblock(index);
        for (minsn_t *instruction = block->head; instruction; instruction = instruction->next)
        {
            if (!collect_local_candidates(block, instruction, 0, visited, candidates))
            {
                break;
            }
        }
    }

    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const LocalCandidate &left, const LocalCandidate &right)
                     { return left.cost > right.cost; });

    for (const LocalCandidate &candidate : candidates)
    {
        if (budget.spent_ns / 1000000 >= budget.limit_ms || user_cancelled())
        {
            break;
        }
        if (simplify_once(mba, budget, candidate.block, candidate.instruction) != 0)
        {
            return 1;
        }
    }
    return 0;
}
} // namespace

int simplify(mbl_array_t *mba, FunctionBudget &budget)
{
    qstring enabled;
    if (mba == nullptr || (qgetenv("CHERNOBOG_MBA_SMT", &enabled) && enabled == "0"))
    {
        return 0;
    }
    if (has_volatile_inputs(mba->entry_ea))
    {
        // The CFG memory model represents ordinary sequential memory. A
        // declared volatile pointee cannot participate in those equalities;
        // independent pure scalars remain eligible in the final ctree pass.
        ++budget.totals.unsupported;
        return 0;
    }

    int total_changes = 0;
    while (budget.spent_ns / 1000000 < budget.limit_ms && !user_cancelled())
    {
        int changes = 0;
        if (mba->maturity == MMAT_LOCOPT && mba->qty > 3)
        {
            changes = simplify_once(mba, budget);
        }
        if (changes == 0 && budget.spent_ns / 1000000 < budget.limit_ms)
        {
            changes = simplify_local_trees(mba, budget);
        }
        if (changes == 0 && budget.spent_ns / 1000000 < budget.limit_ms)
        {
            changes = simplify_once(mba, budget);
        }
        if (changes == 0)
        {
            break;
        }
        total_changes += changes;
        // Each accepted rewrite requires a fresh analysis snapshot.
    }
    return total_changes;
}
} // namespace chernobog::mba_smt
