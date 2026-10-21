#include "mba_smt_memory.h"
#include "mba_smt_ctree.h"
#include "mba_smt_emission.hpp"
#include <allins.hpp>
#include <frame.hpp>

#include <chrono>
#include <map>
#include <set>
#include <stdexcept>

namespace chernobog::mba_smt
{
namespace
{
using Clock = std::chrono::steady_clock;
constexpr size_t max_slice_statements = 64;
constexpr size_t max_native_bytes = 16384;

bool safe_local(const lvar_t &local)
{
    return !local.tif.is_volatile() && !local.is_used_byref() && !local.is_overlapped_var() &&
           !local.is_shared() && !local.is_fake_var() && !local.is_noprop() && !local.in_asm();
}

cexpr_t local_reference(mba_t *owner, size_t index, const tinfo_t &type, ea_t ea)
{
    cexpr_t result;
    result.op = cot_var;
    result.v.mba = owner;
    result.v.idx = int(index);
    result.type = type;
    result.ea = ea;
    return result;
}

cexpr_t *rhs(cinsn_t &node)
{
    if (node.op == cit_return && node.creturn)
        return &node.creturn->expr;
    if (node.op == cit_expr && node.cexpr && node.cexpr->op == cot_asg && node.cexpr->x)
        return node.cexpr->y;
    return nullptr;
}

struct Read
{
    cexpr_t source;
    Term address;
    size_t local;
    Read(const cexpr_t &expression, Term address, size_t local)
        : source(expression), address(std::move(address)), local(local)
    {
    }
};
struct Item
{
    cinsn_t source, lifted, emitted;
    std::vector<Read> reads;
    size_t site = 0;
    Term original;
    std::shared_ptr<const CtreeEmissionProof> proof;
    Item(const cinsn_t &node) : source(node), lifted(node), emitted(node) {}
};

// Accepted instruction ranges have exactly the ctree's ordinary reads and no
// hidden memory write, control transfer or call. RMW and vector/paired accesses
// are refused. The source order is the native instruction order, not AST order.
bool read_instruction(ea_t ea, unsigned bytes)
{
    insn_t instruction;
    if (!decode_insn(&instruction, ea))
        return false;
    const bool ordinary =
        PH.id == PLFM_386
            ? instruction.itype == NN_mov || instruction.itype == NN_movsx ||
                  instruction.itype == NN_movsxd || instruction.itype == NN_movzx ||
                  instruction.itype == NN_add || instruction.itype == NN_sub ||
                  instruction.itype == NN_imul || instruction.itype == NN_and ||
                  instruction.itype == NN_or || instruction.itype == NN_xor ||
                  instruction.itype == NN_cmp || instruction.itype == NN_test
            : PH.id == PLFM_ARM && (instruction.itype == ARM_ldr || instruction.itype == ARM_ldur);
    if (!ordinary)
        return false;
    const uint32 features = instruction.get_canon_feature(PH);
    if (features & (CF_CALL | CF_JUMP | CF_STOP))
        return false;
    size_t count = 0;
    for (int i = 0; i < UA_MAXOP; ++i)
    {
        const auto &operand = instruction.ops[i];
        if (operand.type != o_mem && operand.type != o_phrase && operand.type != o_displ)
            continue;
        // CF_USE1..CF_USE8 and CF_CHG1..CF_CHG8 are contiguous SDK bit fields.
        if (!(features & (CF_USE1 << i)) || (features & (CF_CHG1 << i)) ||
            get_dtype_size(operand.dtype) != bytes)
            return false;
        ++count;
    }
    return count == 1;
}

class Slice
{
  public:
    Slice(cfunc_t &function, FunctionBudget &budget, const MemorySliceTestHooks *tests)
        : function_(function), budget_(budget), owner_(function.mba), tests_(tests),
          started_(now()), source_(function.body), source_locals_(*function.get_lvars()),
          locals_(source_locals_), snapshot_(budget.snapshot)
    {
        const uint64_t limit = uint64_t(budget.limit_ms) * 1000000;
        deadline_ = started_ +
                    std::chrono::nanoseconds(limit > budget.spent_ns ? limit - budget.spent_ns : 0);
    }
    ~Slice()
    {
        budget_.spent_ns += uint64_t(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now() - started_).count());
    }
    Clock::time_point now() const { return tests_ && tests_->now ? tests_->now() : Clock::now(); }
    bool cancelled() const
    {
        return user_cancelled() || (tests_ && tests_->cancelled && tests_->cancelled());
    }
    bool available() const { return now() < deadline_ && !cancelled(); }

    int run()
    {
        if (!build() || !available())
            return 0;
        int changes = 0;
        size_t original_cost = 0, emitted_cost = 0;
        std::unique_ptr<Analysis> final_analysis;
        std::shared_ptr<const CtreeEmissionProof> final_proof;
        for (auto &item : items_)
        {
            if (!available())
                return 0;
            cexpr_t *value = rhs(item.emitted);
            if (!value)
                continue;
            const size_t before = scalar_expression_cost(*value);
            original_cost += before;
            Options options;
            options.backend = budget_.backend;
            options.profile = budget_.profile;
            options.snapshot = snapshot_;
            options.snapshot_values = true;
            options.absolute_deadline = deadline_;
            options.budget_ms = unsigned(std::max<int64_t>(
                0, std::min<int64_t>(
                       budget_.profile == Profile::Deep ? 1000 : 500,
                       std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - now())
                           .count())));
            options.max_invariants = 0;
            options.cancelled = [&] { return cancelled(); };
            program_.targets = {{0, item.site}};
            auto analysis = std::make_unique<Analysis>(program_, options);
            const auto proposals = before ? analysis->run() : std::vector<Proposal>{};
            if (!proposals.empty())
            {
                const auto &proposal = proposals.front();
                cexpr_t replacement;
                const auto emitted_at = Clock::now();
                ScalarContext unused({});
                if (emit_scalar_expression(function_, unused, proposal.replacement, value->type,
                                           replacement, &leaves_))
                {
                    replacement.ea = value->ea;
                    replacement.exflags = value->exflags;
                    replacement.label_num = value->label_num;
                    const auto proof = CtreeEmissionProof::prove(
                        *analysis, *proposal.proof, replacement,
                        [&](const cexpr_t &actual)
                        {
                            return lift_scalar_expression(actual, bindings_, owner_,
                                                          [&] { return available(); });
                        });
                    analysis->record_emission(
                        uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() -
                                                                                      emitted_at)
                                     .count()));
                    if (proof && replacement.type == value->type &&
                        scalar_expression_cost(replacement) < before &&
                        analysis->eligible_for_commit(proof->core(), false, [&]
                                                      { return available() && source_matches(); }))
                    {
                        value->swap(replacement);
                        item.proof = proof;
                        program_.blocks[0].statements[item.site].value =
                            lift_scalar_expression(*value, bindings_, owner_);
                        ++changes;
                        final_proof = proof;
                    }
                }
            }
            emitted_cost += scalar_expression_cost(*value);
            accumulate_statistics(budget_.totals, analysis->statistics());
            if (item.proof)
                final_analysis = std::move(analysis);
        }
        if (!changes || emitted_cost >= original_cost || !final_analysis || !final_proof)
            return 0;
        cinsn_t staged;
        staged.op = cit_block;
        staged.ea = source_.ea;
        staged.label_num = source_.label_num;
        staged.cblock = new cblock_t;
        for (const auto &item : items_)
        {
            for (const auto &read : item.reads)
            {
                cinsn_t &statement = staged.new_insn(read.source.ea);
                statement.op = cit_expr;
                statement.cexpr =
                    new cexpr_t(cot_asg,
                                new cexpr_t(local_reference(
                                    owner_, read.local, locals_[read.local].tif, read.source.ea)),
                                new cexpr_t(read.source));
                statement.cexpr->type = locals_[read.local].tif;
                statement.cexpr->ea = read.source.ea;
            }
            staged.cblock->push_back(item.emitted);
        }
        if (tests_ && tests_->before_commit)
            tests_->before_commit(staged, locals_);
        if (!frame(staged) || !final_analysis->eligible_for_commit(
                                  final_proof->core(), false,
                                  [&] { return available() && source_matches() && frame(staged); }))
            return 0;
        // All allocation, re-lifting and proof work precedes this no-throw commit.
        function_.body.swap(staged);
        function_.get_lvars()->swap(locals_);
        ++budget_.snapshot.mutation_epoch;
        budget_.totals.applied += changes;
        for (const auto &item : items_)
            budget_.totals.cobra.applied += item.proof && item.proof->from_cobra();
        return changes;
    }

  private:
    Term pointer(const cexpr_t &node, unsigned depth = 0)
    {
        if (depth > 8 || !node.type.is_ptr() || node.type.get_pointed_object().is_volatile() ||
            node.type.is_volatile() || node.type.get_size() * 8 != program_.address_bits)
            return {};
        if (node.op == cot_var)
        {
            const int index = node.v.idx;
            if (node.v.mba != owner_ || index < 0 || size_t(index) >= source_locals_.size() ||
                !safe_local(source_locals_[index]) || assigned_.count(index))
                return {};
            return variable(index, program_.address_bits);
        }
        if (node.op == cot_cast && node.x)
            return pointer(*node.x, depth + 1);
        if ((node.op == cot_add || node.op == cot_sub) && node.x && node.y && node.y->op == cot_num)
        {
            const Term base = pointer(*node.x, depth + 1);
            const size_t scale = node.x->type.get_ptrarr_objsize();
            if (base && scale && scale <= 8)
                return expression(node.op == cot_add ? Op::Add : Op::Sub, base,
                                  constant(node.y->numval() * scale, program_.address_bits));
        }
        return {};
    }
    Term address(const cexpr_t &node)
    {
        if (node.op == cot_ptr && node.x)
            return pointer(*node.x);
        if (node.op == cot_idx && node.x && node.y && node.y->op == cot_num)
        {
            const Term base = pointer(*node.x);
            const size_t scale = node.x->type.get_ptrarr_objsize();
            if (base && scale && scale <= 8)
                return expression(Op::Add, base,
                                  constant(node.y->numval() * scale, program_.address_bits));
        }
        return {};
    }
    bool build()
    {
        if (!owner_ || source_.op != cit_block || !source_.cblock ||
            source_.cblock->size() > max_slice_statements || source_locals_.empty() ||
            source_locals_.size() >= limits::storage_regions || source_.label_num >= 0)
            return false;
        program_.address_bits = inf_is_64bit() ? 64 : 32;
        program_.big_endian = inf_is_be();
        for (size_t i = 0; i < source_locals_.size(); ++i)
        {
            const auto &local = source_locals_[i];
            const unsigned bits =
                local.tif.is_ptr() ? program_.address_bits : scalar_integer_bits(local.tif);
            if (!bits || !safe_local(local))
                return false;
            program_.widths.push_back(bits);
            if (!local.tif.is_ptr())
            {
                const Term term = variable(i, bits);
                bindings_[int(i)] = term;
                leaves_.emplace_back(term,
                                     local_reference(owner_, i, local.tif, function_.entry_ea));
                program_.available.push_back(term);
            }
        }
        for (const auto &statement : *source_.cblock)
        {
            if (statement.label_num >= 0)
                return false;
            if (statement.op == cit_expr && statement.cexpr && statement.cexpr->op == cot_asg &&
                statement.cexpr->x && statement.cexpr->x->op == cot_var)
                assigned_.insert(statement.cexpr->x->v.idx);
            else if (statement.op != cit_return && statement.op != cit_empty &&
                     !(statement.op == cit_expr && statement.cexpr &&
                       statement.cexpr->op == cot_asg))
                return false;
        }
        func_t *native = get_func(function_.entry_ea);
        if (!native || native->start_ea != function_.entry_ea || (native->flags & FUNC_TAIL) ||
            native->end_ea <= native->start_ea ||
            native->end_ea - native->start_ea > max_native_bytes)
            return false;
        // Refuse tail chunks: a single ordered native range is required.
        if (get_func_tail_qty(native->start_ea) != 0)
            return false;
        native_start_ = native->start_ea;
        native_bytes_.resize(size_t(native->end_ea - native->start_ea));
        if (get_bytes(native_bytes_.data(), native_bytes_.size(), native_start_) !=
            ssize_t(native_bytes_.size()))
            return false;
        program_.blocks.resize(1);
        bool saw_return = false;
        size_t read_count = 0;
        ea_t previous_effect = BADADDR;
        for (const auto &statement : *source_.cblock)
        {
            if (saw_return || !available())
                return false;
            items_.emplace_back(statement);
            auto &item = items_.back();
            cexpr_t *value = rhs(item.emitted);
            if (!value)
            {
                if (statement.op != cit_empty)
                    return false;
                continue;
            }
            if (statement.op == cit_return)
                saw_return = true;
            struct Reads : ctree_visitor_t
            {
                std::vector<cexpr_t *> nodes;
                size_t visits = 0;
                Reads() : ctree_visitor_t(CV_PARENTS) {}
                int idaapi visit_expr(cexpr_t *node) override
                {
                    if (++visits > limits::expression_visits || parents.size() > 64)
                        return 1;
                    if (node->op == cot_ptr || node->op == cot_idx)
                        nodes.push_back(node);
                    return 0;
                }
            } reads;
            if (reads.apply_to(value, nullptr))
                return false;
            std::sort(reads.nodes.begin(), reads.nodes.end(),
                      [](const cexpr_t *a, const cexpr_t *b) { return a->ea < b->ea; });
            for (cexpr_t *node : reads.nodes)
            {
                const unsigned bits = scalar_integer_bits(node->type);
                const Term location = address(*node);
                if (!bits || !location || node->ea < native_start_ ||
                    node->ea >= native_start_ + native_bytes_.size() ||
                    (previous_effect != BADADDR && node->ea <= previous_effect) ||
                    !read_instruction(node->ea, bits / 8) ||
                    locals_.size() >= limits::storage_regions ||
                    program_.widths.size() >= limits::storage_regions)
                    return false;
                previous_effect = node->ea;
                const size_t index = locals_.size();
                const size_t core_index = program_.widths.size();
                lvar_t local;
                size_t name_index = read_count++;
                bool unique;
                do
                {
                    local.name.sprnt("mba_load%zu", name_index++);
                    unique = std::none_of(locals_.begin(), locals_.end(), [&](const lvar_t &entry)
                                          { return entry.name == local.name; });
                } while (!unique);
                local.tif = node->type;
                local.width = bits / 8;
                local.defea = node->ea;
                local.defblk = -1;
                local.set_fake_var();
                local.set_mreg_done();
                locals_.push_back(local);
                program_.widths.push_back(bits);
                item.reads.emplace_back(*node, location, index);
                program_.blocks[0].statements.push_back(
                    Statement::assign(core_index, load(location, bits)));
                const Term term = variable(core_index, bits);
                bindings_[int(index)] = term;
                leaves_.emplace_back(term, local_reference(owner_, index, local.tif, node->ea));
                program_.available.push_back(term);
                cexpr_t reference = local_reference(owner_, index, local.tif, node->ea);
                node->swap(reference);
            }
            item.lifted = item.emitted;
            item.original =
                lift_scalar_expression(*value, bindings_, owner_, [&] { return available(); });
            if (!item.original)
                return false;
            item.site = program_.blocks[0].statements.size();
            if (statement.op == cit_expr && statement.cexpr->x->op == cot_var)
            {
                const int index = statement.cexpr->x->v.idx;
                if (index < 0 || !bindings_.count(index) || statement.cexpr->x->v.mba != owner_)
                    return false;
                const Term assigned =
                    convert_scalar_integer(item.original, value->type, statement.cexpr->x->type);
                if (!assigned || assigned->bits != item.original->bits)
                    return false;
                program_.blocks[0].statements.push_back(Statement::assign(index, item.original));
            }
            else
            {
                if (program_.widths.size() >= limits::storage_regions)
                    return false;
                const size_t temporary = program_.widths.size();
                program_.widths.push_back(item.original->bits);
                program_.blocks[0].statements.push_back(
                    Statement::assign(temporary, item.original));
                if (statement.op == cit_expr)
                {
                    const cexpr_t &target = *statement.cexpr->x;
                    const Term location = address(target);
                    if (!location || !scalar_integer_bits(target.type) ||
                        target.type.get_size() != value->type.get_size() || target.ea == BADADDR ||
                        (previous_effect != BADADDR && target.ea <= previous_effect))
                        return false;
                    previous_effect = target.ea;
                    program_.blocks[0].statements.push_back(
                        Statement::store(location, variable(temporary, item.original->bits)));
                }
            }
        }
        expected_locals_ = locals_;
        return saw_return && read_count && validate(program_) && validate_ranges();
    }
    bool validate_ranges() const
    {
        // Decode every native access between the first and last modeled access.
        // Stack spills are also refused unless explicitly represented in ctree.
        std::map<ea_t, unsigned> accesses;
        std::set<ea_t> stores;
        for (const auto &item : items_)
        {
            for (const auto &read : item.reads)
                accesses.emplace(read.source.ea, unsigned(read.source.type.get_size()));
            if (item.source.op == cit_expr && item.source.cexpr->x->op != cot_var)
            {
                stores.insert(item.source.cexpr->x->ea);
                accesses.emplace(item.source.cexpr->x->ea,
                                 unsigned(item.source.cexpr->x->type.get_size()));
            }
        }
        if (accesses.empty())
            return false;
        const ea_t last = accesses.rbegin()->first;
        std::set<ea_t> observed;
        std::map<sval_t, unsigned> argument_spills;
        std::set<mreg_t> overwritten;
        for (ea_t ea = native_start_; ea <= last;)
        {
            insn_t instruction;
            if (!available() || !decode_insn(&instruction, ea))
                return false;
            const uint32 features = instruction.get_canon_feature(PH);
            if (features & (CF_CALL | CF_JUMP | CF_STOP))
                return false;
            const bool address_only = PH.id == PLFM_386 && instruction.itype == NN_lea;
            for (int i = 0; i < UA_MAXOP; ++i)
            {
                const auto &operand = instruction.ops[i];
                if (address_only ||
                    (operand.type != o_mem && operand.type != o_phrase && operand.type != o_displ))
                    continue;
                // Address calculation has no memory effect (e.g. x86 LEA).
                if (!(features & ((CF_USE1 | CF_CHG1) << i)))
                    continue;
                const auto expected = accesses.find(ea);
                if (expected == accesses.end())
                {
                    if (private_frame_access(instruction, i))
                        continue;
                    if ((PH.id == PLFM_386 || PH.id == PLFM_ARM) && is_stkvar(get_flags(ea), i))
                    {
                        const sval_t offset = calc_frame_offset_ea(
                            function_.entry_ea, sval_t(operand.addr), &instruction, &operand);
                        const unsigned bytes = get_dtype_size(operand.dtype);
                        const bool write = (features & (CF_CHG1 << i)) != 0;
                        // A canonical register argument may have a compiler
                        // spill which IDA has already eliminated from ctree.
                        // Recognize only its initial direct store, before any
                        // modeled access or overwrite of the incoming register.
                        bool initialized_spill = false;
                        const int source_operand =
                            PH.id == PLFM_386 && instruction.itype == NN_mov && i == 0 ? 1
                            : PH.id == PLFM_ARM &&
                                    (instruction.itype == ARM_str ||
                                     instruction.itype == ARM_stur) &&
                                    i == 1
                                ? 0
                                : -1;
                        if (ea < accesses.begin()->first && source_operand >= 0 && write &&
                            instruction.ops[source_operand].type == o_reg &&
                            !overwritten.count(reg2mreg(instruction.ops[source_operand].reg)))
                            for (const auto &local : source_locals_)
                                if (local.is_arg_var() && safe_local(local) &&
                                    local.location.is_reg1() &&
                                    local.location.reg1() ==
                                        reg2mreg(instruction.ops[source_operand].reg) &&
                                    local.width == int(bytes))
                                    initialized_spill =
                                        argument_spills.emplace(offset, bytes).second;
                        const auto spill = argument_spills.find(offset);
                        if (spill != argument_spills.end() && spill->second == bytes &&
                            ((!write && (features & (CF_USE1 << i))) || initialized_spill))
                            continue;
                    }
                }
                const bool store = stores.count(ea) != 0;
                if (expected == accesses.end() ||
                    get_dtype_size(operand.dtype) != expected->second ||
                    bool(features & (CF_CHG1 << i)) != store ||
                    (store && (features & (CF_USE1 << i))) || !observed.insert(ea).second)
                    return false;
            }
            for (int i = 0; i < UA_MAXOP; ++i)
                if (instruction.ops[i].type == o_reg && (features & (CF_CHG1 << i)))
                    overwritten.insert(reg2mreg(instruction.ops[i].reg));
            ea += instruction.size;
        }
        return observed.size() == accesses.size();
    }
    bool private_frame_access(const insn_t &instruction, int operand) const
    {
        // IDA's nonescaping scalar locals represent private, accessible frame
        // storage. No arbitrary stack-relative operand receives this exemption.
        if (!is_stkvar(get_flags(instruction.ea), operand))
            return false;
        const auto &access = instruction.ops[operand];
        const sval_t frame =
            calc_frame_offset_ea(function_.entry_ea, sval_t(access.addr), &instruction, &access);
        const sval_t offset = owner_->stkoff_ida2vd(frame);
        for (const auto &local : source_locals_)
            if (safe_local(local) && local.location.is_stkoff() &&
                local.location.stkoff() == offset &&
                local.width == int(get_dtype_size(access.dtype)))
                return true;
        // IDA may eliminate a scalar spill's ctree local entirely. Its exact
        // typed frame member still has to be wholly inside the private local
        // area. The admitted complete body cannot take/escape a frame address.
        range_t private_area;
        tinfo_t frame_type;
        udm_t member;
        const unsigned bytes = get_dtype_size(access.dtype);
        return frame >= 0 && get_frame_part_ea(&private_area, function_.entry_ea, FPC_LVARS) &&
               private_area.contains(ea_t(frame)) && bytes <= private_area.end_ea - ea_t(frame) &&
               get_func_frame_ea(&frame_type, function_.entry_ea) &&
               frame_type.get_udm_by_offset(&member, uint64_t(frame) * 8) >= 0 &&
               member.offset == uint64_t(frame) * 8 && member.size == uint64_t(bytes) * 8 &&
               !member.type.is_volatile() && (member.type.is_integral() || member.type.is_ptr());
    }
    bool source_matches() const
    {
        if (function_.mba != owner_ || budget_.snapshot != snapshot_ ||
            !same_ctree_locals(source_locals_, *function_.get_lvars()) ||
            !same_ctree_body(source_, function_.body))
            return false;
        std::vector<unsigned char> current(native_bytes_.size());
        return get_bytes(current.data(), current.size(), native_start_) ==
                   ssize_t(current.size()) &&
               current == native_bytes_;
    }
    bool frame(cinsn_t &staged) const
    {
        if (staged.op != cit_block || !staged.cblock || staged.ea != source_.ea ||
            staged.label_num != source_.label_num || !same_ctree_locals(locals_, expected_locals_))
            return false;
        size_t expected_size = 0;
        for (const auto &item : items_)
            expected_size += item.reads.size() + 1;
        if (staged.cblock->size() != expected_size)
            return false;
        auto current = staged.cblock->begin();
        for (const auto &item : items_)
        {
            for (const auto &read : item.reads)
            {
                const cinsn_t &statement = *current++;
                cinsn_t expected;
                expected.op = cit_expr;
                expected.ea = read.source.ea;
                expected.cexpr =
                    new cexpr_t(cot_asg,
                                new cexpr_t(local_reference(owner_, read.local, read.source.type,
                                                            read.source.ea)),
                                new cexpr_t(read.source));
                expected.cexpr->type = read.source.type;
                expected.cexpr->ea = read.source.ea;
                if (!same_ctree_body(statement, expected))
                    return false;
            }
            const cinsn_t &statement = *current++;
            // Reconstruct the sole authorized RHS substitution in the original
            // frame; this independently checks all targets, reads and metadata.
            cinsn_t expected(item.lifted);
            cexpr_t *value = rhs(expected);
            if (value)
            {
                if (item.proof)
                {
                    cexpr_t proved(item.proof->emitted_snapshot());
                    value->swap(proved);
                }
            }
            if (!same_ctree_body(expected, statement))
                return false;
        }
        return current == staged.cblock->end();
    }

    cfunc_t &function_;
    FunctionBudget &budget_;
    mba_t *owner_;
    const MemorySliceTestHooks *tests_;
    Clock::time_point started_, deadline_;
    cinsn_t source_;
    lvars_t source_locals_, locals_, expected_locals_;
    SnapshotToken snapshot_;
    ea_t native_start_ = BADADDR;
    std::vector<unsigned char> native_bytes_;
    Program program_;
    ScalarContext::Bindings bindings_;
    ScalarLeaves leaves_;
    std::set<int> assigned_;
    std::vector<Item> items_;
};
}
int simplify_memory_values(cfunc_t &function, FunctionBudget &budget,
                           const MemorySliceTestHooks *tests)
{
    try
    {
        if (!function.mba || !function.get_lvars() ||
            function.get_lvars()->size() >= limits::storage_regions ||
            function.body.op != cit_block || !function.body.cblock ||
            function.body.cblock->size() > max_slice_statements)
            return 0;
        struct Bound : ctree_visitor_t
        {
            size_t visits = 0, reads = 0;
            Bound() : ctree_visitor_t(CV_PARENTS) {}
            int idaapi visit_expr(cexpr_t *node) override
            {
                reads += node->op == cot_ptr || node->op == cot_idx;
                return ++visits > 4096 || parents.size() > 64;
            }
            int idaapi visit_insn(cinsn_t *) override
            {
                return ++visits > 4096 || parents.size() > 64;
            }
        } bound;
        if (bound.apply_to(&function.body, nullptr) || !bound.reads)
            return 0;
        return Slice(function, budget, tests).run();
    }
    catch (...)
    {
        // The staged body and locals own all allocations until the final swap.
        return 0;
    }
}
}
