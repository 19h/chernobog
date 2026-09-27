#include <fstream>

#include "deobf/rules/rule_registry.h"
#include "deobf/rules/rule_verifier.h"
#include "deobf/rules/rules_sub.h"
#include "deobf/analysis/ast_builder.h"
#include "deobf/analysis/match_capture.h"
#include "common/bitvector.h"
#include <iomanip>
#include <cstdarg>
#include <cstdlib>
#include <iostream>
#include <map>
#include <stdexcept>
#include <tuple>

namespace
{

using chernobog::ast::AstPtr;
using chernobog::ast::MatchBindings;
using chernobog::ast::make_leaf;
using chernobog::ast::make_node;
using chernobog::ast::match_pattern;

std::size_t empty_operand_erases = 0;
std::size_t operand_copies = 0;

} // namespace

// catalog_hexdsp.h redirects every test translation unit to this entry point.
// Keep its C linkage and validate the actual calls from the SDK inline code.
extern "C" void *chernobog_catalog_hexdsp(int code, ...)
{
    if (code == hx_minsn_t_init)
    {
        va_list arguments;
        va_start(arguments, code);
        minsn_t *instruction = va_arg(arguments, minsn_t *);
        const ea_t ea = va_arg(arguments, ea_t);
        va_end(arguments);
        instruction->opcode = m_nop;
        instruction->iprops = 0;
        instruction->ea = ea;
        instruction->next = instruction->prev = nullptr;
        instruction->l.zero();
        instruction->r.zero();
        instruction->d.zero();
        return nullptr;
    }
    // Copy only allocation-free SDK operands. Recursive payload copies remain
    // real-runtime operations and are never emulated by these component tests.
    if (code == hx_mop_t_copy || code == hx_mop_t_assign)
    {
        va_list arguments;
        va_start(arguments, code);
        auto *destination = va_arg(arguments, mop_t *);
        const auto *source = va_arg(arguments, const mop_t *);
        va_end(arguments);
        if (!destination || !source ||
            (source->t != mop_z && source->t != mop_r && source->t != mop_v))
            std::abort();
        if (code == hx_mop_t_assign && destination->t != mop_z && destination->t != mop_r &&
            destination->t != mop_v)
            std::abort();
        if (destination == source)
            return destination;
        destination->zero();
        destination->t = source->t;
        destination->size = source->size;
        destination->oprops = source->oprops;
        destination->valnum = source->valnum;
        if (source->t == mop_r)
            destination->r = source->r;
        else if (source->t == mop_v)
            destination->g = source->g;
        ++operand_copies;
        return destination;
    }
    // The SDK's link stub is not an initialized Hex-Rays runtime. Fail on any
    // operation that would require real decompiler behavior.
    if (code != hx_mop_t_erase)
    {
        std::cerr << "unsupported catalog SDK operation: " << code << '\n';
        std::abort();
    }
    va_list arguments;
    va_start(arguments, code);
    mop_t *operand = va_arg(arguments, mop_t *);
    va_end(arguments);
    if (operand == nullptr || (operand->t != mop_z && operand->t != mop_r && operand->t != mop_v))
    {
        std::cerr << "catalog SDK erase requires a nonnull allocation-free operand\n";
        std::abort();
    }
    operand->zero();
    ++empty_operand_erases;
    return nullptr;
}

namespace
{

// These value-only fixtures borrow nested instructions/constants. Their
// destructor clears the non-owning pointers before SDK operand destruction.
struct ValueInsn : minsn_t
{
    explicit ValueInsn(mcode_t operation, int bytes) : minsn_t(BADADDR)
    {
        opcode = operation;
        d.size = bytes;
    }
    ~ValueInsn()
    {
        l.zero();
        r.zero();
        d.zero();
    }
};
void reg(mop_t &operand, int id, int bytes)
{
    operand.t = mop_r;
    operand.r = id;
    operand.size = bytes;
}
void nested(mop_t &operand, minsn_t &instruction)
{
    operand.t = mop_d;
    operand.d = &instruction;
    operand.size = instruction.d.size;
}
void constant(mop_t &operand, mnumber_t &number, int bytes)
{
    operand.t = mop_n;
    operand.nnn = &number;
    operand.size = bytes;
}

template <class T> struct BorrowedVector
{
    qvector<T> &value;
    T *data;
    BorrowedVector(qvector<T> &vector, T *storage, size_t size) : value(vector), data(storage)
    {
        value.inject(data, size);
    }
    ~BorrowedVector() { value.extract(); }
    void resize(size_t size)
    {
        value.extract();
        value.inject(data, size);
    }
};

bool test_builder_value_identity()
{
    using chernobog::ast::AstBuilderContext;
    using chernobog::ast::MopKey;
    size_t checks = 0, failures = 0;
    bool okay = true;
    const auto check = [&](bool condition)
    {
        ++checks;
        failures += !condition;
        okay &= condition;
    };
    const auto separate = [&](const MopKey &first, const MopKey &second)
    {
        check(!(first == second));
        AstBuilderContext context;
        const auto a = make_leaf("first"), b = make_leaf("second");
        context.add(first, a);
        context.add(second, b);
        check(context.get(first) == a && context.get(second) == b);
        // Equality and ordering must inspect metadata even on a hash collision.
        auto collision = second;
        collision.hash = first.hash;
        check(!(first == collision));
        check((first < collision) != (collision < first));
        AstBuilderContext colliding;
        colliding.add(first, a);
        colliding.add(collision, b);
        check(colliding.get(first) == a && colliding.get(collision) == b);
    };
    // Borrow SDK descriptors without owning or dereferencing the dummy frames.
    const auto frame1 = reinterpret_cast<mba_t *>(uintptr_t{0x1000});
    const auto frame2 = reinterpret_cast<mba_t *>(uintptr_t{0x2000});
    for (int bytes : {1, 2, 4, 8})
        for (mopt_t type : {mop_r, mop_v, mop_S, mop_l})
        {
            ValueInsn fixture(m_mov, bytes), reference(m_mov, bytes);
            stkvar_ref_t stack1(frame1, 24), stack2(frame2, 24);
            lvar_ref_t local1(frame1, 3, 8), local2(frame2, 3, 8);
            auto &operand = fixture.l;
            operand.t = type;
            operand.size = bytes;
            if (type == mop_r)
                operand.r = 100;
            else if (type == mop_v)
                operand.g = 0x3000;
            else if (type == mop_S)
                operand.s = &stack1;
            else
                operand.l = &local1;
            reference.l.t = type;
            reference.l.size = bytes;
            if (type == mop_r)
                reference.l.r = operand.r;
            else if (type == mop_v)
                reference.l.g = operand.g;
            else if (type == mop_S)
                reference.l.s = &stack1;
            else
                reference.l.l = &local1;
            const auto base = MopKey::from_mop(operand);
            check(base == MopKey::from_mop(operand));
            check(chernobog::ast::mops_equal_strict(reference.l, operand));
            for (unsigned number : {1u, 65535u})
            {
                operand.valnum = number;
                separate(base, MopKey::from_mop(operand));
                check(!chernobog::ast::mops_equal_strict(reference.l, operand));
            }
            operand.valnum = 0;
            for (unsigned property : {1u, 2u, 4u, 8u, 16u, 32u, 64u, 128u, 255u})
            {
                operand.oprops = property;
                separate(base, MopKey::from_mop(operand));
                check(!chernobog::ast::mops_equal_strict(reference.l, operand));
            }
            operand.oprops = 0;
            if (type == mop_S || type == mop_l)
            {
                if (type == mop_S)
                    operand.s = &stack2;
                else
                    operand.l = &local2;
                separate(base, MopKey::from_mop(operand));
                check(!chernobog::ast::mops_equal_strict(reference.l, operand));
            }
            operand.size = bytes + 65536;
            separate(base, MopKey::from_mop(operand));
            check(!chernobog::ast::mops_equal_strict(reference.l, operand));
        }
    if (!okay)
    {
        std::cerr << "AST leaf value identity: " << checks << " checks; failures=" << failures
                  << "; key bytes=" << sizeof(MopKey) << '\n';
        return false;
    }
    ValueInsn first(m_add, 4), second(m_add, 4);
    reg(first.l, 100, 4);
    reg(first.r, 200, 4);
    reg(second.l, 100, 4);
    reg(second.r, 200, 4);
    const auto initial = MopKey::hash_insn(&first);
    check(initial == MopKey::hash_insn(&second));
    second.l.valnum = 1;
    check(initial != MopKey::hash_insn(&second));
    second.l.valnum = 0;
    second.r.oprops = OPROP_ABI;
    check(initial != MopKey::hash_insn(&second));
    second.r.oprops = 0;
    second.d.valnum = 1;
    check(initial != MopKey::hash_insn(&second));
    second.d.valnum = 0;
    second.d.oprops = OPROP_UDEFVAL;
    check(initial != MopKey::hash_insn(&second));
    second.d.oprops = 0;
    second.iprops = IPROP_MBARRIER;
    check(initial != MopKey::hash_insn(&second));
    second.iprops = 0;
    ValueInsn left(m_mov, 4), right(m_mov, 4);
    nested(left.l, first);
    nested(right.l, second);
    check(chernobog::ast::mops_equal_strict(left.l, right.l));
    second.r.valnum = 2;
    check(!chernobog::ast::mops_equal_strict(left.l, right.l));
    second.r.valnum = 0;
    second.l.oprops = OPROP_UDEFVAL;
    check(!chernobog::ast::mops_equal_strict(left.l, right.l));
    second.l.oprops = 0;
    second.iprops = IPROP_MBARRIER;
    check(!chernobog::ast::mops_equal_strict(left.l, right.l));
    second.iprops = 0;
    first.opcode = second.opcode = m_ldx;
    first.ea = 0x4000;
    second.ea = 0x4001;
    check(!chernobog::ast::mops_equal_strict(left.l, right.l));
    second.ea = first.ea;
    check(chernobog::ast::mops_equal_strict(left.l, right.l));
    first.opcode = second.opcode = m_mov;
    nested(first.l, first);
    nested(second.l, second);
    check(!chernobog::ast::mops_equal_strict(left.l, right.l));
    // The holder uses the C++ allocator; minsn_t's class allocator needs IDA.
    struct OwnedValue
    {
        ValueInsn instruction;
        explicit OwnedValue(mcode_t opcode) : instruction(opcode, 4) {}
    };
    const auto balanced = [](unsigned depth, std::vector<std::unique_ptr<OwnedValue>> &nodes,
                             const auto &self) -> ValueInsn &
    {
        auto node = std::make_unique<OwnedValue>(depth ? m_add : m_mov);
        auto &result = node->instruction;
        if (depth)
        {
            nested(result.l, self(depth - 1, nodes, self));
            nested(result.r, self(depth - 1, nodes, self));
        }
        else
            reg(result.l, 100, 4);
        nodes.push_back(std::move(node));
        return result;
    };
    for (unsigned depth : {5u, 7u})
    {
        std::vector<std::unique_ptr<OwnedValue>> a, b;
        nested(left.l, balanced(depth, a, balanced));
        nested(right.l, balanced(depth, b, balanced));
        check(chernobog::ast::mops_equal_strict(left.l, right.l) == (depth == 5));
        left.l.zero();
        right.l.zero();
    }
    std::cout << "AST value identity: " << checks << " checks; key bytes=" << sizeof(MopKey)
              << "; failures=" << failures << "; passed=" << okay << '\n';
    return okay;
}

#ifndef CHERNOBOG_LEGACY_AST_BOUNDS
bool test_builder_bounds()
{
    using namespace chernobog::ast;
    size_t checks = 0;
    const auto check = [&](bool condition)
    {
        ++checks;
        if (!condition)
            throw std::runtime_error("AST construction bound control " + std::to_string(checks));
    };
    AstBuildReport report;
    ValueInsn cycle(m_add, 4);
    nested(cycle.l, cycle);
    check(!validate_ast_structure(&cycle, &report) && report.status == AstBuildStatus::Cycle);
    const auto rejected = MopKey::from_mop(cycle.l, &report);
    check(!rejected.complete && report.status == AstBuildStatus::Cycle);
    AstBuilderContext context;
    context.add(rejected, make_leaf("rejected"));
    check(!context.has(rejected) && !context.get(rejected));
    check(MopKey::hash_insn(&cycle, &report) == 0 && report.status == AstBuildStatus::Cycle);
    const auto copies_before_rejection = operand_copies;
    check(!minsn_to_ast(&cycle, &report) && report.status == AstBuildStatus::Cycle);
    check(operand_copies == copies_before_rejection);
    ValueInsn ordinary(m_add, 4);
    reg(ordinary.l, 100, 4);
    reg(ordinary.r, 200, 4);
    reg(ordinary.d, 300, 4);
    auto converted = minsn_to_ast(&ordinary, &report);
    check(converted && report.status == AstBuildStatus::Complete &&
          std::static_pointer_cast<AstNode>(converted)->left->mop.r == 100 &&
          std::static_pointer_cast<AstNode>(converted)->right->mop.r == 200 &&
          converted->dest_size == 4 && operand_copies > copies_before_rejection);

    struct OwnedInstruction
    {
        ValueInsn instruction{m_add, 4};
    };
    struct AddressOperand : mop_addr_t
    {
        ~AddressOperand() { zero(); }
    };
    struct OwnedAddress
    {
        AddressOperand operand;
    };
    std::vector<std::unique_ptr<OwnedInstruction>> chain;
    for (unsigned i = 0; i < 66; ++i)
        chain.push_back(std::make_unique<OwnedInstruction>());
    for (unsigned i = 0; i + 1 < chain.size(); ++i)
        nested(chain[i]->instruction.l, chain[i + 1]->instruction);
    reg(chain.back()->instruction.l, 100, 4);
    check(!validate_ast_structure(&chain[0]->instruction, &report) &&
          report.status == AstBuildStatus::DepthLimit && report.maximum_depth == 65);
    check(validate_ast_structure(&chain[1]->instruction, &report) && report.maximum_depth == 64 &&
          report.instructions == 65);
    check(MopKey::hash_insn(&chain[1]->instruction, &report) != 0 &&
          report.status == AstBuildStatus::Complete);
    check(!minsn_to_ast(&chain[0]->instruction, &report) &&
          report.status == AstBuildStatus::DepthLimit);

    std::vector<std::unique_ptr<OwnedInstruction>> tree;
    std::vector<ValueInsn *> leaves;
    const auto balanced = [&](unsigned depth, const auto &self) -> ValueInsn &
    {
        auto node = std::make_unique<OwnedInstruction>();
        auto &ins = node->instruction;
        reg(ins.d, 300, 4);
        if (depth)
        {
            nested(ins.l, self(depth - 1, self));
            nested(ins.r, self(depth - 1, self));
        }
        else
        {
            reg(ins.l, 100, 4);
            reg(ins.r, 200, 4);
            leaves.push_back(&ins);
        }
        tree.push_back(std::move(node));
        return ins;
    };
    auto &root = balanced(7, balanced);
    check(validate_ast_structure(&root, &report) && report.visits == 1020 &&
          report.instructions == 255);
    std::vector<std::unique_ptr<OwnedAddress>> addresses;
    for (unsigned i = 0; i < 5; ++i)
    {
        auto address = std::make_unique<OwnedAddress>();
        reg(address->operand, 100, 4);
        leaves[i]->l.t = mop_a;
        leaves[i]->l.a = &address->operand;
        addresses.push_back(std::move(address));
        const bool okay = validate_ast_structure(&root, &report);
        check(okay == (i < 4));
        check(report.visits == std::min<size_t>(1024, 1021 + i));
        check(report.status == (i < 4 ? AstBuildStatus::Complete : AstBuildStatus::VisitLimit));
    }
    check(!minsn_to_ast(&root, &report) && report.status == AstBuildStatus::VisitLimit);
    // A repeated child is acyclic but its expansion still consumes visits.
    ValueInsn shared(m_add, 4);
    nested(shared.l, chain[1]->instruction);
    nested(shared.r, chain[1]->instruction);
    check(!validate_ast_structure(&shared, &report) && report.status == AstBuildStatus::DepthLimit);
    nested(shared.l, chain[2]->instruction);
    nested(shared.r, chain[2]->instruction);
    check(validate_ast_structure(&shared, &report) && report.instructions == 129);

    ValueInsn text(m_add, 4);
    std::string label(4095, 'a');
    text.l.t = mop_h;
    text.l.helper = label.data();
    check(validate_ast_structure(&text, &report) && report.text_bytes == 4096);
    label.push_back('a');
    text.l.helper = label.data();
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::TextLimit);
    check(!minsn_to_ast(&text, &report) && report.status == AstBuildStatus::TextLimit);
    text.l.zero();
    label.resize(4095);
    for (unsigned i = 0; i < 5; ++i)
        reg(leaves[i]->l, 100, 4);
    for (unsigned i = 0; i < 17; ++i)
    {
        leaves[i]->l.t = mop_h;
        leaves[i]->l.helper = label.data();
        const bool okay = validate_ast_structure(&root, &report);
        check(okay == (i < 16));
        check(report.text_bytes == std::min<size_t>(65536, (i + 1) * 4096));
        check(report.status == (i < 16 ? AstBuildStatus::Complete : AstBuildStatus::TextLimit));
    }
    AddressOperand address_cycle;
    address_cycle.t = mop_a;
    address_cycle.a = &address_cycle;
    text.l.t = mop_a;
    text.l.a = &address_cycle;
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::Cycle);
    text.l.zero();
    for (mopt_t type :
         {mop_n, mop_S, mop_l, mop_a, mop_h, mop_str, mop_f, mop_c, mop_fn, mop_p, mop_sc})
    {
        text.l.t = type;
        text.l.d = nullptr;
        check(!validate_ast_structure(&text, &report) &&
              report.status == AstBuildStatus::MalformedOperand);
        text.l.zero();
    }
    for (mopt_t type : {mopt_t{16}, mopt_t{127}, mopt_t{255}})
    {
        text.l.t = type;
        check(!validate_ast_structure(&text, &report) &&
              report.status == AstBuildStatus::UnsupportedOperand);
        text.l.zero();
    }
    check(!validate_ast_structure(nullptr, &report) &&
          report.status == AstBuildStatus::NullInstruction);
    // Recursive SDK containers remain admissible when their payloads fit.
    mcallinfo_t call;
    std::array<mcallarg_t, 1024> arguments;
    BorrowedVector<mcallarg_t> argument_storage(call.args, arguments.data(), 1);
    reg(call.args[0], 100, 4);
    text.l.t = mop_f;
    text.l.f = &call;
    check(validate_ast_structure(&text, &report));
    call.args[0].t = mop_f;
    call.args[0].f = &call;
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::Cycle);
    call.args[0].zero();
    argument_storage.resize(1024);
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::VisitLimit);
    text.l.zero();
    mop_pair_t pair;
    reg(pair.lop, 100, 4);
    reg(pair.hop, 200, 4);
    text.l.t = mop_p;
    text.l.pair = &pair;
    check(validate_ast_structure(&text, &report));
    pair.hop.t = mop_p;
    pair.hop.pair = &pair;
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::Cycle);
    pair.hop.zero();
    text.l.zero();
    mcases_t cases;
    std::array<svalvec_t, 1> groups;
    std::array<int, 1> targets{};
    std::array<sval_t, 1024> values{};
    BorrowedVector<svalvec_t> case_storage(cases.values, groups.data(), 1);
    BorrowedVector<int> target_storage(cases.targets, targets.data(), 1);
    BorrowedVector<sval_t> group_storage(groups[0], values.data(), 0);
    text.l.t = mop_c;
    text.l.c = &cases;
    check(validate_ast_structure(&text, &report));
    group_storage.resize(1024);
    check(!validate_ast_structure(&text, &report) && report.status == AstBuildStatus::VisitLimit);
    text.l.zero();
    fnumber_t number{};
    text.l.t = mop_fn;
    text.l.fpc = &number;
    check(validate_ast_structure(&text, &report));
    text.l.zero();
    std::cout << "AST construction bounds: " << checks << " checks passed\n";
    return true;
}
#endif

bool test_typed_instances()
{
    using namespace chernobog::rules;
    reset_instance_verification_stats();
    std::vector<RuleVerificationResult> observations;
    RuleVerifier verifier;
    const auto expect =
        [&](minsn_t &before, minsn_t &after, RuleVerificationStatus status, const char *label)
    {
        const auto result = verifier.verify_instance(&before, &after);
        observations.push_back(result);
        if (result.status == status)
            return true;
        std::cerr << label << ": " << rule_verification_status_name(result.status) << " "
                  << result.detail << '\n';
        return false;
    };
    bool okay = true;
    for (int bytes : {1, 2, 4, 8})
    {
        ValueInsn both(m_and, bytes), either(m_or, bytes), sum(m_add, bytes), direct(m_add, bytes);
        reg(both.l, 100, bytes);
        reg(both.r, 200, bytes);
        reg(either.l, 100, bytes);
        reg(either.r, 200, bytes);
        nested(sum.l, both);
        nested(sum.r, either);
        reg(direct.l, 100, bytes);
        reg(direct.r, 200, bytes);
        okay &= expect(sum, direct, RuleVerificationStatus::VERIFIED, "typed carry identity");
        if (bytes == 4)
        {
            RuleVerifier exhausted(10'000, 1);
            const auto limited = exhausted.verify_instance(&sum, &direct);
            observations.push_back(limited);
            if (limited.status != RuleVerificationStatus::UNKNOWN || limited.verified())
            {
                std::cerr << "typed resource exhaustion must remain unverified UNKNOWN\n";
                okay = false;
            }
        }
        direct.opcode = m_xor;
        okay &= expect(sum, direct, RuleVerificationStatus::DISPROVED, "missing carry");
    }
    ValueInsn narrow_not(m_bnot, 1), wide_input(m_xdu, 4), extend_not(m_xdu, 4),
        wide_not(m_bnot, 4);
    reg(narrow_not.l, 100, 1);
    reg(wide_input.l, 100, 1);
    nested(extend_not.l, narrow_not);
    nested(wide_not.l, wide_input);
    okay &= expect(extend_not, wide_not, RuleVerificationStatus::DISPROVED,
                   "NOT cannot cross zero extension");
    ValueInsn signed_input(m_xds, 4);
    reg(signed_input.l, 100, 1);
    okay &= expect(wide_input, signed_input, RuleVerificationStatus::DISPROVED,
                   "signed versus unsigned extension");
    ValueInsn narrow_add(m_add, 1), extended_sum(m_xdu, 4), other_input(m_xdu, 4),
        wide_add(m_add, 4), masked(m_and, 4);
    reg(narrow_add.l, 100, 1);
    reg(narrow_add.r, 200, 1);
    nested(extended_sum.l, narrow_add);
    reg(other_input.l, 200, 1);
    nested(wide_add.l, wide_input);
    nested(wide_add.r, other_input);
    mnumber_t mask(255), zero(0);
    nested(masked.l, wide_add);
    constant(masked.r, mask, 4);
    okay &= expect(extended_sum, masked, RuleVerificationStatus::VERIFIED,
                   "explicit truncation preserves narrow carry");
    okay &= expect(extended_sum, wide_add, RuleVerificationStatus::DISPROVED, "lost truncation");
    ValueInsn low(m_low, 1), high(m_high, 1), direct(m_mov, 1);
    nested(low.l, wide_input);
    nested(high.l, wide_input);
    reg(direct.l, 100, 1);
    okay &= expect(low, direct, RuleVerificationStatus::VERIFIED, "low after extension");
    constant(direct.l, zero, 1);
    okay &= expect(high, direct, RuleVerificationStatus::VERIFIED, "high after extension");
    ValueInsn samples(m_xor, 4), zero_value(m_mov, 4);
    reg(samples.l, 100, 4);
    reg(samples.r, 200, 4);
    constant(zero_value.l, zero, 4);
    okay &= expect(samples, zero_value, RuleVerificationStatus::DISPROVED,
                   "distinct reaching values cannot cancel");
    samples.r.r = 100;
    okay &= expect(samples, zero_value, RuleVerificationStatus::VERIFIED, "same value can cancel");
    samples.r.valnum = 1;
    okay &= expect(samples, zero_value, RuleVerificationStatus::DISPROVED,
                   "different value numbers cannot cancel");
    samples.r.valnum = 0;
    samples.r.size = 1;
    okay &= expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED,
                   "implicit width conversion");
    samples.r.size = 4;
    samples.l.oprops |= OPROP_UDEFVAL;
    okay &= expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED, "undefined input");
    samples.l.oprops = 0;
    samples.iprops |= IPROP_MBARRIER;
    okay &= expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED, "memory barrier");
    samples.iprops = 0;
    samples.d.oprops |= OPROP_FLOAT;
    okay &=
        expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED, "floating destination");
    samples.d.oprops = 0;
    ValueInsn effect(m_stx, 4);
    nested(samples.l, effect);
    nested(samples.r, effect);
    okay &= expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED,
                   "intervening write cannot be an opaque equal leaf");
    nested(samples.l, samples);
    okay &= expect(samples, zero_value, RuleVerificationStatus::UNSUPPORTED,
                   "cyclic expression budget");
    stkvar_ref_t first_frame(reinterpret_cast<mba_t *>(uintptr_t(1)), 16);
    stkvar_ref_t second_frame(reinterpret_cast<mba_t *>(uintptr_t(2)), 16);
    samples.l.t = samples.r.t = mop_S;
    samples.l.size = samples.r.size = 4;
    samples.l.s = samples.r.s = &first_frame;
    okay &= expect(samples, zero_value, RuleVerificationStatus::VERIFIED, "same frame snapshot");
    samples.r.s = &second_frame;
    okay &= expect(samples, zero_value, RuleVerificationStatus::DISPROVED,
                   "different frame owners cannot cancel");

    for (int bytes : {1, 2, 4, 8})
        for (int address_bytes : {4, 8})
        {
            ValueInsn first(m_ldx, bytes), second(m_ldx, bytes), changed(m_ldx, bytes),
                left_not(m_bnot, bytes), right_not(m_bnot, bytes), both_not(m_and, bytes),
                either(m_or, bytes), inverted(m_bnot, bytes), first_only(m_mov, bytes),
                distinct_xor(m_xor, bytes), distinct_sub(m_sub, bytes), extra(m_or, bytes),
                converted(bytes == 8 ? m_xdu : m_low, bytes), nested_address(m_ldx, address_bytes);
            first.ea = changed.ea = 0x1000;
            second.ea = 0x1004;
            for (auto *load : {&first, &second, &changed})
            {
                reg(load->l, 500, 2);
                reg(load->r, 600, address_bytes);
            }
            second.r.r = 700;
            nested(left_not.l, first);
            nested(right_not.l, second);
            nested(both_not.l, left_not);
            nested(both_not.r, right_not);
            nested(either.l, first);
            nested(either.r, second);
            nested(inverted.l, either);
            okay &= expect(both_not, inverted, RuleVerificationStatus::VERIFIED,
                           "De Morgan preserves explicit memory reads");
            nested(first_only.l, first);
            okay &= expect(both_not, first_only, RuleVerificationStatus::UNSUPPORTED,
                           "dropping a memory read rejects");
            nested(extra.l, first);
            nested(extra.r, second);
            nested(either.l, extra);
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "duplicating a memory read rejects");
            nested(either.l, second);
            nested(either.r, first);
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "reordering memory reads rejects");
            nested(either.l, changed);
            nested(either.r, second);
            changed.r.r = 601;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "changing memory address rejects");
            changed.r.r = 600;
            changed.r.valnum = 1;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "changing address value number rejects");
            changed.r.valnum = 0;
            changed.l.r = 501;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "changing segment selector rejects");
            changed.l.r = 500;
            changed.d.size = bytes == 8 ? 4 : 2 * bytes;
            nested(converted.l, changed);
            nested(either.l, converted);
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "changing memory read width rejects");
            changed.d.size = bytes;
            nested(either.l, changed);
            reg(nested_address.l, 500, 2);
            reg(nested_address.r, 900, address_bytes);
            nested(changed.r, nested_address);
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "memory-dependent load address rejects");
            reg(changed.r, 600, address_bytes);
            changed.ea = 0x1008;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "changing load provenance rejects");
            changed.ea = first.ea;
            changed.iprops = IPROP_MBARRIER;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "barrier load cannot be opaque");
            changed.iprops = 0;
            nested(either.l, first);
            first.d.t = mop_v;
            first.d.g = 0x3000;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "nested load cannot carry an additional destination write");
            first.d.zero();
            first.d.size = bytes;
            second.r.r = first.r.r;
            okay &= expect(both_not, inverted, RuleVerificationStatus::VERIFIED,
                           "aliased loads retain both independent occurrences");
            nested(distinct_xor.l, first);
            nested(distinct_xor.r, second);
            nested(distinct_sub.l, first);
            nested(distinct_sub.r, second);
            okay &= expect(distinct_xor, distinct_sub, RuleVerificationStatus::DISPROVED,
                           "aliased reads do not imply equal observed values");
            either.r.t = mop_v;
            either.r.g = 0x2000;
            either.r.size = bytes;
            right_not.l.t = mop_v;
            right_not.l.g = 0x2000;
            right_not.l.size = bytes;
            okay &= expect(both_not, inverted, RuleVerificationStatus::UNSUPPORTED,
                           "implicit and explicit memory reads cannot mix");
        }
    // Real rejected SDK trees exercise independent width/reason keys beyond
    // the diagnostic quota. Dropping a reason must never drop its rejection.
    for (int bytes : {1, 2, 4, 8})
        for (unsigned invalid = 0; invalid < 11; ++invalid)
        {
            ValueInsn before(m_mov, bytes), after(m_mov, bytes), inner(m_mov, bytes == 8 ? 4 : 8);
            reg(before.l, 100, bytes);
            reg(after.l, 100, bytes);
            const int other = bytes == 8 ? 4 : 8;
            switch (invalid)
            {
            case 0:
                before.iprops |= IPROP_MBARRIER;
                break;
            case 1:
                before.l.oprops |= OPROP_UDEFVAL;
                break;
            case 2:
                before.l.t = mop_S;
                before.l.s = nullptr;
                break;
            case 3:
                before.l.t = mop_l;
                before.l.l = nullptr;
                break;
            case 4:
                before.l.t = mop_z;
                break;
            case 5:
                before.opcode = m_ldx;
                break;
            case 6:
                reg(before.r, 200, bytes);
                break;
            case 7:
                nested(before.l, inner);
                before.l.size = bytes;
                break;
            case 8:
                before.l.size = other;
                break;
            case 9:
                before.opcode = m_add;
                reg(before.r, 200, other);
                break;
            case 10:
                nested(before.l, before);
                break;
            }
            okay &= expect(before, after, RuleVerificationStatus::UNSUPPORTED,
                           "diagnostic quota retains rejection");
        }
    const auto expect_constant =
        [&](minsn_t &before, uint64_t proposed, RuleVerificationStatus status, const char *label)
    {
        const auto result = verifier.verify_constant(&before, proposed);
        observations.push_back(result);
        if (result.status == status)
            return true;
        std::cerr << label << ": " << rule_verification_status_name(result.status) << " "
                  << result.detail << '\n';
        return false;
    };
    for (int bytes : {1, 2, 4, 8})
    {
        for (const auto &[opcode, self_value] :
             std::array<std::pair<mcode_t, uint64_t>, 10>{{{m_setz, 1},
                                                           {m_setnz, 0},
                                                           {m_setae, 1},
                                                           {m_setb, 0},
                                                           {m_seta, 0},
                                                           {m_setbe, 1},
                                                           {m_setg, 0},
                                                           {m_setge, 1},
                                                           {m_setl, 0},
                                                           {m_setle, 1}}})
        {
            ValueInsn comparison(opcode, 1);
            reg(comparison.l, 100, bytes);
            reg(comparison.r, 100, bytes);
            okay &= expect_constant(comparison, self_value, RuleVerificationStatus::VERIFIED,
                                    "typed self comparison");
            okay &= expect_constant(comparison, self_value ^ 1, RuleVerificationStatus::DISPROVED,
                                    "wrong self comparison proposal");
            comparison.r.valnum = 1;
            okay &= expect_constant(comparison, self_value, RuleVerificationStatus::DISPROVED,
                                    "different comparison value numbers");
            comparison.r.valnum = 0;
            comparison.r.size = bytes == 8 ? 4 : bytes * 2;
            okay &= expect_constant(comparison, self_value, RuleVerificationStatus::UNSUPPORTED,
                                    "comparison widths must match each other");
            comparison.r.size = bytes;
            comparison.d.size = 4;
            okay &= expect_constant(comparison, self_value, RuleVerificationStatus::UNSUPPORTED,
                                    "set result must retain byte width");
        }
        mnumber_t sign_bit(uint64_t{1} << (8 * bytes - 1));
        mnumber_t zero_number(0);
        for (const auto &[opcode, value] : std::array<std::pair<mcode_t, uint64_t>, 4>{
                 {{m_setl, 1}, {m_setge, 0}, {m_setb, 0}, {m_setae, 1}}})
        {
            ValueInsn comparison(opcode, 1);
            constant(comparison.l, sign_bit, bytes);
            constant(comparison.r, zero_number, bytes);
            okay &= expect_constant(comparison, value, RuleVerificationStatus::VERIFIED,
                                    "signed and unsigned sign-bit comparisons differ");
        }
        ValueInsn sign(m_sets, 1);
        constant(sign.l, sign_bit, bytes);
        okay &=
            expect_constant(sign, 1, RuleVerificationStatus::VERIFIED, "explicit sign extraction");
        for (int result_bytes : {1, 2, 4, 8})
        {
            ValueInsn logical(m_lnot, result_bytes);
            constant(logical.l, zero_number, bytes);
            okay &= expect_constant(logical, 1, RuleVerificationStatus::VERIFIED,
                                    "logical zero writes one at result width");
            constant(logical.l, sign_bit, bytes);
            okay &= expect_constant(logical, 0, RuleVerificationStatus::VERIFIED,
                                    "logical nonzero writes zero at result width");
        }
    }
    ValueInsn comparison(m_setz, 1), read(m_ldx, 4);
    reg(read.l, 500, 2);
    reg(read.r, 600, 8);
    nested(comparison.l, read);
    nested(comparison.r, read);
    okay &= expect_constant(comparison, 1, RuleVerificationStatus::UNSUPPORTED,
                            "constant comparison must not drop explicit reads");
    comparison.l.t = comparison.r.t = mop_S;
    comparison.l.size = comparison.r.size = 4;
    comparison.l.s = comparison.r.s = &first_frame;
    okay &= expect_constant(comparison, 1, RuleVerificationStatus::VERIFIED,
                            "same stable frame comparison");
    comparison.r.s = &second_frame;
    okay &= expect_constant(comparison, 1, RuleVerificationStatus::DISPROVED,
                            "different frame comparison rejects");
    reg(comparison.l, 100, 4);
    reg(comparison.r, 100, 4);
    comparison.iprops = IPROP_MBARRIER;
    okay &= expect_constant(comparison, 1, RuleVerificationStatus::UNSUPPORTED,
                            "predicate barrier rejects before mutation");
    comparison.iprops = 0;
    comparison.l.oprops = OPROP_UDEFVAL;
    okay &= expect_constant(comparison, 1, RuleVerificationStatus::UNSUPPORTED,
                            "undefined predicate input rejects");
    comparison.l.oprops = 0;
    for (mcode_t opcode : {m_cfshl, m_cfshr})
    {
        comparison.opcode = opcode;
        okay &= expect_constant(comparison, 1, RuleVerificationStatus::UNSUPPORTED,
                                "unmodeled flag semantics reject");
    }
    for (int bytes : {1, 2, 4, 8})
        for (mcode_t opcode : {m_cfadd, m_ofadd, m_seto, m_setp})
        {
            ValueInsn flag(opcode, 1);
            reg(flag.l, 100, bytes);
            reg(flag.r, 100, bytes);
            if (opcode == m_seto || opcode == m_setp)
            {
                const unsigned value = opcode == m_setp;
                okay &= expect_constant(flag, value, RuleVerificationStatus::VERIFIED,
                                        "same integer operands subtraction flags");
                okay &= expect_constant(flag, value ^ 1, RuleVerificationStatus::DISPROVED,
                                        "wrong integer flag proposal");
                flag.r.valnum = 1;
                okay &= expect_constant(flag, value, RuleVerificationStatus::DISPROVED,
                                        "flag value numbers must agree");
                flag.r.valnum = 0;
            }
            else
                okay &= expect_constant(flag, 0, RuleVerificationStatus::DISPROVED,
                                        "addition flags of same free value are not constant");
            flag.iprops = IPROP_FPINSN;
            okay &= expect_constant(flag, 0, RuleVerificationStatus::UNSUPPORTED,
                                    "floating flag operation excluded");
            flag.iprops = IPROP_MBARRIER;
            okay &= expect_constant(flag, 0, RuleVerificationStatus::UNSUPPORTED,
                                    "flag barrier excluded");
            flag.iprops = 0;
            flag.d.size = 4;
            okay &= expect_constant(flag, 0, RuleVerificationStatus::UNSUPPORTED,
                                    "flag result must remain one byte");
            flag.d.size = 1;
            flag.r.size = bytes == 8 ? 4 : bytes * 2;
            okay &= expect_constant(flag, 0, RuleVerificationStatus::UNSUPPORTED,
                                    "flag operands must have equal widths");
        }
    ValueInsn conjunction(m_and, 4), disjunction(m_or, 4), combined(m_add, 4),
        ordinary_sum(m_add, 4), equivalent(m_setz, 1);
    for (auto *node : {&conjunction, &disjunction, &ordinary_sum})
    {
        reg(node->l, 100, 4);
        reg(node->r, 200, 4);
    }
    nested(combined.l, conjunction);
    nested(combined.r, disjunction);
    nested(equivalent.l, combined);
    nested(equivalent.r, ordinary_sum);
    okay &= expect_constant(equivalent, 1, RuleVerificationStatus::VERIFIED,
                            "typed comparison of a carry identity");
    RuleVerifier predicate_exhausted(10'000, 1);
    const auto exhausted_predicate = predicate_exhausted.verify_constant(&equivalent, 1);
    observations.push_back(exhausted_predicate);
    okay &= exhausted_predicate.status == RuleVerificationStatus::UNKNOWN &&
            !exhausted_predicate.verified() && !exhausted_predicate.detail.empty();

    const auto stats = instance_verification_stats();
    using Key = std::tuple<RuleVerificationStatus, unsigned, std::string>;
    std::map<Key, size_t> expected;
    std::map<RuleVerificationStatus, size_t> statuses;
    size_t verified = 0, rejected = 0, recorded = 0;
    for (const auto &result : observations)
    {
        ++statuses[result.status];
        if (result.verified())
            ++verified;
        else
        {
            ++rejected;
            ++expected[{result.status, result.bit_width, result.detail}];
        }
    }
    std::map<Key, size_t> actual;
    for (const auto &entry : stats.rejection_reasons)
    {
        const Key key{entry.status, entry.bit_width, entry.detail};
        okay &= entry.count == expected.at(key) && entry.detail.size() <= 256 &&
                actual.emplace(key, entry.count).second;
        recorded += entry.count;
    }
    okay &= stats.verified == verified &&
            stats.disproved == statuses[RuleVerificationStatus::DISPROVED] &&
            stats.unsupported == statuses[RuleVerificationStatus::UNSUPPORTED] &&
            stats.unknown == statuses[RuleVerificationStatus::UNKNOWN] &&
            stats.disproved + stats.unsupported + stats.unknown == rejected &&
            recorded + stats.unrecorded_rejections == rejected &&
            stats.rejection_reasons.size() == 32 && stats.unrecorded_rejections > 0;
    reset_instance_verification_stats();
    const auto reset = instance_verification_stats();
    okay &= reset.verified == 0 && reset.disproved == 0 && reset.unsupported == 0 &&
            reset.unknown == 0 && reset.rejection_reasons.empty() &&
            reset.unrecorded_rejections == 0;
    okay &=
        expect(samples, zero_value, RuleVerificationStatus::DISPROVED, "new rejection after reset");
    const auto restarted = instance_verification_stats();
    okay &= restarted.disproved == 1 && restarted.rejection_reasons.size() == 1 &&
            restarted.rejection_reasons[0].count == 1 && restarted.unrecorded_rejections == 0;
    reset_instance_verification_stats();
    if (okay)
        std::cout << "MBA typed instances: " << observations.size() - 1 << " initial results, "
                  << stats.verified << " verified, " << stats.disproved << " disproved, "
                  << stats.unsupported << " unsupported, " << stats.unknown
                  << " unknown; 32-key quota, " << stats.unrecorded_rejections
                  << " unrecorded; reset and one new rejection passed\n";
    return okay;
}

class RejectedCatalogRule final : public chernobog::rules::PatternMatchingRule
{
  public:
    const char *name() const override { return "catalog_intentionally_rejected"; }
    AstPtr get_pattern() const override
    {
        return make_node(m_add, make_leaf("x"), chernobog::ast::make_const(1));
    }
    AstPtr get_replacement() const override { return make_leaf("x"); }
};

bool test_verifier_rejection_states()
{
    using namespace chernobog::rules;
    // Resource exhaustion is deterministic with this solver-bound identity;
    // a millisecond timeout would make the negative control scheduler-dependent.
    Sub_HackersDelightRule_3 identity;
    RuleVerifier exhausted(10'000, 1);
    const auto unknown = exhausted.verify(identity.get_pattern(), identity.get_replacement());
    if (unknown.status != RuleVerificationStatus::UNKNOWN || unknown.verified() ||
        unknown.detail.empty())
    {
        std::cerr << "resource exhaustion must remain UNKNOWN and unverified: "
                  << rule_verification_status_name(unknown.status) << " (" << unknown.detail
                  << ")\n";
        return false;
    }

    RuleVerifier verifier;
    const auto unsupported =
        verifier.verify(make_node(m_udiv, make_leaf("x"), make_leaf("y")), make_leaf("x"));
    if (unsupported.status != RuleVerificationStatus::UNSUPPORTED || unsupported.verified())
    {
        std::cerr << "unsupported opcode was not rejected\n";
        return false;
    }
    // Equal at 8/16/32 bits, unequal only at 64: all admitted widths matter.
    const auto wide_mismatch = verifier.verify(chernobog::ast::make_const(uint64_t{1} << 32),
                                               chernobog::ast::make_const(0));
    if (wide_mismatch.status != RuleVerificationStatus::DISPROVED ||
        wide_mismatch.bit_width != 64 || wide_mismatch.verified())
    {
        std::cerr << "64-bit-only counterexample was not rejected\n";
        return false;
    }
    std::cout << "MBA verifier rejection states: UNKNOWN, UNSUPPORTED, "
                 "and 64-bit DISPROVED checked\n";
    return true;
}

bool test_commutative_matching()
{
    constexpr mcode_t commutative_ops[] = {m_add, m_mul, m_and, m_or, m_xor};
    for (mcode_t op : commutative_ops)
    {
        AstPtr pattern =
            make_node(op, make_leaf("x"), make_node(m_sub, make_leaf("y"), make_leaf("z")));
        AstPtr candidate =
            make_node(op, make_node(m_sub, make_leaf("a"), make_leaf("b")), make_leaf("c"));
        MatchBindings bindings;
        if (!match_pattern(pattern.get(), candidate.get(), bindings) || bindings.count != 3)
            return false;

        if (!bindings.find("x"))
            return false;
    }

    // Exercise nested rollback: both XOR and AND require their swapped branch,
    // and the repeated x binding must survive both checkpoints.
    AstPtr nested_pattern = make_node(
        m_xor, make_leaf("x"),
        make_node(m_and, make_leaf("y"), make_node(m_sub, make_leaf("z"), make_leaf("w"))));
    AstPtr nested_candidate = make_node(
        m_xor, make_node(m_and, make_node(m_sub, make_leaf("a"), make_leaf("b")), make_leaf("c")),
        make_leaf("d"));
    MatchBindings nested_bindings;
    if (!match_pattern(nested_pattern.get(), nested_candidate.get(), nested_bindings) ||
        nested_bindings.count != 4)
        return false;

    // Subtraction is order-sensitive and must not take the commuted branch.
    AstPtr ordered_pattern =
        make_node(m_sub, make_leaf("x"), make_node(m_and, make_leaf("y"), make_leaf("x")));
    AstPtr reversed_candidate =
        make_node(m_sub, make_node(m_and, make_leaf("a"), make_leaf("b")), make_leaf("a"));
    MatchBindings ordered_bindings;
    return !match_pattern(ordered_pattern.get(), reversed_candidate.get(), ordered_bindings) &&
           ordered_bindings.count == 0;
}

bool test_match_failure_witnesses()
{
    using namespace chernobog::ast;
    size_t checks = 0, failed = 0;
    const auto check = [&](bool condition)
    {
        ++checks;
        failed += !condition;
        if (!condition)
            std::cerr << "match failure witness check " << checks << " failed\n";
    };
    const auto mismatch = [&](const AstPtr &pattern, const AstPtr &candidate, MatchFailureKind kind,
                              const char *p, const char *c)
    {
        MatchBindings plain, traced;
        MatchFailure failure;
        check(!match_pattern(pattern.get(), candidate.get(), plain));
        check(!match_pattern(pattern.get(), candidate.get(), traced, &failure));
        check(plain.count == 0 && traced.count == 0 && failure.kind == kind &&
              failure.pattern_path == p && failure.candidate_path == c && !failure.path_truncated);
        check(match_failure_detail(failure).size() <= 256);
        return failure;
    };
    auto pattern =
        make_node(m_sub, make_leaf("x"), make_node(m_and, make_leaf("x"), make_leaf("y")));
    auto candidate =
        make_node(m_sub, make_leaf("a"), make_node(m_or, make_leaf("a"), make_leaf("b")));
    auto failure = mismatch(pattern, candidate, MatchFailureKind::Opcode, "R", "R");
    check(failure.matched_nodes == 2 && failure.has_values && failure.expected == m_and &&
          failure.actual == m_or);
    candidate = make_node(m_sub, make_leaf("a"), make_leaf("b"));
    mismatch(pattern, candidate, MatchFailureKind::NodeRequired, "R", "R");
    candidate = make_unary(m_sub, make_leaf("a"));
    failure = mismatch(pattern, candidate, MatchFailureKind::Arity, "", "");
    check(failure.has_values && failure.expected == 3 && failure.actual == 1);
    // The swapped ADD branch matches a longer prefix. Its candidate path is L,
    // while the failed AND still occupies pattern path R.
    pattern = make_node(m_add, make_node(m_sub, make_leaf("x"), make_leaf("y")),
                        make_node(m_and, make_leaf("y"), make_leaf("z")));
    candidate = make_node(m_add, make_node(m_or, make_leaf("a"), make_leaf("b")),
                          make_node(m_sub, make_leaf("c"), make_leaf("d")));
    failure = mismatch(pattern, candidate, MatchFailureKind::Opcode, "R", "L");
    check(failure.matched_nodes == 4);
    // Equal prefixes keep the first actual failure, even if another branch
    // reports a different kind. The witness is not a semantic distance metric.
    pattern = make_node(m_add, make_leaf("x"), make_node(m_and, make_leaf("y"), make_leaf("z")));
    candidate = make_node(m_add, make_node(m_or, make_leaf("a"), make_leaf("b")), make_leaf("c"));
    failure = mismatch(pattern, candidate, MatchFailureKind::NodeRequired, "R", "R");
    check(failure.matched_nodes == 2);
    auto constant_pattern = make_const(255, 1), constant_candidate = make_leaf("number");
    mnumber_t number(254);
    constant(constant_candidate->mop, number, 1);
    failure =
        mismatch(constant_pattern, constant_candidate, MatchFailureKind::ConstantValue, "", "");
    check(failure.expected == 255 && failure.actual == 254 && failure.has_values);
    constant_candidate->mop.zero();
    mismatch(constant_pattern, make_leaf("nonnumeric"), MatchFailureKind::NumericRequired, "", "");
    constant_candidate->mop.t = mop_n;
    constant_candidate->mop.nnn = nullptr;
    mismatch(constant_pattern, constant_candidate, MatchFailureKind::NullPayload, "", "");
    constant_candidate->mop.zero();
    // Successful commutation clears every discarded failure and keeps bindings.
    for (mcode_t opcode : {m_add, m_mul, m_and, m_or, m_xor})
    {
        pattern =
            make_node(opcode, make_leaf("x"), make_node(m_sub, make_leaf("y"), make_leaf("z")));
        candidate =
            make_node(opcode, make_node(m_sub, make_leaf("a"), make_leaf("b")), make_leaf("c"));
        MatchBindings plain, traced;
        failure.kind = MatchFailureKind::Opcode;
        failure.pattern_path = "stale";
        check(match_pattern(pattern.get(), candidate.get(), plain) &&
              match_pattern(pattern.get(), candidate.get(), traced, &failure));
        check(plain.count == 3 && traced.count == 3 && failure.kind == MatchFailureKind::None &&
              failure.pattern_path.empty() && match_failure_detail(failure).empty());
    }
    // Actual repeated bindings reject width/snapshot/storage differences.
    for (int bytes : {1, 2, 4, 8})
    {
        pattern = make_node(m_sub, make_leaf("x"), make_leaf("x"));
        auto a = make_leaf("a"), b = make_leaf("b");
        reg(a->mop, 100, bytes);
        reg(b->mop, 100, bytes);
        candidate = make_node(m_sub, a, b);
        b->mop.size = bytes == 8 ? 4 : 8;
        failure = mismatch(pattern, candidate, MatchFailureKind::OperandWidth, "R", "R");
        check(failure.expected == uint64_t(bytes) && failure.actual == uint64_t(b->mop.size));
        b->mop.size = bytes;
        b->mop.valnum = 17;
        failure = mismatch(pattern, candidate, MatchFailureKind::ValueNumber, "R", "R");
        check(failure.expected == 0 && failure.actual == 17);
        b->mop.valnum = 0;
        b->mop.oprops = OPROP_ABI;
        mismatch(pattern, candidate, MatchFailureKind::OperandProperties, "R", "R");
        b->mop.oprops = 0;
        b->mop.r = 101;
        mismatch(pattern, candidate, MatchFailureKind::RegisterIdentity, "R", "R");
        b->mop.t = mop_v;
        b->mop.g = 0x3000;
        mismatch(pattern, candidate, MatchFailureKind::OperandKind, "R", "R");
    }
    const auto difference = [&](const mop_t &a, const mop_t &b, MatchFailureKind kind)
    {
        MatchFailure first;
        check(!mops_equal_strict(a, b) && !mops_equal_strict(a, b, &first));
        check(first.kind == kind && first.pattern_path.empty() && first.candidate_path.empty());
        check(match_failure_detail(first).size() <= 256);
    };
    // Borrowed SDK payloads test metadata comparison without kernel allocation
    // or pretending to implement the SDK's recursive operand copy operation.
    ValueInsn a(m_mov, 4), b(m_mov, 4), inner_a(m_mov, 4), inner_b(m_mov, 4);
    const auto frame_a = reinterpret_cast<mba_t *>(uintptr_t{0x1000});
    const auto frame_b = reinterpret_cast<mba_t *>(uintptr_t{0x2000});
    stkvar_ref_t stack_a(frame_a, 24), stack_b(frame_b, 24), stack_same(frame_a, 25);
    a.l.t = b.l.t = mop_S;
    a.l.size = b.l.size = 4;
    a.l.s = &stack_a;
    b.l.s = &stack_b;
    difference(a.l, b.l, MatchFailureKind::FrameOwner);
    b.l.s = &stack_same;
    difference(a.l, b.l, MatchFailureKind::StackOffset);
    b.l.s = nullptr;
    difference(a.l, b.l, MatchFailureKind::NullPayload);
    lvar_ref_t local_a(frame_a, 3, 8), local_b(frame_b, 3, 8), local_same(frame_a, 4, 8);
    a.l.t = b.l.t = mop_l;
    a.l.l = &local_a;
    b.l.l = &local_b;
    difference(a.l, b.l, MatchFailureKind::FrameOwner);
    b.l.l = &local_same;
    difference(a.l, b.l, MatchFailureKind::LocalIndex);
    local_same.idx = 3;
    local_same.off = 9;
    difference(a.l, b.l, MatchFailureKind::LocalOffset);
    a.l.t = b.l.t = mop_v;
    a.l.g = 0x3000;
    b.l.g = 0x3001;
    difference(a.l, b.l, MatchFailureKind::GlobalAddress);
    mnumber_t one(1), two(2);
    constant(a.l, one, 4);
    constant(b.l, two, 4);
    difference(a.l, b.l, MatchFailureKind::NumberValue);
    a.l.t = b.l.t = mop_b;
    a.l.b = 1;
    b.l.b = 2;
    difference(a.l, b.l, MatchFailureKind::BlockIdentity);
    a.l.t = b.l.t = mop_f;
    difference(a.l, b.l, MatchFailureKind::UnsupportedOperand);
    char first[] = "a", second[] = "b";
    a.l.t = b.l.t = mop_h;
    a.l.helper = first;
    b.l.helper = second;
    difference(a.l, b.l, MatchFailureKind::TextValue);
    nested(a.l, inner_a);
    nested(b.l, inner_b);
    inner_b.opcode = m_neg;
    difference(a.l, b.l, MatchFailureKind::NestedOpcode);
    inner_b.opcode = inner_a.opcode;
    inner_b.iprops = IPROP_MBARRIER;
    difference(a.l, b.l, MatchFailureKind::InstructionProps);
    inner_b.iprops = 0;
    inner_a.opcode = inner_b.opcode = m_ldx;
    inner_a.ea = 0x4000;
    inner_b.ea = 0x4001;
    difference(a.l, b.l, MatchFailureKind::LoadSource);
    inner_a.opcode = inner_b.opcode = m_mov;
    nested(inner_a.l, inner_a);
    nested(inner_b.l, inner_b);
    difference(a.l, b.l, MatchFailureKind::ComparisonBudget);
    // Diagnostic paths alone truncate. Matcher acceptance stays unchanged.
    pattern = make_const(0);
    candidate = make_leaf("deep");
    for (unsigned depth = 0; depth < 65; ++depth)
    {
        pattern = make_unary(m_bnot, pattern);
        candidate = make_unary(m_bnot, candidate);
    }
    MatchBindings deep;
    check(!match_pattern(pattern.get(), candidate.get(), deep, &failure) &&
          failure.kind == MatchFailureKind::NumericRequired && failure.path_truncated &&
          failure.pattern_path.size() == 64 && failure.candidate_path.size() == 64);
    failure.kind = MatchFailureKind::OperandProperties;
    failure.expected = UINT64_MAX;
    failure.actual = UINT64_MAX - 1;
    failure.has_values = true;
    failure.matched_nodes = SIZE_MAX;
    check(match_failure_detail(failure).size() == 245);
    // Nine distinct leaves exceed the existing eight-binding capacity.
    pattern = make_leaf("0");
    candidate = make_leaf("a");
    for (unsigned index = 1; index < 9; ++index)
    {
        pattern = make_node(m_sub, pattern, make_leaf(std::to_string(index)));
        candidate = make_node(m_sub, candidate, make_leaf("a"));
    }
    check(!match_pattern(pattern.get(), candidate.get(), deep, &failure) && deep.count == 0 &&
          failure.kind == MatchFailureKind::BindingCapacity);
    check(!match_pattern(pattern.get(), nullptr, deep, &failure) &&
          failure.kind == MatchFailureKind::NullTree);
    std::cout << "MBA match failure witnesses: " << checks << " checks; failures=" << failed
              << '\n';
    return failed == 0;
}

// Destroying an AST reaches mop_t's hexapi destructor. With the real
// dispatcher absent that call jumped to an address derived from its arguments
// and killed the process, so the catalog previously depended on retaining
// every tree it built -- an invariant an exception unwind out of rule
// verification silently breaks. Exercise both shapes directly so the
// dispatcher redirection cannot regress unnoticed.
bool test_ast_destruction()
{
    for (int depth = 0; depth < 64; ++depth)
    {
        AstPtr tree =
            make_node(m_xor, make_leaf("x"), make_node(m_add, make_leaf("y"), make_leaf("z")));
        if (!tree)
            return false;
    }

    try
    {
        AstPtr tree = make_node(m_add, make_leaf("x"), make_leaf("y"));
        if (!tree)
            return false;
        throw std::runtime_error("unwind past a live AST");
    }
    catch (const std::runtime_error &)
    {
    }
    return true;
}

bool test_input_capture_bounds()
{
    using namespace chernobog::ast;
    using chernobog::mba_diagnostics::CaptureStatus;
    size_t checks = 0;
    const auto check = [&](bool value)
    {
        ++checks;
        if (!value)
            throw std::runtime_error("input capture bound check " + std::to_string(checks));
    };
    check(capture_match_input(nullptr).status == CaptureStatus::NoAst);
    auto root = make_node(m_add, make_leaf("x"), make_leaf("y"));
    const auto plain = capture_match_input(root);
    check(plain.status == CaptureStatus::Complete &&
          plain.payload.find("\"prefix_status\":\"missing_anchor\"") != std::string::npos);
    check(plain.payload.find("\"root_iprops\":null") != std::string::npos);
    ValueInsn original(m_add, 4);
    original.iprops = IPROP_FPINSN;
    const auto floating = capture_match_input(root, nullptr, nullptr, &original);
    check(floating.status == CaptureStatus::Complete &&
          floating.payload.find("\"root_iprops\":" + std::to_string(IPROP_FPINSN)) !=
              std::string::npos);
    auto cycle = std::static_pointer_cast<AstNode>(root);
    cycle->left = cycle;
    check(capture_match_input(root).status == CaptureStatus::Cycle);
    cycle->left = make_leaf("x");
    AstPtr chain = make_leaf("x");
    for (int i = 0; i < 63; ++i)
        chain = make_unary(m_neg, chain);
    check(capture_match_input(chain).status == CaptureStatus::Complete);
    chain = make_unary(m_neg, chain);
    check(capture_match_input(chain).status == CaptureStatus::DepthLimit);
    AstPtr wide = make_leaf("x");
    for (int i = 0; i < 8; ++i)
        wide = make_node(m_add, wide, wide);
    check(capture_match_input(wide).status == CaptureStatus::VisitLimit);
    std::string long_text(4095, 'x');
    auto text = make_leaf("helper");
    text->mop.t = mop_h;
    text->mop.helper = long_text.data();
    check(capture_match_input(text).status == CaptureStatus::ByteLimit);
    text->mop.zero();
    struct Head
    {
        ValueInsn instruction{m_nop, 4};
    };
    std::vector<std::unique_ptr<Head>> heads;
    for (int i = 0; i < 66; ++i)
    {
        heads.push_back(std::make_unique<Head>());
        if (i)
        {
            heads[i]->instruction.prev = &heads[i - 1]->instruction;
            heads[i - 1]->instruction.next = &heads[i]->instruction;
        }
    }
    auto encoded = capture_match_input(root, &heads[64]->instruction, &heads[0]->instruction);
    check(encoded.status == CaptureStatus::Complete &&
          encoded.payload.find("\"prefix_status\":\"block_entry\"") != std::string::npos);
    encoded = capture_match_input(root, &heads[65]->instruction, &heads[0]->instruction);
    check(encoded.status == CaptureStatus::Complete &&
          encoded.payload.find("\"prefix_status\":\"head_limit\"") != std::string::npos);
    heads[64]->instruction.next = nullptr;
    encoded = capture_match_input(root, &heads[65]->instruction, &heads[0]->instruction);
    check(encoded.payload.find("\"prefix_status\":\"link_error\",\"prefix\":[]") !=
          std::string::npos);
    check(capture_catalog_patterns({{"bad-name", root}}, true).find("\"status\":\"malformed\"") !=
          std::string::npos);
    check(capture_catalog_patterns({}, false).find("\"status\":\"not_initialized\"") !=
          std::string::npos);
    std::cout << "MBA matcher input capture bounds: " << checks << " passed\n";
    return true;
}

int export_matcher_inputs()
{
    using namespace chernobog::ast;
    auto &registry = chernobog::rules::RuleRegistry::instance();
    registry.initialize();
    if (registry.verified_rule_count() != 108 || registry.rejected_rule_count() != 0)
        return EXIT_FAILURE;
    std::cout << "{\"catalog\":" << registry.catalog_pattern_snapshot() << ",\"fixtures\":[";
    bool first = true;
    const auto emit = [&](const std::string &name, const AstPtr &pattern, const AstPtr &candidate,
                          const minsn_t *anchor = nullptr, const minsn_t *head = nullptr,
                          int resolved = -1, int value = -1)
    {
        MatchBindings bindings;
        MatchFailure failure;
        const bool actual = match_pattern(pattern.get(), candidate.get(), bindings, &failure);
        const auto captured = capture_match_input(candidate, anchor, head);
        if (captured.status != chernobog::mba_diagnostics::CaptureStatus::Complete)
            throw std::runtime_error("fixture capture failed: " + name);
        if (!first)
            std::cout << ',';
        first = false;
        std::cout << "{\"name\":" << std::quoted(name) << ",\"pattern_catalog\":"
                  << capture_catalog_patterns({{"Fixture", pattern}}, true)
                  << ",\"input\":" << captured.payload
                  << ",\"matched\":" << (actual ? "true" : "false")
                  << ",\"failure\":" << std::quoted(match_failure_detail(failure))
                  << ",\"resolved\":" << resolved << ",\"value\":" << value << '}';
    };
    auto a = make_leaf("a"), b = make_leaf("b");
    reg(a->mop, 100, 4);
    reg(b->mop, 200, 4);
    a->dest_size = b->dest_size = 4;
    auto pattern = make_node(m_sub, make_leaf("x"), make_leaf("x"));
    auto candidate = make_node(m_sub, a, b);
    emit("register", pattern, candidate);
    reg(b->mop, 100, 8);
    emit("width", pattern, candidate);
    b->mop.size = 4;
    b->mop.valnum = 19;
    emit("value_number", pattern, candidate);
    b->mop.valnum = 0;
    b->mop.oprops = 1;
    emit("properties", pattern, candidate);
    b->mop.oprops = 0;
    emit("same_snapshot", pattern, candidate);
    pattern = make_node(m_add, make_node(m_sub, make_leaf("x"), make_leaf("y")),
                        make_node(m_and, make_leaf("y"), make_leaf("z")));
    candidate = make_node(m_add, make_node(m_or, a, b), make_node(m_sub, a, b));
    emit("longer_commuted", pattern, candidate);
    pattern = make_node(m_add, make_leaf("x"), make_node(m_and, make_leaf("y"), make_leaf("z")));
    candidate = make_node(m_add, make_node(m_or, a, b), a);
    emit("first_tie", pattern, candidate);
    pattern = make_node(m_add, make_leaf("x"), make_node(m_sub, make_leaf("y"), make_leaf("z")));
    candidate = make_node(m_add, make_node(m_sub, a, b), a);
    emit("success_after_commutation", pattern, candidate);
    mnumber_t zero(0), one(1);
    pattern = make_node(m_xor, make_leaf("x"), make_const(0, 4));
    reg(b->mop, 200, 4);
    candidate = make_node(m_xor, a, b);
    candidate->dest_size = 4;
    ValueInsn definition(m_mov, 4), overwrite(m_mov, 1), anchor(m_xor, 4);
    constant(definition.l, zero, 4);
    reg(definition.d, 200, 4);
    reg(anchor.l, 100, 4);
    reg(anchor.r, 200, 4);
    definition.next = &anchor;
    anchor.prev = &definition;
    emit("local_zero", pattern, candidate, &anchor, &definition, 1, 0);
    constant(overwrite.l, one, 1);
    reg(overwrite.d, 201, 1);
    definition.next = &overwrite;
    overwrite.prev = &definition;
    overwrite.next = &anchor;
    anchor.prev = &overwrite;
    emit("overlapping_byte", pattern, candidate, &anchor, &definition, 1, 256);
    overwrite.opcode = m_call;
    emit("call_barrier", pattern, candidate, &anchor, &definition, 0);
    overwrite.opcode = m_mov;
    b->mop.valnum = 1;
    emit("stale_value_number", pattern, candidate, &anchor, &definition, 0);
    b->mop.valnum = 0;
    b->mop.size = b->dest_size = 8;
    emit("insufficient_bytes", pattern, candidate, &anchor, &definition, 0);
    b->mop.size = b->dest_size = 4;
    b->mop.oprops = 1;
    emit("read_properties", pattern, candidate, &anchor, &definition, 0);
    b->mop.oprops = 0;
    pattern = make_node(m_sub, make_leaf("x"), make_const(0, 4));
    std::static_pointer_cast<AstNode>(candidate)->opcode = m_sub;
    constant(b->mop, one, 4);
    emit("fixed_constant", pattern, candidate);
    constant(b->mop, zero, 4);
    emit("actual_numeric_zero", pattern, candidate);
    b->mop.zero();
    std::cout << "],\"equalities\":[";
    first = true;
    auto pair = make_node(m_sub, a, b);
    const auto equality = [&](const std::string &name)
    {
        MatchFailure difference;
        const bool equal = mops_equal_strict(a->mop, b->mop, &difference);
        const auto captured = capture_match_input(pair);
        if (captured.status != chernobog::mba_diagnostics::CaptureStatus::Complete)
            throw std::runtime_error("equality fixture capture failed");
        if (!first)
            std::cout << ',';
        first = false;
        std::cout << "{\"name\":" << std::quoted(name) << ",\"input\":" << captured.payload
                  << ",\"equal\":" << (equal ? "true" : "false")
                  << ",\"failure\":" << std::quoted(match_failure_detail(difference)) << '}';
    };
    const auto owner_a = reinterpret_cast<mba_t *>(uintptr_t{0x1000});
    const auto owner_b = reinterpret_cast<mba_t *>(uintptr_t{0x2000});
    stkvar_ref_t stack_a(owner_a, 24), stack_b(owner_b, 24), stack_same(owner_a, 25);
    a->mop.t = b->mop.t = mop_S;
    a->mop.s = &stack_a;
    b->mop.s = &stack_b;
    b->mop.size = 4;
    equality("frame_tokens");
    b->mop.s = &stack_same;
    equality("stack_offset");
    lvar_ref_t local_a(owner_a, 3, 8), local_b(owner_a, 4, 8);
    a->mop.t = b->mop.t = mop_l;
    a->mop.l = &local_a;
    b->mop.l = &local_b;
    equality("local_index");
    local_b.idx = 3;
    local_b.off = 9;
    equality("local_offset");
    a->mop.t = b->mop.t = mop_h;
    char text_a[] = "a\"\n", text_b[] = "b\"\n";
    a->mop.helper = text_a;
    b->mop.helper = text_b;
    equality("hex_helper");
    a->mop.t = b->mop.t = mop_f;
    equality("opaque_call");
    ValueInsn inner_a(m_ldx, 4), inner_b(m_ldx, 4);
    nested(a->mop, inner_a);
    nested(b->mop, inner_b);
    inner_a.ea = 0x3000;
    inner_b.ea = 0x3001;
    equality("load_source");
    inner_a.opcode = inner_b.opcode = m_mov;
    equality("ordinary_source_ignored");
    reg(inner_b.d, 100, 4);
    reg(inner_b.l, 100, 4);
    equality("destination_before_left");
    inner_b.d.zero();
    inner_b.l.zero();
    inner_b.iprops = IPROP_MBARRIER;
    equality("nested_properties");
    a->mop.zero();
    b->mop.zero();
    std::cout << "]}\n";
    registry.clear();
    return EXIT_SUCCESS;
}

} // namespace

int verify_native_flags(const char *path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return EXIT_FAILURE;
    chernobog::rules::RuleVerifier verifier;
    size_t checks = 0;
    const auto pair = [&](int bytes, uint64_t x, uint64_t y)
    {
        for (mcode_t opcode : {m_cfadd, m_ofadd, m_seto, m_setp})
        {
            const int expected = input.get();
            if (expected != 0 && expected != 1)
                return false;
            ValueInsn flag(opcode, 1);
            mnumber_t left(x), right(y);
            constant(flag.l, left, bytes);
            constant(flag.r, right, bytes);
            if (!verifier.verify_constant(&flag, uint64_t(expected)).verified())
                return false;
            ++checks;
        }
        return true;
    };
    for (unsigned x = 0; x < 256; ++x)
        for (unsigned y = 0; y < 256; ++y)
            if (!pair(1, x, y))
                return EXIT_FAILURE;
    for (int bytes : {2, 4, 8})
    {
        const uint64_t mask = chernobog::bitvector::mask(bytes);
        const uint64_t sign = uint64_t{1} << (8 * bytes - 1);
        const std::array<uint64_t, 8> corners{0, 1, 2, sign - 1, sign, sign + 1, mask - 1, mask};
        for (uint64_t x : corners)
            for (uint64_t y : corners)
                if (!pair(bytes, x, y))
                    return EXIT_FAILURE;
    }
    if (checks != 262912 || input.get() != std::char_traits<char>::eof())
        return EXIT_FAILURE;
    std::cout << "{\"passed\":true,\"native_flag_checks\":" << checks << "}\n";
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc == 3 && std::string(argv[1]) == "--native-flag-values")
        return verify_native_flags(argv[2]);
    if (argc == 2 && std::string(argv[1]) == "--matcher-input-fixtures")
        return export_matcher_inputs();
    if (argc == 2 && std::string(argv[1]) == "--ast-cycle-control")
    {
        ValueInsn cycle(m_add, 4);
        nested(cycle.l, cycle);
        const uint64_t hash = chernobog::ast::MopKey::hash_insn(&cycle);
        std::cout << "cyclic AST hash: " << hash << '\n';
        return hash == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
#ifndef CHERNOBOG_LEGACY_AST_BOUNDS
    if (!test_builder_bounds())
        return EXIT_FAILURE;
#endif
    if (!test_builder_value_identity())
        return EXIT_FAILURE;
    if (!test_typed_instances())
        return EXIT_FAILURE;
    if (!test_verifier_rejection_states())
        return EXIT_FAILURE;
    if (!test_ast_destruction())
    {
        std::cerr << "AST destruction regression\n";
        return EXIT_FAILURE;
    }

    if (!test_commutative_matching())
    {
        std::cerr << "commutative matcher regression\n";
        return EXIT_FAILURE;
    }
    if (!test_match_failure_witnesses())
        return EXIT_FAILURE;
    if (!test_input_capture_bounds())
        return EXIT_FAILURE;

    auto &registry = chernobog::rules::RuleRegistry::instance();
    {
        ValueInsn instruction(m_add, 4);
        reg(instruction.l, 100, 4);
        reg(instruction.r, 200, 4);
        const auto ignored = registry.find_match(&instruction);
        if (ignored.attempted || ignored.matched() || registry.total_matches() != 0)
        {
            std::cerr << "uninitialized registry cannot report an AST attempt\n";
            return EXIT_FAILURE;
        }
    }
    registry.initialize();
    if (registry.find_match(nullptr).attempted || registry.total_matches() != 0)
    {
        std::cerr << "null instruction cannot report an AST attempt\n";
        return EXIT_FAILURE;
    }
    std::cout << "MBA attempt admission controls: 2 passed\n";
    {
        ValueInsn instruction(m_add, 4), unindexed(m_shl, 4);
        reg(instruction.l, 100, 4);
        reg(instruction.r, 200, 4);
        reg(unindexed.l, 100, 4);
        reg(unindexed.r, 200, 1);
        const auto failed = registry.find_match(&instruction);
        const auto absent = registry.find_match(&unindexed);
        const auto names = registry.list_rules();
        if (!failed.attempted || failed.matched() ||
            failed.outcome != chernobog::mba_diagnostics::Outcome::StructuralMismatch ||
            failed.rejection_detail.find("match_failed;kind=") != 0 ||
            std::find(names.begin(), names.end(), failed.rejected_rule) == names.end() ||
            absent.matched() ||
            absent.outcome != chernobog::mba_diagnostics::Outcome::NoIndexedPattern ||
            absent.rejection_detail != "root_opcode_unindexed;opcode=" + std::to_string(m_shl) ||
            !absent.rejected_rule.empty())
            return EXIT_FAILURE;
        registry.clear_statistics();
        std::cout << "MBA failed pattern and unindexed root attribution: 2 passed\n";
    }
#ifndef CHERNOBOG_LEGACY_AST_BOUNDS
    {
        ValueInsn cycle(m_add, 4);
        nested(cycle.l, cycle);
        const auto rejected_ast = registry.find_match(&cycle);
        if (!rejected_ast.attempted || rejected_ast.matched() ||
            rejected_ast.outcome != chernobog::mba_diagnostics::Outcome::NoAst ||
            rejected_ast.rejection_detail != "cyclic_operand_payload" ||
            rejected_ast.indexed_patterns != 0 || !registry.find_all_matches(&cycle).empty())
            return EXIT_FAILURE;
        registry.clear_statistics();
        std::cout << "MBA bounded AST rejection attribution: passed\n";
    }
#endif

    const std::size_t registered = registry.rule_count();
    const std::size_t verified = registry.verified_rule_count();
    const std::size_t rejected = registry.rejected_rule_count();
    std::cout << "MBA catalog: " << registered << " registered, " << verified << " verified, "
              << rejected << " rejected\n";

    if (registered < 100 || verified != registered || rejected != 0)
    {
        // CI uses a separate correctness budget. Every production identity
        // must still prove; a timeout remains a failed test.
        std::cerr << "production catalog contains an unverified rule\n";
        return EXIT_FAILURE;
    }

    // A rejected pattern is destroyed during registry initialization, unlike
    // accepted patterns retained by storage. This deterministically exercises
    // the cleanup path that previously jumped through the SDK link stub.
    registry.register_rule(std::make_unique<RejectedCatalogRule>());
    const std::size_t erases_before_rebuild = empty_operand_erases;
    registry.reinitialize();
    std::cout << "MBA rejection control: " << registry.rule_count() << " registered, "
              << registry.verified_rule_count() << " verified, " << registry.rejected_rule_count()
              << " rejected\n";
    if (registry.rule_count() != registered + 1 || registry.verified_rule_count() != registered ||
        registry.rejected_rule_count() != 1 || registry.pattern_count() != registered ||
        empty_operand_erases <= erases_before_rebuild)
    {
        std::cerr << "rejection control failed: patterns=" << registry.pattern_count()
                  << ", erases before=" << erases_before_rebuild
                  << ", erases after=" << empty_operand_erases << '\n';
        return EXIT_FAILURE;
    }
    registry.clear();
    if (registry.rule_count() != 0 || registry.pattern_count() != 0 ||
        registry.verified_rule_count() != 0 || registry.rejected_rule_count() != 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
