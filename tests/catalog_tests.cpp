#include "deobf/rules/rule_registry.h"
#include "deobf/rules/rule_verifier.h"
#include "deobf/rules/rules_sub.h"
#include <cstdarg>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace
{

using chernobog::ast::AstPtr;
using chernobog::ast::MatchBindings;
using chernobog::ast::make_leaf;
using chernobog::ast::make_node;
using chernobog::ast::match_pattern;

std::size_t empty_operand_erases = 0;

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
    // The SDK's link stub is not an initialized Hex-Rays runtime. Catalog
    // patterns own only empty SDK operands; emulate precisely their cleanup
    // and fail on any operation that would require real decompiler behavior.
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

bool test_typed_instances()
{
    using namespace chernobog::rules;
    RuleVerifier verifier;
    const auto expect =
        [&](minsn_t &before, minsn_t &after, RuleVerificationStatus status, const char *label)
    {
        const auto result = verifier.verify_instance(&before, &after);
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
    if (okay)
        std::cout << "MBA typed instances: 25 positive/negative controls passed\n";
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

} // namespace

int main()
{
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

    auto &registry = chernobog::rules::RuleRegistry::instance();
    registry.initialize();

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
