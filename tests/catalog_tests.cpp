#include "deobf/rules/rule_registry.h"
#include "deobf/rules/rule_verifier.h"
#include "deobf/rules/rules_sub.h"
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
