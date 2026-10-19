#include "deobf/analysis/mba_smt_context.hpp"

#include <cstdio>

using namespace chernobog::mba_smt;

namespace
{
int failures = 0;

void check(bool condition, const char *description)
{
    if (!condition)
    {
        std::fprintf(stderr, "FAIL: %s\n", description);
        ++failures;
    }
}

Term equal(Term left, Term right)
{
    return expression(Op::Equal, std::move(left), std::move(right), 8);
}

Term query_constant(const ScalarContext &context, Term value)
{
    ContextQuery query(context, std::move(value));
    if (!query.valid())
    {
        return {};
    }
    Options options = Options::deep();
    options.max_invariants = 2;
    Analysis analysis(query.program(), options);
    return analysis.constant_value(query.block(), 0);
}

void test_symbolic_assignments()
{
    ScalarContext context({32, 32, 32});
    const Term original = context.value(0);
    context.assign(1, expression(Op::Xor, original, constant(0xA9, 32)));
    context.assign(2, context.value(1));
    Term result = query_constant(context, expression(Op::Xor, context.value(1), context.value(2)));
    check(result && result->value == 0, "symbolic copies retain the same value");

    context.assign(0, expression(Op::Add, original, constant(1, 32)));
    result = query_constant(context, expression(Op::Sub, context.value(0), original));
    check(result && result->value == 1, "reassignment retains the old symbol in derived values");
    check(!query_constant(context, expression(Op::Xor, context.value(0), context.value(1))),
          "different versions do not become equal");

    context.forget(1);
    check(!query_constant(context, expression(Op::Xor, context.value(1), context.value(2))),
          "an unknown write invalidates only the overwritten value");
}

void test_path_conditions()
{
    ScalarContext context({32, 32});
    const Term x = context.value(0);
    const Term y = context.value(1);
    context.assume(equal(x, y), true);
    Term result = query_constant(context, expression(Op::Xor, x, y));
    check(result && result->value == 0, "a dominating equality constrains a rewrite");

    context.assign(0, expression(Op::Add, x, constant(1, 32)));
    result = query_constant(context, expression(Op::Sub, context.value(0), y));
    check(result && result->value == 1, "path facts refer to the pre-assignment value");
    check(!query_constant(context, expression(Op::Xor, context.value(0), y)),
          "a path equality cannot silently constrain a new version");

    ScalarContext negative({32, 32});
    negative.assume(expression(Op::NotEqual, negative.value(0), negative.value(1), 8), false);
    result = query_constant(negative, expression(Op::Xor, negative.value(0), negative.value(1)));
    check(result && result->value == 0, "the false edge supplies the negated condition");

    ScalarContext bounded({32});
    bounded.assume(expression(Op::UnsignedLess, bounded.value(0), constant(256, 32), 8), true);
    result =
        query_constant(bounded, expression(Op::And, bounded.value(0), constant(0xFFFFFF00, 32)));
    check(result && result->value == 0, "unsigned ranges constrain observed high bits");

    bounded.assume(expression(Op::UnsignedLess, bounded.value(0), constant(256, 32), 8), false);
    check(!query_constant(bounded, bounded.value(0)),
          "an infeasible path does not authorize a vacuous rewrite");
}

void test_branch_merges()
{
    ScalarContext incoming({32, 32, 32});
    const Term shared = expression(Op::Xor, incoming.value(0), constant(0x56, 32));
    ScalarContext left = incoming;
    ScalarContext right = incoming;
    left.assign(1, shared);
    right.assign(1, shared);
    left.assign(2, constant(11, 32));
    right.assign(2, constant(42, 32));
    left.assume(equal(incoming.value(0), constant(7, 32)), true);
    right.assume(equal(incoming.value(0), constant(7, 32)), false);
    left.merge_from(right);

    Term result = query_constant(left, expression(Op::Xor, left.value(1), shared));
    check(result && result->value == 0, "equal incoming values survive a join");
    check(!query_constant(left, left.value(2)), "different incoming values remain unconstrained");
    check(left.conditions().empty(), "edge-specific assumptions do not escape their branch");

    ScalarContext common({32, 32});
    common.assume(equal(common.value(0), common.value(1)), true);
    ScalarContext branch = common;
    branch.assign(0, constant(13, 32));
    common.merge_from(branch);
    check(!query_constant(common, expression(Op::Xor, common.value(0), common.value(1))),
          "retained historical facts cannot constrain a merged replacement symbol");

    common.reset();
    check(common.conditions().empty(), "loop and label barriers discard path assumptions");
}

void test_compaction_and_emitted_proofs()
{
    ScalarContext context({32, 32});
    for (unsigned index = 0; index < 200; ++index)
    {
        context.forget(0);
    }
    const Term input = context.value(0);
    ContextQuery query(context, expression(Op::Xor, input, constant(0, 32)));
    check(query.valid() && query.program().widths.size() <= 3,
          "queries compact historical symbol identifiers");
    Analysis analysis(query.program(), Options::deep());
    const auto proposals = analysis.run();
    check(!proposals.empty(), "a contextual query can produce a nonconstant replacement");
    if (!proposals.empty())
    {
        const Term restored = query.restore(proposals.front().replacement);
        check(restored && key(restored) == key(input),
              "emission restores original symbol identities");
        check(analysis.verify(query.block(), 0, query.lower(restored)) == Verdict::Verified,
              "the emitted expression is proved in the same context");
    }

    ScalarContext widths({8, 64, 0});
    check(widths.value(0)->bits == 8 && widths.value(1)->bits == 64 && !widths.value(2),
          "unsupported locals cannot enter scalar expressions");
    widths.assign(0, constant(0, 64));
    check(widths.value(0)->bits == 8 && widths.value(0)->op == Op::Variable,
          "mismatched assignment widths become unknown");

    Term excessive = input;
    for (unsigned depth = 0; depth < limits::expression_depth + 2; ++depth)
    {
        excessive = expression(Op::Not, excessive);
    }
    ContextQuery oversized(context, excessive);
    check(!oversized.valid(), "query construction respects expression bounds");
}
} // namespace

int main()
{
    test_symbolic_assignments();
    test_path_conditions();
    test_branch_merges();
    test_compaction_and_emitted_proofs();
    std::printf("MBA contextual failures: %d\n", failures);
    return failures != 0;
}
