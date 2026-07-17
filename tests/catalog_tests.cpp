#include "deobf/rules/rule_registry.h"
#include <cstdlib>
#include <iostream>

namespace {

using chernobog::ast::AstPtr;
using chernobog::ast::MatchBindings;
using chernobog::ast::make_leaf;
using chernobog::ast::make_node;
using chernobog::ast::match_pattern;

bool test_commutative_matching()
{
    // The standalone catalog executable has no initialized IDA kernel. Retain
    // SDK mop_t-owning ASTs and bindings for process lifetime so their IDA-side
    // destructors are not invoked after the test.
    static auto* retained_asts = new std::vector<AstPtr>();
    const auto retain = [&](const AstPtr& ast) {
        retained_asts->push_back(ast);
    };

    constexpr mcode_t commutative_ops[] = {m_add, m_mul, m_and, m_or, m_xor};
    for ( mcode_t op : commutative_ops )
    {
        AstPtr pattern = make_node(
            op, make_leaf("x"),
            make_node(m_sub, make_leaf("y"), make_leaf("z")));
        AstPtr candidate = make_node(
            op, make_node(m_sub, make_leaf("a"), make_leaf("b")),
            make_leaf("c"));
        retain(pattern);
        retain(candidate);

        auto* bindings = new MatchBindings();
        if ( !match_pattern(pattern.get(), candidate.get(), *bindings) ||
             bindings->count != 3 )
            return false;

        if ( !bindings->find("x") )
            return false;
    }

    // Exercise nested rollback: both XOR and AND require their swapped branch,
    // and the repeated x binding must survive both checkpoints.
    AstPtr nested_pattern = make_node(
        m_xor, make_leaf("x"),
        make_node(m_and, make_leaf("y"),
                  make_node(m_sub, make_leaf("z"), make_leaf("w"))));
    AstPtr nested_candidate = make_node(
        m_xor,
        make_node(m_and,
                  make_node(m_sub, make_leaf("a"), make_leaf("b")),
                  make_leaf("c")),
        make_leaf("d"));
    retain(nested_pattern);
    retain(nested_candidate);
    auto* nested_bindings = new MatchBindings();
    if ( !match_pattern(nested_pattern.get(), nested_candidate.get(),
                        *nested_bindings) ||
         nested_bindings->count != 4 )
        return false;

    // Subtraction is order-sensitive and must not take the commuted branch.
    AstPtr ordered_pattern = make_node(
        m_sub, make_leaf("x"),
        make_node(m_and, make_leaf("y"), make_leaf("x")));
    AstPtr reversed_candidate = make_node(
        m_sub, make_node(m_and, make_leaf("a"), make_leaf("b")),
        make_leaf("a"));
    retain(ordered_pattern);
    retain(reversed_candidate);
    auto* ordered_bindings = new MatchBindings();
    return !match_pattern(ordered_pattern.get(), reversed_candidate.get(),
                          *ordered_bindings) &&
           ordered_bindings->count == 0;
}

} // namespace

int main()
{
    if ( !test_commutative_matching() )
    {
        std::cerr << "commutative matcher regression\n";
        return EXIT_FAILURE;
    }

    auto& registry = chernobog::rules::RuleRegistry::instance();
    registry.initialize();

    const std::size_t registered = registry.rule_count();
    const std::size_t verified = registry.verified_rule_count();
    const std::size_t rejected = registry.rejected_rule_count();
    std::cout << "MBA catalog: " << registered << " registered, "
              << verified << " verified, " << rejected << " rejected\n";

    if ( registered < 100 || verified != registered || rejected != 0 )
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
