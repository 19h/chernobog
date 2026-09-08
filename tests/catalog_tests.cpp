#include "deobf/rules/rule_registry.h"
#include <cstdarg>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {

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
    // The SDK's link stub is not an initialized Hex-Rays runtime. Catalog
    // patterns own only empty SDK operands; emulate precisely their cleanup
    // and fail on any operation that would require real decompiler behavior.
    if ( code != hx_mop_t_erase )
    {
        std::cerr << "unsupported catalog SDK operation: " << code << '\n';
        std::abort();
    }
    va_list arguments;
    va_start(arguments, code);
    mop_t *operand = va_arg(arguments, mop_t *);
    va_end(arguments);
    if ( operand == nullptr || operand->t != mop_z )
    {
        std::cerr << "catalog SDK erase requires a nonnull empty operand\n";
        std::abort();
    }
    operand->zero();
    ++empty_operand_erases;
    return nullptr;
}

namespace {

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

bool test_commutative_matching()
{
    constexpr mcode_t commutative_ops[] = {m_add, m_mul, m_and, m_or, m_xor};
    for ( mcode_t op : commutative_ops )
    {
        AstPtr pattern = make_node(
            op, make_leaf("x"),
            make_node(m_sub, make_leaf("y"), make_leaf("z")));
        AstPtr candidate = make_node(
            op, make_node(m_sub, make_leaf("a"), make_leaf("b")),
            make_leaf("c"));
        MatchBindings bindings;
        if ( !match_pattern(pattern.get(), candidate.get(), bindings) ||
             bindings.count != 3 )
            return false;

        if ( !bindings.find("x") )
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
    MatchBindings nested_bindings;
    if ( !match_pattern(nested_pattern.get(), nested_candidate.get(),
                        nested_bindings) ||
         nested_bindings.count != 4 )
        return false;

    // Subtraction is order-sensitive and must not take the commuted branch.
    AstPtr ordered_pattern = make_node(
        m_sub, make_leaf("x"),
        make_node(m_and, make_leaf("y"), make_leaf("x")));
    AstPtr reversed_candidate = make_node(
        m_sub, make_node(m_and, make_leaf("a"), make_leaf("b")),
        make_leaf("a"));
    MatchBindings ordered_bindings;
    return !match_pattern(ordered_pattern.get(), reversed_candidate.get(),
                          ordered_bindings) &&
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
    for ( int depth = 0; depth < 64; ++depth )
    {
        AstPtr tree = make_node(
            m_xor, make_leaf("x"),
            make_node(m_add, make_leaf("y"), make_leaf("z")));
        if ( !tree )
            return false;
    }

    try
    {
        AstPtr tree = make_node(m_add, make_leaf("x"), make_leaf("y"));
        if ( !tree )
            return false;
        throw std::runtime_error("unwind past a live AST");
    }
    catch ( const std::runtime_error & )
    {
    }
    return true;
}

} // namespace

int main()
{
    if ( !test_ast_destruction() )
    {
        std::cerr << "AST destruction regression\n";
        return EXIT_FAILURE;
    }

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
    {
        // Keep production verification budgets and fail-closed behavior. A
        // solver timeout remains a failed test rather than an SDK-stub crash.
        return EXIT_FAILURE;
    }

    // A rejected pattern is destroyed during registry initialization, unlike
    // accepted patterns retained by storage. This deterministically exercises
    // the cleanup path that previously jumped through the SDK link stub.
    registry.register_rule(std::make_unique<RejectedCatalogRule>());
    const std::size_t erases_before_rebuild = empty_operand_erases;
    registry.reinitialize();
    std::cout << "MBA rejection control: " << registry.rule_count()
              << " registered, " << registry.verified_rule_count()
              << " verified, " << registry.rejected_rule_count() << " rejected\n";
    if ( registry.rule_count() != registered + 1
      || registry.verified_rule_count() != registered
      || registry.rejected_rule_count() != 1
      || registry.pattern_count() != registered
      || empty_operand_erases <= erases_before_rebuild )
    {
        return EXIT_FAILURE;
    }
    registry.clear();
    if ( registry.rule_count() != 0 || registry.pattern_count() != 0
      || registry.verified_rule_count() != 0 || registry.rejected_rule_count() != 0 )
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
