#pragma once

#include "../analysis/ast.h"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <z3++.h>

namespace chernobog
{
namespace rules
{

// Semantic result for an MBA identity. Only VERIFIED rules are admitted to
// the runtime registry; every other state is fail-closed.
enum class RuleVerificationStatus
{
    VERIFIED,
    DISPROVED,
    UNSUPPORTED,
    UNKNOWN,
};

struct RuleVerificationResult
{
    RuleVerificationStatus status = RuleVerificationStatus::UNKNOWN;
    unsigned bit_width = 0;
    std::string detail;

    bool verified() const { return status == RuleVerificationStatus::VERIFIED; }
};

const char *rule_verification_status_name(RuleVerificationStatus status);

struct InstanceVerificationStats
{
    size_t verified = 0, disproved = 0, unsupported = 0, unknown = 0;
};
// Process-local diagnostic counters; they are not persistent proof receipts.
InstanceVerificationStats instance_verification_stats();
void reset_instance_verification_stats();

// Proves bitvector equivalence of a pattern and replacement at all operand
// widths accepted by the MBA rewriter (8, 16, 32, and 64 bits).
class RuleVerifier
{
  public:
    // A nonzero resource limit bounds Z3 work independently of wall-clock
    // scheduling. Zero leaves Z3's resource policy unchanged.
    explicit RuleVerifier(unsigned timeout_ms = 250, unsigned resource_limit = 0);

    RuleVerificationResult verify(const ast::AstPtr &pattern, const ast::AstPtr &replacement);

    // Verify the instantiated, typed value trees at one program point. No
    // reaching-definition substitution or equality across memory writes is
    // inferred. Unsupported effects and widths reject the replacement.
    RuleVerificationResult verify_instance(const minsn_t *original, const minsn_t *replacement);

  private:
    RuleVerificationResult verify_instance_impl(const minsn_t *original,
                                                const minsn_t *replacement);
    using VariableMap = std::unordered_map<std::string, z3::expr>;

    std::optional<z3::expr> translate(const ast::AstBase *expression, unsigned bit_width,
                                      const std::string &symbol_prefix, VariableMap &variables,
                                      std::string &error);
    std::optional<uint64_t> constant_value(const ast::AstConstant &constant,
                                           std::string &error) const;

    z3::context context_;
    z3::solver solver_;
    unsigned timeout_ms_;
    unsigned resource_limit_;
};

} // namespace rules
} // namespace chernobog
