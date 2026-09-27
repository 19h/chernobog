#pragma once

#include "../analysis/ast.h"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
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

struct ReplacementAttempt
{
    bool instance_checked = false;
    RuleVerificationResult verification;
};

const char *rule_verification_status_name(RuleVerificationStatus status);

struct InstanceRejectionCount
{
    RuleVerificationStatus status;
    unsigned bit_width;
    std::string detail;
    size_t count = 0;
};

struct InstanceVerificationStats
{
    size_t verified = 0, disproved = 0, unsupported = 0, unknown = 0;
    std::vector<InstanceRejectionCount> rejection_reasons;
    size_t unrecorded_rejections = 0;
};
// Process-local diagnostic counters, atomically snapshotted/reset under one
// lock. At most 32 distinct status/width/reason keys and 256 bytes per reason
// are retained. Unrecorded reasons still contribute to their status counters.
// These diagnostics are not persistent proof receipts or IR applicability.
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
    // inferred. Explicit loads remain independent inputs and must preserve
    // occurrence count, binary branches, selector/address, width and source EA.
    // Operand identities retain SDK value numbers and frame ownership.
    // Unsupported effects and widths reject the replacement.
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
