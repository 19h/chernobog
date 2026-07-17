#pragma once

#include "../analysis/ast.h"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <z3++.h>

namespace chernobog {
namespace rules {

// Semantic result for an MBA identity. Only VERIFIED rules are admitted to
// the runtime registry; every other state is fail-closed.
enum class RuleVerificationStatus {
    VERIFIED,
    DISPROVED,
    UNSUPPORTED,
    UNKNOWN,
};

struct RuleVerificationResult {
    RuleVerificationStatus status = RuleVerificationStatus::UNKNOWN;
    unsigned bit_width = 0;
    std::string detail;

    bool verified() const
    {
        return status == RuleVerificationStatus::VERIFIED;
    }
};

const char* rule_verification_status_name(RuleVerificationStatus status);

// Proves bitvector equivalence of a pattern and replacement at all operand
// widths accepted by the MBA rewriter (8, 16, 32, and 64 bits).
class RuleVerifier {
public:
    explicit RuleVerifier(unsigned timeout_ms = 250);

    RuleVerificationResult verify(const ast::AstPtr& pattern,
                                  const ast::AstPtr& replacement);

private:
    using VariableMap = std::unordered_map<std::string, z3::expr>;

    std::optional<z3::expr> translate(const ast::AstBase* expression,
                                     unsigned bit_width,
                                     const std::string& symbol_prefix,
                                     VariableMap& variables,
                                     std::string& error);
    std::optional<uint64_t> constant_value(const ast::AstConstant& constant,
                                           std::string& error) const;

    z3::context context_;
    z3::solver solver_;
    unsigned timeout_ms_;
};

} // namespace rules
} // namespace chernobog
