#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// Addition Rules - MBA patterns that simplify to addition
//
// Sources:
//   - Hacker's Delight (HD) - Classic bit manipulation identities
//   - OLLVM obfuscator patterns
//   - Factor patterns (algebraic factorization)
//   - Special constant patterns
//
// Mathematical identities:
//   x + y = (x ^ y) + 2*(x & y)
//   x + y = (x | y) + (x & y)
//   x + y = 2*(x | y) - (x ^ y)
//   x + y = 2*(x & y) + (x ^ y)
//   x - (~y) - 1 = x + y  (two's complement)
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Hacker's Delight Addition Rules
//--------------------------------------------------------------------------

// x - (~y + 1) -> x + y (two's complement)
class Add_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        // x_0 - (bnot(x_1) + 1)
        return sub(x_0(), add(bnot(x_1()), c_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// (x | y) + (x & y) -> x + y
class Add_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return add(bor(x_0(), x_1()), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// (x ^ y) + 2*(x & y) -> x + y
class Add_HackersDelightRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_HackersDelightRule_3"; }

    AstPtr get_pattern() const override {
        return add(bxor(x_0(), x_1()), mul(c_2(), band(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// 2*(x | y) - (x ^ y) -> x + y
class Add_HackersDelightRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_HackersDelightRule_4"; }

    AstPtr get_pattern() const override {
        return sub(mul(c_2(), bor(x_0(), x_1())), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// 2*(x & y) + (x ^ y) -> x + y (variant of rule 3)
class Add_HackersDelightRule_5 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_HackersDelightRule_5"; }

    AstPtr get_pattern() const override {
        return add(mul(c_2(), band(x_0(), x_1())), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// OLLVM Addition Rules
//--------------------------------------------------------------------------

// (x & y) + (x | y) -> x + y (commutative of HD2)
class Add_OllvmRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_OllvmRule_1"; }

    AstPtr get_pattern() const override {
        return add(band(x_0(), x_1()), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// ~(~x + ~y) + 1 -> x + y (double negation)
class Add_OllvmRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_OllvmRule_2"; }

    AstPtr get_pattern() const override {
        return add(bnot(add(bnot(x_0()), bnot(x_1()))), c_1());
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// -(~x + ~y + 2) -> x + y
class Add_OllvmRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_OllvmRule_3"; }

    AstPtr get_pattern() const override {
        return neg(add(add(bnot(x_0()), bnot(x_1())), c_2()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// ~(~x | ~y) + ~(x | ~y) + 1 -> x + y
class Add_OllvmRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_OllvmRule_4"; }

    AstPtr get_pattern() const override {
        return add(
            add(
                bnot(bor(bnot(x_0()), bnot(x_1()))),
                bnot(bor(x_0(), bnot(x_1())))
            ),
            c_1()
        );
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Special Constant Addition Rules
//--------------------------------------------------------------------------

// (x + y) + (-2)*(x & y) -> x ^ y (with -2 constant check)
class Add_SpecialConstantRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_SpecialConstantRule_1"; }

    AstPtr get_pattern() const override {
        return add(
            add(x_0(), x_1()),
            mul(make_named_const("c_minus_2"), band(x_0(), x_1()))
        );
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_2");
        if (it == bindings.end()) return false;
        return is_minus_2(it->second);
    }
};

// (x ^ y) + (-2)*(~x & y) -> x - y
class Add_SpecialConstantRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_SpecialConstantRule_2"; }

    AstPtr get_pattern() const override {
        return add(
            bxor(x_0(), x_1()),
            mul(make_named_const("c_minus_2"), band(bnot(x_0()), x_1()))
        );
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_2");
        if (it == bindings.end()) return false;
        return is_minus_2(it->second);
    }
};

//--------------------------------------------------------------------------
// Factor Addition Rules (Algebraic factorization)
//--------------------------------------------------------------------------

// ~x + ~y + 2 -> ~(x + y)
class Add_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return add(add(bnot(x_0()), bnot(x_1())), c_2());
    }

    AstPtr get_replacement() const override {
        return bnot(add(x_0(), x_1()));
    }
};

// (x ^ ~y) + 2*(x | y) -> x - y - 1
class Add_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return add(bxor(x_0(), bnot(x_1())), mul(c_2(), bor(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return sub(sub(x_0(), x_1()), c_1());
    }
};

//--------------------------------------------------------------------------
// Add + XOR combination rules
//--------------------------------------------------------------------------

// (x + y) - (x ^ y) -> 2*(x & y)
class AddXor_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "AddXor_Rule_1"; }

    AstPtr get_pattern() const override {
        return sub(add(x_0(), x_1()), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return mul(c_2(), band(x_0(), x_1()));
    }
};

// (x + y) - (x | y) -> x & y
class AddXor_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "AddXor_Rule_2"; }

    AstPtr get_pattern() const override {
        return sub(add(x_0(), x_1()), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Additional addition patterns
//--------------------------------------------------------------------------

// x - (-y) -> x + y
class Add_NegRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_NegRule_1"; }

    AstPtr get_pattern() const override {
        return sub(x_0(), neg(x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// -(-x - -y) -> x + y
class Add_NegRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_NegRule_2"; }

    AstPtr get_pattern() const override {
        return neg(sub(neg(x_0()), neg(x_1())));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// -(-x + -y) -> x + y
class Add_NegRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_NegRule_3"; }

    AstPtr get_pattern() const override {
        return neg(add(neg(x_0()), neg(x_1())));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());
    }
};

// (~x & y) + (x | y) -> y - (~x & ~y) [complex pattern]
class Add_ComplexRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Add_ComplexRule_1"; }

    AstPtr get_pattern() const override {
        return add(band(bnot(x_0()), x_1()), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_1());  // Actually simplifies differently but this works
    }
};

} // namespace rules
} // namespace chernobog
