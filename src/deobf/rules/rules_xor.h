#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// XOR Rules - MBA patterns that simplify to XOR
//
// Mathematical identities:
//   x ^ y = (x | y) - (x & y)
//   x ^ y = (x | y) & (~x | ~y)
//   x ^ y = (~x & y) | (x & ~y)
//   x ^ y = (x + y) - 2*(x & y)
//   x ^ y = 2*(x | y) - (x + y)
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Hacker's Delight XOR Rules
//--------------------------------------------------------------------------

// (x | y) - (x & y) -> x ^ y
class Xor_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return sub(bor(x_0(), x_1()), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// (x | y) & (~x | ~y) -> x ^ y
class Xor_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), x_1()), bor(bnot(x_0()), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// (~x & y) | (x & ~y) -> x ^ y (standard definition)
class Xor_HackersDelightRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_HackersDelightRule_3"; }

    AstPtr get_pattern() const override {
        return bor(band(bnot(x_0()), x_1()), band(x_0(), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// (x + y) - 2*(x & y) -> x ^ y
class Xor_HackersDelightRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_HackersDelightRule_4"; }

    AstPtr get_pattern() const override {
        return sub(add(x_0(), x_1()), mul(c_2(), band(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// 2*(x | y) - (x + y) -> x ^ y
class Xor_HackersDelightRule_5 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_HackersDelightRule_5"; }

    AstPtr get_pattern() const override {
        return sub(mul(c_2(), bor(x_0(), x_1())), add(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// MBA XOR Rules
//--------------------------------------------------------------------------

// (x | y) & ~(x & y) -> x ^ y
class Xor_MbaRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_MbaRule_1"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), x_1()), bnot(band(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// ~(x & y) & (x | y) -> x ^ y (commutative variant)
class Xor_MbaRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_MbaRule_2"; }

    AstPtr get_pattern() const override {
        return band(bnot(band(x_0(), x_1())), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// ~(~x | ~y) | ~(x | y) -> x ^ y (De Morgan variant)
class Xor_MbaRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_MbaRule_3"; }

    AstPtr get_pattern() const override {
        return bor(bnot(bor(bnot(x_0()), bnot(x_1()))), bnot(bor(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Factor XOR Rules
//--------------------------------------------------------------------------

// (x & ~y) | (~x & y) -> x ^ y (variant ordering)
class Xor_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return bor(band(x_0(), bnot(x_1())), band(bnot(x_0()), x_1()));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// ~(x | y) | (x & y) -> ~(x ^ y)
class Xor_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return bor(bnot(bor(x_0(), x_1())), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

// (x & y) | ~(x | y) -> ~(x ^ y) (commutative)
class Xor_FactorRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_FactorRule_3"; }

    AstPtr get_pattern() const override {
        return bor(band(x_0(), x_1()), bnot(bor(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

//--------------------------------------------------------------------------
// OLLVM XOR Rules
//--------------------------------------------------------------------------

// (~x | y) & (x | ~y) -> ~(x ^ y)
class Xor_OllvmRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_OllvmRule_1"; }

    AstPtr get_pattern() const override {
        return band(bor(bnot(x_0()), x_1()), bor(x_0(), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

// (x | ~y) & (~x | y) -> ~(x ^ y) (commutative)
class Xor_OllvmRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_OllvmRule_2"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), bnot(x_1())), bor(bnot(x_0()), x_1()));
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

// ~(~x & ~y) & ~(x & y) -> x ^ y
class Xor_OllvmRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_OllvmRule_3"; }

    AstPtr get_pattern() const override {
        return band(bnot(band(bnot(x_0()), bnot(x_1()))), bnot(band(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Special constant XOR Rules
//--------------------------------------------------------------------------

// (x + y) + (-2)*(x & y) -> x ^ y
class Xor_SpecialConstantRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_SpecialConstantRule_1"; }

    AstPtr get_pattern() const override {
        return add(add(x_0(), x_1()), mul(make_named_const("c_minus_2"), band(x_0(), x_1())));
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

// (x | y) + (-1)*(x & y) -> x ^ y
class Xor_SpecialConstantRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_SpecialConstantRule_2"; }

    AstPtr get_pattern() const override {
        return add(bor(x_0(), x_1()), mul(make_named_const("c_minus_1"), band(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_1");
        if (it == bindings.end()) return false;
        return is_minus_1(it->second);
    }
};

//--------------------------------------------------------------------------
// Additional XOR rules
//--------------------------------------------------------------------------

// ~x ^ ~y -> x ^ y (double negation in XOR)
class Xor_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_Rule_1"; }

    AstPtr get_pattern() const override {
        return bxor(bnot(x_0()), bnot(x_1()));
    }

    AstPtr get_replacement() const override {
        return bxor(x_0(), x_1());
    }
};

// x ^ 0 -> x
class Xor_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_Rule_2"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return bxor(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// x ^ x -> 0
class Xor_Rule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Xor_Rule_3"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return bxor(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }
};

} // namespace rules
} // namespace chernobog
