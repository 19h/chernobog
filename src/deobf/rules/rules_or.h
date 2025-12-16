#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// OR Rules - MBA patterns that simplify to bitwise OR
//
// Mathematical identities:
//   x | y = (x & y) + (x ^ y)
//   x | y = (x + y) - (x & y)
//   x | y = ~(~x & ~y)
//   x | y = (x ^ y) | (x & y)
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Hacker's Delight OR Rules
//--------------------------------------------------------------------------

// (x & y) + (x ^ y) -> x | y
class Or_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return add(band(x_0(), x_1()), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

// (x + y) - (x & y) -> x | y
class Or_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return sub(add(x_0(), x_1()), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// MBA OR Rules
//--------------------------------------------------------------------------

// ~(~x & ~y) -> x | y (De Morgan)
class Or_MbaRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_MbaRule_1"; }

    AstPtr get_pattern() const override {
        return bnot(band(bnot(x_0()), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

// (x ^ y) | (x & y) -> x | y
class Or_MbaRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_MbaRule_2"; }

    AstPtr get_pattern() const override {
        return bor(bxor(x_0(), x_1()), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

// (x & y) | (x ^ y) -> x | y (commutative)
class Or_MbaRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_MbaRule_3"; }

    AstPtr get_pattern() const override {
        return bor(band(x_0(), x_1()), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Factor OR Rules
//--------------------------------------------------------------------------

// x | (x & y) -> x (absorption)
class Or_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return bor(x_0(), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// (x & y) | x -> x (absorption, commutative)
class Or_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return bor(band(x_0(), x_1()), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// (x | y) | (x & y) -> x | y
class Or_FactorRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_FactorRule_3"; }

    AstPtr get_pattern() const override {
        return bor(bor(x_0(), x_1()), band(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// OLLVM OR Rules
//--------------------------------------------------------------------------

// (~x & y) | (x & ~y) | (x & y) -> x | y
class Or_OllvmRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_OllvmRule_1"; }

    AstPtr get_pattern() const override {
        return bor(
            bor(band(bnot(x_0()), x_1()), band(x_0(), bnot(x_1()))),
            band(x_0(), x_1())
        );
    }

    AstPtr get_replacement() const override {
        return bor(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// OR with BNOT Factor Rules
//--------------------------------------------------------------------------

// ~x | ~y -> ~(x & y) (De Morgan)
class OrBnot_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "OrBnot_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return bor(bnot(x_0()), bnot(x_1()));
    }

    AstPtr get_replacement() const override {
        return bnot(band(x_0(), x_1()));
    }
};

// x | ~x -> -1 (all ones)
class OrBnot_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "OrBnot_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return bor(x_0(), bnot(x_0()));
    }

    AstPtr get_replacement() const override {
        return c_minus_1();
    }
};

// ~x | x -> -1 (all ones)
class OrBnot_FactorRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "OrBnot_FactorRule_3"; }

    AstPtr get_pattern() const override {
        return bor(bnot(x_0()), x_0());
    }

    AstPtr get_replacement() const override {
        return c_minus_1();
    }
};

//--------------------------------------------------------------------------
// Identity OR rules
//--------------------------------------------------------------------------

// x | x -> x
class Or_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_Rule_1"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return bor(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// x | 0 -> x
class Or_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_Rule_2"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return bor(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// x | -1 -> -1
class Or_Rule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Or_Rule_3"; }

    AstPtr get_pattern() const override {
        return bor(x_0(), make_named_const("c_minus_1"));
    }

    AstPtr get_replacement() const override {
        return c_minus_1();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_1");
        if (it == bindings.end()) return false;
        return is_minus_1(it->second);
    }
};

} // namespace rules
} // namespace chernobog
