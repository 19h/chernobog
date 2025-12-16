#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// AND Rules - MBA patterns that simplify to bitwise AND
//
// Mathematical identities:
//   x & y = (x + y) - (x | y)
//   x & y = (x | y) - (x ^ y)
//   x & y = (x | y) & ~(~x | ~y)
//   x & y = ~(~x | ~y)
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Hacker's Delight AND Rules
//--------------------------------------------------------------------------

// (x + y) - (x | y) -> x & y
class And_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return sub(add(x_0(), x_1()), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

// (x | y) - (x ^ y) -> x & y
class And_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return sub(bor(x_0(), x_1()), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

// ~(~x | ~y) -> x & y (De Morgan)
class And_HackersDelightRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_HackersDelightRule_3"; }

    AstPtr get_pattern() const override {
        return bnot(bor(bnot(x_0()), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

// (x ^ ~y) & x -> x & y (strange but valid)
class And_HackersDelightRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_HackersDelightRule_4"; }

    AstPtr get_pattern() const override {
        return band(bxor(x_0(), bnot(x_1())), x_0());
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// OLLVM AND Rules
//--------------------------------------------------------------------------

// (x | y) & ~(x ^ y) -> x & y
class And_OllvmRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_OllvmRule_1"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), x_1()), bnot(bxor(x_0(), x_1())));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

// ~(x ^ y) & (x | y) -> x & y (commutative)
class And_OllvmRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_OllvmRule_2"; }

    AstPtr get_pattern() const override {
        return band(bnot(bxor(x_0(), x_1())), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

// (~x | y) & (x | ~y) & (x | y) -> x & y
class And_OllvmRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_OllvmRule_3"; }

    AstPtr get_pattern() const override {
        return band(
            band(bor(bnot(x_0()), x_1()), bor(x_0(), bnot(x_1()))),
            bor(x_0(), x_1())
        );
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Factor AND Rules
//--------------------------------------------------------------------------

// x & (x | y) -> x (absorption)
class And_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return band(x_0(), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// (x | y) & x -> x (absorption, commutative)
class And_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), x_1()), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

//--------------------------------------------------------------------------
// AND with BNOT Factor Rules
//--------------------------------------------------------------------------

// ~x & ~y -> ~(x | y) (De Morgan)
class AndBnot_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndBnot_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return band(bnot(x_0()), bnot(x_1()));
    }

    AstPtr get_replacement() const override {
        return bnot(bor(x_0(), x_1()));
    }
};

// x & ~x -> 0
class AndBnot_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndBnot_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return band(x_0(), bnot(x_0()));
    }

    AstPtr get_replacement() const override {
        return c_0();
    }
};

// ~x & x -> 0
class AndBnot_FactorRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndBnot_FactorRule_3"; }

    AstPtr get_pattern() const override {
        return band(bnot(x_0()), x_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }
};

// (x ^ y) & ~y -> x & ~y
class AndBnot_FactorRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndBnot_FactorRule_4"; }

    AstPtr get_pattern() const override {
        return band(bxor(x_0(), x_1()), bnot(x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), bnot(x_1()));
    }
};

//--------------------------------------------------------------------------
// AND + OR Factor Rules
//--------------------------------------------------------------------------

// (x | y) & (x | ~y) -> x
class AndOr_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndOr_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return band(bor(x_0(), x_1()), bor(x_0(), bnot(x_1())));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

//--------------------------------------------------------------------------
// AND + XOR Factor Rules
//--------------------------------------------------------------------------

// (x ^ y) & (x | y) -> x & y... actually no, = x XOR y stuff
// This is tricky - let me use a valid one

// (x & y) & (x | y) -> x & y
class AndXor_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "AndXor_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return band(band(x_0(), x_1()), bor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return band(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Identity AND rules
//--------------------------------------------------------------------------

// x & x -> x
class And_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_Rule_1"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return band(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// x & 0 -> 0
class And_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_Rule_2"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return band(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "0", 0, 8);
    }
};

// x & -1 -> x (all ones)
class And_Rule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "And_Rule_3"; }

    AstPtr get_pattern() const override {
        return band(x_0(), make_named_const("c_minus_1"));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_1");
        if (it == bindings.end()) return false;
        return is_minus_1(it->second);
    }
};

} // namespace rules
} // namespace chernobog
