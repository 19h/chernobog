#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// Subtraction Rules - MBA patterns that simplify to subtraction
//
// Mathematical identities:
//   x - y = x + ~y + 1
//   x - y = (x ^ y) - 2*(~x & y)
//   x - y = x + (-y)
//   x - y = ~(~x + y)
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Hacker's Delight Subtraction Rules
//--------------------------------------------------------------------------

// x + ~y + 1 -> x - y
class Sub_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return add(add(x_0(), bnot(x_1())), c_1());
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

// ~(~x + y) -> x - y
class Sub_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return bnot(add(bnot(x_0()), x_1()));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

// (x ^ y) + 2*(x & ~y) -> x - y
class Sub_HackersDelightRule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_HackersDelightRule_3"; }

    AstPtr get_pattern() const override {
        return add(bxor(x_0(), x_1()), mul(c_2(), band(x_0(), bnot(x_1()))));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

// 2*(x & ~y) + (x ^ y) -> x - y (commutative)
class Sub_HackersDelightRule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_HackersDelightRule_4"; }

    AstPtr get_pattern() const override {
        return add(mul(c_2(), band(x_0(), bnot(x_1()))), bxor(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Subtraction by 1 Rules
//--------------------------------------------------------------------------

// ~(~x + 1) -> x - 1
class Sub1_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub1_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return bnot(add(bnot(x_0()), c_1()));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), c_1());
    }
};

// x + ~0 -> x - 1 (since ~0 = -1)
class Sub1_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub1_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return add(x_0(), make_named_const("c_minus_1"));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), c_1());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_1");
        if (it == bindings.end()) return false;
        return is_minus_1(it->second);
    }
};

//--------------------------------------------------------------------------
// Negation-based Subtraction Rules
//--------------------------------------------------------------------------

// x + (-y) -> x - y
class Sub_NegRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_NegRule_1"; }

    AstPtr get_pattern() const override {
        return add(x_0(), neg(x_1()));
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

// -y + x -> x - y
class Sub_NegRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_NegRule_2"; }

    AstPtr get_pattern() const override {
        return add(neg(x_1()), x_0());
    }

    AstPtr get_replacement() const override {
        return sub(x_0(), x_1());
    }
};

//--------------------------------------------------------------------------
// Special Constant Subtraction Rules
//--------------------------------------------------------------------------

// (x ^ y) + (-2)*(~x & y) -> x - y
class Sub_SpecialConstantRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_SpecialConstantRule_1"; }

    AstPtr get_pattern() const override {
        return add(bxor(x_0(), x_1()), mul(make_named_const("c_minus_2"), band(bnot(x_0()), x_1())));
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
// Identity Subtraction Rules
//--------------------------------------------------------------------------

// x - 0 -> x
class Sub_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_Rule_1"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return sub(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "0", 0, 8);
    }
};

// x - x -> 0
class Sub_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_Rule_2"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return sub(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }
};

// 0 - x -> -x
class Sub_Rule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Sub_Rule_3"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return sub(c_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return neg(x_0());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "0", 0, 8);
    }
};

} // namespace rules
} // namespace chernobog
