#pragma once
#include "pattern_rule.h"
#include "rule_registry.h"

//--------------------------------------------------------------------------
// Miscellaneous Rules - BNOT, NEG, MUL, and Constant simplification
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//==========================================================================
// BNOT (Bitwise NOT) Rules
//==========================================================================

// ~~x -> x (double negation)
class Bnot_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Bnot_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return bnot(bnot(x_0()));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// -x - 1 -> ~x
class Bnot_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Bnot_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return sub(neg(x_0()), c_1());
    }

    AstPtr get_replacement() const override {
        return bnot(x_0());
    }
};

// ~(x - 1) -> -x
class Bnot_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Bnot_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return bnot(sub(x_0(), c_1()));
    }

    AstPtr get_replacement() const override {
        return neg(x_0());
    }
};

// ~(x + 1) -> -x - 2
class Bnot_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Bnot_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return bnot(add(x_0(), c_1()));
    }

    AstPtr get_replacement() const override {
        return sub(neg(x_0()), c_2());
    }
};

// ~x ^ y -> ~(x ^ y) when y is -1
// Actually: x ^ ~y -> ~(x ^ y)
class BnotXor_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "BnotXor_Rule_1"; }

    AstPtr get_pattern() const override {
        return bxor(bnot(x_0()), x_1());
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

// x ^ ~y -> ~(x ^ y)
class BnotXor_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "BnotXor_Rule_2"; }

    AstPtr get_pattern() const override {
        return bxor(x_0(), bnot(x_1()));
    }

    AstPtr get_replacement() const override {
        return bnot(bxor(x_0(), x_1()));
    }
};

//==========================================================================
// NEG (Negation) Rules
//==========================================================================

// -(-x) -> x (double negation)
class Neg_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Neg_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return neg(neg(x_0()));
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// ~x + 1 -> -x
class Neg_HackersDelightRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Neg_HackersDelightRule_2"; }

    AstPtr get_pattern() const override {
        return add(bnot(x_0()), c_1());
    }

    AstPtr get_replacement() const override {
        return neg(x_0());
    }
};

// -(x - y) -> y - x
class NegSub_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "NegSub_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return neg(sub(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return sub(x_1(), x_0());
    }
};

// -(x + y) -> -x - y
class NegAdd_HackersDelightRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "NegAdd_HackersDelightRule_1"; }

    AstPtr get_pattern() const override {
        return neg(add(x_0(), x_1()));
    }

    AstPtr get_replacement() const override {
        return sub(neg(x_0()), x_1());
    }
};

// -0 -> 0
class Neg_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Neg_Rule_1"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return neg(c_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_0", 0, 8);
    }
};

//==========================================================================
// MUL (Multiplication) Rules
//==========================================================================

// x * 0 -> 0
class Mul_Rule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_Rule_1"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return mul(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return c_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_0", 0, 8);
    }
};

// x * 1 -> x
class Mul_Rule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_Rule_2"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return mul(x_0(), c_1());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_1", 1, 8);
    }
};

// x * 2 -> x + x
class Mul_Rule_3 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_Rule_3"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return mul(x_0(), c_2());
    }

    AstPtr get_replacement() const override {
        return add(x_0(), x_0());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_2", 2, 8);
    }
};

// x * (-1) -> -x
class Mul_Rule_4 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_Rule_4"; }

    AstPtr get_pattern() const override {
        return mul(x_0(), make_named_const("c_minus_1"));
    }

    AstPtr get_replacement() const override {
        return neg(x_0());
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        auto it = bindings.find("c_minus_1");
        if (it == bindings.end()) return false;
        return is_minus_1(it->second);
    }
};

// (-x) * y -> -(x * y)
class Mul_FactorRule_1 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_FactorRule_1"; }

    AstPtr get_pattern() const override {
        return mul(neg(x_0()), x_1());
    }

    AstPtr get_replacement() const override {
        return neg(mul(x_0(), x_1()));
    }
};

// (-x) * (-y) -> x * y
class Mul_FactorRule_2 : public PatternMatchingRule {
public:
    const char* name() const override { return "Mul_FactorRule_2"; }

    AstPtr get_pattern() const override {
        return mul(neg(x_0()), neg(x_1()));
    }

    AstPtr get_replacement() const override {
        return mul(x_0(), x_1());
    }
};

//==========================================================================
// Constant Simplification Rules
//==========================================================================

// These handle cascaded operations that evaluate to constants

// x + 0 -> x
class Const_AddZero : public PatternMatchingRule {
public:
    const char* name() const override { return "Const_AddZero"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return add(x_0(), c_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_0", 0, 8);
    }
};

// 0 + x -> x
class Const_ZeroAdd : public PatternMatchingRule {
public:
    const char* name() const override { return "Const_ZeroAdd"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return add(c_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }

    bool check_constants(const std::map<std::string, mop_t>& bindings) override {
        return check_const_value(bindings, "c_0", 0, 8);
    }
};

// x | x -> x (duplicate)
class Const_OrSelf : public PatternMatchingRule {
public:
    const char* name() const override { return "Const_OrSelf"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return bor(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

// x & x -> x (duplicate)
class Const_AndSelf : public PatternMatchingRule {
public:
    const char* name() const override { return "Const_AndSelf"; }

    bool fuzz_pattern() const override { return false; }

    AstPtr get_pattern() const override {
        return band(x_0(), x_0());
    }

    AstPtr get_replacement() const override {
        return x_0();
    }
};

} // namespace rules
} // namespace chernobog
