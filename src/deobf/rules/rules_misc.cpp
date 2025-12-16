#include "rules_misc.h"

namespace chernobog {
namespace rules {

// Register all BNOT rules
REGISTER_MBA_RULE(Bnot_HackersDelightRule_1);
REGISTER_MBA_RULE(Bnot_HackersDelightRule_2);
REGISTER_MBA_RULE(Bnot_FactorRule_1);
REGISTER_MBA_RULE(Bnot_FactorRule_2);
REGISTER_MBA_RULE(BnotXor_Rule_1);
REGISTER_MBA_RULE(BnotXor_Rule_2);

// Register all NEG rules
REGISTER_MBA_RULE(Neg_HackersDelightRule_1);
REGISTER_MBA_RULE(Neg_HackersDelightRule_2);
REGISTER_MBA_RULE(NegSub_HackersDelightRule_1);
REGISTER_MBA_RULE(NegAdd_HackersDelightRule_1);
REGISTER_MBA_RULE(Neg_Rule_1);

// Register all MUL rules
REGISTER_MBA_RULE(Mul_Rule_1);
REGISTER_MBA_RULE(Mul_Rule_2);
REGISTER_MBA_RULE(Mul_Rule_3);
REGISTER_MBA_RULE(Mul_Rule_4);
REGISTER_MBA_RULE(Mul_FactorRule_1);
REGISTER_MBA_RULE(Mul_FactorRule_2);

// Register all Constant simplification rules
REGISTER_MBA_RULE(Const_AddZero);
REGISTER_MBA_RULE(Const_ZeroAdd);
REGISTER_MBA_RULE(Const_OrSelf);
REGISTER_MBA_RULE(Const_AndSelf);

} // namespace rules
} // namespace chernobog
