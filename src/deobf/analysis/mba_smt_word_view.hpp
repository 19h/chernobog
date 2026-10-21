#pragma once

#include "mba_smt_internal.hpp"

namespace chernobog::mba_smt::detail
{
// A candidate-only view. Virtual values never enter Program, SMT evaluation,
// receipts or SDK emission: restore() must run before the complete-site proof.
class CobraWordView
{
  public:
    CobraWordView(const Term &source, SolverSession &session);
    const Term &input() const noexcept { return input_; }
    Term restore(const Term &candidate) const;
    bool certify(SymbolicProgram &program, const SymbolicState &state, const Term &candidate) const;
    bool lifted() const noexcept { return !atoms_.empty(); }
    static bool useful(const Term &source);

  private:
    Term input_;
    Term source_;
    std::vector<Term> atoms_;
    size_t first_virtual_ = 0;
};
} // namespace chernobog::mba_smt::detail
