#pragma once

#include "mba_smt.hpp"

#include <map>
#include <set>

namespace chernobog::mba_smt
{
// Values refer to immutable symbol versions. Copies share the version allocator,
// so assignments in different branches cannot accidentally create equal symbols.
class ScalarContext
{
  public:
    using Bindings = std::map<int, Term>;

    explicit ScalarContext(std::vector<unsigned> local_widths);

    Term value(int local) const;
    bool derived(int local) const;
    void assign(int local, Term value);
    void forget(int local);
    void reset();
    void assume(Term condition, bool taken);
    void merge_from(const ScalarContext &other);

    const Bindings &bindings() const;
    const std::vector<Term> &conditions() const;

  private:
    std::vector<unsigned> widths_;
    std::shared_ptr<size_t> next_symbol_;
    Bindings bindings_;
    std::set<int> derived_;
    std::vector<Term> conditions_;
};

// Lower one expression and its path facts into an ordinary, immutable CFG.
// The entry edge supplies the assumptions; the existing inductive verifier must
// establish them at the rewrite site. No solver assertion bypasses that proof.
// Omitting conditions requires equality for every valuation of the bindings.
class ContextQuery
{
  public:
    ContextQuery(const ScalarContext &context, Term value, bool include_conditions = true);

    bool valid() const;
    const Program &program() const;
    size_t block() const;
    Term lower(const Term &value) const;
    Term restore(const Term &value) const;

  private:
    Program program_;
    std::map<size_t, size_t> symbols_;
    std::vector<Term> originals_;
    bool valid_ = false;
};
} // namespace chernobog::mba_smt
