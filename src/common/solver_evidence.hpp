#pragma once
#include <z3++.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace chernobog::solver_evidence {
using Row = std::map<std::string, std::string>;
struct Origin
{
  int64_t database = -1;
  uint64_t function = UINT64_MAX, site = UINT64_MAX;
  int maturity = -1;
  const char *phase = "unknown";
  // Optional concrete-capture attribution. Zero revision means no such claim.
  uint64_t capture_revision = 0, run = 0, seed = 0, sequence = 0, transition_check = 0;
};
inline thread_local const Origin *origin = nullptr;
class Scope
{
  Origin value;
  const Origin *previous;
public:
  explicit Scope(Origin next) : value(next), previous(origin) { origin = &value; }
  ~Scope() { origin = previous; }
  Scope(const Scope &) = delete;
  Scope &operator=(const Scope &) = delete;
};
// A nested producer can provide a precise EA without inventing a function or
// stage when its caller did not establish one.
class SiteScope
{
  Origin value;
  const Origin *previous;
public:
  explicit SiteScope(uint64_t site) : value(origin ? *origin : Origin{}), previous(origin)
  { if (origin) { value.site = site; origin = &value; } }
  ~SiteScope() { origin = previous; }
  SiteScope(const SiteScope &) = delete;
  SiteScope &operator=(const SiteScope &) = delete;
};

struct Collector
{
  virtual ~Collector() = default;
  virtual bool accepts(const Origin &) = 0;
  virtual void publish(const Origin &, Row) = 0;
};
inline Collector *collector = nullptr;
inline constexpr size_t formula_limit = 16384, model_limit = 32;

inline std::string prefix(const char *value, size_t limit)
{
  if (!value) return {};
  size_t size = 0;
  while (size < limit && value[size]) ++size;
  return std::string(value, size);
}

inline bool printable_name(const std::string &name)
{
  return name.size() <= 128 && std::all_of(name.begin(), name.end(),
      [](unsigned char ch) { return ch >= 32 && ch < 127; });
}

// Count tree occurrences, not just shared AST nodes: an exponentially expanded
// DAG must not evade the printing budget. Quantifiers, arrays and wide sorts
// are recorded as omitted rather than serialized without a bound.
inline bool printable(const z3::expr &expression, size_t &visits, unsigned depth = 0)
{
  if (++visits > 512 || depth > 64 || !expression.is_app()) return false;
  if (!expression.is_bool() && (!expression.is_bv() || expression.get_sort().bv_size() > 64)) return false;
  const auto symbol = expression.decl().name();
  if (symbol.kind() == Z3_STRING_SYMBOL
    && !printable_name(prefix(Z3_get_symbol_string(expression.ctx(), symbol), 129))) return false;
  for (unsigned i = 0; i < expression.num_args(); ++i)
    if (!printable(expression.arg(i), visits, depth + 1)) return false;
  return true;
}

inline void describe(z3::solver &solver, const z3::check_result &result, Row &row)
{
  const auto assertions = solver.assertions();
  size_t visits = 0;
  bool bounded = assertions.size() <= 64;
  for (unsigned i = 0; bounded && i < assertions.size(); ++i)
    bounded = printable(assertions[i], visits);
  row["assertions"] = std::to_string(assertions.size());
  row["formula_complete"] = "false";
  if (bounded)
  {
    const std::string formula = solver.to_smt2();
    row["formula"] = formula.substr(0, formula_limit);
    row["formula_complete"] = formula.size() <= formula_limit ? "true" : "false";
    row["formula_status"] = formula.size() <= formula_limit ? "complete" : "text-limit";
  }
  else row["formula_status"] = "AST/sort/name budget rejected";
  row["model_interpretation"] = "symbolic assignment satisfying the recorded query; not a native input replay";
  if (result == z3::unknown)
    row["reason"] = prefix(solver.reason_unknown().c_str(), 512);
  if (result != z3::sat) return;
  const auto model = solver.get_model();
  row["model_constants"] = std::to_string(model.num_consts());
  row["model_functions_omitted"] = std::to_string(model.num_funcs());
  bool complete = model.num_consts() <= model_limit && model.num_funcs() == 0;
  size_t captured = 0;
  for (unsigned i = 0; i < model.num_consts() && i < model_limit; ++i)
  {
    const auto declaration = model.get_const_decl(i);
    const auto value = model.get_const_interp(declaration);
    visits = 0;
    if (!printable(value, visits) || (!value.is_numeral() && !value.is_true() && !value.is_false()))
    { complete = false; continue; }
    const auto symbol = declaration.name();
    const std::string name = symbol.kind() == Z3_STRING_SYMBOL
        ? prefix(Z3_get_symbol_string(solver.ctx(), symbol), 129) : symbol.str();
    if (!printable_name(name)) { complete = false; continue; }
    const std::string key = "model_" + std::to_string(captured++);
    row[key + "_symbol"] = name;
    row[key + "_sort"] = value.is_bool() ? "Bool" : "BV" + std::to_string(value.get_sort().bv_size());
    row[key + "_value"] = value.to_string();
  }
  row["model_constants_omitted"] = std::to_string(model.num_consts() - captured);
  row["model_complete"] = complete ? "true" : "false";
}

// Capture is observational. A collector/serialization failure cannot change
// the solver result, add assertions, make another query, or authorize a rewrite.
inline z3::check_result check(z3::solver &solver, const char *role,
                             const char *parameters = "caller configured; not captured")
{
  const auto start = std::chrono::steady_clock::now();
  const auto result = solver.check();
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start).count();
  try
  {
    if (collector && origin && collector->accepts(*origin))
    {
      Row row{{"role", role}, {"result", result == z3::sat ? "sat" : result == z3::unsat ? "unsat" : "unknown"},
              {"parameters", parameters}, {"elapsed_ns", std::to_string(elapsed)},
              {"z3_version", Z3_get_full_version()},
              {"applicability", "recorded formula only; current IR and native-input applicability not revalidated"}};
      try { describe(solver, result, row); }
      catch (...) { row["capture_error"] = "formula/model serialization failed"; }
      collector->publish(*origin, std::move(row));
    }
  }
  catch (...) { /* Inspection must not affect the analysis result. */ }
  return result;
}
} // namespace chernobog::solver_evidence
