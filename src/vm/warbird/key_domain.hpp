#pragma once
#include <z3++.h>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace chernobog::warbird
{
enum class KeyDomainStatus
{
    COMPLETE,
    UNSATISFIABLE,
    VALUE_LIMIT,
    SOLVER_UNKNOWN,
    INVALID,
};
struct KeyDomain
{
    KeyDomainStatus status = KeyDomainStatus::INVALID;
    std::vector<uint64_t> values;
    size_t queries = 0;
    bool complete() const { return status == KeyDomainStatus::COMPLETE; }
};
// Resolve every possible 64-bit key under domain. Finite ITE leaves propagated through pure
// bit-vector operations provide an algebraic cover; otherwise enumeration requires a final UNSAT
// check after blocking every returned value. A model prefix is never complete.
// Work is bounded by 4096 DAG nodes, 10000 constant evaluations, and
// max_values + 1 solver queries. Cartesian covers may include unreachable
// values; callers must retain the exact key-equality guard on every edge.
KeyDomain resolve_key_domain(const z3::expr &key, const z3::expr &domain, size_t max_values = 16,
                             unsigned timeout_ms = 50, unsigned resource_limit = 200000);
}
