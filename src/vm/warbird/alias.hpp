#pragma once
#include <z3++.h>
#include <cstdint>
#include <map>
#include <tuple>
#include <utility>
#include <vector>

namespace chernobog::warbird
{
using AddressRanges = std::vector<std::pair<uint64_t, uint64_t>>;
// Regions are half-open. Adjacent/overlapping regions are merged.
AddressRanges merge_ranges(AddressRanges);
// Test the entire modular byte span, including wrap through address zero.
z3::expr overlaps(const z3::expr &address, unsigned bytes, const AddressRanges &);
// A zero-length symbolic span is empty. All arithmetic is modulo 2^64.
z3::expr overlaps(const z3::expr &address, const z3::expr &bytes, const AddressRanges &);
enum class AliasResult
{
    DISJOINT,
    MAY_ALIAS,
    UNKNOWN
};
class AliasOracle
{
    z3::context &context_;
    unsigned budget_;
    unsigned queries_ = 0;
    using Key = std::tuple<unsigned, unsigned, unsigned, AddressRanges>;
    // Keep AST references alive: numeric Z3 IDs alone can be recycled after
    // destruction and must never authenticate a cached no-alias proof.
    struct Entry
    {
        z3::expr address;
        z3::expr domain;
        AliasResult result;
    };
    std::map<Key, Entry> cache_;

  public:
    explicit AliasOracle(z3::context &context, unsigned budget = 256)
        : context_(context), budget_(budget)
    {
    }
    AliasResult classify(const z3::expr &address, unsigned bytes, const z3::expr &domain,
                         const AddressRanges &);
    unsigned queries() const { return queries_; }
};
}
