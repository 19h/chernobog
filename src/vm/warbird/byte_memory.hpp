#pragma once
#include "alias.hpp"
#include <z3++.h>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace chernobog::warbird
{
// Persistent byte-addressed memory. Concrete stores stay in a copy-on-write
// overlay. A symbolic store materializes every possibly aliased cell; only
// proven-disjoint cells can remain cached. No section-name rules,
// whole-word alias assumptions, or implicit zero initialization are used.
class ByteMemory
{
    using Cells = std::map<uint64_t, z3::expr>;
    z3::expr base_;
    std::shared_ptr<Cells> cells_;
    size_t max_cells_;
    void unique();

  public:
    explicit ByteMemory(z3::context &, size_t max_cells = 65536);
    z3::expr read(const z3::expr &address, unsigned bits) const;
    // `unchanged` requires a no-overlap proof under the caller's path domain.
    // Empty ranges retain the fully alias-aware default behavior.
    void write(const z3::expr &address, const z3::expr &value, unsigned bits,
               const AddressRanges &unchanged = {});
    // Repeat one 16-byte value over a modular byte interval. The caller proves
    // bytes is a multiple of 16 and that unchanged ranges are disjoint.
    void repeat(const z3::expr &address, const z3::expr &bytes, const z3::expr &pattern,
                const AddressRanges &unchanged = {});
    // Replace exactly a modular byte interval with fresh unconstrained bytes.
    // Required on allocation/reuse and free; existing contents are not zeros.
    // Half-open exclusions explicitly retain their contents. An allocation
    // model must constrain its returned region to be disjoint from them.
    void havoc(const z3::expr &address, const z3::expr &bytes, const z3::expr &fresh_array,
               const std::vector<std::pair<uint64_t, uint64_t>> &excluded = {});
    z3::expr materialize() const;
    // The same selector must be used for registers, flags and stack state.
    // Neither source snapshot is modified by this conditional memory join.
    static ByteMemory choose(const z3::expr &condition, const ByteMemory &left,
                             const ByteMemory &right);
    bool uses_context(const z3::context &context) const { return &base_.ctx() == &context; }
    size_t concrete_bytes() const { return cells_->size(); }
    // Collision-free structural identity for conservative state comparison.
    void append_identity(std::vector<unsigned> &) const;
    // Hold these roots while comparing their numeric IDs: Z3 may recycle an
    // ID after its last AST reference is released.
    void append_identity_roots(std::vector<z3::expr> &) const;
};
}
