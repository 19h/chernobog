#pragma once
#include <z3++.h>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace chernobog::warbird
{
// Persistent byte-addressed memory. Concrete stores stay in a copy-on-write
// overlay. A symbolic store materializes that overlay before entering the base
// array, preserving ordering and every possible alias. No section-name rules,
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
    void write(const z3::expr &address, const z3::expr &value, unsigned bits);
    z3::expr materialize() const;
    size_t concrete_bytes() const { return cells_->size(); }
    // Collision-free structural identity for conservative state comparison.
    void append_identity(std::vector<unsigned> &) const;
};
}
