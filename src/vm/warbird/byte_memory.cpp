#include "byte_memory.hpp"
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
z3::expr simplify(const z3::expr &e)
{
    z3::params p(e.ctx());
    p.set("max_steps", 10000u);
    return e.simplify(p);
}
void validate(const z3::expr &address, unsigned bits)
{
    if (!address.is_bv() || address.get_sort().bv_size() != 64 ||
        (bits != 8 && bits != 16 && bits != 32 && bits != 64))
        throw std::invalid_argument("invalid byte memory address or width");
}
}
ByteMemory::ByteMemory(z3::context &ctx, size_t max_cells)
    : base_(ctx.constant("memory", ctx.array_sort(ctx.bv_sort(64), ctx.bv_sort(8)))),
      cells_(std::make_shared<Cells>()), max_cells_(max_cells)
{
    if (max_cells == 0 || max_cells > 65536)
        throw std::invalid_argument("invalid concrete byte quota");
}
void ByteMemory::unique()
{
    if (cells_.use_count() != 1)
        cells_ = std::make_shared<Cells>(*cells_);
}
z3::expr ByteMemory::read(const z3::expr &address, unsigned bits) const
{
    validate(address, bits);
    auto &ctx = base_.ctx();
    if (&address.ctx() != &ctx)
        throw std::invalid_argument("byte memory context mismatch");
    const auto at = simplify(address);
    uint64_t absolute = 0;
    const bool concrete = at.is_numeral_u64(absolute);
    // A symbolic read must see the complete overlay; reading the base alone
    // would lose aliases with earlier concrete stores.
    const auto array = concrete ? base_ : materialize();
    auto byte = [&](unsigned offset)
    {
        if (concrete)
        {
            auto cell = cells_->find(absolute + offset);
            if (cell != cells_->end())
                return cell->second;
        }
        return z3::select(array, at + ctx.bv_val(offset, 64));
    };
    auto result = byte(0);
    for (unsigned offset = 1; offset < bits / 8; ++offset)
        result = z3::concat(byte(offset), result);
    return simplify(result);
}
void ByteMemory::write(const z3::expr &address, const z3::expr &value, unsigned bits)
{
    validate(address, bits);
    auto &ctx = base_.ctx();
    if (&address.ctx() != &ctx || &value.ctx() != &ctx || !value.is_bv() ||
        value.get_sort().bv_size() != bits)
        throw std::invalid_argument("byte memory value/context mismatch");
    const auto at = simplify(address);
    uint64_t absolute = 0;
    if (at.is_numeral_u64(absolute))
    {
        size_t new_cells = 0;
        for (unsigned offset = 0; offset < bits / 8; ++offset)
            new_cells += cells_->count(absolute + offset) == 0;
        if (new_cells > max_cells_ - cells_->size())
            throw std::runtime_error("concrete byte memory quota");
        unique();
        for (unsigned offset = 0; offset < bits / 8; ++offset)
            cells_->insert_or_assign(absolute + offset,
                                     simplify(value.extract(offset * 8 + 7, offset * 8)));
        return;
    }
    // Commit all preceding concrete writes before an alias-unknown write.
    // Distinct byte addresses commute, so map order is semantically neutral.
    auto next = materialize();
    for (unsigned offset = 0; offset < bits / 8; ++offset)
        next =
            z3::store(next, at + ctx.bv_val(offset, 64), value.extract(offset * 8 + 7, offset * 8));
    base_ = next;
    cells_ = std::make_shared<Cells>();
}
z3::expr ByteMemory::materialize() const
{
    auto result = base_;
    auto &ctx = base_.ctx();
    for (const auto &[address, value] : *cells_)
        result = z3::store(result, ctx.bv_val(address, 64), value);
    return result;
}
void ByteMemory::append_identity(std::vector<unsigned> &out) const
{
    out.push_back(base_.id());
    out.push_back(unsigned(cells_->size()));
    for (const auto &[address, value] : *cells_)
    {
        out.push_back(unsigned(address));
        out.push_back(unsigned(address >> 32));
        out.push_back(value.id());
    }
}
}
