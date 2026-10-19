#include "byte_memory.hpp"
#include <algorithm>
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
        (bits != 8 && bits != 16 && bits != 32 && bits != 64 && bits != 128))
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
void ByteMemory::write(const z3::expr &address, const z3::expr &value, unsigned bits,
                       const AddressRanges &unchanged)
{
    validate(address, bits);
    auto &ctx = base_.ctx();
    if (&address.ctx() != &ctx || &value.ctx() != &ctx || !value.is_bv() ||
        value.get_sort().bv_size() != bits)
        throw std::invalid_argument("byte memory value/context mismatch");
    const auto at = simplify(address);
    if (unchanged.size() > 256)
        throw std::invalid_argument("unchanged memory range quota");
    for (const auto &[begin, end] : unchanged)
        if (begin >= end)
            throw std::invalid_argument("invalid unchanged memory range");
    uint64_t absolute = 0;
    if (at.is_numeral_u64(absolute))
    {
        for (unsigned offset = 0; offset < bits / 8; ++offset)
            for (const auto &[begin, end] : unchanged)
                if (absolute + offset >= begin && absolute + offset < end)
                    throw std::invalid_argument("concrete write violates no-overlap proof");
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
    auto retained = std::make_shared<Cells>();
    auto next = base_;
    for (const auto &[cell_address, cell] : *cells_)
    {
        const bool keep = std::any_of(
            unchanged.begin(), unchanged.end(), [position = cell_address](const auto &range)
            { return position >= range.first && position < range.second; });
        if (keep)
            retained->emplace(cell_address, cell);
        else
            next = z3::store(next, ctx.bv_val(cell_address, 64), cell);
    }
    for (unsigned offset = 0; offset < bits / 8; ++offset)
        next =
            z3::store(next, at + ctx.bv_val(offset, 64), value.extract(offset * 8 + 7, offset * 8));
    base_ = next;
    cells_ = std::move(retained);
}
z3::expr ByteMemory::materialize() const
{
    auto result = base_;
    auto &ctx = base_.ctx();
    for (const auto &[address, value] : *cells_)
        result = z3::store(result, ctx.bv_val(address, 64), value);
    return result;
}
void ByteMemory::repeat(const z3::expr &address, const z3::expr &bytes, const z3::expr &pattern,
                        const AddressRanges &unchanged)
{
    validate(address, 128);
    auto &ctx = base_.ctx();
    if (&address.ctx() != &ctx || &bytes.ctx() != &ctx || &pattern.ctx() != &ctx ||
        !bytes.is_bv() || bytes.get_sort().bv_size() != 64 || !pattern.is_bv() ||
        pattern.get_sort().bv_size() != 128 || unchanged.size() > 256)
        throw std::invalid_argument("invalid repeated byte store");
    for (const auto &[begin, end] : unchanged)
        if (begin >= end)
            throw std::invalid_argument("invalid unchanged memory range");
    auto retained = std::make_shared<Cells>();
    auto previous = base_;
    for (const auto &[at, value] : *cells_)
    {
        const bool keep =
            std::any_of(unchanged.begin(), unchanged.end(), [position = at](const auto &range)
                        { return position >= range.first && position < range.second; });
        if (keep)
            retained->emplace(at, value);
        else
            previous = z3::store(previous, ctx.bv_val(at, 64), value);
    }
    z3::expr index(ctx, Z3_mk_fresh_const(ctx, "repeat_index", ctx.bv_sort(64)));
    const auto offset = index - address;
    const auto shift = z3::zext((offset & ctx.bv_val(15, 64)) * ctx.bv_val(8, 64), 64);
    auto byte = z3::lshr(pattern, shift).extract(7, 0);
    const auto first = simplify(pattern.extract(7, 0));
    bool uniform = true;
    for (unsigned i = 1; i < 16; ++i)
        uniform = uniform && z3::eq(first, simplify(pattern.extract(i * 8 + 7, i * 8)));
    if (uniform)
        byte = first;
    base_ = z3::lambda(index, z3::ite(z3::ult(offset, bytes), byte, z3::select(previous, index)));
    cells_ = std::move(retained);
}
void ByteMemory::havoc(const z3::expr &address, const z3::expr &bytes, const z3::expr &fresh_array,
                       const std::vector<std::pair<uint64_t, uint64_t>> &excluded)
{
    validate(address, 8);
    validate(bytes, 8);
    auto &ctx = base_.ctx();
    if (&address.ctx() != &ctx || &bytes.ctx() != &ctx || &fresh_array.ctx() != &ctx ||
        !Z3_is_eq_sort(ctx, fresh_array.get_sort(), base_.get_sort()))
        throw std::invalid_argument("invalid byte memory havoc");
    if (excluded.size() > 256)
        throw std::invalid_argument("excluded memory range quota");
    z3::expr index(ctx, Z3_mk_fresh_const(ctx, "havoc_index", ctx.bv_sort(64)));
    auto affected = z3::ult(index - address, bytes);
    for (const auto &[begin, end] : excluded)
    {
        if (begin >= end)
            throw std::invalid_argument("invalid excluded memory range");
        affected = affected &&
                   !(z3::uge(index, ctx.bv_val(begin, 64)) && z3::ult(index, ctx.bv_val(end, 64)));
    }
    auto retained = std::make_shared<Cells>();
    auto previous = base_;
    for (const auto &[at, value] : *cells_)
    {
        const bool keep =
            std::any_of(excluded.begin(), excluded.end(), [position = at](const auto &range)
                        { return position >= range.first && position < range.second; });
        if (keep)
            retained->emplace(at, value);
        else
            previous = z3::store(previous, ctx.bv_val(at, 64), value);
    }
    auto next = z3::lambda(
        index, z3::ite(affected, z3::select(fresh_array, index), z3::select(previous, index)));
    base_ = std::move(next);
    cells_ = std::move(retained);
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
void ByteMemory::append_identity_roots(std::vector<z3::expr> &out) const
{
    out.push_back(base_);
    for (const auto &cell : *cells_)
        out.push_back(cell.second);
}
}
