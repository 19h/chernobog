#pragma once

#include "bitvector.h"

#include <algorithm>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

namespace chernobog::finite_domain
{

// A bounded, correlated expression domain. Unknown scalar subexpressions may
// be overapproximated, but repeated nodes always denote the same value. No
// sample is accepted as a proof: every assignment must be evaluated.
enum class Op
{
    constant,
    variable,
    low,
    sign_extend,
    add,
    sub,
    mul,
    bit_and,
    bit_or,
    bit_xor,
    shl,
    shr,
    sar,
    bit_not,
    neg,
    logical_not,
    load,
};

using Id = size_t;
constexpr Id invalid = size_t(-1);

struct Node
{
    Op op;
    int bytes;
    Id left = invalid;
    Id right = invalid;
    uint64_t value = 0;
    bool table = false;
};

struct Values
{
    std::vector<Id> inputs;
    // Lexicographic assignments, lowest numbered input varying fastest.
    std::vector<uint64_t> results;
};

class Graph
{
  public:
    using Reader = std::function<std::optional<uint64_t>(uint64_t, int)>;
    explicit Graph(Reader reader) : reader_(std::move(reader)) {}

    static constexpr size_t maximum_nodes = 4096;
    static constexpr size_t maximum_assignments = 256;
    static constexpr size_t maximum_work = 2000000;

    Id constant(uint64_t value, int bytes)
    {
        return intern({Op::constant, bytes, invalid, invalid, mask(value, bytes)});
    }

    // token identifies the source value, bits its independently variable bits.
    Id variable(uint64_t token, int bytes, unsigned bits)
    {
        return intern({Op::variable, bytes, invalid, Id(bits), token});
    }

    Id make(Op op, int bytes, Id left, Id right = invalid, uint64_t extra = 0)
    {
        if (failed_ || left == invalid || (binary(op) && right == invalid) ||
            !bitvector::valid_byte_width(bytes))
            return invalid;
        if (left == right && (op == Op::bit_xor || op == Op::sub))
            return constant(0, bytes);
        if (left == right && (op == Op::bit_and || op == Op::bit_or))
            return make(Op::low, bytes, left);
        if (op == Op::low && nodes_[left].bytes == bytes)
            return left;

        Node node{op, bytes, left, right, extra};
        node.table =
            op == Op::load || nodes_[left].table || (right != invalid && nodes_[right].table);
        const Id id = intern(node);
        if (id == invalid)
            return id;
        if (const auto value = constant_value(id))
            return constant(*value, bytes);

        // Abstract pure byte arithmetic as one byte, without abstracting away
        // any lookup relation. This bounds (a-b)*k before T[u] ^ u to 256
        // assignments even if a and b have arbitrarily wide runtime values.
        if (bytes == 1 && !node.table)
            return variable(uint64_t(id) | (uint64_t{1} << 63), bytes, 8);
        return id;
    }

    std::optional<uint64_t> literal(Id id) const
    {
        if (id != invalid && nodes_[id].op == Op::constant)
            return nodes_[id].value;
        return std::nullopt;
    }

    std::optional<Values> enumerate(Id root)
    {
        if (root == invalid || failed_)
            return std::nullopt;
        std::set<Id> inputs;
        std::set<Id> visited;
        collect(root, inputs, visited);
        size_t count = 1;
        for (Id input : inputs)
        {
            const unsigned bits = unsigned(nodes_[input].right);
            if (bits > 8 || count > maximum_assignments / (size_t{1} << bits))
                return std::nullopt;
            count *= size_t{1} << bits;
        }
        Values values{{inputs.begin(), inputs.end()}, {}};
        values.results.reserve(count);
        for (size_t assignment = 0; assignment < count; ++assignment)
        {
            std::map<Id, uint64_t> cache;
            size_t remaining = assignment;
            for (Id input : inputs)
            {
                const size_t domain = size_t{1} << unsigned(nodes_[input].right);
                cache[input] = remaining % domain;
                remaining /= domain;
            }
            const auto value = evaluate(root, cache);
            if (!value)
                return std::nullopt;
            values.results.push_back(*value);
        }
        return values;
    }

    bool bounded_inputs(Id root) const
    {
        if (root == invalid || failed_)
            return false;
        std::set<Id> inputs;
        std::set<Id> visited;
        collect(root, inputs, visited);
        size_t count = 1;
        for (Id input : inputs)
        {
            const unsigned bits = unsigned(nodes_[input].right);
            if (bits > 8 || count > maximum_assignments / (size_t{1} << bits))
                return false;
            count *= size_t{1} << bits;
        }
        return true;
    }

    const Node &node(Id id) const { return nodes_.at(id); }
    bool failed() const { return failed_; }

  private:
    Reader reader_;
    std::vector<Node> nodes_;
    std::map<std::tuple<Op, int, Id, Id, uint64_t>, Id> interned_;
    std::map<std::pair<uint64_t, int>, std::optional<uint64_t>> reads_;
    size_t work_ = 0;
    bool failed_ = false;

    static uint64_t mask(uint64_t value, int bytes) { return bitvector::truncate(value, bytes); }

    static bool binary(Op op) { return op >= Op::add && op <= Op::sar; }

    Id intern(const Node &node)
    {
        const auto key = std::make_tuple(node.op, node.bytes, node.left, node.right, node.value);
        const auto old = interned_.find(key);
        if (old != interned_.end())
            return old->second;
        if (nodes_.size() >= maximum_nodes)
        {
            failed_ = true;
            return invalid;
        }
        const Id id = nodes_.size();
        nodes_.push_back(node);
        interned_.emplace(key, id);
        return id;
    }

    void collect(Id id, std::set<Id> &inputs, std::set<Id> &visited) const
    {
        if (!visited.insert(id).second)
            return;
        const Node &n = nodes_[id];
        if (n.op == Op::variable)
            inputs.insert(id);
        else if (n.op != Op::constant)
        {
            collect(n.left, inputs, visited);
            if (n.right != invalid)
                collect(n.right, inputs, visited);
        }
    }

    std::optional<uint64_t> constant_value(Id id)
    {
        const Node &n = nodes_[id];
        if (!n.table && (!literal(n.left) || (binary(n.op) && !literal(n.right))))
            return std::nullopt;
        const auto values = enumerate(id);
        if (!values || values->results.empty())
            return std::nullopt;
        const uint64_t value = values->results.front();
        if (!std::all_of(values->results.begin(), values->results.end(),
                         [value](uint64_t candidate) { return candidate == value; }))
            return std::nullopt;
        return value;
    }

    std::optional<uint64_t> evaluate(Id id, std::map<Id, uint64_t> &cache)
    {
        const auto old = cache.find(id);
        if (old != cache.end())
            return old->second;
        if (++work_ > maximum_work)
        {
            failed_ = true;
            return std::nullopt;
        }
        const Node n = nodes_[id];
        if (n.op == Op::constant)
            return n.value;
        if (n.op == Op::variable)
            return std::nullopt;
        const auto l = evaluate(n.left, cache);
        const auto r = binary(n.op) ? evaluate(n.right, cache) : std::optional<uint64_t>(0);
        if (!l || !r)
            return std::nullopt;
        uint64_t value = 0;
        switch (n.op)
        {
        case Op::low:
            value = *l;
            break;
        case Op::sign_extend:
            value = uint64_t(bitvector::sign_extend(*l, int(n.value)));
            break;
        case Op::add:
            value = *l + *r;
            break;
        case Op::sub:
            value = *l - *r;
            break;
        case Op::mul:
            value = *l * *r;
            break;
        case Op::bit_and:
            value = *l & *r;
            break;
        case Op::bit_or:
            value = *l | *r;
            break;
        case Op::bit_xor:
            value = *l ^ *r;
            break;
        case Op::shl:
            value = bitvector::shift_left(*l, *r, n.bytes);
            break;
        case Op::shr:
            value = bitvector::shift_right_logical(*l, *r, n.bytes);
            break;
        case Op::sar:
            value = bitvector::shift_right_arithmetic(*l, *r, n.bytes);
            break;
        case Op::bit_not:
            value = ~*l;
            break;
        case Op::neg:
            value = uint64_t{0} - *l;
            break;
        case Op::logical_not:
            value = *l == 0;
            break;
        case Op::load:
        {
            const auto key = std::make_pair(*l, n.bytes);
            auto found = reads_.find(key);
            if (found == reads_.end())
                found = reads_.emplace(key, reader_(*l, n.bytes)).first;
            if (!found->second)
                return std::nullopt;
            value = *found->second;
            break;
        }
        default:
            return std::nullopt;
        }
        value = mask(value, n.bytes);
        cache.emplace(id, value);
        return value;
    }
};

} // namespace chernobog::finite_domain
