#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace chernobog
{
// Must-analysis over an explicitly supplied graph. State{} denotes unknown,
// join retains facts true on both inputs, and transfer must be monotone.
// Edges are never removed using provisional analysis results.
struct FlowNode
{
    std::vector<size_t> predecessors;
    bool unknown_entry = false;
};

// Retain correlations across a bounded set of alternatives. Overflow widens
// every member with State::join; no predecessor or concrete path is dropped.
template <class State, size_t Limit = 8> class BoundedAlternatives
{
    static_assert(Limit > 0);
    std::vector<State> states_{State{}};
    bool widened_ = false;

  public:
    BoundedAlternatives() = default;
    explicit BoundedAlternatives(State state) : states_{std::move(state)} {}
    const std::vector<State> &states() const { return states_; }
    bool widened() const { return widened_; }
    State common() const
    {
        State result = states_.front();
        for (size_t i = 1; i < states_.size(); ++i)
            result.join(states_[i]);
        return result;
    }
    void join(const BoundedAlternatives &other)
    {
        if (widened_ || other.widened_)
        {
            State result = common();
            for (const auto &state : other.states_)
                result.join(state);
            states_ = {std::move(result)};
            widened_ = true;
            return;
        }
        for (const auto &state : other.states_)
            if (std::find(states_.begin(), states_.end(), state) == states_.end())
                states_.push_back(state);
        if (states_.size() > Limit)
        {
            State result = common();
            states_ = {std::move(result)};
            widened_ = true;
        }
    }
    template <class Transfer> BoundedAlternatives apply(Transfer transfer) const
    {
        BoundedAlternatives result;
        result.states_.clear();
        result.widened_ = widened_;
        for (const auto &state : states_)
        {
            State next = transfer(state);
            if (std::find(result.states_.begin(), result.states_.end(), next) ==
                result.states_.end())
                result.states_.push_back(std::move(next));
        }
        return result;
    }
    bool operator==(const BoundedAlternatives &other) const
    {
        return widened_ == other.widened_ && states_.size() == other.states_.size() &&
               std::all_of(states_.begin(), states_.end(),
                           [&](const State &state)
                           {
                               return std::find(other.states_.begin(), other.states_.end(),
                                                state) != other.states_.end();
                           });
    }
};

// Optional inputs distinguish graph bottom from unknown entry. Explicit-entry
// mode is required after removing edges: a newly orphaned node is not an entry.
template <class State, class Transfer>
std::optional<std::vector<std::optional<State>>>
bounded_graph_inputs(const std::vector<FlowNode> &graph, size_t node_limit, size_t round_limit,
                     Transfer transfer, bool implicit_entries)
{
    if (graph.empty() || graph.size() > node_limit || !round_limit)
        return std::nullopt;
    for (const auto &node : graph)
    {
        if (node.predecessors.size() > node_limit)
            return std::nullopt;
        for (size_t predecessor : node.predecessors)
            if (predecessor >= graph.size())
                return std::nullopt;
    }
    // Absent output is unreachable so far (lattice bottom), not unknown input.
    // This permits loop invariants to propagate from an actual entry, while
    // later back-edge disagreement can only discard facts before convergence.
    std::vector<std::optional<State>> outputs(graph.size());
    std::vector<std::optional<State>> inputs(graph.size());
    for (size_t round = 0; round < round_limit; ++round)
    {
        bool changed = false;
        auto next = outputs;
        for (size_t i = 0; i < graph.size(); ++i)
        {
            const auto &node = graph[i];
            State input;
            bool initialized =
                node.unknown_entry || (implicit_entries && node.predecessors.empty());
            for (size_t predecessor : node.predecessors)
            {
                if (!outputs[predecessor])
                    continue;
                if (!initialized)
                    input = *outputs[predecessor];
                else
                    input.join(*outputs[predecessor]);
                initialized = true;
            }
            if (!initialized)
            {
                inputs[i].reset();
                next[i].reset();
                changed |= outputs[i].has_value();
                continue;
            }
            inputs[i] = input;
            next[i] = transfer(i, input);
            changed |= !outputs[i] || !(*next[i] == *outputs[i]);
        }
        outputs = std::move(next);
        if (!changed)
            return inputs;
    }
    // Provisional iterations are never returned as a fixed-point proof.
    return std::nullopt;
}

template <class State, class Transfer>
std::optional<std::vector<State>> bounded_dataflow(const std::vector<FlowNode> &graph,
                                                   size_t node_limit, size_t round_limit,
                                                   Transfer transfer)
{
    const auto inputs = bounded_graph_inputs<State>(graph, node_limit, round_limit, transfer, true);
    if (!inputs)
        return std::nullopt;
    std::vector<State> result;
    result.reserve(inputs->size());
    for (const auto &input : *inputs)
        result.push_back(input.value_or(State{}));
    return result;
}

template <class State, class Transfer>
std::optional<std::vector<std::optional<State>>>
bounded_reachable_dataflow(const std::vector<FlowNode> &graph, size_t node_limit,
                           size_t round_limit, Transfer transfer)
{
    return bounded_graph_inputs<State>(graph, node_limit, round_limit, transfer, false);
}
} // namespace chernobog
