#pragma once

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

template <class State, class Transfer>
std::optional<std::vector<State>> bounded_dataflow(const std::vector<FlowNode> &graph,
                                                   size_t node_limit, size_t round_limit,
                                                   Transfer transfer)
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
    std::vector<State> inputs(graph.size());
    for (size_t round = 0; round < round_limit; ++round)
    {
        bool changed = false;
        auto next = outputs;
        for (size_t i = 0; i < graph.size(); ++i)
        {
            const auto &node = graph[i];
            State input;
            bool initialized = node.unknown_entry || node.predecessors.empty();
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
                continue;
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
} // namespace chernobog
