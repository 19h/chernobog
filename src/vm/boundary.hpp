#pragma once
#include "region.hpp"
#include <cstddef>
#include <functional>

namespace chernobog::vm
{
// Read-only native topology. Neither decoded branches nor absence of IDB xrefs
// establish VM identity, complete dynamic reachability, or execution ownership.
enum class BoundaryFlow
{
    linear,
    direct,
    conditional,
    call,
    indirect,
    ret,
    stop
};
struct BoundaryNode
{
    uint64_t address = bad_address, owner = bad_address, target = bad_address;
    unsigned size = 0, mode = 0;
    BoundaryFlow flow = BoundaryFlow::stop;
    // Empty means the adapter verified a loaded executable instruction span.
    std::string rejection;
    std::string bytes;
    bool shared_tail = false, incoming_complete = true;
    std::vector<uint64_t> incoming;
};
struct BoundaryEdge
{
    uint64_t from = bad_address, to = bad_address;
    bool fallthrough = false;
};
struct BoundaryFrontier
{
    std::string reason;
    uint64_t site = bad_address, target = bad_address;
};
struct BoundaryLimits
{
    size_t heads = 1024, incoming_per_head = 64, incoming_total = 8192;
};
struct BoundaryAudit
{
    std::vector<BoundaryNode> nodes;
    std::vector<BoundaryEdge> edges;
    std::vector<BoundaryFrontier> frontiers;
    size_t decoded = 0, ownerless = 0, incoming_examined = 0, entry_incoming = 0;
    bool head_limit = false, incoming_limit = false;
};
// The reader must return at most incoming_budget existing code references and
// indicate whether enumeration ended. It is called once per scheduled address.
// Hard ceilings equal the default limits; callers may only reduce them.
using BoundaryReader = std::function<BoundaryNode(uint64_t, size_t incoming_budget)>;
BoundaryAudit audit_boundaries(uint64_t entry, unsigned mode, const BoundaryReader &,
                               BoundaryLimits = {});
const char *boundary_flow_name(BoundaryFlow);
} // namespace chernobog::vm
