#include "vm/boundary.hpp"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
using namespace chernobog::vm;
namespace
{
size_t checks = 0;
void require(bool value, const char *name)
{
    ++checks;
    if (!value)
    {
        std::cerr << name << '\n';
        std::exit(1);
    }
}
bool has(const BoundaryAudit &audit, const char *reason, uint64_t site = bad_address)
{
    return std::any_of(audit.frontiers.begin(), audit.frontiers.end(), [&](const auto &f)
                       { return f.reason == reason && (site == bad_address || f.site == site); });
}
BoundaryNode node(uint64_t ea, BoundaryFlow flow, uint64_t target = bad_address, unsigned mode = 64)
{
    BoundaryNode n;
    n.address = ea;
    n.mode = mode;
    n.size = 1;
    n.bytes = "90";
    n.flow = flow;
    n.target = target;
    n.owner = ea == 0x1000 ? 0x1000 : bad_address;
    return n;
}
struct Graph
{
    std::map<uint64_t, BoundaryNode> nodes;
    std::map<uint64_t, size_t> reads;
    BoundaryNode read(uint64_t ea, size_t budget)
    {
        ++reads[ea];
        if (!nodes.count(ea))
        {
            BoundaryNode n;
            n.address = ea;
            n.rejection = "missing_code_head";
            return n;
        }
        auto n = nodes.at(ea);
        if (n.incoming.size() > budget)
        {
            n.incoming.resize(budget);
            n.incoming_complete = false;
        }
        return n;
    }
    BoundaryAudit run(unsigned mode = 64, BoundaryLimits limits = {})
    {
        reads.clear();
        return audit_boundaries(
            0x1000, mode, [&](auto ea, auto budget) { return read(ea, budget); }, limits);
    }
};
}
int main()
{
    for (unsigned mode : {32u, 64u})
    {
        Graph g;
        g.nodes[0x1000] = node(0x1000, BoundaryFlow::conditional, 0x2000, mode);
        g.nodes[0x1001] = node(0x1001, BoundaryFlow::direct, 0x2000, mode);
        g.nodes[0x2000] = node(0x2000, BoundaryFlow::direct, 0x1000, mode);
        g.nodes[0x1000].incoming = {0x9999, 0x2000};
        g.nodes[0x1001].incoming = {0x1000};
        g.nodes[0x2000].incoming = {0x1000, 0x1001};
        auto a = g.run(mode);
        require(a.decoded == 3 && a.ownerless == 2 && a.edges.size() == 4,
                "diamond and cycle native topology");
        require(a.frontiers.empty() && a.entry_incoming == 2,
                "entry references distinct from interior side entries");
        require(std::all_of(g.reads.begin(), g.reads.end(), [](auto v) { return v.second == 1; }),
                "each head decoded once");
        g.nodes[0x2000].incoming.push_back(0x8888);
        a = g.run(mode);
        require(has(a, "external_code_entry", 0x8888), "external incoming edge retained");
        g.nodes[0x1001].incoming.push_back(0x2000);
        a = g.run(mode);
        require(has(a, "unverified_internal_xref", 0x2000), "xref is not decoded edge proof");
        for (auto flow :
             {BoundaryFlow::call, BoundaryFlow::indirect, BoundaryFlow::ret, BoundaryFlow::stop})
        {
            g.nodes[0x1000].flow = flow;
            a = g.run(mode);
            require(a.nodes.size() == 1 && a.edges.empty(),
                    "unmodeled transfer never follows xrefs or continuation");
            require(has(a, flow == BoundaryFlow::call       ? "call_requires_summary"
                           : flow == BoundaryFlow::indirect ? "unresolved_indirect"
                           : flow == BoundaryFlow::ret      ? "unresolved_return"
                                                            : "unsupported_control"),
                    "transfer-specific boundary");
        }
        g.nodes[0x1000].flow = BoundaryFlow::direct;
        g.nodes[0x2000].owner = 0x9999;
        a = g.run(mode);
        require(has(a, "foreign_function", 0x2000) && a.decoded == 1, "foreign function excluded");
        g.nodes[0x2000].owner = 0x1000;
        g.nodes[0x2000].shared_tail = true;
        a = g.run(mode);
        require(has(a, "shared_function_tail") && a.decoded == 1,
                "shared tail excluded even if root is primary owner");
        g.nodes[0x2000].shared_tail = false;
        g.nodes[0x2000].mode = mode == 32 ? 64 : 32;
        require(has(g.run(mode), "mode_boundary"), "mode boundary explicit");
        g.nodes[0x2000].mode = mode;
        for (const char *reason :
             {"unmapped_target", "nonexecutable_target", "missing_code_head", "decode_failure",
              "unloaded_instruction_byte", "instruction_ownership_boundary", "unsupported_prefix"})
        {
            g.nodes[0x2000].rejection = reason;
            require(has(g.run(mode), reason), "adapter rejection retained");
        }
        g.nodes[0x2000].rejection.clear();
        g.nodes[0x2000].address = 0x2001;
        require(has(g.run(mode), "projection_address_mismatch"), "wrong adapter address rejected");
        g.nodes[0x2000].address = 0x2000;
        for (unsigned size : {0u, 16u})
        {
            g.nodes[0x2000].size = size;
            require(has(g.run(mode), "invalid_instruction_span"), "invalid x86 instruction length");
        }
        g.nodes[0x2000].size = 1;
        for (const char *bytes : {"", "0", "0000", "zz"})
        {
            g.nodes[0x2000].bytes = bytes;
            require(has(g.run(mode), "missing_instruction_bytes"),
                    "bytes match span and hex encoding");
        }
        g.nodes[0x2000].bytes = "90";
        g.nodes[0x1000].owner = bad_address;
        require(has(g.run(mode), "entry_ownership_changed"), "root ownership required");
    }
    Graph g;
    g.nodes[0x1000] = node(0x1000, BoundaryFlow::conditional, 0x1002);
    g.nodes[0x1001] = node(0x1001, BoundaryFlow::ret);
    g.nodes[0x1001].size = 2;
    g.nodes[0x1001].bytes = "9090";
    g.nodes[0x1002] = node(0x1002, BoundaryFlow::ret);
    require(has(g.run(), "overlapping_instruction", 0x1001), "overlap with next span rejected");
    g.nodes[0x1000].target = 0x1001;
    g.nodes[0x1001].flow = BoundaryFlow::direct;
    g.nodes[0x1001].target = 0x1002;
    require(has(g.run(), "overlapping_instruction", 0x1002),
            "overlap with preceding span rejected");
    g.nodes[0x1000].flow = BoundaryFlow::direct;
    g.nodes[0x1000].target = bad_address;
    require(has(g.run(), "unknown_direct_target"), "unknown immediate target does not form edge");
    g.nodes[0x1000].target = bad_address - 1;
    g.nodes[bad_address - 1] = node(bad_address - 1, BoundaryFlow::linear);
    require(has(g.run(), "invalid_instruction_span"), "address overflow or sentinel end rejected");
    g.nodes.clear();
    g.nodes[0x1000] = node(0x1000, BoundaryFlow::linear);
    require(has(g.run(), "missing_code_head", 0x1001), "missing fallthrough is explicit");
    auto a = g.run(64, {0, 64, 8192});
    require(a.head_limit && a.nodes.empty() && g.reads.empty(), "zero head quota reads nothing");
    a = g.run(64, {1, 64, 8192});
    require(a.head_limit && a.nodes.size() == 1 && a.edges.size() == 1,
            "head quota retains frontier edge");
    g.nodes[0x1000].incoming = {5, 6, 7};
    a = g.run(64, {1, 2, 8192});
    require(a.incoming_limit && a.incoming_examined == 2 && a.entry_incoming == 2,
            "per-head incoming cap explicit");
    a = g.run(64, {1, 64, 0});
    require(a.incoming_limit && a.incoming_examined == 0,
            "zero incoming quota with refs is incomplete");
    g.nodes[0x1000].incoming.clear();
    g.nodes[0x1000].flow = BoundaryFlow::ret;
    a = g.run(64, {1, 64, 0});
    require(!a.incoming_limit, "zero incoming quota with no refs completes");
    g.nodes[0x1000].flow = BoundaryFlow::linear;
    g.nodes[0x1000].incoming = {1, 2};
    g.nodes[0x1001] = node(0x1001, BoundaryFlow::ret);
    g.nodes[0x1001].incoming = {0x1000, 3};
    a = g.run(64, {2, 64, 3});
    require(a.incoming_limit && a.incoming_examined == 3 && has(a, "incoming_limit", 0x1001),
            "global incoming budget distributed");
    a = audit_boundaries(0x1000, 64,
                         [](auto ea, size_t)
                         {
                             auto n = node(ea, BoundaryFlow::ret);
                             n.incoming.resize(100, 9);
                             return n;
                         },
                         {1, 2, 2});
    require(a.incoming_limit && a.incoming_examined == 2,
            "faulty reader cannot expand retained xref quota");
    a = audit_boundaries(0x1000, 64, [](auto ea, size_t) { return node(ea, BoundaryFlow::linear); },
                         {SIZE_MAX, SIZE_MAX, SIZE_MAX});
    require(a.nodes.size() == 1024 && a.head_limit, "hard head ceiling clamps caller request");
    a = audit_boundaries(0x1000, 64,
                         [](auto ea, size_t budget)
                         {
                             auto n = node(ea, BoundaryFlow::linear);
                             n.incoming.resize(budget, 0x8000);
                             n.incoming_complete = false;
                             return n;
                         });
    require(a.nodes.size() == 1024 && a.incoming_examined == 8192 && a.incoming_limit,
            "hard total xref ceiling");
    require(has(audit_boundaries(bad_address, 64, {}), "invalid_request"), "bad entry rejected");
    require(has(g.run(16), "invalid_request") && g.reads.empty(),
            "unsupported mode rejected before read");
    require(has(audit_boundaries(0x1000, 64, {}), "invalid_request"), "absent reader rejected");
    std::cout << "VM boundary checks=" << checks << '\n';
}
