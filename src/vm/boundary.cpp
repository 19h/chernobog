#include "boundary.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <set>

namespace chernobog::vm {
const char *boundary_flow_name(BoundaryFlow flow)
{
  switch(flow)
  {
    case BoundaryFlow::linear:return "linear";
    case BoundaryFlow::direct:return "direct";
    case BoundaryFlow::conditional:return "conditional";
    case BoundaryFlow::call:return "call";
    case BoundaryFlow::indirect:return "indirect";
    case BoundaryFlow::ret:return "return";
    case BoundaryFlow::stop:return "stop";
  }
  return "unknown";
}

BoundaryAudit audit_boundaries(uint64_t entry, unsigned mode,
    const BoundaryReader &read, BoundaryLimits limits)
{
  BoundaryAudit result;
  auto frontier=[&](const char *reason,uint64_t site,uint64_t target=bad_address)
  { result.frontiers.push_back({reason,site,target}); };
  if(entry==bad_address || (mode!=32 && mode!=64) || !read)
  { frontier("invalid_request",entry);return result; }
  limits.heads=std::min(limits.heads,size_t(1024));
  limits.incoming_per_head=std::min(limits.incoming_per_head,size_t(64));
  limits.incoming_total=std::min(limits.incoming_total,size_t(8192));
  if(!limits.heads)
  { result.head_limit=true;frontier("head_limit",entry);return result; }
  std::deque<uint64_t> pending{entry};
  std::set<uint64_t> scheduled{entry}, accepted;
  std::set<std::pair<uint64_t,uint64_t>> links;
  std::map<uint64_t,uint64_t> spans;
  auto follow=[&](uint64_t from,uint64_t to,bool fallthrough)
  {
    if(to==bad_address)
    { frontier("unknown_direct_target",from);return; }
    result.edges.push_back({from,to,fallthrough});
    links.emplace(from,to);
    if(scheduled.count(to))return;
    if(scheduled.size()==limits.heads)
    { result.head_limit=true;frontier("head_limit",from,to);return; }
    scheduled.insert(to);pending.push_back(to);
  };
  while(!pending.empty())
  {
    const auto address=pending.front();pending.pop_front();
    const size_t allowance=std::min(limits.incoming_per_head,
        limits.incoming_total-result.incoming_examined);
    auto node=read(address,allowance);
    // A faulty adapter cannot silently increase the core's retained xref bound.
    if(node.incoming.size()>allowance)
    { node.incoming.resize(allowance);node.incoming_complete=false; }
    result.incoming_examined+=node.incoming.size();
    if(!node.incoming_complete)
    { result.incoming_limit=true;frontier("incoming_limit",address); }
    if(node.address!=address)node.rejection="projection_address_mismatch";
    node.address=address;
    if(node.rejection.empty())
    {
      if(node.mode!=mode)node.rejection="mode_boundary";
      else if(!node.size || node.size>15 || address>=bad_address-node.size)
        node.rejection="invalid_instruction_span";
      else if(node.bytes.size()!=node.size*2
          || node.bytes.find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos)
        node.rejection="missing_instruction_bytes";
      else if(node.shared_tail)node.rejection="shared_function_tail";
      else if(node.owner!=bad_address && node.owner!=entry)node.rejection="foreign_function";
      else if(address==entry && node.owner!=entry)node.rejection="entry_ownership_changed";
    }
    if(node.rejection.empty())
    {
      const auto next=spans.lower_bound(address);
      if((next!=spans.end() && next->first<address+node.size)
          || (next!=spans.begin() && std::prev(next)->second>address))
        node.rejection="overlapping_instruction";
    }
    result.nodes.push_back(std::move(node));
    const auto &current=result.nodes.back();
    if(!current.rejection.empty())
    { frontier(current.rejection.c_str(),address);continue; }
    accepted.insert(address);spans.emplace(address,address+current.size);
    ++result.decoded;
    if(current.owner==bad_address)++result.ownerless;
    switch(current.flow)
    {
      case BoundaryFlow::linear:follow(address,address+current.size,true);break;
      case BoundaryFlow::direct:follow(address,current.target,false);break;
      case BoundaryFlow::conditional:
        follow(address,current.target,false);follow(address,address+current.size,true);break;
      // A call's return behavior needs a separate summary. Even a known target
      // does not authorize either entering its body or continuing after it.
      case BoundaryFlow::call:frontier("call_requires_summary",address,current.target);break;
      case BoundaryFlow::indirect:frontier("unresolved_indirect",address);break;
      // A native RET may be a VMP dispatch; never claim it proves region exit.
      case BoundaryFlow::ret:frontier("unresolved_return",address);break;
      case BoundaryFlow::stop:frontier("unsupported_control",address);break;
    }
  }
  for(const auto &node:result.nodes)
  {
    if(!accepted.count(node.address))continue;
    if(node.address==entry){result.entry_incoming=node.incoming.size();continue;}
    for(uint64_t source:node.incoming)
    {
      if(!accepted.count(source))frontier("external_code_entry",source,node.address);
      else if(!links.count({source,node.address}))
        frontier("unverified_internal_xref",source,node.address);
    }
  }
  return result;
}
} // namespace chernobog::vm
