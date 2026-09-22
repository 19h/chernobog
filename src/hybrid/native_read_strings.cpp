#include "evidence.hpp"
#include "../common/string_recovery.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace chernobog::hybrid {
namespace {
using Run = std::pair<uint32_t,uint64_t>;
using Shape = std::vector<std::pair<uint64_t,uint64_t>>;
using Key = std::pair<decltype(UseSnapshot{}.semantic_key()),Shape>;
struct Stream { UseSnapshot use;std::vector<UseSnapshot> parts;std::string value; };
struct Records
{
  std::vector<const UseSnapshot *> uses;
  std::map<uint64_t,const DataAcc *> data;
  std::map<uint64_t,const AllocationLifetime *> objects;
  std::set<uint64_t> barriers;
};

bool valid_read(const UseSnapshot &use,const Records &records,uint64_t context)
{
  if(use.context!=context || use.producer!=UseProducer::EXECUTED_READ || use.status!=UseCaptureStatus::EXACT
      || use.argument!=-1 || use.callee || use.model_kind || !use.occurrence
      || use.bytes.empty() || use.bytes.size()>8 || use.bytes.size()!=use.observed_size
      || use.sequence==UINT64_MAX || use.address>UINT64_MAX-use.observed_size)return false;
  const auto found=records.data.find(use.sequence+1);
  if(found==records.data.end())return false;
  const auto &data=*found->second;
  if(data.kind!=RAX_MEM_READ || data.from!=use.site || data.addr!=use.address
      || data.size!=use.observed_size || data.scope!=use.scope)return false;
  for(size_t i=0;i<use.bytes.size();++i)
    if(use.bytes[i]!=uint8_t(data.value>>(8*i)))return false;
  if(use.scope==DataScope::IMAGE)return use.object_site==use.address;
  if(use.scope==DataScope::STACK)return use.object_site==use.context;
  if(use.scope!=DataScope::HEAP)return false;
  const auto object=records.objects.find(use.allocation_id);
  if(object==records.objects.end())return false;
  const auto &a=*object->second;
  return a.id && a.generation==use.generation && a.context==use.context
      && a.site==use.object_site && a.callee==use.object_callee
      && a.occurrence==use.object_occurrence && a.size==use.object_size
      && use.address>=a.address && use.address-a.address<=a.size && use.offset>=0
      && uint64_t(use.offset)==use.address-a.address
      && use.observed_size<=a.size-(use.address-a.address)
      && use.sequence>a.allocated
      && (a.live?a.released==0:use.sequence+1<a.released);
}

bool follows(const Stream &stream,const UseSnapshot &next,const Records &records)
{
  if(stream.parts.empty())return false;
  const auto &first=stream.use;const auto &last=stream.parts.back();
  if(last.sequence+1>=next.sequence || first.context!=next.context || first.scope!=next.scope
      || first.address>UINT64_MAX-first.observed_size
      || first.address+first.observed_size!=next.address)return false;
  auto barrier=records.barriers.upper_bound(last.sequence);
  if(barrier!=records.barriers.end() && *barrier<=next.sequence)return false;
  // Any intervening read, including one without an eligible use snapshot,
  // interrupts the stream. Control-only loop instructions need not do so.
  auto data=records.data.upper_bound(last.sequence+1);
  if(data==records.data.end() || data->first!=next.sequence+1)return false;
  if(first.scope==DataScope::HEAP)
    return first.allocation_id==next.allocation_id && first.generation==next.generation;
  if(first.scope==DataScope::STACK)
    return first.observed_size<=uint64_t(INT64_MAX)
        && first.offset<=INT64_MAX-int64_t(first.observed_size)
        && first.offset+int64_t(first.observed_size)==next.offset;
  return true;
}
}

std::vector<RuntimeUseStringCandidate> hybrid_consensus_native_read_strings(
    const TargetEvidence &evidence,size_t minimum_length,size_t maximum_length)
{
  std::vector<RuntimeUseStringCandidate> result;
  if(!minimum_length || maximum_length<minimum_length || evidence.runs.empty())return result;
  std::map<Run,Records> runs;
  for(const auto &run:evidence.runs)
  {
    const auto &out=run.outcome;
    if(!run.ran || !out.temporal_observation_available || !out.temporal_capture_complete
        || out.temporal_capture_truncated || !out.memory_observation_available
        || out.data_trace_filtered || out.data_trace_truncated)return result;
    // data_trace_complete additionally forbids every environment model, even
    // malloc/free. Temporal evidence has its own completed-model contract;
    // require lossless recorded memory order without promoting that evidence
    // to the model-free proof contract. Calls and lifetime changes are barriers.
    if(!runs.emplace(Run{run.provenance.run_id,run.provenance.seed},Records{}).second)return result;
  }
  for(const auto &use:evidence.events.uses)
  {
    const auto run=runs.find({use.run_id,use.seed});if(run==runs.end())return {};
    auto &r=run->second;
    if(r.uses.size()==TemporalMemory::use_limit)return {};
    r.uses.push_back(&use);
    if(use.producer!=UseProducer::EXECUTED_READ)r.barriers.insert(use.sequence);
  }
  for(const auto &data:evidence.events.data)
  {
    const auto run=runs.find({data.run_id,data.seed});if(run==runs.end())return {};
    auto &r=run->second;
    if(r.data.size()==65536 || !r.data.emplace(data.sequence,&data).second)return {};
    if(data.kind!=RAX_MEM_READ)r.barriers.insert(data.sequence);
  }
  for(const auto &a:evidence.events.allocations)
  {
    const auto run=runs.find({a.run_id,a.seed});if(run==runs.end())return {};
    auto &r=run->second;
    if(r.objects.size()==TemporalMemory::allocation_limit || !r.objects.emplace(a.id,&a).second)return {};
    r.barriers.insert(a.allocated);if(!a.live)r.barriers.insert(a.released);
  }
  for(const auto &edge:evidence.events.edges)
  {
    const auto run=runs.find({edge.run_id,edge.seed});if(run==runs.end())return {};
    if(edge.kind==ExecEdge::Kind::Call || edge.kind==ExecEdge::Kind::Unknown)
    {
      if(run->second.barriers.size()>=81920)return {};
      run->second.barriers.insert(edge.sequence);
    }
  }
  std::map<Key,std::map<Run,Stream>> values;
  std::set<Key> ambiguous;
  for(auto &[identity,records]:runs)
  {
    std::sort(records.uses.begin(),records.uses.end(),[](const auto *a,const auto *b)
        {return a->sequence<b->sequence;});
    Stream stream;uint64_t previous=0;bool first=true;size_t retained=0;
    for(const auto *pointer:records.uses)
    {
      const auto &use=*pointer;
      if(!first && use.sequence<=previous)return {};
      previous=use.sequence;first=false;
      if(!valid_read(use,records,evidence.scope.function_start)){stream={};continue;}
      if(!follows(stream,use,records))stream={};
      if(stream.parts.empty())
      {
        stream.use=use;stream.use.producer=UseProducer::EXECUTED_READ_STREAM;
        stream.use.bytes.clear();stream.use.observed_size=0;
      }
      if(use.bytes.size()>TemporalMemory::snapshot_limit-stream.use.bytes.size())
      {stream={};continue;}
      stream.use.bytes.insert(stream.use.bytes.end(),use.bytes.begin(),use.bytes.end());
      stream.use.observed_size+=use.observed_size;stream.parts.push_back(use);
      if(std::find(use.bytes.begin(),use.bytes.end(),0)==use.bytes.end())continue;
      if(stream.parts.size()>1)
      {
        const auto decoded=string_recovery::recover_runtime_utf8_prefix(
            stream.use.bytes,minimum_length,maximum_length);
        if(decoded)
        {
          if(stream.use.bytes.size()>TemporalMemory::total_byte_limit-retained)return {};
          retained+=stream.use.bytes.size();stream.value=decoded->utf8;
          Shape shape;for(const auto &part:stream.parts)shape.emplace_back(part.site,part.observed_size);
          Key key{stream.use.semantic_key(),std::move(shape)};
          if(!values[key].emplace(identity,std::move(stream)).second)ambiguous.insert(key);
        }
      }
      stream={};
    }
  }
  for(auto &[key,witnesses]:values)
  {
    if(ambiguous.count(key) || witnesses.size()!=runs.size())continue;
    RuntimeUseStringCandidate candidate;const auto &first=witnesses.begin()->second;
    candidate.use=first.use;candidate.value=first.value;candidate.eligible_runs=runs.size();
    bool same=true;
    for(auto &[run,stream]:witnesses)
    {
      if(stream.value!=candidate.value){same=false;break;}
      candidate.witnesses.push_back(stream.use);
      candidate.read_fragments.push_back(std::move(stream.parts));
    }
    if(same)result.push_back(std::move(candidate));
  }
  return result;
}
}
