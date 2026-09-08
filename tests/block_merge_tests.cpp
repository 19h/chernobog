#include "block_merge_ida_stub.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>

namespace {

struct Graph
{
  mbl_array_t mba;
  std::vector<mblock_t> blocks;
  std::vector<std::vector<minsn_t>> instructions;

  explicit Graph(size_t count) : blocks(count), instructions(count)
  {
    mba.qty = int(count);
    for ( size_t index = 0; index < count; ++index )
    {
      mba.blocks.push_back(&blocks[index]);
      set_instructions(index, 1);
    }
  }

  void set_instructions(size_t index, size_t count, bool ends_in_goto = true)
  {
    auto &items = instructions[index];
    items.assign(count, {});
    for ( size_t offset = 1; offset < count; ++offset )
      items[offset - 1].next.pointer = &items[offset];
    blocks[index].head = count == 0 ? nullptr : &items.front();
    blocks[index].tail = count == 0 ? nullptr : &items.back();
    if ( count != 0 && ends_in_goto )
      items.back().opcode = m_goto;
  }

  void update_predecessors()
  {
    for ( auto &block : blocks )
      block.predecessors = 0;
    for ( const auto &block : blocks )
      for ( int successor : block.successors )
        if ( successor >= 0 && size_t(successor) < blocks.size() )
          ++blocks[size_t(successor)].predecessors;
  }
};

size_t graphs_checked = 0;
int failures = 0;
size_t equivalence_mismatches = 0;

void check(bool condition, const char *message)
{
  if ( !condition )
  {
    if ( failures < 20 )
      std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

bool equivalent(Graph &graph)
{
  const bool reference = reference_detect_split_blocks(&graph.mba);
  graph.mba.block_lookups = 0;
  instruction_link_reads = 0;
  const bool actual = block_merge_handler_t::detect_split_blocks(&graph.mba);
  ++graphs_checked;
  equivalence_mismatches += actual != reference ? 1 : 0;
  check(actual == reference, "production detector differs from frozen exact-chain oracle");
  check(graph.mba.block_lookups <= 7 * graph.blocks.size(),
        "block visits exceed the linear seven-per-block bound");
  check(instruction_link_reads <= 2 * graph.blocks.size(),
        "candidate classification must stop at the third instruction");
  return actual;
}

void exhaustive_graphs()
{
  // Enumerate every partial functional graph through five nodes, independently
  // marking each node as a short candidate or a long noncandidate. Incoming
  // edge counts are derived from topology, including self-loops and joins.
  for ( size_t count = 1; count <= 5; ++count )
  {
    Graph graph(count);
    size_t topology_count = 1;
    for ( size_t index = 0; index < count; ++index )
      topology_count *= count + 1;
    for ( size_t topology = 0; topology < topology_count; ++topology )
    {
      size_t encoded = topology;
      for ( auto &block : graph.blocks )
      {
        const size_t successor = encoded % (count + 1);
        encoded /= count + 1;
        block.successors.clear();
        if ( successor != count )
          block.successors.push_back(int(successor));
      }
      graph.update_predecessors();
      for ( size_t mask = 0; mask < (size_t(1) << count); ++mask )
      {
        for ( size_t index = 0; index < count; ++index )
          graph.set_instructions(index, (mask & (size_t(1) << index)) != 0 ? 1 : 3);
        equivalent(graph);
      }
    }
  }
}

void randomized_graphs()
{
  std::mt19937_64 random(0x436865726e6f626fULL);
  for ( size_t iteration = 0; iteration < 100000; ++iteration )
  {
    const size_t count = 1 + random() % 64;
    Graph graph(count);
    for ( size_t index = 0; index < count; ++index )
    {
      graph.set_instructions(index, random() % 6, random() % 5 != 0);
      if ( random() % 19 == 0 )
        graph.mba.blocks[index] = nullptr;
      const size_t successors = random() % 4;
      for ( size_t edge = 0; edge < successors; ++edge )
        graph.blocks[index].successors.push_back(int(random() % (count + 4)) - 2);
    }
    graph.update_predecessors();
    // Invalid metadata must preserve the old rejection/acceptance semantics.
    for ( auto &block : graph.blocks )
      if ( random() % 7 == 0 )
        block.predecessors = int(random() % 4);
    graph.mba.bad_sp = random() % 101 == 0;
    graph.mba.bad_call_sp = random() % 101 == 0;
    equivalent(graph);
  }
}

void make_chain(Graph &graph, size_t candidate_count, bool cycle)
{
  for ( size_t index = 0; index < graph.blocks.size(); ++index )
  {
    graph.blocks[index].successors.clear();
    graph.set_instructions(index, index < candidate_count ? 1 : 3);
    if ( index < candidate_count )
    {
      const int successor = index + 1 < candidate_count
          ? int(index + 1) : cycle ? 0 : int(candidate_count);
      graph.blocks[index].successors.push_back(successor);
    }
  }
  graph.update_predecessors();
}

void targeted_graphs()
{
  check(!block_merge_handler_t::detect_split_blocks(nullptr), "null MBA must be rejected");
  Graph empty(0);
  check(!equivalent(empty), "empty MBA must be rejected");

  Graph threshold(20);
  make_chain(threshold, 6, false);
  check(!equivalent(threshold), "a ratio of exactly 0.30 must be rejected despite a long chain");
  make_chain(threshold, 7, false);
  check(equivalent(threshold), "a ratio above 0.30 and four-block witness must be detected");
  threshold.mba.bad_sp = true;
  check(!equivalent(threshold), "bad stack-pointer state must remain a detector barrier");
  threshold.mba.bad_sp = false;
  threshold.mba.bad_call_sp = true;
  check(!equivalent(threshold), "bad call stack-pointer state must remain a detector barrier");

  for ( size_t length = 1; length <= 4; ++length )
  {
    Graph ring(length);
    make_chain(ring, length, true);
    check(equivalent(ring) == (length == 4), "cycles require four distinct candidate blocks");
  }
  Graph dense(2048);
  make_chain(dense, 2047, false);
  check(equivalent(dense), "a long straight chain must be detected with bounded traversal");
  make_chain(dense, 2048, true);
  check(equivalent(dense), "a long cycle must be detected with bounded traversal");
  make_chain(dense, 400, false);
  check(!equivalent(dense), "a sparse long chain below the ratio threshold must be rejected");

  Graph long_blocks(64);
  for ( size_t index = 0; index < long_blocks.blocks.size(); ++index )
    long_blocks.set_instructions(index, 4096);
  check(!equivalent(long_blocks), "long instruction lists must be classified with bounded reads");
}

using Detector = bool (*)(mbl_array_t *);
volatile uint64_t benchmark_sink = 0;

struct Measurement
{
  uint64_t elapsed_ns = 0;
  uint64_t block_lookups = 0;
  uint64_t link_reads = 0;
};

Measurement measure(Graph &graph, Detector detector, size_t repetitions)
{
  graph.mba.block_lookups = 0;
  instruction_link_reads = 0;
  uint64_t selected = 0;
  const auto begin = std::chrono::steady_clock::now();
  for ( size_t iteration = 0; iteration < repetitions; ++iteration )
    selected += detector(&graph.mba) ? 1 : 0;
  const auto end = std::chrono::steady_clock::now();
  benchmark_sink += selected;
  return {uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count()),
          graph.mba.block_lookups, instruction_link_reads};
}

void benchmark_case(const char *name, Graph &graph, size_t repetitions)
{
  for ( size_t sample = 0; sample < 7; ++sample )
  {
    const bool baseline_first = sample % 2 == 0;
    Measurement before, after;
    if ( baseline_first )
    {
      before = measure(graph, reference_detect_split_blocks, repetitions);
      after = measure(graph, block_merge_handler_t::detect_split_blocks, repetitions);
    }
    else
    {
      after = measure(graph, block_merge_handler_t::detect_split_blocks, repetitions);
      before = measure(graph, reference_detect_split_blocks, repetitions);
    }
    std::cout << name << ',' << graph.mba.qty << ',' << sample << ',' << repetitions
              << ',' << before.elapsed_ns << ',' << after.elapsed_ns
              << ',' << before.block_lookups << ',' << after.block_lookups
              << ',' << before.link_reads << ',' << after.link_reads << '\n';
  }
}

void benchmarks()
{
  std::cout << "case,blocks,sample,repetitions,reference_ns,bounded_ns,reference_block_lookups,bounded_block_lookups,reference_link_reads,bounded_link_reads\n";
  Graph dense(4096);
  make_chain(dense, 4095, false);
  benchmark_case("straight_chain", dense, 1);
  make_chain(dense, 4096, true);
  benchmark_case("cycle", dense, 1);
  make_chain(dense, 1000, false);
  benchmark_case("sparse_chain", dense, 1);
  for ( size_t index = 0; index < dense.blocks.size(); ++index )
  {
    dense.set_instructions(index, 1);
    dense.blocks[index].successors = {int(index + 1 == dense.blocks.size()
        ? index : index / 3 * 3 + (index + 1) % 3)};
  }
  dense.update_predecessors();
  benchmark_case("short_cycles", dense, 10);

  Graph long_blocks(512);
  for ( size_t index = 0; index < long_blocks.blocks.size(); ++index )
    long_blocks.set_instructions(index, 4096);
  benchmark_case("long_blocks", long_blocks, 1);
  Graph ordinary(16);
  benchmark_case("small_negative", ordinary, 10000);
}

} // namespace

int main(int argc, char **argv)
{
  exhaustive_graphs();
  randomized_graphs();
  targeted_graphs();
  if ( failures != 0 )
  {
    std::cerr << failures << " failed assertions; " << equivalence_mismatches
              << " equivalence mismatches across " << graphs_checked << " graphs\n";
    return EXIT_FAILURE;
  }
  std::cerr << "block_merge_tests: PASS (" << graphs_checked
            << " graphs; exhaustive, random, boundary, and operation bounds)\n";
  if ( argc == 2 && std::string(argv[1]) == "--benchmark" )
    benchmarks();
  return EXIT_SUCCESS;
}
