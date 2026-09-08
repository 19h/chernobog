#include "static_analysis_ida_stub.hpp"
#include "hybrid/static_analysis.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

using namespace chernobog::hybrid;

namespace {

struct Head
{
  uint16_t size = 1;
  bool code = true;
  bool decodable = true;
};

struct Fixture
{
  std::map<ea_t, Head> heads;
  size_t flags_calls = 0;
  size_t next_calls = 0;
  size_t decode_calls = 0;
  size_t projection_calls = 0;
  size_t rax_calls = 0;
  size_t smir_calls = 0;
  size_t cancel_polls = 0;
  size_t cancel_at_poll = 0;
  uint32_t rax_size = 1;
};

Fixture fixture;
int failures = 0;

void check(bool condition, const char *message)
{
  if ( !condition )
  {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

rax_status decode_rax(int, uint32_t, uint64_t, const void *, size_t,
                      rax_decoded *out)
{
  ++fixture.rax_calls;
  *out = {};
  out->valid = 1;
  out->size = fixture.rax_size;
  out->flow = RAX_FLOW_FALLTHROUGH;
  return RAX_OK;
}

rax_status analyze_rax(int, uint32_t, uint64_t, const void *, size_t,
                       rax_analysis *out, rax_analysis_effect *, size_t,
                       size_t *required)
{
  ++fixture.smir_calls;
  *out = {};
  out->struct_size = sizeof(*out);
  out->abi_version = RAX_ANALYSIS_ABI_VERSION;
  out->flags = RAX_ANALYSIS_COMPLETE;
  *required = 0;
  return RAX_OK;
}

StaticAnalysisResult analyze(const std::vector<FuncChunk> &chunks, size_t cap,
                             HybridArch architecture = HybridArch::X86_64,
                             bool want_static = true, bool want_smir = true)
{
  ProgramImage image;
  image.arch = architecture;
  if ( !chunks.empty() )
  {
    const auto first = std::min_element(chunks.begin(), chunks.end(),
        [](const FuncChunk &a, const FuncChunk &b) { return a.start < b.start; });
    const auto last = std::max_element(chunks.begin(), chunks.end(),
        [](const FuncChunk &a, const FuncChunk &b) { return a.end < b.end; });
    SegImage segment;
    segment.start = first->start;
    segment.end = last->end;
    segment.bytes.assign(size_t(segment.end - segment.start), 0x90);
    segment.mask.assign((segment.bytes.size() + 7) / 8, 0xFF);
    image.segs.push_back(std::move(segment));
  }
  FuncRange function;
  function.chunks = chunks;
  if ( !chunks.empty() )
  {
    function.start = chunks.front().start;
    function.end = chunks.front().end;
  }
  HybridConfig config;
  config.max_static_instructions = cap;
  config.want_static = want_static;
  config.want_smir = want_smir;
  RaxApi api;
  api.decode = decode_rax;
  api.analyze = analyze_rax;
  return hybrid_analyze_current_function(&api, image, function, config);
}

void test_large_tail_budget()
{
  fixture = {};
  for ( ea_t address = 0x1000; address < 0x1000 + 10000; ++address )
    fixture.heads.emplace(address, Head{});
  auto result = analyze({{0x1000, 0x1000 + 10000}}, 2);
  check(result.stats.truncated && result.instructions.size() == 2,
        "an over-budget function must report exactly the budgeted evidence");
  check(fixture.decode_calls == 3 && result.stats.instruction_heads == 3,
        "over-budget traversal must stop after one successful IDA lookahead");
  check(fixture.projection_calls == 2 && fixture.rax_calls == 2
        && fixture.smir_calls == 2 && fixture.flags_calls == 3,
        "the cap must bound xrefs, rax, SMIR, and dense-head visits");
  check(fixture.next_calls == 2,
        "truncation must not call next_head again");

  fixture = {};
  fixture.heads = {{0x1000, {}}, {0x2000, {}}, {0x3000, {}}};
  result = analyze({{0x1000, 0x1001}, {0x2000, 0x2001}, {0x3000, 0x3001}}, 1);
  check(result.stats.truncated && fixture.decode_calls == 2
        && fixture.projection_calls == 1 && fixture.flags_calls == 2,
        "successful lookahead must stop traversal across subsequent chunks");
}

void test_exact_cap_and_empty_work()
{
  fixture = {};
  fixture.heads = {
      {0x2000, {}}, {0x1000, {}}, {0x1001, {1, false, false}},
      {0x1002, {1, true, false}}, {0x3000, {1, false, false}}};
  const auto result = analyze(
      {{0x2000, 0x2001}, {0x1000, 0x1003}, {0x2800, 0x2800}, {0x3000, 0x3001}}, 2);
  check(!result.stats.truncated && result.stats.canonical_instructions == 2,
        "exact-cap traversal followed by data, failed decode, and empty chunks is complete");
  check(fixture.decode_calls == 3 && fixture.projection_calls == 2,
        "failed decode must not consume budget or project IDA facts");
  check(result.instructions.size() == 2 && result.instructions[0].address == 0x1000
        && result.instructions[1].address == 0x2000 && result.find(0x2000) != nullptr,
        "evidence from non-address-ordered chunks must remain sorted");

  fixture = {};
  check(!analyze({}, 0).stats.truncated && fixture.cancel_polls == 0,
        "zero budget and an empty function do not imply truncation");
  fixture.heads = {{0x1000, {1, false, false}}, {0x1001, {1, true, false}}};
  check(!analyze({{0x1000, 0x1002}}, 0).stats.truncated
        && fixture.projection_calls == 0 && fixture.rax_calls == 0,
        "zero budget with no decodable instructions is complete");
  fixture = {};
  fixture.heads = {{0x1000, {}}, {0x1001, {}}};
  check(analyze({{0x1000, 0x1002}}, 0).stats.truncated
        && fixture.decode_calls == 1 && fixture.projection_calls == 0,
        "zero budget stops before projection at its first decodable head");
}

void test_macro_components()
{
  fixture = {};
  fixture.rax_size = 4;
  fixture.heads = {{0x1000, {16}}, {0x1010, {4}}, {0x2000, {4}}};
  auto result = analyze({{0x1000, 0x1014}, {0x2000, 0x2004}}, 3, HybridArch::ARM64);
  check(result.stats.truncated && result.stats.canonical_instructions == 3
        && result.stats.ida_macro_heads == 1 && result.stats.ida_macro_components == 3,
        "the budget counts canonical AArch64 macro components");
  check(fixture.decode_calls == 1 && fixture.projection_calls == 1
        && fixture.rax_calls == 3 && fixture.smir_calls == 3 && fixture.next_calls == 0,
        "a partial macro must stop head/chunk traversal immediately");
  check(result.instructions.size() == 3
        && result.instructions[0].ida_projection_present
        && !result.instructions[1].ida_projection_present
        && result.instructions[2].address == 0x1008,
        "macro evidence must retain its one head projection and component addresses");

  fixture = {};
  fixture.rax_size = 4;
  fixture.heads = {{0x1000, {16}}};
  result = analyze({{0x1000, 0x1010}}, 4, HybridArch::ARM64, false, true);
  check(!result.stats.truncated && result.stats.canonical_instructions == 4
        && fixture.decode_calls == 1 && fixture.rax_calls == 4
        && fixture.smir_calls == 4 && result.stats.decoder_comparisons == 0,
        "exact-cap macro remains complete in SMIR-only mode");
}

void test_cancellation()
{
  fixture = {};
  fixture.heads = {{0x1000, {}}};
  fixture.cancel_at_poll = 1;
  auto result = analyze({{0x1000, 0x1001}}, 100);
  check(result.stats.truncated && result.instructions.empty()
        && fixture.decode_calls == 0 && fixture.flags_calls == 0,
        "initial cancellation stops before any database or decoder work");

  for ( const bool trailing_code : {false, true} )
  {
    fixture = {};
    fixture.heads.emplace(0x1000, Head{});
    for ( ea_t address = 0x1001; address < 0x1000 + 10000; ++address )
      fixture.heads.emplace(address, Head{1, trailing_code, false});
    fixture.cancel_at_poll = 2;
    result = analyze({{0x1000, 0x1000 + 10000}}, 10000);
    check(result.stats.truncated && result.instructions.size() == 1
          && fixture.cancel_polls == 2 && fixture.flags_calls <= 256,
          "data and failed-decode tails must poll cancellation within 256 work steps");
  }

  fixture = {};
  fixture.rax_size = 4;
  fixture.heads = {{0x1000, {4096}}, {0x3000, {4}}};
  fixture.cancel_at_poll = 2;
  result = analyze({{0x1000, 0x2000}, {0x3000, 0x3004}}, 10000, HybridArch::ARM64);
  check(result.stats.truncated && result.instructions.size() > 0
        && result.instructions.size() <= 256 && fixture.cancel_polls == 2
        && fixture.decode_calls == 1 && fixture.projection_calls == 1
        && fixture.next_calls == 0,
        "one large macro must remain cancellable and stop before the next head/chunk");
}

} // namespace

flags64_t get_flags(ea_t address)
{
  ++fixture.flags_calls;
  const auto found = fixture.heads.find(address);
  return found == fixture.heads.end() ? 0 : found->second.code ? 3 : 2;
}

ea_t next_head(ea_t address, ea_t end)
{
  ++fixture.next_calls;
  const auto next = fixture.heads.upper_bound(address);
  return next == fixture.heads.end() || next->first >= end ? BADADDR : next->first;
}

int decode_insn(insn_t *instruction, ea_t address)
{
  ++fixture.decode_calls;
  const auto found = fixture.heads.find(address);
  if ( found == fixture.heads.end() || !found->second.decodable )
    return 0;
  instruction->size = found->second.size;
  return instruction->size;
}

bool xrefblk_t::first_from(ea_t, int)
{
  ++fixture.projection_calls;
  return false;
}

bool user_cancelled()
{
  ++fixture.cancel_polls;
  return fixture.cancel_at_poll != 0 && fixture.cancel_polls >= fixture.cancel_at_poll;
}

int main()
{
  test_large_tail_budget();
  test_exact_cap_and_empty_work();
  test_macro_components();
  test_cancellation();
  if ( failures != 0 )
    return EXIT_FAILURE;
  std::cout << "static_analysis_tests: PASS (budget, exact cap, macro, cancellation)\n";
  return EXIT_SUCCESS;
}
