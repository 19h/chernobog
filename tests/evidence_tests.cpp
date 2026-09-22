#include "hybrid/evidence.hpp"
#include "hybrid/evidence_view.hpp"
#include "common/string_recovery.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <string>

using namespace chernobog::hybrid;

namespace {
void check(bool condition, const char *message)
{
  if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

template<class Identity>
void verify_identity(const ProgramImage &image, const Identity &identity)
{
  std::vector<uint8_t> expected(identity.bytes.size(), 0);
  std::vector<uint8_t> mask(expected.size() / 8 + (expected.size() % 8 != 0), 0);
  for (size_t i = 0; i < expected.size(); ++i)
  {
    const uint64_t address = identity.start + i;
    for (const auto &segment : image.segs)
    {
      if (address < segment.start || address >= segment.end) continue;
      const uint64_t offset = address - segment.start;
      if (offset >= segment.bytes.size() || offset / 8 >= segment.mask.size()
          || (segment.mask[offset / 8] & (1u << (offset % 8))) == 0)
        break;
      expected[i] = segment.bytes[offset];
      mask[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
      break;
    }
  }
  check(identity.bytes == expected, "captured identity bytes differ from reference");
  check(identity.loaded_mask == mask, "captured identity mask differs from reference");
}

void verify(const ProgramImage &image, const FuncRange &function)
{
  EmulationJobResult emulation;
  for (const auto &segment : image.segs)
  {
    const auto size = static_cast<uint32_t>(segment.end - segment.start);
    emulation.merged.consumed_image_reads.push_back({segment.start, size, 0, 0});
    if (size > 1)
      emulation.merged.consumed_image_reads.push_back({segment.start + 1, size - 1, 1, 1});
  }
  const auto result = hybrid_build_target_evidence(image, function, function.start, {}, {}, emulation);
  size_t expected_chunks = 0;
  for (const auto &chunk : function.chunks)
  {
    if (chunk.end <= chunk.start) continue;
    const auto &identity = result.function_identity.at(expected_chunks++);
    check(identity.start == chunk.start && identity.bytes.size() == chunk.end - chunk.start,
          "function identity must retain exact range boundaries");
    verify_identity(image, identity);
  }
  check(result.function_identity.size() == expected_chunks, "unexpected function identity count");
  check(result.context_identity.size() == image.segs.size(), "overlapping context reads must merge within each segment");
  for (size_t i = 0; i < result.context_identity.size(); ++i)
  {
    const auto &identity = result.context_identity[i];
    check(identity.start == image.segs[i].start
          && identity.bytes.size() == image.segs[i].end - image.segs[i].start,
          "context identity must retain exact range boundaries");
    verify_identity(image, identity);
  }
}

void regressions()
{
  ProgramImage image;
  SegImage segment;
  segment.start = 11; segment.end = 51;
  segment.bytes.assign(40, 0xa5);
  image.segs.push_back(segment);
  FuncRange function;
  function.start = 0; function.end = 64;
  // All source/destination bit alignments and partial trailing bytes.
  for (unsigned bits = 0; bits < 256; ++bits)
  {
    image.segs[0].mask = {255, static_cast<uint8_t>(bits), 255, 0, 255};
    for (uint64_t start = 3; start < 19; ++start)
    {
      function.chunks = {{start, start + 33}, {8, 8}, {9, 8}};
      verify(image, function);
    }
  }
  std::mt19937_64 random(0x917ec5);
  for (unsigned trial = 0; trial < 1000; ++trial)
  {
    image.segs.clear();
    uint64_t cursor = random() % 8;
    const size_t count = static_cast<size_t>(random() % 16);
    for (size_t i = 0; i < count; ++i)
    {
      segment.start = cursor;
      segment.end = cursor + 1 + random() % 64;
      segment.bytes.resize(static_cast<size_t>(segment.end - segment.start));
      segment.mask.resize((segment.bytes.size() + 7) / 8);
      for (auto &value : segment.bytes) value = static_cast<uint8_t>(random());
      for (auto &value : segment.mask) value = static_cast<uint8_t>(random());
#ifndef CHERNOBOG_LEGACY_EVIDENCE
      // Only exercise partial backing storage in the bounded implementation.
      if (trial % 3 == 0) segment.bytes.resize(segment.bytes.size() / 2);
#endif
      if (trial % 5 == 0) segment.mask.clear();
      cursor = segment.end + random() % 16;
      image.segs.push_back(segment);
    }
    function.chunks = {{0, cursor + 8}, {cursor / 3, cursor + 1}};
    verify(image, function);
  }
  image.segs.clear();
  segment.start = std::numeric_limits<uint64_t>::max() - 40;
  segment.end = std::numeric_limits<uint64_t>::max();
  segment.bytes.assign(40, 0x81); segment.mask.assign(5, 255);
  image.segs.push_back(segment);
  function.chunks = {{segment.start - 7, segment.end}};
  verify(image, function);
}

void benchmark()
{
  constexpr size_t total = 8 * 1024 * 1024;
  constexpr unsigned repeats = 10;
  volatile uint64_t sink = 0;
  for (size_t segments : {1u, 256u})
    for (const std::string pattern : {"loaded", "unloaded", "alternating"})
    {
      ProgramImage image;
      for (size_t i = 0; i < segments; ++i)
      {
        SegImage segment;
        segment.start = i * (total / segments + 8);
        segment.end = segment.start + total / segments;
        segment.bytes.assign(total / segments, 0x81);
        segment.mask.assign(total / segments / 8,
                            pattern == "loaded" ? 255 : pattern == "unloaded" ? 0 : 0x55);
        image.segs.push_back(std::move(segment));
      }
      FuncRange function;
      function.chunks = {{0, image.segs.back().end}};
      const auto begin = std::chrono::steady_clock::now();
      for (unsigned i = 0; i < repeats; ++i)
      {
        const auto result = hybrid_build_target_evidence(image, function, 0, {}, {}, {});
        sink = result.function_identity[0].bytes.back();
      }
      const double seconds = std::chrono::duration<double>(
          std::chrono::steady_clock::now() - begin).count() / repeats;
      std::cout << segments << " segments, " << pattern << ": " << seconds
                << " s/capture; last byte=" << sink << '\n';
    }
}

IdentityComparison reference_comparison(
    const std::vector<uint8_t> &expected, const std::vector<uint8_t> &expected_mask,
    const std::vector<uint8_t> &actual, const std::vector<uint8_t> &actual_mask)
{
  IdentityComparison result;
  if (expected.size() != actual.size())
  {
    result.mismatch = IdentityMismatchKind::BYTE_VECTOR_SIZE;
    result.expected_size = expected.size(); result.actual_size = actual.size();
    return result;
  }
  const size_t required = expected.size() / 8 + (expected.size() % 8 != 0);
  if (expected_mask.size() < required || actual_mask.size() < required)
  {
    result.mismatch = IdentityMismatchKind::MASK_VECTOR_SIZE;
    result.expected_size = expected_mask.size(); result.actual_size = actual_mask.size();
    return result;
  }
  for (size_t i = 0; i < expected.size(); ++i)
  {
    const bool left = ((expected_mask[i / 8] >> (i % 8)) & 1) != 0;
    const bool right = ((actual_mask[i / 8] >> (i % 8)) & 1) != 0;
    if (left != right)
    {
      result.mismatch = IdentityMismatchKind::LOADED_STATE;
      result.offset = i; result.expected_byte = left; result.actual_byte = right;
      return result;
    }
    if (left && expected[i] != actual[i])
    {
      result.mismatch = IdentityMismatchKind::BYTE_VALUE;
      result.offset = i; result.expected_byte = expected[i]; result.actual_byte = actual[i];
      return result;
    }
  }
  return result;
}

void verify_comparison(
    const std::vector<uint8_t> &expected, const std::vector<uint8_t> &expected_mask,
    const std::vector<uint8_t> &actual, const std::vector<uint8_t> &actual_mask)
{
  const auto reference = reference_comparison(expected, expected_mask, actual, actual_mask);
  const auto result = hybrid_compare_identity_bytes(expected, expected_mask, actual, actual_mask);
  check(result.mismatch == reference.mismatch && result.offset == reference.offset
        && result.expected_size == reference.expected_size && result.actual_size == reference.actual_size
        && result.expected_byte == reference.expected_byte && result.actual_byte == reference.actual_byte,
        "identity comparison must preserve every first-mismatch diagnostic field");
}

void comparison_regressions()
{
  for (unsigned bits = 0; bits < 256; ++bits)
  {
    const std::vector<uint8_t> expected(64, 0x81);
    auto actual = expected;
    const std::vector<uint8_t> mask(8, static_cast<uint8_t>(bits));
    for (size_t i = 0; i < actual.size(); ++i)
      if ((bits & (1u << (i % 8))) == 0) actual[i] ^= 0xff;
    verify_comparison(expected, mask, actual, mask);
    for (size_t i = 0; i < actual.size(); ++i)
    {
      actual[i] ^= 1;
      verify_comparison(expected, mask, actual, mask);
      actual[i] ^= 1;
    }
  }
  for (size_t size = 0; size <= 193; ++size)
  {
    const std::vector<uint8_t> expected(size, 0x81);
    std::vector<uint8_t> actual = expected;
    const std::vector<uint8_t> mask(size / 8 + (size % 8 != 0), 255);
    verify_comparison(expected, mask, actual, mask);
    for (size_t index = 0; index < size; ++index)
    {
      actual[index] ^= 1;
      verify_comparison(expected, mask, actual, mask);
      auto changed_mask = mask;
      changed_mask.back() ^= static_cast<uint8_t>(1u << ((size - 1) % 8));
      verify_comparison(expected, mask, actual, changed_mask);
      // The earlier payload difference must beat a later loaded-state change.
      actual[index] ^= 1;
      changed_mask = mask;
      changed_mask[index / 8] ^= static_cast<uint8_t>(1u << (index % 8));
      verify_comparison(expected, mask, actual, changed_mask);
      verify_comparison(expected, changed_mask, actual, mask);
    }
    const std::vector<uint8_t> none(mask.size(), 0);
    actual.assign(size, 0xff);
    verify_comparison(expected, none, actual, none);
    if (!mask.empty())
    {
      const std::vector<uint8_t> short_mask(mask.size() - 1, 255);
      verify_comparison(expected, short_mask, actual, mask);
      verify_comparison(expected, mask, actual, short_mask);
    }
    actual.push_back(0);
    verify_comparison(expected, {}, actual, {}); // size error precedes mask errors
  }
  for (size_t size = 1; size < 8; ++size)
    for (unsigned padding = 0; padding < 256; ++padding)
    {
      const auto bits = static_cast<uint8_t>((1u << size) - 1);
      const std::vector<uint8_t> bytes(size, 42);
      verify_comparison(bytes, {bits}, bytes, {static_cast<uint8_t>(bits | padding)});
    }
  std::mt19937_64 random(0xc051de);
  for (unsigned trial = 0; trial < 10000; ++trial)
  {
    const size_t size = static_cast<size_t>(random() % 4097);
    std::vector<uint8_t> expected(size);
    for (auto &byte : expected) byte = static_cast<uint8_t>(random());
    std::vector<uint8_t> actual = expected;
    std::vector<uint8_t> left(size / 8 + (size % 8 != 0));
    for (auto &byte : left)
      byte = trial % 3 == 0 ? 255 : trial % 3 == 1 ? 0 : static_cast<uint8_t>(random());
    auto right = left;
    if (size != 0)
    {
      actual[static_cast<size_t>(random() % size)] ^= 1;
      const size_t index = static_cast<size_t>(random() % size);
      if (trial % 4 != 0) right[index / 8] ^= static_cast<uint8_t>(1u << (index % 8));
    }
    verify_comparison(expected, left, actual, right);
  }
}

void comparison_benchmark()
{
  volatile size_t sink = 0;
  for (size_t size : {32u, 256u, 8u * 1024u * 1024u})
    for (const std::string pattern : {"loaded-equal", "unloaded-equal", "mixed-equal", "mixed-unloaded-diff",
                                    "first-byte", "last-byte", "last-loaded-state"})
    {
      if (size < 1024 && pattern != "loaded-equal") continue;
      std::vector<uint8_t> expected(size, 0x81);
      auto actual = expected;
      std::vector<uint8_t> left((size + 7) / 8,
          pattern == "unloaded-equal" ? 0
          : pattern == "mixed-equal" || pattern == "mixed-unloaded-diff" ? 0x55 : 255);
      auto right = left;
      if (pattern == "mixed-unloaded-diff")
        for (size_t index = 1; index < size; index += 2) actual[index] ^= 1;
      if (pattern == "first-byte") actual.front() ^= 1;
      if (pattern == "last-byte") actual.back() ^= 1;
      if (pattern == "last-loaded-state") right.back() ^= 0x80;
      verify_comparison(expected, left, actual, right);
      const unsigned repeats = size < 1024 || pattern == "first-byte" ? 1000000 : 20;
      const auto begin = std::chrono::steady_clock::now();
      for (unsigned i = 0; i < repeats; ++i)
      {
        const auto result = hybrid_compare_identity_bytes(expected, left, actual, right);
        sink = result.offset + static_cast<size_t>(result.mismatch);
      }
      const double seconds = std::chrono::duration<double>(
          std::chrono::steady_clock::now() - begin).count() / repeats;
      std::cout << size << " bytes, " << pattern << ": " << seconds
                << " s/comparison; diagnostic=" << sink << '\n';
    }
}

#ifndef CHERNOBOG_LEGACY_EVIDENCE
std::vector<uint8_t> terminated(const std::string &text)
{
  std::vector<uint8_t> bytes(text.begin(), text.end());
  bytes.push_back(0);
  return bytes;
}

TargetEvidence string_evidence(const std::vector<uint8_t> &bytes)
{
  TargetEvidence evidence;
  for (uint32_t index = 0; index < 2; ++index)
  {
    RunObservation run;
    run.ran = true;
    run.outcome.memory_observation_available = true;
    run.provenance.run_id = index;
    run.provenance.seed = index + 17;
    evidence.runs.push_back(run);
    MemoryBytes written;
    written.addr = 0x4000;
    written.scope = DataScope::IMAGE;
    written.run_id = index;
    written.seed = index + 17;
    written.bytes = bytes;
    evidence.events.final_writes.push_back(written);
  }
  return evidence;
}

void runtime_string_regressions()
{
  using chernobog::string_recovery::recover_runtime_utf8_prefix;
  for (const std::string text : {u8"Gr\u00fc\u00dfe \u4e16\u754c", u8"\u03b1\u03b2\u03b3\u03b4", u8"\U0001f680\U0001f680\U0001f680\U0001f680", "ASCII"})
  {
    const auto candidates = hybrid_consensus_runtime_strings(string_evidence(terminated(text)));
    check(candidates.size() == 1 && candidates[0].value == text
          && candidates[0].observations == 2 && candidates[0].eligible_runs == 2
          && candidates[0].runs == std::vector<uint32_t>({0, 1}),
          "UTF-8 consensus must preserve exact bytes and run provenance");
  }
  const auto greek = terminated(u8"\u03b1\u03b2\u03b3\u03b4");
  const auto decoded = recover_runtime_utf8_prefix(greek, 4, 8);
  check(decoded && decoded->characters == 4 && decoded->payload_bytes == 8
        && decoded->explicitly_terminated,
        "runtime bounds must distinguish scalar count from encoded byte count");
  check(!recover_runtime_utf8_prefix(greek, 4, 7), "runtime byte cap must be enforced");
  check(!recover_runtime_utf8_prefix(terminated(u8"\U0001f680")),
        "one four-byte scalar must not satisfy the four-character minimum");
  check(!recover_runtime_utf8_prefix(greek, 0, 8)
        && !recover_runtime_utf8_prefix(greek, 4, 3), "invalid runtime limits must reject");

  const std::vector<std::vector<uint8_t>> invalid_suffixes = {
      {0xc0, 0xaf}, {0xe0, 0x80, 0xaf}, {0xf0, 0x80, 0x80, 0x80},
      {0xed, 0xa0, 0x80}, {0xed, 0xbf, 0xbf}, {0xf4, 0x90, 0x80, 0x80},
      {0xf8, 0x88, 0x80, 0x80, 0x80}, {0x80}, {0xe2, 0x82},
      {0xe2, 'A', 0xac}, {'\t'}, {'\n'}, {'\r'}, {0x7f}, {0xc2, 0x85}};
  for (const auto &suffix : invalid_suffixes)
  {
    std::vector<uint8_t> bytes{'a', 'b', 'c', 'd'};
    bytes.insert(bytes.end(), suffix.begin(), suffix.end());
    bytes.push_back(0);
    check(hybrid_consensus_runtime_strings(string_evidence(bytes)).empty(),
          "malformed UTF-8 and control code points must not become runtime strings");
  }
  check(hybrid_consensus_runtime_strings(string_evidence({'a', 'b', 'c', 'd'})).empty(),
        "captured runtime prefixes still require a terminator");
  auto prefix = terminated(u8"Gr\u00fc\u00dfe \u4e16\u754c");
  prefix.push_back(0xff);
  check(hybrid_consensus_runtime_strings(string_evidence(prefix)).size() == 1,
        "bytes after the first terminator are outside the string fact");

  for (const std::vector<uint8_t> &invalid : {std::vector<uint8_t>{},
       std::vector<uint8_t>{'a', 'b', 'c', 'd'}, terminated("different")})
  {
    auto evidence = string_evidence(terminated(u8"Gr\u00fc\u00dfe \u4e16\u754c"));
    auto duplicate = evidence.events.final_writes.back();
    duplicate.bytes = invalid;
    evidence.events.final_writes.push_back(duplicate);
    check(hybrid_consensus_runtime_strings(evidence).empty(),
          "invalid or conflicting duplicates must veto a valid runtime record");
    std::reverse(evidence.events.final_writes.begin(), evidence.events.final_writes.end());
    check(hybrid_consensus_runtime_strings(evidence).empty(),
          "duplicate rejection must be independent of observation order");
  }
  auto evidence = string_evidence(terminated(u8"Gr\u00fc\u00dfe \u4e16\u754c"));
  auto unrelated = evidence.events.final_writes.back();
  unrelated.bytes.clear();
  unrelated.run_id = 99;
  evidence.events.final_writes.push_back(unrelated);
  unrelated.run_id = 1;
  unrelated.scope = DataScope::STACK;
  evidence.events.final_writes.push_back(unrelated);
  check(hybrid_consensus_runtime_strings(evidence).size() == 1,
        "ineligible runs and non-image records must not veto image consensus");
  evidence.events.final_writes = {evidence.events.final_writes.front()};
  check(hybrid_consensus_runtime_strings(evidence).empty(),
        "a missing observable run must reject UTF-8 consensus");
  auto distinct = string_evidence(terminated(u8"caf\u00e9"));
  distinct.events.final_writes.back().bytes = terminated(u8"cafe\u0301");
  check(hybrid_consensus_runtime_strings(distinct).empty(),
        "Unicode equivalence must not replace byte-exact runtime agreement");
}
#endif
void temporal_memory_regressions()
{
  const uint8_t value[]{'s', 'e', 'c', 'r', 'e', 't', 0};
  TargetEvidence evidence;
  for ( uint32_t run_id = 0; run_id < 2; ++run_id )
  {
    TemporalMemory memory;
    memory.enabled = true;
    memory.context = 0x1000;
    memory.heap_begin = 0x8000 + run_id * 0x1000;
    memory.heap_end = memory.heap_begin + 0x1000;
    memory.run_id = run_id;
    memory.seed = 11 + run_id;
    const auto address = memory.allocate(16, 0x1100, 0x2000, 1);
    check(address == memory.heap_begin, "heap fixture must use its configured base");
    check(memory.identify(address, 16) == UseCaptureStatus::EXACT
          && memory.identify(address + 15, 2) == UseCaptureStatus::OBJECT_BOUNDARY,
          "allocation bounds must use requested object size");
    memory.capture(0x1200, 0x2010, 0, UseProducer::MODELED_ARGUMENT,
        DataScope::HEAP, address, value, sizeof(value), sizeof(value), 2);
    check(!memory.release(address + 1, 3) && memory.release(0, 3)
          && memory.release(address, 3) && !memory.release(address, 4),
          "NULL free, interior free, and double free must have distinct outcomes");
    check(memory.identify(address, 1) == UseCaptureStatus::OUTSIDE_LIFETIME,
          "released storage must not retain a live allocation identity");
    const auto reused = memory.allocate(8, 0x1100, 0x2000, 5);
    check(reused == address && memory.allocations.back().generation == 2
          && memory.allocations.back().occurrence == 2,
          "reuse must change generation and per-origin allocation occurrence");
    memory.capture(0x1200, 0x2010, 0, UseProducer::MODELED_ARGUMENT,
        DataScope::HEAP, reused, value, sizeof(value), sizeof(value), 6);
    check(memory.uses.back().occurrence == 2 && memory.uses.front().occurrence == 1,
          "repeated calls at one site must remain distinct dynamic uses");
    RunObservation run;
    run.ran = true;
    run.provenance.run_id = run_id;
    run.provenance.seed = memory.seed;
    run.outcome.temporal_observation_available = true;
    run.outcome.temporal_capture_complete = true;
    evidence.runs.push_back(run);
    evidence.events.allocations.insert(evidence.events.allocations.end(),
        memory.allocations.begin(), memory.allocations.end());
    evidence.events.uses.insert(evidence.events.uses.end(), memory.uses.begin(), memory.uses.end());
  }
  check(hybrid_consensus_use_strings(evidence).size() == 2,
        "released first generation and live second generation must both retain use values");
  auto different_generations = evidence;
  for ( auto &allocation : different_generations.events.allocations )
    if ( allocation.run_id == 1 ) allocation.generation += 4;
  for ( auto &use : different_generations.events.uses )
    if ( use.run_id == 1 ) use.generation += 4;
  check(hybrid_consensus_use_strings(different_generations).size() == 2,
        "physical generations are per-run lifetime guards, not cross-run object identity");
  for ( unsigned negative = 0; negative < 13; ++negative )
  {
    auto changed = evidence;
    switch ( negative )
    {
      case 0: changed.events.uses.erase(changed.events.uses.begin()); break;
      case 1: changed.events.uses[0].bytes[0] = 'X'; break;
      case 2: changed.events.uses[0].bytes.back() = 'X'; break;
      case 3: changed.events.uses[0].status = UseCaptureStatus::BYTE_LIMIT; break;
      case 4: changed.events.uses[0].generation = 2; break;
      case 5: changed.events.uses[0].sequence = 3; break; // free boundary
      case 6: changed.events.uses[0].sequence = 1; break; // allocation boundary
      case 7: changed.events.uses[0].offset = 15; break;
      case 8: changed.events.uses[0].bytes[1] = 0xFF; break;
      case 9:
        changed.events.uses.push_back(changed.events.uses[0]);
        changed.events.uses.back().address += 1;
        break;
      case 10:
        changed.events.allocations.push_back(changed.events.allocations[0]);
        changed.events.allocations.back().released = 2;
        break;
      case 11: changed.events.uses[0].object_site += 1; break;
      case 12: changed.events.uses[0].producer = UseProducer::EXECUTED_READ; break;
    }
    const auto candidates = hybrid_consensus_use_strings(changed);
    check(candidates.size() == 1 && candidates[0].use.occurrence == 2,
          "missing/conflicting/invalid first-use evidence must fail closed independently");
  }
  for ( unsigned negative = 0; negative < 4; ++negative )
  {
    auto changed = evidence;
    switch ( negative )
    {
      case 0: changed.runs[0].ran = false; break;
      case 1: changed.runs[0].outcome.temporal_capture_complete = false; break;
      case 2: changed.runs[0].outcome.temporal_observation_available = false; break;
      case 3: changed.runs[0].outcome.temporal_capture_truncated = true; break;
    }
    check(hybrid_consensus_use_strings(changed).empty(),
          "failed or incomplete scheduled runs must never be removed to create agreement");
  }
  TemporalMemory bounded;
  bounded.heap_begin = 0x1000;
  bounded.heap_end = 0x100000;
  for ( size_t i = 0; i < TemporalMemory::allocation_limit; ++i )
    check(bounded.allocate(1, i, 0x2000, i) != 0, "allocation cap admits its bounded prefix");
  check(bounded.allocate(1, 0, 0x2000, 9999) == 0 && bounded.allocation_exhausted,
        "allocation ledger exhaustion must be explicit");
  bounded.enabled = true;
  bounded.byte_budget = 1;
  bounded.capture(0x10, 0, -1, UseProducer::EXECUTED_READ, DataScope::IMAGE,
      0x20, value, sizeof(value), sizeof(value), 0);
  check(bounded.truncated && bounded.uses[0].bytes.size() == 1
        && bounded.uses[0].status == UseCaptureStatus::BYTE_LIMIT,
        "byte truncation must retain status rather than inventing a terminated value");
  for ( size_t i = 1; i <= TemporalMemory::use_limit; ++i )
    bounded.capture(i, 0, -1, UseProducer::EXECUTED_READ, DataScope::IMAGE,
        0x20, value, 1, 1, i);
  check(bounded.uses.size() == TemporalMemory::use_limit && bounded.truncated,
        "event and occurrence bookkeeping must remain bounded after byte exhaustion");
  TemporalMemory occurrences;
  occurrences.heap_begin = 0x8000;
  occurrences.heap_end = 0x9000;
  occurrences.enabled = true;
  check(occurrences.allocate(0, 0x10, 0x20, 0) == 0, "zero-size allocation follows explicit failure model");
  const auto object = occurrences.allocate(8, 0x10, 0x20, 1);
  check(occurrences.allocations.back().occurrence == 2,
        "failed allocations must retain their place in semantic origin occurrence counts");
  occurrences.capture(0x30, 0x40, 1, UseProducer::MODELED_ARGUMENT,
      DataScope::HEAP, object, nullptr, 0, 0, 2);
  occurrences.capture(0x30, 0x40, 1, UseProducer::MODELED_ARGUMENT,
      DataScope::HEAP, object, value, sizeof(value), sizeof(value), 3);
  check(occurrences.uses.size() == 1 && occurrences.uses[0].occurrence == 2,
        "zero-byte calls must not collapse dynamic use occurrence identities");
  TemporalMemory wide;
  wide.enabled = true;
  std::vector<uint8_t> long_bytes(8192, 'a');
  long_bytes.back() = 0;
  wide.capture(1, 2, 0, UseProducer::MODELED_ARGUMENT, DataScope::IMAGE,
      0x1000, long_bytes.data(), long_bytes.size(), long_bytes.size(), 0);
  check(wide.uses[0].bytes.size() == TemporalMemory::snapshot_limit
        && wide.uses[0].status == UseCaptureStatus::BYTE_LIMIT && wide.truncated,
        "a single snapshot must respect its cap even with remaining total budget");
  wide.capture(2, 0, -1, UseProducer::EXECUTED_READ, DataScope::IMAGE,
      0x1000, nullptr, 0, 16, 1);
  check(wide.uses.back().status == UseCaptureStatus::INCOMPLETE_VALUE
        && wide.uses.back().bytes.empty(),
        "missing original wide-read bytes must never be reconstructed after retirement");
  occurrences.capture(0x60, 0, -1, UseProducer::EXECUTED_READ, DataScope::STACK,
      occurrences.heap_begin - 1, value, 2, 2, 4);
  check(occurrences.uses.back().scope == DataScope::HEAP
        && occurrences.uses.back().status != UseCaptureStatus::EXACT,
        "a heap-boundary crossing must not acquire stack-frame identity");
}
} // namespace

void evidence_view_regressions()
{
  TargetEvidence source;
  source.scope.function_start = 0x1000;
  source.scope.generation = UINT64_MAX;
  source.events.execution = {{0x1002, 1, 9, 2, 7}, {0x1001, 1, 3, 1, 8}};
  AllocationLifetime allocation;
  allocation.id = 1; allocation.generation = 2; allocation.address = 0x8000;
  allocation.size = 16; allocation.site = 0x1010; allocation.allocated = 2;
  allocation.released = 8; allocation.live = false; allocation.run_id = 1; allocation.seed = 8;
  source.events.allocations.push_back(allocation);
  UseSnapshot use;
  use.allocation_id = 1; use.generation = 2; use.sequence = 5; use.site = 0x1020;
  use.run_id = 1; use.seed = 8; use.producer = UseProducer::MODELED_ARGUMENT;
  use.bytes.assign(80, 0xA5);
  source.events.uses.push_back(use);
  BranchObservation branch;
  branch.instruction = 0x1030; branch.sequence = 6; branch.provenance.run_id = 1;
  branch.provenance.seed = 8; branch.disposition = BranchDisposition::FALLTHROUGH;
  branch.consumed_context_complete = true;
  source.branches.push_back(branch);
  auto view = project_evidence_view(source);
  check(view.events.size() == 6 && view.events[0].at("kind") == "allocate"
        && view.events[4].at("kind") == "release" && view.events[5].at("run") == "0x2",
        "inspection orders within run/seed and retains branch/allocate/use/release events");
  check(view.events[2].at("bytes_hex").size() == 128
        && view.events[2].at("display_truncated") == "true",
        "inspection caps byte display without claiming the snapshot itself is incomplete");
  check(view.events[4].at("site") == "0x0" && view.events[4].at("allocation_site") == "0x1010",
        "release order must not fabricate a freeing callsite");
  check(view.claims.size() == 2 && view.claims[1].at("falsifies_claim") == "true",
        "inspection exposes context-complete opposing branch observations");
  auto json = evidence_view_json(source, view, false, 17);
  check(json.find("\"fresh\":false") != std::string::npos
        && json.find("0xffffffffffffffff") != std::string::npos,
        "stale state and full 64-bit generation remain exact in JSON");
  source.events.execution.clear();
  for (size_t i = 0; i < 2000; ++i)
    source.events.execution.push_back({0x1000, 1, 2000 - i, uint32_t(i % 2), 8});
  for (size_t i = 0; i < 129; ++i)
  {
    source.events.edges.push_back({0x1000 + i, 0x2000 + i, 1, 8, ExecEdge::Kind::Jump, i});
    StaticInstructionEvidence item;
    item.address = 0x1000 + i; item.ida.valid = true;
    item.ida.has_target = true; item.ida.target = 0x2000 + i;
    source.static_analysis.instructions.push_back(item);
  }
  view = project_evidence_view(source);
  check(view.events.size() == EvidenceView::event_limit && view.omitted.at("events") == 1109,
        "inspection caps retained events and counts every omitted event");
  check(view.edges.size() == EvidenceView::edge_limit
        && view.omitted.at("encoded_edges") == 1 && view.omitted.at("observed_edges") == 1,
        "encoded and observed edges have separate retention allowances");
  check(view.edges.front().at("truth") == "encoding" && view.edges.back().at("truth") == "witness",
        "observations cannot acquire a static-proof label");
  source = TargetEvidence{};
  RunObservation stopped;
  stopped.ran = true;
  stopped.outcome.function_boundary = true;
  stopped.outcome.function_boundary_source = 0x1100;
  stopped.outcome.function_boundary_target = 0x2100;
  stopped.outcome.temporal_capture_truncated = true;
  source.runs.push_back(stopped);
  StatePoint state;
  state.sequence = 1;
  state.regs.resize(34);
  source.events.states.push_back(state);
  for (size_t i = 0; i < 129; ++i)
  {
    source.events.allocations.push_back(allocation);
    source.runs.push_back(stopped);
    branch.instruction = 0x1000 + i;
    source.branches.push_back(branch);
  }
  view = project_evidence_view(source);
  check(view.runs.size() == 128 && view.omitted.at("runs") == 2
        && view.lifetimes.size() == 128 && view.omitted.at("lifetimes") == 1
        && view.claims.size() == 128 && view.omitted.at("claims") == 130,
        "run/lifetime/claim bounds report omitted records exactly");
  check(view.runs[0].at("kind") == "function-boundary"
        && view.runs[0].at("boundary_source") == "0x1100"
        && view.runs[0].at("boundary_target") == "0x2100"
        && view.runs[0].at("temporal_truncated") == "true",
        "boundary stops and truncation survive inspection projection");
  check(view.events[0].at("kind") == "state" && view.events[0].at("registers_omitted") == "2",
        "register-state inspection reports its independent register cap");
}

void native_read_stream_regressions()
{
  TargetEvidence source;
  source.scope.function_start=0x1000;
  const uint8_t text[]{'s','e','c','r','e','t','!',0};
  for(uint32_t id=1;id<=2;++id)
  {
    TemporalMemory memory;memory.enabled=true;memory.context=0x1000;
    memory.heap_begin=0x8000+id*0x1000;memory.heap_end=memory.heap_begin+0x1000;
    memory.run_id=id;memory.seed=id+10;
    for(unsigned lifetime=0;lifetime<2;++lifetime)
    {
      const uint64_t epoch=50*lifetime;
      const uint64_t address=memory.allocate(16,0x1100,0x2000,epoch+1);
      for(size_t i=0;i<sizeof(text);++i)
      {
        const uint64_t sequence=epoch+10+4*i;
        memory.capture(0x1200,0,-1,UseProducer::EXECUTED_READ,DataScope::HEAP,
            address+i,text+i,1,1,sequence);
        source.events.data.push_back({0x1200,address+i,text[i],1,RAX_MEM_READ,
            DataScope::HEAP,sequence+1,id,memory.seed});
      }
      check(memory.release(address,epoch+45),"native stream fixture releases exact allocation");
    }
    RunObservation run;run.ran=true;run.provenance.run_id=id;run.provenance.seed=memory.seed;
    run.outcome.temporal_observation_available=true;run.outcome.temporal_capture_complete=true;
    run.outcome.memory_observation_available=true;source.runs.push_back(run);
    source.events.uses.insert(source.events.uses.end(),memory.uses.begin(),memory.uses.end());
    source.events.allocations.insert(source.events.allocations.end(),memory.allocations.begin(),memory.allocations.end());
  }
  const auto result=hybrid_consensus_use_strings(source);
  {
    std::vector<NativeTemporalStringRun> native;
    for(const auto &run:source.runs)
    {
      NativeTemporalStringRun copy;
      copy.capture=run.provenance.run_id+100;copy.context=0x1000;copy.image_hash=123;copy.generation=1;
      copy.run_id=run.provenance.run_id;copy.seed=run.provenance.seed;copy.ran=true;
      copy.outcome=run.outcome;copy.outcome.temporal_capture_complete=false;
      copy.outcome.native_region=copy.outcome.native_temporal_requested=copy.outcome.native_temporal_complete=true;
      copy.outcome.returned=copy.outcome.stop_valid=true;copy.outcome.stop_reason=RAX_STOP_UNTIL;
      copy.outcome.region_identity=copy.capture;
      copy.bindings={{0x2000,EmuSummaryKind::ALLOCATE,"malloc"},{0x2010,EmuSummaryKind::DEALLOCATE,"free"}};
      for(const auto &u:source.events.uses)if(u.run_id==copy.run_id)copy.events.uses.push_back(u);
      for(const auto &d:source.events.data)if(d.run_id==copy.run_id)copy.events.data.push_back(d);
      for(const auto &a:source.events.allocations)if(a.run_id==copy.run_id)copy.events.allocations.push_back(a);
      native.push_back(std::move(copy));
    }
    const auto projected=hybrid_native_temporal_strings(native);
    check(projected.available && projected.observations.size()==2 && projected.captures.size()==2
          && projected.observations[0].read_fragments.size()==2,
          "separate native projection retains every capture and raw fragment without ordinary proof flags");
    auto forged_function=source;
    forged_function.runs[0].outcome.native_region=true;
    check(hybrid_consensus_use_strings(forged_function).empty(),
          "native scope cannot enter ordinary use publication even with forged function completeness");
    auto oversized=native;oversized.resize(17);
    check(!hybrid_native_temporal_strings({}).available && !hybrid_native_temporal_strings(oversized).available
          && !hybrid_native_temporal_strings(native,0).available
          && !hybrid_native_temporal_strings(native,4,4097).available,
          "native corpus and payload policy have hard bounds");
    std::reverse(native[1].bindings.begin(),native[1].bindings.end());
    check(hybrid_native_temporal_strings(native).observations.size()==2,"binding order does not change model contract");
    for(unsigned failure=0;failure<21;++failure)
    {
      auto bad=native;auto &run=bad[1];
      switch(failure)
      {
        case 0:run.outcome.native_temporal_complete=false;break;
        case 1:run.outcome.temporal_capture_complete=true;break;
        case 2:run.capture=bad[0].capture;break;
        case 3:run.seed=bad[0].seed;run.run_id=bad[0].run_id;break;
        case 4:run.image_hash++;break;
        case 5:run.generation++;break;
        case 6:run.context++;break;
        case 7:run.bindings[0].kind=EmuSummaryKind::MEMSET;break;
        case 8:run.bindings[0].name="renamed";break;
        case 9:run.bindings.push_back(run.bindings[0]);break;
        case 10:run.events.uses[0].seed++;break;
        case 11:run.outcome.region_code_changed=true;break;
        case 12:run.outcome.native_region=false;break;
        case 13:run.outcome.stop_valid=false;break;
        case 14:run.outcome.data_trace_filtered=true;break;
        case 15:run.outcome.environment_model_failure=true;break;
        case 16:run.outcome.consumed_context_complete=true;break;
        case 17:run.events.data.push_back(run.events.data.front());break;
        case 18:run.events.uses.push_back(run.events.uses.front());break;
        case 19:run.outcome.temporal_capture_truncated=true;break;
        case 20:run.ran=false;break;
      }
      const auto rejected=hybrid_native_temporal_strings(bad);
      check(!rejected.available && rejected.observations.empty() && rejected.captures.empty(),
            "native corpus cannot shrink around an incompatible, duplicate or incomplete capture");
    }
    auto divergent=native;
    divergent[1].events.uses[0].bytes[0]='x';divergent[1].events.data[0].value='x';
    const auto partial=hybrid_native_temporal_strings(divergent);
    check(partial.available && partial.observations.size()==1,
          "a disagreeing native use is omitted without losing an unrelated matching lifetime");
  }
  check(result.size()==2,"scalar byte reads form two distinct lifetime-specific strings");
  for(const auto &candidate:result)
    check(candidate.value=="secret!" && candidate.use.producer==UseProducer::EXECUTED_READ_STREAM
          && candidate.read_fragments.size()==2 && candidate.read_fragments.front().size()==8
          && candidate.read_fragments[0][0].address!=candidate.read_fragments[1][0].address
          && candidate.use.bytes.size()==8 && candidate.eligible_runs==2,
          "derived streams preserve every original read and cross-address provenance");
  const auto view=project_evidence_view(source);
  size_t displayed=0;
  for(const auto &event:view.events)if(event.at("kind")=="read-stream")
  {
    ++displayed;
    check(event.at("truth")=="observation" && event.at("read_count")=="8"
          && event.at("fragments_omitted")=="0" && event.at("bytes_hex")=="7365637265742100"
          && event.at("first_sequence")!=event.at("last_sequence"),
          "stream timeline exposes the exact read interval and immutable bytes");
  }
  check(displayed==4,"timeline retains one derived stream per use and agreeing run");
  check(view.read_streams.size()==4,"dedicated stream table retains all four witnesses");
  for(size_t width:{size_t(1),size_t(2),size_t(4)})
  {
    auto unicode=source;unicode.events.uses.clear();unicode.events.data.clear();
    const uint8_t encoded[]{'s',0xc3,0xa9,'c','r','e','t',0};
    for(size_t start=0;start<source.events.uses.size();start+=8)
      for(size_t i=0;i<8;i+=width)
      {
        auto use=source.events.uses[start+i];
        use.bytes.assign(encoded+i,encoded+i+width);use.observed_size=width;
        unicode.events.uses.push_back(use);uint64_t scalar=0;
        for(size_t byte=0;byte<width;++byte)scalar|=uint64_t(encoded[i+byte])<<(8*byte);
        unicode.events.data.push_back({use.site,use.address,scalar,uint32_t(width),RAX_MEM_READ,
            use.scope,use.sequence+1,use.run_id,use.seed});
      }
    const auto streams=hybrid_consensus_native_read_strings(unicode);
    check(streams.size()==2 && streams[0].value==std::string("s\xc3\xa9" "cret")
          && streams[0].read_fragments[0].size()==8/width,
          "UTF-8 scalars can cross byte/word/dword read boundaries");
    check(hybrid_consensus_native_read_strings(unicode,7).empty()
          && hybrid_consensus_native_read_strings(unicode,4,6).empty(),
          "stream minimum counts Unicode scalars while maximum counts payload bytes");
  }
  for(auto scope:{DataScope::IMAGE,DataScope::STACK})
  {
    auto relocated=source;relocated.events.allocations.clear();
    for(size_t i=0;i<relocated.events.uses.size();++i)
    {
      auto &use=relocated.events.uses[i];auto &data=relocated.events.data[i];
      use.scope=scope;use.address=0x4000+i%8+(scope==DataScope::STACK?0x1000*use.run_id:0);
      use.object_site=scope==DataScope::STACK?use.context:use.address;
      use.offset=scope==DataScope::STACK?int64_t(i%8):0;
      use.object_callee=use.object_occurrence=use.object_size=use.allocation_id=use.generation=0;
      data.addr=use.address;data.scope=scope;
    }
    check(hybrid_consensus_native_read_strings(relocated).size()==2,
          "image addresses and relative frame offsets retain their separate stream identities");
  }
  for(unsigned failure=0;failure<21;++failure)
  {
    auto changed=source;
    switch(failure)
    {
      case 0:changed.events.uses[0].bytes[0]='X';break;
      case 1:changed.events.data[0].value='X';break;
      case 2:changed.events.data[0].sequence+=1;break;
      case 3:changed.events.uses[0].status=UseCaptureStatus::INCOMPLETE_VALUE;break;
      case 4:changed.events.uses[0].generation+=1;break;
      case 5:changed.events.allocations[0].released=12;break;
      case 6:changed.events.data.erase(changed.events.data.begin());break;
      case 7:changed.events.uses[0].producer=UseProducer::EXECUTED_READ_STREAM;break;
      case 8:changed.events.uses[0].offset+=1;break;
      case 9:changed.events.uses[0].object_callee+=1;break;
      case 10:changed.events.uses[0].sequence=UINT64_MAX;break;
      case 11:changed.events.uses[0].observed_size=9;break;
      case 12:changed.events.data[0].scope=DataScope::OTHER;break;
      case 13:changed.events.uses[7].bytes[0]='x';changed.events.data[7].value='x';break;
      case 14:changed.events.data.push_back({0x1300,0x5000,0,1,RAX_MEM_WRITE,DataScope::IMAGE,12,1,11});break;
      case 15:changed.events.data.push_back({0x1300,0x5000,0,1,RAX_MEM_READ,DataScope::IMAGE,12,1,11});break;
      case 16:changed.events.edges.push_back({0x1300,0x2000,1,11,ExecEdge::Kind::Call,12});break;
      case 17:changed.events.edges.push_back({0x1300,0x2000,1,11,ExecEdge::Kind::Unknown,12});break;
      case 18:changed.events.uses[1].site+=1;changed.events.data[1].from+=1;break;
      case 19:changed.events.uses[0].occurrence+=1;break;
      case 20:changed.events.uses[0].context+=1;break;
    }
    const auto rejected=hybrid_consensus_native_read_strings(changed);
    check(rejected.size()==1 && rejected[0].use.object_occurrence==2,
          "invalid first-stream witness must not suppress unrelated second lifetime or gain consensus");
  }
  for(unsigned failure=0;failure<7;++failure)
  {
    auto changed=source;
    switch(failure)
    {
      case 0:changed.runs[0].outcome.memory_observation_available=false;break;
      case 1:changed.runs[0].outcome.temporal_capture_truncated=true;break;
      case 2:changed.runs[0].ran=false;break;
      case 3:changed.events.data.push_back(changed.events.data[0]);break;
      case 4:changed.events.uses.push_back(changed.events.uses[0]);break;
      case 5:changed.events.allocations.push_back(changed.events.allocations[0]);break;
      case 6:changed.runs[0].outcome.data_trace_filtered=true;break;
    }
    check(hybrid_consensus_native_read_strings(changed).empty(),
          "incomplete corpus or duplicate sequence/object disables derived stream consensus");
  }
  std::reverse(source.events.uses.begin(),source.events.uses.end());
  std::reverse(source.events.data.begin(),source.events.data.end());
  check(hybrid_consensus_native_read_strings(source).size()==2,
        "normalization storage order does not replace event sequence order");
  for(size_t length:{size_t(20),size_t(1040),size_t(4096),size_t(4097)})
  {
    TargetEvidence bounded;bounded.runs.push_back(source.runs[0]);
    bounded.scope.function_start=source.scope.function_start;
    for(size_t i=0;i<length;++i)
    {
      UseSnapshot use;use.context=0x1000;use.site=0x1200;use.occurrence=i+1;
      use.scope=DataScope::IMAGE;use.address=use.object_site=0x4000+i;
      use.sequence=10+4*i;use.observed_size=1;use.run_id=1;use.seed=11;
      use.status=UseCaptureStatus::EXACT;
      use.bytes={uint8_t((length==1040?i%8==7:i+1==length)?0:'a')};
      bounded.events.uses.push_back(use);
      bounded.events.data.push_back({use.site,use.address,use.bytes[0],1,RAX_MEM_READ,
          use.scope,use.sequence+1,1,11});
    }
    const auto streams=hybrid_consensus_native_read_strings(bounded);
    check(length==1040?streams.size()==130 && streams[0].value.size()==7:
          length<=4096?streams.size()==1 && streams[0].value.size()==length-1:streams.empty(),
          "derived stream read/byte limits reject oversized evidence without silent truncation");
    if(length==20)
    {
      const auto timeline=project_evidence_view(bounded);
      const auto item=std::find_if(timeline.events.begin(),timeline.events.end(),[](const auto &row)
          {return row.at("kind")=="read-stream";});
      check(item!=timeline.events.end() && item->at("fragments_omitted")=="4",
            "stream timeline marks omitted fragment references exactly");
    }
    if(length==4096)
    {
      const auto timeline=project_evidence_view(bounded);
      check(timeline.omitted.at("events")>0 && timeline.read_streams.size()==1
            && timeline.read_streams[0].at("read_count")=="4096"
            && timeline.read_streams[0].at("fragments_omitted")=="4080",
            "dedicated stream evidence survives general timeline truncation with explicit fragment limits");
    }
    if(length==1040)
    {
      const auto timeline=project_evidence_view(bounded);
      check(timeline.read_streams.size()==128 && timeline.omitted.at("read_streams")==2,
            "dedicated stream row quota reports exactly two omitted witnesses");
    }
  }
}

int main(int argc, char **argv)
{
  evidence_view_regressions();
  regressions();
  comparison_regressions();
  temporal_memory_regressions();
  native_read_stream_regressions();
#ifndef CHERNOBOG_LEGACY_EVIDENCE
  runtime_string_regressions();
#endif
  std::cout << "evidence identity regressions passed\n";
  if (argc == 2 && std::string(argv[1]) == "--benchmark") benchmark();
  if (argc == 2 && std::string(argv[1]) == "--compare-benchmark") comparison_benchmark();
}
