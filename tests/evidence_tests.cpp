#include "hybrid/evidence.hpp"
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

int main(int argc, char **argv)
{
  regressions();
  comparison_regressions();
  temporal_memory_regressions();
#ifndef CHERNOBOG_LEGACY_EVIDENCE
  runtime_string_regressions();
#endif
  std::cout << "evidence identity regressions passed\n";
  if (argc == 2 && std::string(argv[1]) == "--benchmark") benchmark();
  if (argc == 2 && std::string(argv[1]) == "--compare-benchmark") comparison_benchmark();
}
