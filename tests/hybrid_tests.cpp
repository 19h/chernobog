#include "hybrid/abi_policy.hpp"
#include "hybrid/decoder_core.hpp"
#include "hybrid/emulation_rax_executor.hpp"
#include "hybrid/evidence.hpp"
#include "hybrid/hybrid_config.hpp"
#include "hybrid/program_model.hpp"
#include "hybrid/rax_loader.hpp"
#include "hybrid/smir_analysis.hpp"

#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace chernobog::hybrid;

namespace {

int failures = 0;

void check(bool condition, const char *message)
{
  if ( condition )
    return;
  ++failures;
  std::cerr << "FAIL: " << message << '\n';
}

void set_environment(const char *name, const char *value)
{
#if defined(_WIN32)
  _putenv_s(name, value == nullptr ? "" : value);
#else
  if ( value == nullptr )
    unsetenv(name);
  else
    setenv(name, value, 1);
#endif
}

ProgramImage branch_image()
{
  ProgramImage image;
  image.arch = HybridArch::X86_64;
  image.big_endian = false;
  image.lo = 0x100000;
  image.hi = 0x101000;
  image.generation = 7;

  SegImage segment;
  segment.start = image.lo;
  segment.end = image.hi;
  segment.perm = uint32_t(HybridSegPerm::READ)
               | uint32_t(HybridSegPerm::EXEC);
  segment.bitness = 2;
  segment.bytes.assign(size_t(segment.end - segment.start), 0x90);
  segment.mask.assign((segment.bytes.size() + 7) / 8, 0xFF);

  // test edi,edi; je target; mov eax,1; ret; xor eax,eax; ret
  const uint8_t code[] = {
    0x85, 0xFF,
    0x74, 0x06,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xC3,
    0x31, 0xC0,
    0xC3,
  };
  std::copy(std::begin(code), std::end(code), segment.bytes.begin());
  image.segs.push_back(std::move(segment));

  FuncRange function;
  function.start = image.lo;
  function.end = image.lo + sizeof(code);
  function.chunks.push_back(FuncChunk{ function.start, function.end });
  function.generation = image.generation;
  image.entries.push_back(function);
  image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
  image.content_hash = hybrid_program_content_hash(image);
  return image;
}

void test_config_bounds()
{
  set_environment("CHERNOBOG_RAX_MAX_INSNS", "0");
  set_environment("CHERNOBOG_RAX_TIMEOUT_MS", "18446744073709551615");
  set_environment("CHERNOBOG_RAX_EXPLORE_RUNS", "99");
  set_environment("CHERNOBOG_RAX_MAX_IMAGE_BYTES", "1");
  const HybridConfig config = hybrid_load_config();
  check(config.max_insns == kHybridDefaultMaxInstructions,
        "zero instruction cap must fail closed");
  check(config.timeout_ms == kHybridHardTimeoutMs,
        "timeout override must respect the hard cap");
  check(config.explore_runs == 32, "run corpus must respect hard cap");
  check(config.max_image_bytes == (1ull << 20), "image cap must have 1 MiB floor");
  set_environment("CHERNOBOG_RAX_MAX_INSNS", nullptr);
  set_environment("CHERNOBOG_RAX_TIMEOUT_MS", nullptr);
  set_environment("CHERNOBOG_RAX_EXPLORE_RUNS", nullptr);
  set_environment("CHERNOBOG_RAX_MAX_IMAGE_BYTES", nullptr);
}

void test_identity_comparison()
{
  const std::vector<uint8_t> expected{ 0xAA, 0xBB, 0xCC };
  const std::vector<uint8_t> fully_loaded{ 0x07 };

  // IDA does not assign semantics to the five padding bits above a 3-byte
  // request. A live mask that leaves those bits set must still compare equal.
  check(hybrid_compare_identity_bytes(
            expected, fully_loaded, expected, std::vector<uint8_t>{ 0xFF })
            .matches(),
        "identity comparison must ignore mask padding bits");

  std::vector<uint8_t> unloaded_payload = expected;
  unloaded_payload[1] = 0x11;
  check(hybrid_compare_identity_bytes(
            expected, std::vector<uint8_t>{ 0x05 }, unloaded_payload,
            std::vector<uint8_t>{ 0xFD }).matches(),
        "identity comparison must ignore payload at uninitialized addresses");

  const IdentityComparison loaded_state = hybrid_compare_identity_bytes(
      expected, std::vector<uint8_t>{ 0x05 }, expected, fully_loaded);
  check(loaded_state.mismatch == IdentityMismatchKind::LOADED_STATE
        && loaded_state.offset == 1,
        "identity comparison must detect initialized-state changes");

  std::vector<uint8_t> changed = expected;
  changed[2] ^= 0x01;
  const IdentityComparison byte_value = hybrid_compare_identity_bytes(
      expected, fully_loaded, changed, fully_loaded);
  check(byte_value.mismatch == IdentityMismatchKind::BYTE_VALUE
        && byte_value.offset == 2,
        "identity comparison must detect loaded-byte changes");
}

void test_decoder_and_smir(const RaxApi *api, const ProgramImage &image)
{
  const SegImage &segment = image.segs.front();
  const uint64_t branch = image.lo + 2;
  const uint8_t *bytes = segment.bytes.data() + 2;
  const DecoderDecodeResult decoded = hybrid_decode_one(
      api->decode, RAX_ARCH_X86, RAX_MODE_64, branch, bytes, 11);
  check(decoded.status == DecoderDecodeStatus::Valid, "rax must decode x86 conditional");
  check(decoded.instruction.flow == RAX_FLOW_COND_BRANCH,
        "conditional decode flow classification");
  check(decoded.instruction.target == image.lo + 10,
        "conditional decode direct target");
  check(decoded.instruction.fallthrough == image.lo + 4,
        "conditional decode fallthrough");

  DecoderInstruction ida = decoded.instruction;
  DecoderComparison same = hybrid_compare_decoders(ida, decoded.instruction);
  check(same.comparable && !same.size_disagreement
        && !same.flow_disagreement && !same.target_disagreement
        && !same.fallthrough_disagreement,
        "identical decoder projections must compare equal");
  ida.fallthrough++;
  check(hybrid_compare_decoders(ida, decoded.instruction).fallthrough_disagreement,
        "fallthrough disagreement must be visible");

  const SmirInstructionAnalysis smir = hybrid_analyze_instruction_effects(
      api, image, image.lo + 10, RAX_MODE_64, 3);
  check(smir.valid(), "SMIR analysis must negotiate caller-owned effects");
  check((smir.summary.flags & RAX_ANALYSIS_VALID) != 0,
        "SMIR summary must mark decoded instruction valid");
  check(!smir.effects.empty(), "xor eax,eax should expose effects");
}

EmulationRunRequest explicit_argument(uint32_t run_id, uint64_t value)
{
  EmulationRunRequest request;
  request.has_input = true;
  request.record_pcs = true;
  request.input.run_id = run_id;
  request.input.seed = UINT64_C(0x1000) + run_id;
  request.input.args.push_back(value);
  request.run_id = request.input.run_id;
  request.seed = request.input.seed;
  return request;
}

void test_inflight_cancellation(const RaxApi *api)
{
  ProgramImage image = branch_image();
  SegImage &segment = image.segs.front();
  segment.bytes[0] = 0xEB; // jmp $
  segment.bytes[1] = 0xFE;
  FuncRange &function = image.entries.front();
  function.end = image.lo + 2;
  function.chunks = { FuncChunk{ function.start, function.end } };
  function.byte_hash = hybrid_function_byte_hash(image, function);
  image.content_hash = hybrid_program_content_hash(image);

  auto immutable = std::make_shared<const ProgramImage>(std::move(image));
  RaxWorkerOptions options;
  options.api = api;
  options.image = immutable;
  options.strict_perms = true;
  EmulationWorkerPool pool(
      1, hybrid_make_rax_worker_factory(std::move(options)), 1);
  check(pool.wait_for_initialization(std::chrono::seconds(2)),
        "cancellation worker must initialize");

  EmulationJob job;
  job.function = immutable->entries.front();
  job.config = HybridConfig{};
  job.config.max_insns = kHybridHardMaxInstructions;
  job.config.timeout_ms = kHybridHardTimeoutMs;
  job.runs.push_back(EmulationRunRequest{});
  check(pool.try_submit(std::move(job)), "loop job submission");
  for ( size_t attempt = 0; attempt < 100000 && pool.stats().running == 0;
        ++attempt )
    std::this_thread::yield();

  const auto started = std::chrono::steady_clock::now();
  pool.cancel_pending();
  EmulationJobResult result;
  check(pool.wait_take_next(result, std::chrono::seconds(2)),
        "in-flight cancellation must settle promptly");
  check(result.status == EmulationJobStatus::CANCELLED,
        "cancelled loop must retain CANCELLED status");
  check(std::chrono::steady_clock::now() - started < std::chrono::seconds(2),
        "code-hook cancellation must not wait for the 60 s run cap");
  if ( !result.runs.empty() )
    check(result.runs.front().outcome.cancelled,
          "in-flight run outcome must record cooperative cancellation");
  pool.shutdown();
}

void test_worker_and_evidence(const RaxApi *api, ProgramImage image)
{
  auto immutable = std::make_shared<const ProgramImage>(std::move(image));
  RaxWorkerOptions options;
  options.api = api;
  options.image = immutable;
  options.strict_perms = true;

  EmulationWorkerPool pool(
      1, hybrid_make_rax_worker_factory(std::move(options)), 1);
  EmulationJob job;
  job.function = immutable->entries.front();
  job.config = HybridConfig{};
  job.config.max_insns = 1000;
  job.config.timeout_ms = 1000;
  job.runs.push_back(explicit_argument(0, 0));
  job.runs.push_back(explicit_argument(1, 1));

  uint64_t ticket = 0;
  check(pool.try_submit(job, &ticket), "single current-function job submission");
  EmulationJobResult result;
  check(pool.wait_take_next(result, std::chrono::seconds(10)),
        "bounded worker result must arrive");
  check(result.status == EmulationJobStatus::COMPLETED,
        "rax worker must complete explicit branch corpus");
  check(result.runs.size() == 2, "both explicit inputs must run");
  check(result.runs[0].outcome.returned && result.runs[1].outcome.returned,
        "both branch paths must return through sentinel");
  check(result.runs[0].outcome.consumed_context_complete
        && result.runs[1].outcome.consumed_context_complete,
        "x86 branch runs must capture complete consumed context");

  StaticAnalysisResult static_result;
  static_result.function_start = immutable->entries.front().start;
  StaticInstructionEvidence branch;
  branch.address = immutable->lo + 2;
  branch.ida.valid = true;
  branch.ida.size = 2;
  branch.ida.flow = RAX_FLOW_COND_BRANCH;
  branch.ida.has_target = true;
  branch.ida.target = immutable->lo + 10;
  branch.ida.has_fallthrough = true;
  branch.ida.fallthrough = immutable->lo + 4;
  branch.rax = hybrid_decode_one(
      api->decode, RAX_ARCH_X86, RAX_MODE_64, branch.address,
      immutable->segs.front().bytes.data() + 2, 11);
  branch.comparison = hybrid_compare_decoders(
      branch.ida, branch.rax.instruction);
  static_result.instructions.push_back(branch);

  std::vector<ConcreteInput> inputs;
  for ( const EmulationRunRequest &request : job.runs )
  {
    ConcreteInput input;
    input.origin = InputOrigin::Z3_MODEL;
    input.input = request.input;
    input.label = "test model";
    inputs.push_back(std::move(input));
  }
  const TargetEvidence evidence = hybrid_build_target_evidence(
      *immutable, immutable->entries.front(), immutable->lo + 2,
      static_result, inputs, result);
  check(evidence.summary.completed_runs == 2, "evidence must retain run provenance");
  check(evidence.branches.size() == 2, "two conditional outcomes must be reconstructed");
  const BranchClaimCheck always_taken = evidence.check_branch_claim(
      immutable->lo + 2, true);
  const BranchClaimCheck always_fallthrough = evidence.check_branch_claim(
      immutable->lo + 2, false);
  check(always_taken.verdict == BranchClaimVerdict::MIXED
        && always_taken.falsifies_universal_claim(),
        "fallthrough run must falsify always-taken claim");
  check(always_fallthrough.verdict == BranchClaimVerdict::MIXED
        && always_fallthrough.falsifies_universal_claim(),
        "taken run must falsify always-fallthrough claim");
  TargetEvidence incomplete_evidence = evidence;
  for ( BranchObservation &observation : incomplete_evidence.branches )
    observation.consumed_context_complete = false;
  const BranchClaimCheck incomplete_claim =
      incomplete_evidence.check_branch_claim(immutable->lo + 2, true);
  check(incomplete_claim.verdict == BranchClaimVerdict::MIXED
        && !incomplete_claim.falsifies_universal_claim()
        && incomplete_claim.opposing_context_complete == 0,
        "context-incomplete observations must never veto a universal claim");
  check(evidence.function_identity.size() == 1,
        "evidence must retain exact current-function bytes");
  check(!evidence.context_identity.empty()
        && evidence.summary.context_identity_bytes != 0,
        "evidence must retain bytes consumed by concrete execution");
  check(evidence.summary.permission_violating_runs == 0,
        "valid branch corpus must not violate strict permissions");
  check(evidence.summary.context_incomplete_runs == 0,
        "complete x86 branch corpus must remain proof-eligible");
  pool.shutdown();
}

} // namespace

int main()
{
  test_config_bounds();
  test_identity_comparison();
  const RaxApi *api = rax_load();
  check(api != nullptr, rax_unavailable_reason());
  if ( api != nullptr )
  {
    ProgramImage image = branch_image();
    check(image.function_at(image.lo + 12) != nullptr,
          "complete function chunk membership");
    test_decoder_and_smir(api, image);
    test_inflight_cancellation(api);
    test_worker_and_evidence(api, std::move(image));
  }
  if ( failures != 0 )
  {
    std::cerr << failures << " hybrid test(s) failed\n";
    return 1;
  }
  std::cout << "hybrid tests passed\n";
  return 0;
}
