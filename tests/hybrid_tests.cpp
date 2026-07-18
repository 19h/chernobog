#include "hybrid/abi_policy.hpp"
#include "hybrid/call_summary_policy.hpp"
#include "hybrid/decoder_core.hpp"
#include "hybrid/emu_driver.hpp"
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
#include <map>
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

ProgramImage arm64_image(const std::vector<uint8_t> &code,
                         const HybridFunctionProfile &profile = {},
                         bool external_segment = false)
{
  ProgramImage image;
  image.arch = HybridArch::ARM64;
  image.big_endian = false;
  image.lo = 0x1000;
  image.hi = external_segment ? 0x2004 : image.lo + code.size();
  image.generation = 11;

  SegImage text;
  text.start = image.lo;
  text.end = image.lo + code.size();
  text.perm = uint32_t(HybridSegPerm::READ)
            | uint32_t(HybridSegPerm::EXEC);
  text.bitness = 2;
  text.bytes = code;
  text.mask.assign((text.bytes.size() + 7) / 8, 0xFF);
  image.segs.push_back(std::move(text));

  if ( external_segment )
  {
    SegImage external;
    external.start = 0x2000;
    external.end = 0x2004;
    external.perm = uint32_t(HybridSegPerm::READ)
                  | uint32_t(HybridSegPerm::EXEC);
    external.bitness = 2;
    external.kind = HybridSegmentKind::EXTERNAL;
    external.bytes.assign(4, 0);
    external.mask.assign(1, 0x0F);
    image.segs.push_back(std::move(external));
  }

  FuncRange function;
  function.start = image.lo;
  function.end = image.lo + code.size();
  function.chunks.push_back(FuncChunk{ function.start, function.end });
  function.profile = profile;
  function.generation = image.generation;
  image.entries.push_back(std::move(function));
  image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
  image.content_hash = hybrid_program_content_hash(image);
  return image;
}

HybridConfig short_run_config()
{
  HybridConfig config;
  config.max_insns = 64;
  config.timeout_ms = 1000;
  config.want_drefs = true;
  config.want_runtime_strings = true;
  config.want_smc_evidence = true;
  return config;
}

bool run_direct(const RaxApi *api, const ProgramImage &image,
                const std::vector<EmuCallSummary> &summaries,
                EmuEvents *events, EmuOutcome *outcome,
                uint64_t seed = 0, const EmuInput *input = nullptr)
{
  EmuDriver driver(api, image, true, false, summaries);
  check(driver.can_discover(), "ARM64 direct-test driver must initialize");
  if ( !driver.can_discover() )
    return false;
  return driver.emulate_from(
      image.entries.front().start, image.entries.front().end,
      short_run_config(), *events, outcome, true, seed, 0, input);
}

void test_function_profiles_and_call_policy()
{
  const HybridFunctionProfile instance =
      hybrid_function_profile_from_name("-[AppDelegate randomStringWithLength:]");
  check(instance.flavor == HybridFunctionFlavor::OBJC_INSTANCE,
        "Objective-C instance method profile");
  check(instance.objc_selector == "randomStringWithLength:"
        && instance.explicit_arguments_known
        && instance.explicit_arguments == 1
        && instance.total_arguments() == 3,
        "Objective-C selector arity must preserve two hidden ABI arguments");

  const HybridFunctionProfile klass =
      hybrid_function_profile_from_name("+[Factory objectWithA:b:]");
  check(klass.flavor == HybridFunctionFlavor::OBJC_CLASS
        && klass.explicit_arguments == 2,
        "Objective-C class method and multi-part selector profile");
  const HybridFunctionProfile native =
      hybrid_function_profile_from_name("_ordinary_function");
  check(native.flavor == HybridFunctionFlavor::NATIVE
        && !native.explicit_arguments_known,
        "native name must not fabricate an arity");

  check(hybrid_canonical_call_name("__imp__objc_retain") == "objc_retain",
        "import-prefix canonicalization");
  const auto retain = hybrid_classify_call_summary_name("_objc_retain");
  check(retain && *retain == EmuSummaryKind::RETURN_ARG0,
        "objc_retain must be an identity summary");
  const auto store = hybrid_classify_call_summary_name("j__objc_storeStrong");
  check(store && *store == EmuSummaryKind::STORE_POINTER_ARG1,
        "objc_storeStrong must be a pointer-store summary");
  check(!hybrid_classify_call_summary_name("_objc_msgSend"),
        "dynamic Objective-C dispatch must remain explicitly unmodeled");
}

void test_arm64_memory_and_accounting(const RaxApi *api)
{
  // mov x0,#0x1122; str x0,[sp]; ldr x1,[sp]; ret
  const ProgramImage image = arm64_image({
      0x40, 0x24, 0x82, 0xD2, 0xE0, 0x03, 0x00, 0xF9,
      0xE1, 0x03, 0x40, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 });
  EmuEvents events;
  EmuOutcome outcome;
  check(run_direct(api, image, {}, &events, &outcome),
        "ARM64 memory test must run");
  check(outcome.returned, "ARM64 memory test must return through sentinel");
  check(outcome.attempted_steps_valid
        && outcome.attempted_steps == outcome.instruction_count,
        "normal ARM64 run must expose an exact attempted-step count");
  check(outcome.memory_observation_requested
        && outcome.memory_observation_available,
        "ARM64 memory-hook capability must be reported explicitly");
  check(outcome.consumed_context_complete,
        "ARM64 run with working memory hooks must be context-complete");
  check(events.execution.size() == 4,
        "ARM64 code hook must report four physical instructions");
  for ( const ExecPoint &point : events.execution )
    check(point.size == 4,
          "ARM64 code dependency width must be four bytes, not one");
  size_t reads = 0;
  size_t writes = 0;
  for ( const DataAcc &access : events.data )
  {
    if ( access.kind == RAX_MEM_READ )
      ++reads;
    if ( access.kind == RAX_MEM_WRITE )
      ++writes;
  }
  check(reads == 1 && writes == 1,
        "ARM64 data hooks must distinguish one load and one store");

  StaticAnalysisResult static_result;
  static_result.function_start = image.lo;
  static_result.stats.instruction_heads = 3;
  static_result.stats.canonical_instructions = 4;
  static_result.stats.ida_macro_heads = 1;
  static_result.stats.ida_macro_components = 2;
  static_result.stats.decoder_comparisons = 2;
  static_result.stats.mismatched_instructions = 1;
  static_result.stats.flow_disagreements = 1;
  for ( size_t index = 0; index < 4; ++index )
  {
    StaticInstructionEvidence instruction;
    instruction.address = image.lo + uint64_t(index * 4);
    static_result.instructions.push_back(std::move(instruction));
  }
  EmulationJobResult emulation;
  emulation.status = EmulationJobStatus::COMPLETED;
  EmulationRunResult run;
  run.ran = true;
  run.events = events;
  run.outcome = outcome;
  emulation.runs.push_back(run);
  emulation.merged = events;
  const TargetEvidence evidence = hybrid_build_target_evidence(
      image, image.entries.front(), image.lo, static_result, {}, emulation);
  check(evidence.summary.executed_instruction_addresses == 4
        && evidence.summary.static_instructions == 4
        && evidence.summary.executed_addresses_without_static_record == 0,
        "coverage must compare physical ARM64 PCs against a physical denominator");
  check(evidence.summary.ida_instruction_heads == 3
        && evidence.summary.ida_macro_heads == 1
        && evidence.summary.ida_macro_components == 2,
        "IDA macro heads and physical components must remain separate metrics");
  check(evidence.summary.decoder_comparisons == 2
        && evidence.summary.decoder_disagreements == 1
        && evidence.summary.decoder_disagreement_flags == 1,
        "decoder reports must separate comparisons, unique sites, and flags");
  check(evidence.summary.context_identity_ranges == 1
        && evidence.summary.context_identity_bytes == 16,
        "contiguous ARM64 instruction dependencies must merge into one 16-byte range");
  check(evidence.summary.memory_observation_available_runs == 1
        && evidence.summary.context_incomplete_runs == 0,
        "evidence summary must retain memory capability and completeness");
}

void test_arm64_external_boundaries(const RaxApi *api)
{
  // mov x0,#42; mov x8,#0x2000; save LR; blr x8; restore LR; ret
  const ProgramImage image = arm64_image({
      0x40, 0x05, 0x80, 0xD2, 0x08, 0x00, 0x84, 0xD2,
      0xE9, 0x03, 0x1E, 0xAA, 0x00, 0x01, 0x3F, 0xD6,
      0xFE, 0x03, 0x09, 0xAA, 0xC0, 0x03, 0x5F, 0xD6 }, {}, true);

  EmuEvents modeled_events;
  EmuOutcome modeled;
  check(run_direct(api, image,
                   { EmuCallSummary{ 0x2000, EmuSummaryKind::RETURN_ARG0,
                                     "_objc_retain" } },
                   &modeled_events, &modeled),
        "modeled Objective-C external call must run");
  check(modeled.summarized_calls == 1,
        "objc_retain summary must execute exactly once");
  check(modeled.returned,
        "objc_retain summary must resume at LR and reach the return sentinel");
  check(modeled.attempted_steps_valid
        && modeled.instruction_count == modeled.attempted_steps,
        "ARM64 retired count must remain monotonic across summary resumptions");
  check(!modeled.unmodeled_external && !modeled.environment_model_failure,
        "objc_retain summary must not be classified as an environment failure");
  check(modeled.external_model_used && !modeled.consumed_context_complete,
        "external summary runs must remain exploratory, not proof-complete");
  check(std::none_of(modeled_events.execution.begin(), modeled_events.execution.end(),
                     [](const ExecPoint &point) { return point.pc == 0x2000; }),
        "external placeholder bytes must never be executed after a summary");

  EmuEvents unknown_events;
  EmuOutcome unknown;
  check(run_direct(api, image,
                   { EmuCallSummary{ 0x2000, EmuSummaryKind::UNMODELED,
                                     "_objc_msgSend" } },
                   &unknown_events, &unknown),
        "unmodeled external boundary must produce a run outcome");
  check(unknown.unmodeled_external && unknown.external_target == 0x2000
        && unknown.external_name == "_objc_msgSend" && !unknown.returned,
        "unmodeled external must stop cleanly with target and symbol provenance");
  check(unknown.stop_reason != RAX_STOP_COUNT
        && unknown.instruction_count < short_run_config().max_insns
        && unknown.attempted_steps_valid
        && unknown.attempted_steps == unknown.instruction_count
        && !unknown.consumed_context_complete,
        "unmodeled external must not execute a placeholder until the count cap");
  check(std::none_of(unknown_events.execution.begin(), unknown_events.execution.end(),
                     [](const ExecPoint &point) { return point.pc == 0x2000; }),
        "unmodeled external placeholder bytes must not enter execution evidence");
}

void test_arm64_application_boundary(const RaxApi *api)
{
  // An architecturally undefined instruction enters the AArch64 exception
  // vector in rax full-system semantics. Application-mode emulation must stop
  // at that first boundary instead of running vector zero-fill to the budget.
  const ProgramImage image = arm64_image({ 0x00, 0x00, 0x00, 0x00 });
  EmuEvents events;
  EmuOutcome outcome;
  check(run_direct(api, image, {}, &events, &outcome),
        "ARM64 undefined-instruction boundary must remain a reportable run");
  check(outcome.stop_reason != RAX_STOP_COUNT
        && outcome.instruction_count < short_run_config().max_insns,
        "ARM64 exception handling must stop before the instruction budget");
  check(outcome.escaped_image || outcome.stop_reason == RAX_STOP_EXCEPTION,
        "ARM64 first fault must be classified as image escape or backend exception");
  if ( outcome.escaped_image )
  {
    check(outcome.escape_source == image.lo,
          "exception-vector escape must retain the faulting source PC");
    check(outcome.stop_pc == 0x200,
          "AArch64 synchronous exception vector must be reported as 0x200");
  }
}

std::map<uint64_t, uint64_t> stack_store_values(const EmuEvents &events)
{
  std::map<uint64_t, uint64_t> result;
  for ( const DataAcc &access : events.data )
    if ( access.kind == RAX_MEM_WRITE && access.scope == DataScope::STACK )
      result[access.from] = access.value;
  return result;
}

void test_objc_entry_abi(const RaxApi *api)
{
  HybridFunctionProfile profile =
      hybrid_function_profile_from_name("-[AppDelegate valueForIndex:]");
  // str x0,[sp]; str x1,[sp,#8]; str x2,[sp,#16]; ret
  const ProgramImage image = arm64_image({
      0xE0, 0x03, 0x00, 0xF9, 0xE1, 0x07, 0x00, 0xF9,
      0xE2, 0x0B, 0x00, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 }, profile);
  EmuEvents seeded_events;
  EmuOutcome seeded_outcome;
  check(run_direct(api, image, {}, &seeded_events, &seeded_outcome,
                   UINT64_C(0x123456789ABCDEF0)),
        "Objective-C deterministic entry must run");
  check(seeded_outcome.synthetic_entry_context
        && !seeded_outcome.consumed_context_complete,
        "synthetic Objective-C hidden arguments must be marked proof-ineligible");
  const auto seeded = stack_store_values(seeded_events);
  check(seeded.size() == 3, "Objective-C entry must expose x0/x1/x2 stores");
  if ( seeded.size() == 3 )
  {
    check(seeded.at(0x1000) != 0
          && seeded.at(0x1004) == seeded.at(0x1000) + 0x200,
          "Objective-C self and selector placeholders must be mapped and distinct");
    check(seeded.at(0x1008) != seeded.at(0x1000)
          && seeded.at(0x1008) != seeded.at(0x1004),
          "deterministic explicit argument must begin at x2");
  }

  EmuInput solver_input;
  solver_input.seed = 7;
  solver_input.run_id = 1;
  solver_input.positional_argument_offset = 2;
  solver_input.args = { UINT64_C(0xFEEDFACE) };
  EmuEvents replay_events;
  EmuOutcome replay_outcome;
  check(run_direct(api, image, {}, &replay_events, &replay_outcome,
                   solver_input.seed, &solver_input),
        "Objective-C explicit-argument replay must run");
  check(replay_outcome.synthetic_entry_context
        && !replay_outcome.consumed_context_complete,
        "source-level replay still depends on synthetic self/_cmd context");
  const auto replay = stack_store_values(replay_events);
  check(replay.size() == 3 && replay.at(0x1008) == UINT64_C(0xFEEDFACE),
        "Objective-C solver argument zero must map to physical x2");
  if ( replay.size() == 3 )
    check(replay.at(0x1000) != 0
          && replay.at(0x1004) == replay.at(0x1000) + 0x200,
          "source-level replay must not overwrite self or _cmd");

  EmuInput callsite_input;
  callsite_input.seed = 9;
  callsite_input.run_id = 2;
  callsite_input.arg_overrides = {
      { 0, UINT64_C(0x11110000) },
      { 1, UINT64_C(0x22220000) },
      { 2, UINT64_C(0x33330000) },
  };
  EmuEvents callsite_events;
  EmuOutcome callsite_outcome;
  check(run_direct(api, image, {}, &callsite_events, &callsite_outcome,
                   callsite_input.seed, &callsite_input),
        "Objective-C observed call-site state must run");
  check(!callsite_outcome.synthetic_entry_context
        && callsite_outcome.consumed_context_complete,
        "observed self and _cmd must remove the synthetic-entry assumption");
  const auto callsite = stack_store_values(callsite_events);
  check(callsite.size() == 3
        && callsite.at(0x1000) == UINT64_C(0x11110000)
        && callsite.at(0x1004) == UINT64_C(0x22220000)
        && callsite.at(0x1008) == UINT64_C(0x33330000),
        "call-site physical argument overrides must retain x0/x1/x2 order");
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
  test_function_profiles_and_call_policy();
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
    test_arm64_memory_and_accounting(api);
    test_arm64_external_boundaries(api);
    test_arm64_application_boundary(api);
    test_objc_entry_abi(api);
  }
  if ( failures != 0 )
  {
    std::cerr << failures << " hybrid test(s) failed\n";
    return 1;
  }
  std::cout << "hybrid tests passed\n";
  return 0;
}
