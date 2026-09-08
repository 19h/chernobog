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
#include <limits>
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

ProgramImage x86_tls_image()
{
  ProgramImage image;
  image.arch = HybridArch::X86_64;
  image.big_endian = false;
  image.lo = 0x100000;
  image.generation = 8;

  // mov rax, qword ptr fs:[0]; ret
  const uint8_t code[] = {
    0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
    0xC3,
  };
  image.hi = image.lo + sizeof(code);

  SegImage segment;
  segment.start = image.lo;
  segment.end = image.hi;
  segment.perm = uint32_t(HybridSegPerm::READ)
               | uint32_t(HybridSegPerm::EXEC);
  segment.bitness = 2;
  segment.bytes.assign(std::begin(code), std::end(code));
  segment.mask.assign((segment.bytes.size() + 7) / 8, 0xFF);
  image.segs.push_back(std::move(segment));

  FuncRange function;
  function.start = image.lo;
  function.end = image.hi;
  function.chunks.push_back(FuncChunk{ function.start, function.end });
  function.generation = image.generation;
  image.entries.push_back(std::move(function));
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
  check(driver.can_discover(), "direct-test driver must initialize");
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

  ProgramImage identity = arm64_image({
      0xC0, 0x03, 0x5F, 0xD6 }, native);
  const uint64_t unknown_arity_hash = identity.entries.front().byte_hash;
  identity.entries.front().profile.explicit_arguments = 2;
  identity.entries.front().profile.explicit_arguments_known = true;
  const uint64_t known_arity_hash = hybrid_function_byte_hash(
      identity, identity.entries.front());
  check(unknown_arity_hash != known_arity_hash,
        "entry-profile refinement must invalidate proof execution identity");

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
  check(hybrid_classify_call_summary_name("__imp__memchr") == EmuSummaryKind::MEMCHR
        && hybrid_classify_call_summary_name("j__strnlen") == EmuSummaryKind::STRNLEN,
        "bounded byte-search summaries must recognize decorated external names");
  check(!hybrid_classify_call_summary_name("wmemchr")
        && !hybrid_classify_call_summary_name("strnlen_s")
        && !hybrid_classify_call_summary_name("__memchr_chk"),
        "different code-unit widths and checked-call contracts require separate models");
}

ProgramImage byte_search_image(HybridArch arch, const std::vector<uint8_t> &payload,
                              uint32_t source_permissions)
{
  // Arguments arrive through the driver's ABI input plan. After the external
  // call, store its actual return register into image memory for observation.
  const std::vector<uint8_t> arm64_code = {
      0x08, 0x00, 0x84, 0xD2, // mov x8,#0x2000
      0xE9, 0x03, 0x1E, 0xAA, // mov x9,lr
      0x00, 0x01, 0x3F, 0xD6, // blr x8
      0xFE, 0x03, 0x09, 0xAA, // mov lr,x9
      0x08, 0x00, 0x88, 0xD2, // mov x8,#0x4000
      0x00, 0x01, 0x00, 0xF9, // str x0,[x8]
      0xC0, 0x03, 0x5F, 0xD6 }; // ret
  const std::vector<uint8_t> x64_code = {
      0x48, 0xC7, 0xC0, 0x00, 0x20, 0x00, 0x00, // mov rax,0x2000
      0xFF, 0xD0, // call rax
      0x48, 0xA3, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov [0x4000],rax
      0xC3 }; // ret
  ProgramImage image = arm64_image(
      arch == HybridArch::ARM64 ? arm64_code : x64_code, {}, true);
  image.arch = arch;
  SegImage source;
  source.start = 0x3000;
  source.end = source.start + payload.size();
  source.perm = source_permissions;
  source.bitness = 2;
  source.bytes = payload;
  source.mask.assign((payload.size() + 7) / 8, 0xFF);
  image.segs.push_back(std::move(source));
  SegImage result;
  result.start = 0x4000;
  result.end = result.start + 8;
  result.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::WRITE);
  result.bitness = 2;
  result.bytes.assign(8, 0xA5);
  result.mask.assign(1, 0xFF);
  image.hi = result.end;
  image.segs.push_back(std::move(result));
  image.entries.front().byte_hash = hybrid_function_byte_hash(image, image.entries.front());
  image.content_hash = hybrid_program_content_hash(image);
  return image;
}

void test_bounded_byte_search_summaries(const RaxApi *api)
{
  struct AbiCase { HybridArch arch; bool windows_x64; const char *name; };
  for ( const AbiCase abi : { AbiCase{HybridArch::ARM64, false, "AAPCS64"},
                             AbiCase{HybridArch::X86_64, false, "SysV x86-64"},
                             AbiCase{HybridArch::X86_64, true, "Windows x86-64"} } )
  {
    auto run_case = [&](const char *label, EmuSummaryKind kind,
                        const std::vector<uint8_t> &payload,
                        const std::vector<uint64_t> &arguments,
                        uint64_t expected, uint32_t consumed,
                        bool success = true, bool permission_failure = false,
                        uint32_t permissions = uint32_t(HybridSegPerm::READ))
    {
      const int prior_failures = failures;
      const ProgramImage image = byte_search_image(abi.arch, payload, permissions);
      const char *name = kind == EmuSummaryKind::MEMCHR ? "memchr" : "strnlen";
      EmuDriver driver(api, image, true, abi.windows_x64,
                       { EmuCallSummary{0x2000, kind, name} });
      check(driver.can_discover(), "byte-search test driver must initialize");
      if ( !driver.can_discover() )
        return;
      EmuInput input;
      input.args = arguments;
      input.run_id = 7;
      input.seed = 0xABC;
      EmuEvents events;
      EmuOutcome outcome;
      check(driver.emulate_from(image.entries.front().start, image.entries.front().end,
                                short_run_config(), events, &outcome, true,
                                input.seed, input.run_id, &input),
            "byte-search summary must produce a run outcome");
      check(outcome.returned == success
            && outcome.environment_model_failure == !success
            && outcome.permission_violation == permission_failure
            && outcome.summarized_calls == (success ? 1u : 0u)
            && !outcome.unmodeled_external,
            "byte-search success and failure boundaries must be classified exactly");
      check(!outcome.consumed_context_complete,
            "a modeled external call remains exploratory evidence");
      const auto written = std::find_if(events.data.begin(), events.data.end(),
          [](const DataAcc &access) {
            return access.kind == RAX_MEM_WRITE && access.scope == DataScope::IMAGE
                && access.addr == 0x4000 && access.size == 8;
          });
      if ( success )
      {
        check(written != events.data.end() && written->value == expected,
              "guest code must observe the byte-search function's exact return value");
        check(outcome.external_model_used,
              "successful byte-search summaries must retain external-model provenance");
      }
      else
      {
        check(written == events.data.end() && outcome.external_target == 0x2000
              && outcome.external_name == name,
              "failed byte-search summaries must stop before continuation and retain the symbol");
      }
      check(events.consumed_image_reads.size() == (consumed == 0 ? 0u : 1u),
            "byte searches must record one consumed prefix and no unused tail");
      if ( consumed != 0 && !events.consumed_image_reads.empty() )
      {
        const auto &read = events.consumed_image_reads.front();
        check(read.addr == arguments.front() && read.size == consumed
              && read.run_id == input.run_id && read.seed == input.seed,
              "byte-search dependencies must include exactly the inspected bytes and run identity");
        uint64_t preview = 0;
        for ( size_t i = 0; i < std::min<size_t>(consumed, 8); ++i )
          preview |= uint64_t(payload[i]) << (8 * i);
        const auto recorded = std::find_if(events.data.begin(), events.data.end(),
            [&](const DataAcc &access) {
              return access.kind == RAX_MEM_READ && access.scope == DataScope::IMAGE
                  && access.addr == arguments.front();
            });
        check(recorded != events.data.end() && recorded->size == consumed
              && recorded->value == preview
              && recorded->from == (abi.arch == HybridArch::ARM64 ? 0x1008u : 0x1007u),
              "byte-search memory evidence must retain the first eight bytes and call source");
      }
      check(std::none_of(events.execution.begin(), events.execution.end(),
                         [](const ExecPoint &point) { return point.pc == 0x2000; }),
            "byte-search summaries must not execute external placeholder bytes");
      if ( failures != prior_failures )
        std::cerr << "  byte-search case: " << abi.name << ": " << label << '\n';
    };

    constexpr uint64_t source = 0x3000;
    constexpr uint64_t cap = 1u << 20;
    constexpr uint64_t maximum_address = std::numeric_limits<uint64_t>::max();
    const std::vector<uint8_t> binary{0x41, 0, 0x80, 0x80};
    run_case("memchr unsigned byte conversion and first match", EmuSummaryKind::MEMCHR,
             binary, {source, 0x180, 4}, source + 2, 3);
    run_case("memchr embedded zero", EmuSummaryKind::MEMCHR,
             binary, {source, 0, 4}, source + 1, 2);
    run_case("memchr does not terminate at zero", EmuSummaryKind::MEMCHR,
             binary, {source, 0x80, 2}, 0, 2);
    run_case("memchr negative int and unmapped unused tail", EmuSummaryKind::MEMCHR,
             {0xFF}, {source, maximum_address, 4096}, source, 1);
    run_case("memchr exact bound miss", EmuSummaryKind::MEMCHR,
             {1, 2, 3}, {source, 4, 3}, 0, 3);
    run_case("memchr preview truncation and last-byte match", EmuSummaryKind::MEMCHR,
             {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
             {source, 16, 16}, source + 15, 16);
    run_case("memchr zero bound reads no address", EmuSummaryKind::MEMCHR,
             {1}, {maximum_address, 1, 0}, 0, 0);
    run_case("memchr exact model cap", EmuSummaryKind::MEMCHR,
             {1}, {source, 1, cap}, source, 1);
    run_case("memchr over model cap rejects even an early match", EmuSummaryKind::MEMCHR,
             {1}, {source, 1, cap + 1}, 0, 0, false);
    run_case("memchr unavailable next byte retains observed prefix", EmuSummaryKind::MEMCHR,
             {1, 2}, {source, 3, 3}, 0, 2, false, true);
    run_case("memchr source permission failure", EmuSummaryKind::MEMCHR,
             {1}, {source, 1, 1}, 0, 0, false, true, uint32_t(HybridSegPerm::WRITE));
    run_case("memchr unmapped source", EmuSummaryKind::MEMCHR,
             {1}, {0x9000, 1, 1}, 0, 0, false);
    run_case("memchr address-boundary overflow", EmuSummaryKind::MEMCHR,
             {1}, {maximum_address, 1, 2}, 0, 0, false, true);

    run_case("strnlen unterminated bounded array", EmuSummaryKind::STRNLEN,
             {'a', 'b', 'c'}, {source, 3}, 3, 3);
    run_case("strnlen includes NUL in consumed bytes", EmuSummaryKind::STRNLEN,
             {'a', 'b', 'c', 0}, {source, 4}, 3, 4);
    run_case("strnlen empty string and unmapped unused tail", EmuSummaryKind::STRNLEN,
             {0}, {source, 4096}, 0, 1);
    run_case("strnlen counts encoded bytes", EmuSummaryKind::STRNLEN,
             {0xC3, 0xA9, 0}, {source, 3}, 2, 3);
    run_case("strnlen excludes a NUL beyond the bound", EmuSummaryKind::STRNLEN,
             {'a', 'b', 0}, {source, 2}, 2, 2);
    run_case("strnlen zero bound reads no address", EmuSummaryKind::STRNLEN,
             {0}, {maximum_address, 0}, 0, 0);
    run_case("strnlen exact model cap", EmuSummaryKind::STRNLEN,
             {0}, {source, cap}, 0, 1);
    run_case("strnlen over model cap rejects even an early NUL", EmuSummaryKind::STRNLEN,
             {0}, {source, cap + 1}, 0, 0, false);
    run_case("strnlen unavailable next byte retains observed prefix", EmuSummaryKind::STRNLEN,
             {'a', 'b'}, {source, 3}, 0, 2, false, true);
  }
}

void test_byte_search_scope_transitions(const RaxApi *api)
{
  struct ExpectedRead { uint64_t address; uint32_t size; uint64_t preview; };
  struct AbiCase { HybridArch arch; bool windows_x64; const char *name; };
  for ( const AbiCase abi : { AbiCase{HybridArch::ARM64, false, "AAPCS64"},
                             AbiCase{HybridArch::X86_64, false, "SysV x86-64"},
                             AbiCase{HybridArch::X86_64, true, "Windows x86-64"} } )
  {
    auto run_case = [&](const char *label, const ProgramImage &image, EmuSummaryKind kind,
                        const std::vector<uint64_t> &arguments, uint64_t expected_result,
                        const std::vector<ExpectedRead> &expected_reads,
                        bool strict = false, bool success = true,
                        bool permission_failure = false)
    {
      const int prior_failures = failures;
      const char *name = kind == EmuSummaryKind::MEMCHR ? "memchr" : "strnlen";
      EmuDriver driver(api, image, strict, abi.windows_x64,
                       {{0x2000, kind, name}});
      check(driver.can_discover(), "scope-transition driver must initialize");
      if ( !driver.can_discover() )
        return;
      EmuInput input;
      input.args = arguments;
      input.seed = 0xDEF;
      input.run_id = 9;
      EmuEvents events;
      EmuOutcome outcome;
      check(driver.emulate_from(image.entries.front().start, image.entries.front().end,
                                short_run_config(), events, &outcome, true,
                                input.seed, input.run_id, &input),
            "scope-transition summary must produce an outcome");
      check(outcome.returned == success && outcome.environment_model_failure == !success
            && outcome.permission_violation == permission_failure
            && outcome.summarized_calls == (success ? 1u : 0u)
            && !outcome.consumed_context_complete,
            "scope transitions must retain exact summary outcome classification");
      const auto written = std::find_if(events.data.begin(), events.data.end(),
          [](const DataAcc &access) {
            return access.kind == RAX_MEM_WRITE && access.addr == 0x4000;
          });
      check(success ? written != events.data.end() && written->value == expected_result
                    : written == events.data.end(),
            "scope transitions must preserve the guest result or stop before continuation");
      check(events.consumed_image_reads.size() == expected_reads.size(),
            "scope transitions must preserve every consumed image range");
      std::vector<DataAcc> recorded_reads;
      for ( const auto &access : events.data )
        if ( access.kind == RAX_MEM_READ && access.scope == DataScope::IMAGE )
          recorded_reads.push_back(access);
      check(recorded_reads.size() == expected_reads.size(),
            "scope transitions must preserve each image read's data record");
      for ( size_t i = 0; i < expected_reads.size(); ++i )
      {
        const auto &expected = expected_reads[i];
        if ( i < events.consumed_image_reads.size() )
        {
          const auto &read = events.consumed_image_reads[i];
          check(read.addr == expected.address && read.size == expected.size
                && read.run_id == input.run_id && read.seed == input.seed,
                "split dependencies must preserve exact addresses, lengths, and run provenance");
        }
        if ( i < recorded_reads.size() )
        {
          const auto &read = recorded_reads[i];
          check(read.addr == expected.address && read.size == expected.size
                && read.value == expected.preview
                && read.from == (abi.arch == HybridArch::ARM64 ? 0x1008u : 0x1007u),
                "each split scope must retain its own byte preview and call source");
        }
      }
      if ( failures != prior_failures )
        std::cerr << "  scope-transition case: " << abi.name << ": " << label << '\n';
    };
    const auto padding = byte_search_image(abi.arch, {'a', 'b'},
                                           uint32_t(HybridSegPerm::READ));
    run_case("memchr image to engine padding", padding, EmuSummaryKind::MEMCHR,
             {0x3000, 0, 3}, 0x3002, {{0x3000, 2, 0x6261}});
    run_case("strnlen image to engine padding", padding, EmuSummaryKind::STRNLEN,
             {0x3000, 3}, 2, {{0x3000, 2, 0x6261}});
    run_case("memchr engine padding to image", padding, EmuSummaryKind::MEMCHR,
             {0x2FFF, 'b', 3}, 0x3001, {{0x3000, 2, 0x6261}});
    // Neither page-padding range belongs to the image. A later failed read
    // must retain both initialized image ranges reached before the failure.
    run_case("memchr padding followed by an unmapped page", padding, EmuSummaryKind::MEMCHR,
             {0x3000, 0xFE, 0x2001}, 0,
             {{0x3000, 2, 0x6261}, {0x4000, 8, UINT64_C(0xA5A5A5A5A5A5A5A5)}},
             false, false);

    auto adjacent = byte_search_image(abi.arch, {'a', 'b', 'c', 'd', 0},
                                      uint32_t(HybridSegPerm::READ));
    SegImage tail = adjacent.segs[2];
    tail.start += 2;
    tail.bytes.erase(tail.bytes.begin(), tail.bytes.begin() + 2);
    adjacent.segs[2].end = tail.start;
    adjacent.segs[2].bytes.resize(2);
    adjacent.segs.insert(adjacent.segs.begin() + 3, tail);
    adjacent.content_hash = hybrid_program_content_hash(adjacent);
    run_case("memchr across adjacent image segments", adjacent, EmuSummaryKind::MEMCHR,
             {0x3000, 'd', 5}, 0x3003, {{0x3000, 4, 0x64636261}}, true);
    run_case("strnlen across adjacent image segments", adjacent, EmuSummaryKind::STRNLEN,
             {0x3000, 5}, 4, {{0x3000, 5, 0x64636261}}, true);

    auto gap = adjacent;
    ++gap.segs[3].start;
    ++gap.segs[3].end;
    gap.content_hash = hybrid_program_content_hash(gap);
    run_case("memchr image to padding to image", gap, EmuSummaryKind::MEMCHR,
             {0x3000, 'd', 6}, 0x3004, {{0x3000, 2, 0x6261}, {0x3003, 2, 0x6463}});
    run_case("memchr strict gap retains observed image prefix", gap, EmuSummaryKind::MEMCHR,
             {0x3000, 'd', 6}, 0, {{0x3000, 2, 0x6261}}, true, false, true);
  }
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
  static_result.stats.truncated = true;
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
  check(evidence.summary.static_analysis_truncated,
        "coverage summaries must expose a truncated static denominator");
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
  check(!outcome.consumed_context_complete,
        "application exception/image escape must never be proof-complete");
  if ( outcome.escaped_image )
  {
    check(outcome.escape_source == image.lo,
          "exception-vector escape must retain the faulting source PC");
    check(outcome.stop_pc == 0x200,
          "AArch64 synchronous exception vector must be reported as 0x200");
  }
}

void test_x86_tls_environment_boundary(const RaxApi *api)
{
  const ProgramImage image = x86_tls_image();
  EmuEvents events;
  EmuOutcome outcome;
  check(run_direct(api, image, {}, &events, &outcome),
        "x86-64 TLS dependency must remain a reportable run");
  check(outcome.environment_model_failure && !outcome.returned,
        "unmodeled FS access must be an environment-model failure");
  check(outcome.stop_reason == RAX_STOP_STOPPED
        && outcome.stop_reason != RAX_STOP_ERROR,
        "unmodeled FS access must stop through the host hook, not engine-error");
  check(outcome.external_target == image.lo
        && outcome.external_name == "unmodeled memory or translation dependency",
        "TLS boundary must retain the faulting instruction and classification");
  check(!outcome.consumed_context_complete,
        "unmodeled TLS state must never become proof-quality evidence");
}

void test_arm64_function_boundary(const RaxApi *api)
{
  // bl 0x1010; mov x0,#7; ret; nop; callee: b callee
  ProgramImage image = arm64_image({
      0x04, 0x00, 0x00, 0x94,
      0xE0, 0x00, 0x80, 0xD2,
      0xC0, 0x03, 0x5F, 0xD6,
      0x1F, 0x20, 0x03, 0xD5,
      0x00, 0x00, 0x00, 0x14 });
  image.entries.front().end = 0x100C;
  image.entries.front().chunks = { FuncChunk{ 0x1000, 0x100C } };
  image.entries.front().byte_hash =
      hybrid_function_byte_hash(image, image.entries.front());
  image.content_hash = hybrid_program_content_hash(image);

  EmuEvents events;
  EmuOutcome outcome;
  check(run_direct(api, image, {}, &events, &outcome),
        "ARM64 unmodeled internal call must produce a bounded run outcome");
  check(outcome.function_boundary
        && outcome.function_boundary_kind == ExecEdge::Kind::Call
        && outcome.function_boundary_source == 0x1000
        && outcome.function_boundary_target == 0x1010
        && !outcome.returned,
        "internal call must stop at the selected-function source/target boundary");
  check(outcome.stop_reason == RAX_STOP_STOPPED
        && outcome.instruction_count < short_run_config().max_insns
        && !outcome.consumed_context_complete,
        "function boundary must stop before recursive callee execution");
  check(events.execution.size() == 1 && events.execution.front().pc == 0x1000,
        "callee entry must not enter selected-function execution evidence");
  check(std::none_of(events.execution.begin(), events.execution.end(),
                     [](const ExecPoint &point) { return point.pc == 0x1010; }),
        "unmodeled callee body must never execute");
  check(events.edges.size() == 1
        && events.edges.front().from == 0x1000
        && events.edges.front().to == 0x1010
        && events.edges.front().kind == ExecEdge::Kind::Call,
        "the boundary call target must remain available as positive edge evidence");
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

MemoryBytes runtime_bytes(uint64_t address, const char *value,
                          uint32_t run_id, uint64_t seed,
                          DataScope scope = DataScope::IMAGE,
                          bool terminate = true)
{
  MemoryBytes bytes;
  bytes.addr = address;
  bytes.scope = scope;
  bytes.run_id = run_id;
  bytes.seed = seed;
  while ( *value != '\0' )
    bytes.bytes.push_back(uint8_t(*value++));
  if ( terminate )
    bytes.bytes.push_back(0);
  return bytes;
}

void add_memory_run(TargetEvidence *evidence, uint32_t run_id, uint64_t seed,
                    bool observation_available = true)
{
  RunObservation run;
  run.ran = true;
  run.outcome.memory_observation_available = observation_available;
  run.provenance.run_id = run_id;
  run.provenance.seed = seed;
  evidence->runs.push_back(run);
}

void test_runtime_string_consensus()
{
  TargetEvidence evidence;
  add_memory_run(&evidence, 0, 0x10);
  add_memory_run(&evidence, 1, 0x20);
  add_memory_run(&evidence, 2, 0x30, false);
  evidence.events.final_writes.push_back(
      runtime_bytes(0x4000, "frida-server", 0, 0x10));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x4000, "frida-server", 1, 0x20));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x5000, "only-one-run", 0, 0x10));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x6000, "unterminated", 0, 0x10,
                    DataScope::IMAGE, false));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x6000, "unterminated", 1, 0x20,
                    DataScope::IMAGE, false));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x7000, "stack-only", 0, 0x10, DataScope::STACK));
  evidence.events.final_writes.push_back(
      runtime_bytes(0x7000, "stack-only", 1, 0x20, DataScope::STACK));

  const std::vector<RuntimeStringCandidate> candidates =
      hybrid_consensus_runtime_strings(evidence);
  check(candidates.size() == 1,
        "runtime strings must require identical terminated image bytes in every observable run");
  if ( candidates.size() == 1 )
  {
    check(candidates[0].address == 0x4000
          && candidates[0].value == "frida-server"
          && candidates[0].observations == 2
          && candidates[0].eligible_runs == 2
          && candidates[0].runs == std::vector<uint32_t>({ 0, 1 }),
          "runtime string consensus must retain address, value, and run provenance");
  }

  TargetEvidence conflict = evidence;
  conflict.events.final_writes.back() =
      runtime_bytes(0x4000, "different", 1, 0x20);
  conflict.events.final_writes.push_back(
      runtime_bytes(0x4000, "different", 1, 0x20));
  check(hybrid_consensus_runtime_strings(conflict).empty(),
        "a per-run runtime plaintext conflict must reject the candidate");

  TargetEvidence non_printable;
  add_memory_run(&non_printable, 0, 0x10);
  MemoryBytes binary = runtime_bytes(0x8000, "abcd", 0, 0x10);
  binary.bytes[2] = 1;
  non_printable.events.final_writes.push_back(std::move(binary));
  check(hybrid_consensus_runtime_strings(non_printable).empty(),
        "binary final writes must not be projected as runtime strings");
}

const void *expected_smir_bytes = nullptr;
size_t expected_smir_size = 0;
size_t smir_input_calls = 0;

rax_status check_smir_input(int, uint32_t, uint64_t, const void *bytes, size_t size,
                           rax_analysis *summary, rax_analysis_effect *effects,
                           size_t capacity, size_t *required)
{
  ++smir_input_calls;
  check(bytes == expected_smir_bytes, "SMIR must borrow the exact snapshot bytes");
  check(size == expected_smir_size, "SMIR must respect the initialized backing extent");
  *required = 33; // Exercise both the inline call and larger-effect retry.
  *summary = {};
  summary->struct_size = sizeof(*summary);
  summary->abi_version = RAX_ANALYSIS_ABI_VERSION;
  summary->required_effect_count = 33;
  summary->effect_count = static_cast<uint32_t>(std::min(capacity, size_t(33)));
  summary->flags = RAX_ANALYSIS_VALID;
  for (size_t i = 0; i < summary->effect_count; ++i)
  {
    effects[i] = {};
    effects[i].struct_size = sizeof(effects[i]);
    effects[i].abi_version = RAX_ANALYSIS_ABI_VERSION;
  }
  if (capacity < 33)
  {
    summary->flags |= RAX_ANALYSIS_TRUNCATED;
    return RAX_ERR_BOUNDS;
  }
  return RAX_OK;
}

void test_smir_input_bounds()
{
  RaxApi api{};
  api.analyze = check_smir_input;
  ProgramImage image = branch_image();
  auto &segment = image.segs.front();
  segment.bytes.resize(3);
  expected_smir_bytes = segment.bytes.data() + 1;
  expected_smir_size = 2;
  smir_input_calls = 0;
  const auto truncated = hybrid_analyze_instruction_effects(
      &api, image, segment.start + 1, RAX_MODE_64, 16);
  check(truncated.valid() && smir_input_calls == 2,
        "truncated backing storage must bound both SMIR calls");
  segment.mask[0] = 3;
  expected_smir_size = 1;
  const auto hole = hybrid_analyze_instruction_effects(
      &api, image, segment.start + 1, RAX_MODE_64, 16);
  check(hole.valid(), "SMIR input must stop at the first unloaded byte");
  const size_t calls = smir_input_calls;
  segment.bytes.clear();
  const auto empty = hybrid_analyze_instruction_effects(
      &api, image, segment.start, RAX_MODE_64, 16);
  check(empty.status == SmirStatus::UNMAPPED && smir_input_calls == calls,
        "empty backing storage must not reach the SMIR backend");
  segment.bytes.assign(32, 0x90);
  segment.mask.assign(4, 255);
  expected_smir_bytes = segment.bytes.data();
  expected_smir_size = 16;
  check(hybrid_analyze_instruction_effects(
      &api, image, segment.start, RAX_MODE_64, 32).valid(),
      "SMIR must cap even larger offered windows at 16 bytes");
  expected_smir_size = 3;
  check(hybrid_analyze_instruction_effects(
      &api, image, segment.start, RAX_MODE_64, 3).valid(),
      "SMIR must retain the caller's narrower chunk bound");
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
  test_runtime_string_consensus();
  test_function_profiles_and_call_policy();
  test_smir_input_bounds();
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
    test_x86_tls_environment_boundary(api);
    test_arm64_memory_and_accounting(api);
    test_arm64_external_boundaries(api);
    test_bounded_byte_search_summaries(api);
    test_byte_search_scope_transitions(api);
    test_arm64_application_boundary(api);
    test_arm64_function_boundary(api);
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
