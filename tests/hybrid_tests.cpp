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
#include "vm/native_region.hpp"

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

namespace
{

int failures = 0;

void check(bool condition, const char *message)
{
    if (condition)
        return;
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
}

void set_environment(const char *name, const char *value)
{
#if defined(_WIN32)
    _putenv_s(name, value == nullptr ? "" : value);
#else
    if (value == nullptr)
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
    segment.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::EXEC);
    segment.bitness = 2;
    segment.bytes.assign(size_t(segment.end - segment.start), 0x90);
    segment.mask.assign((segment.bytes.size() + 7) / 8, 0xFF);

    // test edi,edi; je target; mov eax,1; ret; xor eax,eax; ret
    const uint8_t code[] = {
        0x85, 0xFF, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x31, 0xC0, 0xC3,
    };
    std::copy(std::begin(code), std::end(code), segment.bytes.begin());
    image.segs.push_back(std::move(segment));

    FuncRange function;
    function.start = image.lo;
    function.end = image.lo + sizeof(code);
    function.chunks.push_back(FuncChunk{function.start, function.end});
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
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xC3,
    };
    image.hi = image.lo + sizeof(code);

    SegImage segment;
    segment.start = image.lo;
    segment.end = image.hi;
    segment.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::EXEC);
    segment.bitness = 2;
    segment.bytes.assign(std::begin(code), std::end(code));
    segment.mask.assign((segment.bytes.size() + 7) / 8, 0xFF);
    image.segs.push_back(std::move(segment));

    FuncRange function;
    function.start = image.lo;
    function.end = image.hi;
    function.chunks.push_back(FuncChunk{function.start, function.end});
    function.generation = image.generation;
    image.entries.push_back(std::move(function));
    image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
    image.content_hash = hybrid_program_content_hash(image);
    return image;
}

ProgramImage arm64_image(const std::vector<uint8_t> &code,
                         const HybridFunctionProfile &profile = {}, bool external_segment = false)
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
    text.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::EXEC);
    text.bitness = 2;
    text.bytes = code;
    text.mask.assign((text.bytes.size() + 7) / 8, 0xFF);
    image.segs.push_back(std::move(text));

    if (external_segment)
    {
        SegImage external;
        external.start = 0x2000;
        external.end = 0x2004;
        external.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::EXEC);
        external.bitness = 2;
        external.kind = HybridSegmentKind::EXTERNAL;
        external.bytes.assign(4, 0);
        external.mask.assign(1, 0x0F);
        image.segs.push_back(std::move(external));
    }

    FuncRange function;
    function.start = image.lo;
    function.end = image.lo + code.size();
    function.chunks.push_back(FuncChunk{function.start, function.end});
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

void test_native_regions(const RaxApi *api)
{
    using chernobog::vm::plan_native_region;
    for (bool is64 : {false, true})
    {
        // Fixture decoder: the fixed streams below use encodings with identical
        // lengths/control flow in both modes, except the explicitly handled legacy
        // INC/DEC range. General 32-bit decode coverage is supplied by the IDA probe.
        const chernobog::vm::NativeDecoder fixture_decoder =
            [&](uint64_t ea, const uint8_t *data, size_t count, rax_decoded &out)
        {
            if (!is64 && count && data[0] >= 0x40 && data[0] <= 0x4f)
            {
                out = {};
                out.valid = 1;
                out.size = 1;
                out.flow = RAX_FLOW_FALLTHROUGH;
                return true;
            }
            if (!is64 && count >= 2 && data[0] == 0x66 && data[1] >= 0x40 && data[1] <= 0x4f)
            {
                out = {};
                out.valid = 1;
                out.size = 2;
                out.flow = RAX_FLOW_FALLTHROUGH;
                return true;
            }
            return api->decode(RAX_ARCH_X86, RAX_MODE_64, ea, data, count, &out) == RAX_OK;
        };
        auto plan_native_region = [&](const ProgramImage &candidate, const RaxApi *decoder_api,
                                      uint64_t entry, size_t limit = 4096)
        {
            chernobog::vm::NativeDecoder decode;
            if (decoder_api && decoder_api->decode)
                decode = fixture_decoder;
            return chernobog::vm::plan_native_region(candidate, decoder_api, entry, limit, decode);
        };
        auto image = branch_image();
        image.arch = is64 ? HybridArch::X86_64 : HybridArch::X86_32;
        image.segs[0].bitness = is64 ? 2 : 1;
        auto &bytes = image.segs[0].bytes;
        std::fill(bytes.begin(), bytes.end(), 0xcc);
        auto put = [&](size_t at, std::initializer_list<uint8_t> data)
        { std::copy(data.begin(), data.end(), bytes.data() + at); };
        put(0, {0xe9, 0xfb, 0, 0, 0}); // root jumps to ownerless entry prefix
        put(0x100, {0x68, 0xef, 0xff, 0xff, 0xff, 0xe8, 0xf6, 0, 0, 0}); // push -17; call callee
        if (is64)
            put(0x10a, {0x48, 0x83, 0xc4, 8, 0xc3});
        else
            put(0x10a, {0x83, 0xc4, 4, 0xc3});
        put(0x200, {0x8b, 0x04, 0x24, 0xc3}); // mov eax,[sp]; ret
        image.entries[0].end = image.lo + 5;
        image.entries[0].chunks = {{image.lo, image.lo + 5}};
        image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
        FuncRange callee;
        callee.start = image.lo + 0x200;
        callee.end = callee.start + 4;
        callee.chunks = {{callee.start, callee.end}};
        image.entries.push_back(callee);
        image.content_hash = hybrid_program_content_hash(image);
        const auto original_chunks = image.entries[0].chunks;
        const auto region = plan_native_region(image, api, image.lo);
        check(region.available() && !region.truncated() && region.heads().size() == 7,
              "native region spans ownerless prefix and separately owned callee");
        check(region.matches(image) && region.identity() != 0,
              "native region binds immutable image");
        EmuDriver driver(api, image, true);
        EmuEvents ordinary;
        EmuOutcome stopped;
        check(driver.emulate_from(image.lo, image.entries[0].end, short_run_config(), ordinary,
                                  &stopped) &&
                  stopped.function_boundary && ordinary.execution.size() == 1,
              "ordinary function boundary remains unchanged with native regions available");
        EmuEvents events;
        EmuOutcome outcome;
        check(driver.emulate_region(region, short_run_config(), events, outcome) &&
                  outcome.native_region && outcome.returned && !outcome.conclusive() &&
                  !outcome.function_boundary && !outcome.region_boundary &&
                  !outcome.consumed_context_complete,
              "native region executes call and return without producing function conclusions");
        check(outcome.sp_valid && outcome.sp_delta == (is64 ? 8 : 4),
              "native region balances seed and call stack");
        check(events.execution.size() == 7 &&
                  events.states.front().kind == StatePoint::Kind::RegionEntry,
              "native region records complete instruction path and entry state");
        EmuEvents region_sample_events;
        EmuOutcome region_sample_outcome;
        check(driver.emulate_region_states(region, short_run_config(), region_sample_events,
                                           region_sample_outcome) &&
                  region_sample_outcome.returned &&
                  region_sample_outcome.native_state_capture_requested &&
                  region_sample_outcome.native_state_capture_complete &&
                  !region_sample_outcome.native_walk && !region_sample_outcome.conclusive() &&
                  region_sample_events.execution.size() == 7 &&
                  region_sample_events.edges.size() == events.edges.size(),
              "bounded region state capture retains execution without native continuation");
        size_t region_sample_entries = 0;
        for (const auto &state : region_sample_events.states)
            if (state.kind == StatePoint::Kind::NativeInstructionEntry)
            {
                check(region_sample_entries < region_sample_events.execution.size() &&
                          state.pc == region_sample_events.execution[region_sample_entries].pc &&
                          state.sequence ==
                              region_sample_events.execution[region_sample_entries].sequence &&
                          state.regs.size() == (is64 ? 18 : 10),
                      "region state sample identifies each exact entered instruction");
                ++region_sample_entries;
            }
        check(region_sample_entries == region_sample_events.execution.size(),
              "region state capture covers every executed instruction");
        if (is64)
        {
            auto replay_image = branch_image();
            std::fill(replay_image.segs[0].bytes.begin(), replay_image.segs[0].bytes.end(), 0xcc);
            const uint8_t code[] = {0x48, 0x8b, 0x44, 0x24, 0x10, // mov rax,[rsp+16]
                                    0x48, 0x31, 0xe8,             // xor rax,rbp
                                    0x48, 0x8b, 0x54, 0x24, 0xf8, // mov rdx,[rsp-8]
                                    0x48, 0x31, 0xd0,             // xor rax,rdx
                                    0xc3};                        // ret
            std::copy(std::begin(code), std::end(code), replay_image.segs[0].bytes.begin());
            replay_image.entries[0].end = replay_image.lo + sizeof(code);
            replay_image.entries[0].chunks = {{replay_image.lo, replay_image.lo + sizeof(code)}};
            replay_image.entries[0].byte_hash =
                hybrid_function_byte_hash(replay_image, replay_image.entries[0]);
            replay_image.content_hash = hybrid_program_content_hash(replay_image);
            const auto replay_region = plan_native_region(replay_image, api, replay_image.lo);
            check(replay_region.available() && replay_region.heads().size() == 5,
                  "native entry replay fixture has five exact heads");
            EmuDriver replay_driver(api, replay_image, true);
            EmuInput replay_input;
            replay_input.native_entry.emplace();
            auto &entry_state = *replay_input.native_entry;
            entry_state.observed_sp = UINT64_C(0x7fff00000be8);
            entry_state.gprs[4] = entry_state.observed_sp;
            entry_state.gprs[5] = entry_state.observed_sp + 0x40;
            entry_state.gprs[13] = entry_state.observed_sp + 0x50;
            entry_state.rflags = 0x246;
            entry_state.stack_above.assign(32, 0);
            entry_state.stack_below.assign(32, 0);
            const uint64_t stack_pointer = entry_state.observed_sp + 0x20;
            for (unsigned byte = 0; byte < 8; ++byte)
                entry_state.stack_above[16 + byte] = uint8_t(stack_pointer >> (8 * byte));
            const uint64_t below_pointer = entry_state.observed_sp - 0x100;
            for (unsigned byte = 0; byte < 8; ++byte)
                entry_state.stack_below[24 + byte] = uint8_t(below_pointer >> (8 * byte));
            entry_state.stack_relative_gpr_mask = (1u << 4) | (1u << 5) | (1u << 13);
            entry_state.stack_relative_word_offsets = {16};
            entry_state.stack_relative_below_word_offsets = {24};
            EmuEvents replay_events;
            EmuOutcome replay_outcome;
            check(replay_driver.emulate_region_states(replay_region, short_run_config(),
                                                      replay_events, replay_outcome, &replay_input),
                  "explicit native entry replays through the bounded region");
            const uint64_t translated_sp = replay_outcome.entry_sp;
            check((translated_sp & 0xfff) == (entry_state.observed_sp & 0xfff),
                  "native entry replay preserves observed SP page offset");
            auto sampled_register = [&](uint64_t pc, int reg)
            {
                for (const auto &state : replay_events.states)
                    if (state.kind == StatePoint::Kind::NativeInstructionEntry && state.pc == pc)
                        for (const auto &value : state.regs)
                            if (value.reg == reg)
                                return value.value;
                return uint64_t(0);
            };
            const bool translated_registers =
                sampled_register(replay_image.lo, RAX_X86_REG_RBP) == translated_sp + 0x40 &&
                sampled_register(replay_image.lo, RAX_X86_REG_R13) == translated_sp + 0x50 &&
                sampled_register(replay_image.lo + 5, RAX_X86_REG_RAX) == translated_sp + 0x20 &&
                sampled_register(replay_image.lo + 8, RAX_X86_REG_RAX) ==
                    ((translated_sp + 0x20) ^ (translated_sp + 0x40)) &&
                sampled_register(replay_image.lo + 13, RAX_X86_REG_RDX) == translated_sp - 0x100 &&
                sampled_register(replay_image.lo + 16, RAX_X86_REG_RAX) ==
                    ((translated_sp + 0x20) ^ (translated_sp + 0x40) ^ (translated_sp - 0x100));
            check(translated_registers,
                  "translated registers and both caller stack windows affect execution");
            entry_state.stack_relative_word_offsets.clear();
            EmuEvents rejected_replay;
            EmuOutcome rejected_outcome;
            check(!replay_driver.emulate_region_states(replay_region, short_run_config(),
                                                       rejected_replay, rejected_outcome,
                                                       &replay_input) &&
                      !replay_driver.emulate_region(replay_region, short_run_config(),
                                                    rejected_replay, rejected_outcome,
                                                    &replay_input),
                  "unmarked stack pointers and ordinary region runs reject entry replay");
            entry_state.stack_relative_word_offsets = {16};
            entry_state.stack_relative_below_word_offsets.clear();
            check(!replay_driver.emulate_region_states(replay_region, short_run_config(),
                                                       rejected_replay, rejected_outcome,
                                                       &replay_input),
                  "unmarked pointer below entry SP rejects native replay");
            entry_state.stack_relative_below_word_offsets = {24};
            auto checkpoint_input = replay_input;
            auto &checkpoint = *checkpoint_input.native_entry;
            checkpoint.observed_sp += 8;
            checkpoint.gprs[4] = checkpoint.observed_sp;
            EmuEvents checkpoint_events;
            EmuOutcome checkpoint_outcome;
            check(!replay_driver.emulate_region_states(replay_region, short_run_config(),
                                                       checkpoint_events, checkpoint_outcome,
                                                       &checkpoint_input),
                  "ordinary native entry rejects non-ABI SP alignment");
            checkpoint.observed_checkpoint = true;
            check(replay_driver.emulate_region_states(replay_region, short_run_config(),
                                                      checkpoint_events, checkpoint_outcome,
                                                      &checkpoint_input) &&
                      (checkpoint_outcome.entry_sp & 0xfff) == (checkpoint.observed_sp & 0xfff),
                  "explicit observed checkpoint admits recorded non-ABI SP alignment");
        }
        const unsigned width = is64 ? 8 : 4;
        const uint64_t pushed = is64 ? UINT64_C(0xffffffffffffffef) : UINT64_C(0xffffffef);
        bool seed_write = false, call_write = false, callee_input = false, return_value = false;
        for (const auto &access : events.data)
        {
            if (access.kind != RAX_MEM_WRITE)
                continue;
            if (access.from == image.lo + 0x100)
                seed_write = access.addr == outcome.entry_sp - width && access.size == width &&
                             access.value == pushed;
            if (access.from == image.lo + 0x105)
                call_write = access.addr == outcome.entry_sp - 2 * width && access.size == width &&
                             access.value == image.lo + 0x10a;
        }
        for (const auto &state : events.states)
            for (const auto &reg : state.regs)
            {
                if (state.pc == callee.start &&
                    reg.reg == (is64 ? RAX_X86_REG_RSP : RAX_X86_REG_ESP))
                    callee_input = reg.value == outcome.entry_sp - 2 * width;
                if (state.pc == image.lo + 0x10a &&
                    reg.reg == (is64 ? RAX_X86_REG_RAX : RAX_X86_REG_EAX))
                    return_value = reg.value == image.lo + 0x10a;
            }
        check(seed_write && call_write && callee_input && return_value,
              "independent push sign-extension and call return-address oracle");
        check(outcome.data_trace_complete && !outcome.external_model_used,
              "native region uses actual instruction accesses, no callee summaries");
        EmulationJobResult mixed;
        EmulationRunResult region_run;
        region_run.ran = true;
        region_run.outcome = outcome;
        region_run.events = events;
        mixed.runs.push_back(region_run);
        mixed.merged = events;
        const auto refused =
            hybrid_build_target_evidence(image, image.entries[0], image.lo, {}, {}, mixed);
        check(refused.runs.empty() && refused.events.execution.empty() &&
                  refused.function_identity.empty() &&
                  refused.diagnostic == "native-region observations require separate publication",
              "ordinary evidence builder rejects region and mixed-scope publications");
        check(image.entries[0].chunks.size() == original_chunks.size() &&
                  image.entries[0].chunks[0].end == original_chunks[0].end,
              "region capture preserves function topology");
        check(!driver.emulate_region(region, short_run_config(), events, outcome),
              "region capture rejects an occupied ordinary or region event sink");
        EmuEvents repeat;
        EmuOutcome repeated;
        check(driver.emulate_region(region, short_run_config(), repeat, repeated) &&
                  repeated.entry_sp == stopped.entry_sp && repeat.data.size() == events.data.size(),
              "region run restores baseline after previous run");
        auto limited = plan_native_region(image, api, image.lo, 1);
        EmuEvents boundary;
        EmuOutcome boundary_out;
        check(limited.truncated() &&
                  driver.emulate_region(limited, short_run_config(), boundary, boundary_out) &&
                  boundary_out.region_boundary && boundary.execution.size() == 1 &&
                  boundary_out.region_boundary_target == image.lo + 0x100,
              "region quota is an execution boundary before target instruction");
        if (is64)
        {
            auto long_image = branch_image();
            long_image.hi = long_image.lo + 5001;
            long_image.segs[0].end = long_image.hi;
            long_image.segs[0].bytes.assign(5001, 0x90);
            long_image.segs[0].bytes.back() = 0xc3;
            long_image.segs[0].mask.assign((5001 + 7) / 8, 0xff);
            long_image.entries.clear();
            long_image.content_hash = hybrid_program_content_hash(long_image);
            const auto default_limit = plan_native_region(long_image, api, long_image.lo, 4096);
            const auto extended_limit = plan_native_region(long_image, api, long_image.lo, 6000);
            check(default_limit.truncated() && default_limit.heads().size() == 4096 &&
                      !default_limit.at(long_image.lo + 5000) && !extended_limit.truncated() &&
                      extended_limit.heads().size() == 5001 &&
                      extended_limit.at(long_image.lo + 5000) &&
                      extended_limit.at(long_image.lo + 5000)->flow == RAX_FLOW_RETURN,
                  "explicit larger native plan reaches a return beyond the default head bound");
        }
        auto changed = image;
        changed.generation++;
        check(!region.matches(changed), "region generation identity rejects stale plan");
        changed = image;
        changed.segs[0].bytes[0x200] ^= 1;
        check(!region.matches(changed), "region remote code patch invalidates plan");
        changed = image;
        changed.segs[0].perm = 0;
        check(!plan_native_region(changed, api, image.lo).available(),
              "unknown permissions do not admit region");
        changed = image;
        changed.segs[0].mask[0] = 0;
        check(!plan_native_region(changed, api, image.lo).available(),
              "unloaded entry does not admit region");
        changed = image;
        changed.segs[0].bitness = is64 ? 1 : 2;
        check(!plan_native_region(changed, api, image.lo).available(), "mixed mode rejected");
        changed = image;
        changed.segs[0].kind = HybridSegmentKind::EXTERNAL;
        check(!plan_native_region(changed, api, image.lo).available(), "external entry rejected");
        check(!plan_native_region(image, api, image.lo, 0).available(), "zero native-region quota");
        check(!plan_native_region(image, nullptr, image.lo).available(),
              "missing decoder rejects region");
        if (!is64)
        {
            check(!chernobog::vm::plan_native_region(image, api, image.lo).available(),
                  "32-bit region requires a mode-aware decoder instead of 64-bit SMIR oracle");
            auto legacy = image;
            std::fill(legacy.segs[0].bytes.begin(), legacy.segs[0].bytes.end(), 0xcc);
            const uint8_t stream[] = {0x4a, 0x33, 0xda, 0xc3};
            std::copy(std::begin(stream), std::end(stream), legacy.segs[0].bytes.begin());
            legacy.content_hash = hybrid_program_content_hash(legacy);
            const auto legacy_plan = plan_native_region(legacy, api, legacy.lo);
            EmuDriver legacy_driver(api, legacy, true);
            EmuEvents legacy_events;
            EmuOutcome legacy_out;
            check(legacy_plan.heads().size() == 3 && legacy_plan.at(legacy.lo)->bytes.size() == 1 &&
                      legacy_driver.emulate_region(legacy_plan, short_run_config(), legacy_events,
                                                   legacy_out) &&
                      legacy_out.returned && legacy_events.execution.size() == 3 &&
                      legacy_events.execution[0].size == 1 &&
                      legacy_events.execution[1].pc == legacy.lo + 1,
                  "region capture uses 32-bit INC/DEC boundaries through runtime hooks");
            for (bool word : {false, true})
                for (bool decrement : {false, true})
                    for (bool carry : {false, true})
                        for (uint32_t value :
                             {0u, 0x7fffu, 0x8000u, 0xffffu, 0x7fffffffu, 0x80000000u, 0xffffffffu})
                        {
                            // Materialized CF deliberately differs from the pending arithmetic CF.
                            // INC/DEC must preserve the latter in both legacy operand widths.
                            auto pending = image;
                            auto &code = pending.segs[0].bytes;
                            std::fill(code.begin(), code.end(), 0xcc);
                            std::vector<uint8_t> stream{
                                uint8_t(carry ? 0xf8 : 0xf9), 0xb9, 0, 0, 0, 0};
                            if (carry)
                                stream.insert(stream.end(), {0x83, 0xe9, 1});
                            else
                                stream.insert(stream.end(), {0x31, 0xc9});
                            stream.push_back(0xba);
                            for (unsigned byte = 0; byte < 4; ++byte)
                                stream.push_back(uint8_t(value >> (8 * byte)));
                            if (word)
                                stream.push_back(0x66);
                            stream.push_back(decrement ? 0x4a : 0x42);
                            stream.push_back(0xc3);
                            std::copy(stream.begin(), stream.end(), code.begin());
                            pending.content_hash = hybrid_program_content_hash(pending);
                            auto plan = plan_native_region(pending, api, pending.lo);
                            EmuDriver run(api, pending, true);
                            EmuEvents captured;
                            EmuOutcome out;
                            const bool ran =
                                run.emulate_region_walk(plan, short_run_config(), captured, out,
                                                        fixture_decoder, 64, nullptr, true);
                            uint64_t flags = UINT64_MAX, edx = UINT64_MAX;
                            for (const auto &state : captured.states)
                                if (state.kind == StatePoint::Kind::NativeInstructionEntry &&
                                    state.pc == pending.lo + stream.size() - 1)
                                    for (const auto &reg : state.regs)
                                    {
                                        if (reg.reg == RAX_X86_REG_EFLAGS)
                                            flags = reg.value;
                                        if (reg.reg == RAX_X86_GPR32(2))
                                            edx = reg.value;
                                    }
                            const uint32_t result = decrement ? value - 1 : value + 1;
                            const uint32_t expected =
                                word ? (value & 0xffff0000u) | (result & 0xffffu) : result;
                            check(
                                ran && out.returned && out.native_state_capture_complete &&
                                    flags != UINT64_MAX && (flags & 1) == uint64_t(carry) &&
                                    edx == expected,
                                "legacy INC/DEC preserves pending carry across 16/32-bit boundaries");
                            EmuEvents unsampled;
                            EmuOutcome unsampled_out;
                            const bool again = run.emulate_region(plan, short_run_config(),
                                                                  unsampled, unsampled_out);
                            uint64_t final_flags = UINT64_MAX, final_edx = UINT64_MAX;
                            for (const auto &reg : unsampled_out.native_final_registers)
                            {
                                if (reg.reg == RAX_X86_REG_EFLAGS)
                                    final_flags = reg.value;
                                if (reg.reg == RAX_X86_GPR32(2))
                                    final_edx = reg.value;
                            }
                            check(
                                again && unsampled_out.returned &&
                                    unsampled_out.native_final_registers_complete &&
                                    final_flags == flags && final_edx == expected,
                                "legacy carry materialization does not depend on instruction-state sampling");
                        }
        }
        EmuDriver permissive(api, image, false);
        EmuEvents rejected;
        EmuOutcome rejected_out;
        {
            auto object_image = image;
            auto &code = object_image.segs[0].bytes;
            std::fill(code.begin(), code.end(), 0xcc);
            const std::vector<uint8_t> prefix =
                is64
                    ? std::vector<uint8_t>{0x48, 0x89, 0xd1}
                    : std::vector<uint8_t>{0x8b, 0x4c, 0x24, 0x0c}; // pointer argument 2 -> [r/e]cx
            const std::vector<uint8_t> body = {0x8b, 0x01, 0x83, 0xc0, 1, 0x89, 0x01, 0xc3};
            std::copy(prefix.begin(), prefix.end(), code.begin());
            std::copy(body.begin(), body.end(),
                      code.begin() + static_cast<std::ptrdiff_t>(prefix.size()));
            object_image.content_hash = hybrid_program_content_hash(object_image);
            auto object_region = plan_native_region(object_image, api, object_image.lo);
            EmuDriver object_driver(api, object_image, true);
            EmuInput supplied;
            supplied.args = {0, 0, 0};
            supplied.native_objects.push_back(
                {2, 4, {0xa5, 0xa5, 0xa5, 0xa5, 0xff, 0xff, 0xff, 0xff, 0x5a, 0x5a, 0x5a, 0x5a}});
            auto capture = [&](const EmuInput &value, EmuOutcome &result)
            {
                EmuEvents sink;
                return object_driver.emulate_region(object_region, short_run_config(), sink, result,
                                                    &value);
            };
            EmuOutcome result;
            check(capture(supplied, result) && result.returned &&
                      result.native_final_registers_complete && result.sp_valid &&
                      result.sp_delta == (is64 ? 8 : 4),
                  "explicit object ABI placement and final register capture");
            const std::vector<uint8_t> expected = {0xa5, 0xa5, 0xa5, 0xa5, 0,    0,
                                                   0,    0,    0x5a, 0x5a, 0x5a, 0x5a};
            check(result.native_objects.size() == 1 && result.native_objects[0].readable &&
                      result.native_objects[0].initial == supplied.native_objects[0].bytes &&
                      result.native_objects[0].final == expected,
                  "explicit object captures mutated value and both unchanged guards");
            bool result_ok = false, flags_ok = false;
            for (const auto &reg : result.native_final_registers)
            {
                if (reg.reg == (is64 ? RAX_X86_REG_RAX : RAX_X86_REG_EAX))
                    result_ok = reg.value == 0;
                if (reg.reg == (is64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS))
                    flags_ok = (reg.value & 0x8d5) == 0x55;
            }
            check(result_ok && flags_ok,
                  "explicit object result and defined ADD flags agree with independent arithmetic");
            check(capture(supplied, result) && result.native_objects[0].final == expected,
                  "explicit object reinitializes after prior write");
            EmuEvents ordinary_objects;
            check(!object_driver.emulate_from(object_image.lo, object_image.entries[0].end,
                                              short_run_config(), ordinary_objects, &result, true,
                                              0, 0, &supplied) &&
                      ordinary_objects.execution.empty(),
                  "ordinary execution rejects native input objects");
            auto bad = supplied;
            bad.native_objects[0].offset = 12;
            check(!capture(bad, result), "one-past object pointer rejected");
            bad = supplied;
            bad.native_objects[0].bytes.clear();
            check(!capture(bad, result), "empty object rejected");
            bad = supplied;
            bad.native_objects[0].bytes.resize(4097);
            check(!capture(bad, result), "object byte quota rejected");
            bad = supplied;
            bad.native_objects.push_back(bad.native_objects.front());
            check(!capture(bad, result), "duplicate object argument rejected");
            bad = supplied;
            bad.args[2] = 1;
            check(!capture(bad, result), "conflicting scalar pointer rejected");
            bad = supplied;
            bad.register_overrides.push_back({RAX_X86_REG_EAX, 0});
            check(!capture(bad, result),
                  "custom register override cannot bypass object ABI contract");
            bad = supplied;
            bad.native_objects[0].argument = 3;
            check(!capture(bad, result), "absent object argument rejected");
            bad = supplied;
            bad.native_objects.resize(17);
            check(!capture(bad, result), "object count quota rejected");
            bad = supplied;
            bad.args.resize(33);
            check(!capture(bad, result), "object argument count quota rejected");
        }
        auto zero = short_run_config();
        zero.max_insns = 0;
        check(!driver.emulate_region(region, zero, rejected, rejected_out),
              "zero region step budget cannot reuse old exit metadata");
        zero = short_run_config();
        zero.timeout_ms = 0;
        check(!driver.emulate_region(region, zero, rejected, rejected_out),
              "zero region time budget cannot reuse old exit metadata");
        check(!permissive.emulate_region(region, short_run_config(), rejected, rejected_out) &&
                  rejected.execution.empty(),
              "region execution requires strict permissions");
        changed = image;
        changed.segs[0].bytes[0x200] ^= 1;
        EmuDriver stale_driver(api, changed, true);
        check(!stale_driver.emulate_region(region, short_run_config(), rejected, rejected_out) &&
                  rejected.execution.empty(),
              "stale plan cannot start execution");
        changed = image;
        std::fill(changed.segs[0].bytes.begin(), changed.segs[0].bytes.end(), 0xcc);
        const uint8_t indirect_code[] = {0xb8, 0, 1, 0x10, 0, 0xff, 0xd0, 0xc3};
        std::copy(std::begin(indirect_code), std::end(indirect_code),
                  changed.segs[0].bytes.begin());
        changed.segs[0].bytes[0x100] = 0xc3;
        changed.content_hash = hybrid_program_content_hash(changed);
        const auto indirect_region = plan_native_region(changed, api, changed.lo);
        EmuDriver indirect_driver(api, changed, true);
        EmuEvents indirect_events;
        EmuOutcome indirect_out;
        check(indirect_driver.emulate_region(indirect_region, short_run_config(), indirect_events,
                                             indirect_out) &&
                  indirect_out.region_boundary && indirect_events.execution.size() == 2 &&
                  indirect_out.region_boundary_target == changed.lo + 0x100 &&
                  indirect_events.edges.back().kind == ExecEdge::Kind::Call,
              "unknown indirect callee stops after retaining native call effects");
        {
            auto walked = indirect_region;
            EmuEvents walked_events;
            EmuOutcome walked_out;
            check(indirect_driver.emulate_region_walk(walked, short_run_config(), walked_events,
                                                      walked_out, fixture_decoder) &&
                      walked_out.native_walk && walked_out.returned && !walked_out.conclusive() &&
                      walked_out.native_admissions.size() == 1 &&
                      walked_out.native_admissions[0].admitted && walked_out.sp_valid &&
                      walked_out.sp_delta == (is64 ? 8 : 4),
                  "native walk resumes actual indirect-call machine state and returns");
            check(
                walked_events.execution.size() == 4 && walked_events.edges.size() == 2 &&
                    walked_events.data.size() == 3 &&
                    walked_events.execution[2].pc == changed.lo + 0x100 &&
                    walked_events.execution[2].sequence == walked_events.edges[0].sequence &&
                    walked_events.states[1].sequence == walked_events.edges[0].sequence,
                "native walk retains one call transfer and target sample without duplicate events");
            check(walked_out.data_trace_complete && !walked_out.consumed_context_complete &&
                      walked_out.region_identity == walked.identity() &&
                      walked.identity() != indirect_region.identity(),
                  "native walk labels final plan while excluding universal function evidence");
            auto sampled_plan = indirect_region;
            EmuEvents sampled_events;
            EmuOutcome sampled_out;
            check(indirect_driver.emulate_region_walk(sampled_plan, short_run_config(),
                                                      sampled_events, sampled_out, fixture_decoder,
                                                      64, nullptr, true) &&
                      sampled_out.returned && sampled_out.native_state_capture_requested &&
                      sampled_out.native_state_capture_complete,
                  "native instruction sampling is explicit and complete");
            size_t sampled = 0;
            bool initial_before = false, callee_before = false;
            for (const auto &state : sampled_events.states)
                if (state.kind == StatePoint::Kind::NativeInstructionEntry)
                {
                    if (sampled < sampled_events.execution.size())
                        check(state.pc == sampled_events.execution[sampled].pc &&
                                  state.sequence == sampled_events.execution[sampled].sequence,
                              "instruction-entry state shares exact execution sequence");
                    for (const auto &reg : state.regs)
                    {
                        if (state.pc == changed.lo &&
                            reg.reg == (is64 ? RAX_X86_REG_RAX : RAX_X86_REG_EAX))
                            initial_before = reg.value == 0;
                        if (state.pc == changed.lo + 0x100 &&
                            reg.reg == (is64 ? RAX_X86_REG_RSP : RAX_X86_REG_ESP))
                            callee_before = reg.value == sampled_out.entry_sp - (is64 ? 8 : 4);
                    }
                    ++sampled;
                }
            check(sampled == sampled_events.execution.size() && initial_before && callee_before,
                  "native samples precede each instruction and retain the actual call stack");
            auto too_small = short_run_config();
            too_small.max_insns = 3;
            auto limited_walk = indirect_region;
            EmuEvents limited_events;
            EmuOutcome limited_out;
            check(indirect_driver.emulate_region_walk(limited_walk, too_small, limited_events,
                                                      limited_out, fixture_decoder) &&
                      !limited_out.returned && limited_events.execution.size() <= 3 &&
                      limited_out.instruction_count <= 3,
                  "native walk shares instruction quota across resumptions");
            const chernobog::vm::NativeDecoder delayed =
                [&](uint64_t ea, const uint8_t *data, size_t count, rax_decoded &decoded)
            {
                if (ea == changed.lo + 0x100)
                    std::this_thread::sleep_for(std::chrono::milliseconds(60));
                return fixture_decoder(ea, data, count, decoded);
            };
            auto short_time = short_run_config();
            short_time.timeout_ms = 25;
            auto timed_plan = indirect_region;
            EmuEvents timed_events;
            EmuOutcome timed_out;
            check(
                indirect_driver.emulate_region_walk(timed_plan, short_time, timed_events, timed_out,
                                                    delayed) &&
                    !timed_out.returned && timed_out.region_boundary &&
                    timed_events.execution.size() == 2 && timed_out.native_admissions.size() == 1 &&
                    timed_out.native_admissions[0].admitted &&
                    timed_out.native_walk_stop == "time_budget",
                "native walk includes extension planning in shared wall-time budget before resuming");
            auto invalid_walk = indirect_region;
            EmuEvents invalid_events;
            EmuOutcome invalid_out;
            check(!indirect_driver.emulate_region_walk(invalid_walk, short_run_config(),
                                                       invalid_events, invalid_out, fixture_decoder,
                                                       0) &&
                      !indirect_driver.emulate_region_walk(invalid_walk, short_run_config(),
                                                           invalid_events, invalid_out,
                                                           fixture_decoder, 65) &&
                      !indirect_driver.emulate_region_walk(invalid_walk, short_run_config(),
                                                           invalid_events, invalid_out, {}, 1) &&
                      invalid_events.execution.empty(),
                  "native walk rejects unbounded or undecodable requests");
            const auto extension =
                chernobog::vm::extend_native_region(indirect_region, changed, api, changed.lo + 5,
                                                    changed.lo + 0x100, 4096, fixture_decoder);
            check(extension.admitted && extension.added_heads == 1 &&
                      extension.region.entry() == indirect_region.entry() &&
                      extension.region.at(changed.lo) && extension.region.at(changed.lo + 0x100) &&
                      !indirect_region.at(changed.lo + 0x100),
                  "native extension preserves root and immutable previous plan");
            check(!chernobog::vm::extend_native_region(indirect_region, changed, api, changed.lo,
                                                       changed.lo + 0x100, 4096, fixture_decoder)
                       .admitted,
                  "fallthrough source cannot authorize observed-target extension");
            check(!chernobog::vm::extend_native_region(indirect_region, changed, api,
                                                       changed.lo + 5, changed.lo, 4096,
                                                       fixture_decoder)
                       .admitted,
                  "already admitted target cannot extend native plan");
            check(!chernobog::vm::extend_native_region(
                       indirect_region, changed, api, changed.lo + 5, changed.lo + 0x100,
                       indirect_region.heads().size(), fixture_decoder)
                       .admitted,
                  "native extension head quota enforced");
            auto stale = changed;
            stale.generation++;
            check(!chernobog::vm::extend_native_region(indirect_region, stale, api, changed.lo + 5,
                                                       changed.lo + 0x100, 4096, fixture_decoder)
                       .admitted,
                  "native extension rejects stale generation");
            const auto overlap =
                chernobog::vm::extend_native_region(indirect_region, changed, api, changed.lo + 5,
                                                    changed.lo + 1, 4096, fixture_decoder);
            check(!overlap.admitted && overlap.reason == "overlapping_decode",
                  "native extension rejects interior instruction target");
            const chernobog::vm::NativeDecoder rejecting =
                [&](uint64_t ea, const uint8_t *data, size_t count, rax_decoded &decoded)
            { return ea != changed.lo + 0x100 && fixture_decoder(ea, data, count, decoded); };
            auto refused_walk = indirect_region;
            EmuEvents refused_events;
            EmuOutcome refused_out;
            check(indirect_driver.emulate_region_walk(refused_walk, short_run_config(),
                                                      refused_events, refused_out, rejecting) &&
                      refused_out.region_boundary && refused_events.execution.size() == 2 &&
                      refused_out.native_admissions.size() == 1 &&
                      !refused_out.native_admissions[0].admitted &&
                      refused_out.native_walk_stop == "invalid_decode" &&
                      refused_walk.identity() == indirect_region.identity(),
                  "native walk retains rejected decode as boundary without executing destination");
            // Two computed jumps require two explicit admissions; no register reseeding
            // or baseline restoration may occur between those admissions.
            auto chain = changed;
            auto &chain_bytes = chain.segs[0].bytes;
            std::fill(chain_bytes.begin(), chain_bytes.end(), 0xcc);
            const uint8_t first[] = {0xb8, 0, 1, 0x10, 0, 0xff, 0xe0};
            const uint8_t second[] = {0xb8, 0, 2, 0x10, 0, 0xff, 0xe0};
            const uint8_t last[] = {0xb8, 42, 0, 0, 0, 0xc3};
            std::copy(std::begin(first), std::end(first), chain_bytes.begin());
            std::copy(std::begin(second), std::end(second), chain_bytes.begin() + 0x100);
            std::copy(std::begin(last), std::end(last), chain_bytes.begin() + 0x200);
            chain.content_hash = hybrid_program_content_hash(chain);
            EmuDriver chain_driver(api, chain, true);
            auto chain_plan = plan_native_region(chain, api, chain.lo);
            EmuEvents chain_events;
            EmuOutcome chain_out;
            check(chain_driver.emulate_region_walk(chain_plan, short_run_config(), chain_events,
                                                   chain_out, fixture_decoder, 1) &&
                      !chain_out.returned && chain_out.native_walk_stop == "extension_limit" &&
                      chain_out.native_admissions.size() == 1 && chain_events.execution.size() == 4,
                  "native walk extension limit stops before second computed destination");
            chain_plan = plan_native_region(chain, api, chain.lo);
            chain_events = {};
            chain_out = {};
            check(chain_driver.emulate_region_walk(chain_plan, short_run_config(), chain_events,
                                                   chain_out, fixture_decoder, 2) &&
                      chain_out.returned && chain_out.native_admissions.size() == 2 &&
                      chain_events.execution.size() == 6 && chain_events.edges.size() == 2 &&
                      chain_out.sp_delta == (is64 ? 8 : 4),
                  "native walk admits observed jump chain without duplicated transfers");
            bool exact_result = false;
            for (const auto &reg : chain_out.native_final_registers)
                if (reg.reg == (is64 ? RAX_X86_REG_RAX : RAX_X86_REG_EAX))
                    exact_result = reg.value == 42;
            check(exact_result, "native walk preserves computed chain result");
            {
                auto loop = chain;
                auto &stream = loop.segs[0].bytes;
                std::fill(stream.begin(), stream.end(), 0xcc);
                stream[0] = 0xf9;
                stream[1] = 0x72;
                stream[2] = 0xfe;
                stream[3] = 0xc3; // stc; jb self; ret
                loop.content_hash = hybrid_program_content_hash(loop);
                auto loop_plan = plan_native_region(loop, api, loop.lo);
                EmuDriver loop_driver(api, loop, true);
                auto budget = short_run_config();
                budget.max_insns = 65536;
                budget.timeout_ms = 1000;
                EmuEvents loop_events;
                EmuOutcome loop_out;
                check(
                    loop_driver.emulate_region_walk(loop_plan, budget, loop_events, loop_out,
                                                    fixture_decoder, 64, nullptr, true) &&
                        !loop_out.returned && loop_events.execution.size() == 4096 &&
                        loop_events.states.size() <= 12289 &&
                        loop_out.native_state_capture_complete,
                    "native sample mode clamps instructions and accommodates branch/transfer snapshots");
            }
            // PUSH/RET carries an observable stack write before the target is admitted.
            const uint8_t ret_transfer[] = {0x68, 0, 2, 0x10, 0, 0xc3};
            std::fill(chain_bytes.begin(), chain_bytes.end(), 0xcc);
            std::copy(std::begin(ret_transfer), std::end(ret_transfer), chain_bytes.begin());
            std::copy(std::begin(last), std::end(last), chain_bytes.begin() + 0x200);
            chain.content_hash = hybrid_program_content_hash(chain);
            EmuDriver return_driver(api, chain, true);
            auto return_plan = plan_native_region(chain, api, chain.lo);
            EmuEvents return_events;
            EmuOutcome return_out;
            check(return_driver.emulate_region_walk(return_plan, short_run_config(), return_events,
                                                    return_out, fixture_decoder) &&
                      return_out.returned && return_out.native_admissions.size() == 1 &&
                      return_events.execution.size() == 4 && return_events.edges.size() == 1 &&
                      return_events.edges[0].kind == ExecEdge::Kind::Return &&
                      return_events.data.size() == 3 &&
                      return_events.data[0].kind == RAX_MEM_WRITE && return_out.sp_valid &&
                      return_out.sp_delta == (is64 ? 8 : 4),
                  "native walk follows stack-mediated transfer with actual stack effects");
        }
        // Writable code is captured exactly; a changed future instruction must not
        // execute under its original plan even if the new encoding is also valid.
        changed = image;
        changed.segs[0].perm |= uint32_t(HybridSegPerm::WRITE);
        auto &smc = changed.segs[0].bytes;
        std::fill(smc.begin(), smc.end(), 0xcc);
        if (is64)
        {
            const uint8_t code[] = {0xc6, 0x05, 0xf9, 0, 0, 0, 0x90, 0xe9, 0xf4, 0, 0, 0};
            std::copy(std::begin(code), std::end(code), smc.begin());
        }
        else
        {
            const uint8_t code[] = {0xc6, 0x05, 0, 1, 0x10, 0, 0x90, 0xe9, 0xf4, 0, 0, 0};
            std::copy(std::begin(code), std::end(code), smc.begin());
        }
        smc[0x100] = 0xc3;
        changed.content_hash = hybrid_program_content_hash(changed);
        const auto smc_region = plan_native_region(changed, api, changed.lo);
        EmuDriver smc_driver(api, changed, true);
        EmuEvents smc_events;
        EmuOutcome smc_out;
        check(smc_driver.emulate_region(smc_region, short_run_config(), smc_events, smc_out) &&
                  smc_out.region_code_changed && smc_events.execution.size() == 2 &&
                  !smc_out.data_trace_complete,
              "runtime code change stops before modified instruction");
        {
            auto changed_plan = smc_region;
            EmuEvents changed_events;
            EmuOutcome changed_out;
            check(smc_driver.emulate_region_walk(changed_plan, short_run_config(), changed_events,
                                                 changed_out, fixture_decoder) &&
                      changed_out.region_code_changed && changed_out.native_admissions.empty() &&
                      changed_events.execution.size() == 2,
                  "native walk cannot override existing runtime byte guard");
            const uint8_t tail[] = {0xb8, 0, 1, 0x10, 0, 0xff, 0xe0};
            std::fill(smc.begin() + 7, smc.end(), 0xcc);
            std::copy(std::begin(tail), std::end(tail), smc.begin() + 7);
            smc[0x100] = 0xc3;
            changed.content_hash = hybrid_program_content_hash(changed);
            auto unknown_plan = plan_native_region(changed, api, changed.lo);
            EmuDriver unknown_driver(api, changed, true);
            EmuEvents unknown_events;
            EmuOutcome unknown_out;
            check(
                unknown_driver.emulate_region_walk(unknown_plan, short_run_config(), unknown_events,
                                                   unknown_out, fixture_decoder) &&
                    unknown_out.region_code_changed && unknown_out.native_admissions.size() == 1 &&
                    unknown_out.native_admissions[0].admitted &&
                    unknown_events.execution.size() == 3 && !unknown_out.data_trace_complete,
                "newly admitted destination still requires exact runtime instruction bytes before entry");
        }
    }
}

bool run_direct(const RaxApi *api, const ProgramImage &image,
                const std::vector<EmuCallSummary> &summaries, EmuEvents *events,
                EmuOutcome *outcome, uint64_t seed = 0, const EmuInput *input = nullptr)
{
    EmuDriver driver(api, image, true, false, summaries);
    check(driver.can_discover(), "direct-test driver must initialize");
    if (!driver.can_discover())
        return false;
    return driver.emulate_from(image.entries.front().start, image.entries.front().end,
                               short_run_config(), *events, outcome, true, seed, 0, input);
}

void test_function_profiles_and_call_policy()
{
    const HybridFunctionProfile instance =
        hybrid_function_profile_from_name("-[AppDelegate randomStringWithLength:]");
    check(instance.flavor == HybridFunctionFlavor::OBJC_INSTANCE,
          "Objective-C instance method profile");
    check(instance.objc_selector == "randomStringWithLength:" &&
              instance.explicit_arguments_known && instance.explicit_arguments == 1 &&
              instance.total_arguments() == 3,
          "Objective-C selector arity must preserve two hidden ABI arguments");

    const HybridFunctionProfile klass =
        hybrid_function_profile_from_name("+[Factory objectWithA:b:]");
    check(klass.flavor == HybridFunctionFlavor::OBJC_CLASS && klass.explicit_arguments == 2,
          "Objective-C class method and multi-part selector profile");
    const HybridFunctionProfile native = hybrid_function_profile_from_name("_ordinary_function");
    check(native.flavor == HybridFunctionFlavor::NATIVE && !native.explicit_arguments_known,
          "native name must not fabricate an arity");

    ProgramImage identity = arm64_image({0xC0, 0x03, 0x5F, 0xD6}, native);
    const uint64_t unknown_arity_hash = identity.entries.front().byte_hash;
    identity.entries.front().profile.explicit_arguments = 2;
    identity.entries.front().profile.explicit_arguments_known = true;
    const uint64_t known_arity_hash = hybrid_function_byte_hash(identity, identity.entries.front());
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
    check(hybrid_classify_call_summary_name("__imp__memchr") == EmuSummaryKind::MEMCHR &&
              hybrid_classify_call_summary_name("j__strnlen") == EmuSummaryKind::STRNLEN,
          "bounded byte-search summaries must recognize decorated external names");
    check(!hybrid_classify_call_summary_name("wmemchr") &&
              !hybrid_classify_call_summary_name("strnlen_s") &&
              !hybrid_classify_call_summary_name("__memchr_chk"),
          "different code-unit widths and checked-call contracts require separate models");
}

ProgramImage byte_search_image(HybridArch arch, const std::vector<uint8_t> &payload,
                               uint32_t source_permissions)
{
    // Arguments arrive through the driver's ABI input plan. After the external
    // call, store its actual return register into image memory for observation.
    const std::vector<uint8_t> arm64_code = {0x08, 0x00, 0x84, 0xD2,  // mov x8,#0x2000
                                             0xE9, 0x03, 0x1E, 0xAA,  // mov x9,lr
                                             0x00, 0x01, 0x3F, 0xD6,  // blr x8
                                             0xFE, 0x03, 0x09, 0xAA,  // mov lr,x9
                                             0x08, 0x00, 0x88, 0xD2,  // mov x8,#0x4000
                                             0x00, 0x01, 0x00, 0xF9,  // str x0,[x8]
                                             0xC0, 0x03, 0x5F, 0xD6}; // ret
    const std::vector<uint8_t> x64_code = {
        0x48, 0xC7, 0xC0, 0x00, 0x20, 0x00, 0x00,                   // mov rax,0x2000
        0xFF, 0xD0,                                                 // call rax
        0x48, 0xA3, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov [0x4000],rax
        0xC3};                                                      // ret
    ProgramImage image = arm64_image(arch == HybridArch::ARM64 ? arm64_code : x64_code, {}, true);
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
    struct AbiCase
    {
        HybridArch arch;
        bool windows_x64;
        const char *name;
    };
    for (const AbiCase abi : {AbiCase{HybridArch::ARM64, false, "AAPCS64"},
                              AbiCase{HybridArch::X86_64, false, "SysV x86-64"},
                              AbiCase{HybridArch::X86_64, true, "Windows x86-64"}})
    {
        auto run_case = [&](const char *label, EmuSummaryKind kind,
                            const std::vector<uint8_t> &payload,
                            const std::vector<uint64_t> &arguments, uint64_t expected,
                            uint32_t consumed, bool success = true, bool permission_failure = false,
                            uint32_t permissions = uint32_t(HybridSegPerm::READ))
        {
            const int prior_failures = failures;
            const ProgramImage image = byte_search_image(abi.arch, payload, permissions);
            const char *name = kind == EmuSummaryKind::MEMCHR ? "memchr" : "strnlen";
            EmuDriver driver(api, image, true, abi.windows_x64,
                             {EmuCallSummary{0x2000, kind, name}});
            check(driver.can_discover(), "byte-search test driver must initialize");
            if (!driver.can_discover())
                return;
            EmuInput input;
            input.args = arguments;
            input.run_id = 7;
            input.seed = 0xABC;
            EmuEvents events;
            EmuOutcome outcome;
            check(driver.emulate_from(image.entries.front().start, image.entries.front().end,
                                      short_run_config(), events, &outcome, true, input.seed,
                                      input.run_id, &input),
                  "byte-search summary must produce a run outcome");
            check(outcome.returned == success && outcome.environment_model_failure == !success &&
                      outcome.permission_violation == permission_failure &&
                      outcome.summarized_calls == (success ? 1u : 0u) &&
                      !outcome.unmodeled_external,
                  "byte-search success and failure boundaries must be classified exactly");
            check(!outcome.consumed_context_complete,
                  "a modeled external call remains exploratory evidence");
            const auto written = std::find_if(events.data.begin(), events.data.end(),
                                              [](const DataAcc &access)
                                              {
                                                  return access.kind == RAX_MEM_WRITE &&
                                                         access.scope == DataScope::IMAGE &&
                                                         access.addr == 0x4000 && access.size == 8;
                                              });
            if (success)
            {
                check(written != events.data.end() && written->value == expected,
                      "guest code must observe the byte-search function's exact return value");
                check(outcome.external_model_used,
                      "successful byte-search summaries must retain external-model provenance");
            }
            else
            {
                check(
                    written == events.data.end() && outcome.external_target == 0x2000 &&
                        outcome.external_name == name,
                    "failed byte-search summaries must stop before continuation and retain the symbol");
            }
            check(events.consumed_image_reads.size() == (consumed == 0 ? 0u : 1u),
                  "byte searches must record one consumed prefix and no unused tail");
            if (consumed != 0 && !events.consumed_image_reads.empty())
            {
                const auto &read = events.consumed_image_reads.front();
                check(
                    read.addr == arguments.front() && read.size == consumed &&
                        read.run_id == input.run_id && read.seed == input.seed,
                    "byte-search dependencies must include exactly the inspected bytes and run identity");
                uint64_t preview = 0;
                for (size_t i = 0; i < std::min<size_t>(consumed, 8); ++i)
                    preview |= uint64_t(payload[i]) << (8 * i);
                const auto recorded = std::find_if(events.data.begin(), events.data.end(),
                                                   [&](const DataAcc &access)
                                                   {
                                                       return access.kind == RAX_MEM_READ &&
                                                              access.scope == DataScope::IMAGE &&
                                                              access.addr == arguments.front();
                                                   });
                check(
                    recorded != events.data.end() && recorded->size == consumed &&
                        recorded->value == preview &&
                        recorded->from == (abi.arch == HybridArch::ARM64 ? 0x1008u : 0x1007u),
                    "byte-search memory evidence must retain the first eight bytes and call source");
            }
            check(std::none_of(events.execution.begin(), events.execution.end(),
                               [](const ExecPoint &point) { return point.pc == 0x2000; }),
                  "byte-search summaries must not execute external placeholder bytes");
            if (failures != prior_failures)
                std::cerr << "  byte-search case: " << abi.name << ": " << label << '\n';
        };

        constexpr uint64_t source = 0x3000;
        constexpr uint64_t cap = 1u << 20;
        constexpr uint64_t maximum_address = std::numeric_limits<uint64_t>::max();
        const std::vector<uint8_t> binary{0x41, 0, 0x80, 0x80};
        run_case("memchr unsigned byte conversion and first match", EmuSummaryKind::MEMCHR, binary,
                 {source, 0x180, 4}, source + 2, 3);
        run_case("memchr embedded zero", EmuSummaryKind::MEMCHR, binary, {source, 0, 4}, source + 1,
                 2);
        run_case("memchr does not terminate at zero", EmuSummaryKind::MEMCHR, binary,
                 {source, 0x80, 2}, 0, 2);
        run_case("memchr negative int and unmapped unused tail", EmuSummaryKind::MEMCHR, {0xFF},
                 {source, maximum_address, 4096}, source, 1);
        run_case("memchr exact bound miss", EmuSummaryKind::MEMCHR, {1, 2, 3}, {source, 4, 3}, 0,
                 3);
        run_case("memchr preview truncation and last-byte match", EmuSummaryKind::MEMCHR,
                 {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, {source, 16, 16},
                 source + 15, 16);
        run_case("memchr zero bound reads no address", EmuSummaryKind::MEMCHR, {1},
                 {maximum_address, 1, 0}, 0, 0);
        run_case("memchr exact model cap", EmuSummaryKind::MEMCHR, {1}, {source, 1, cap}, source,
                 1);
        run_case("memchr over model cap rejects even an early match", EmuSummaryKind::MEMCHR, {1},
                 {source, 1, cap + 1}, 0, 0, false);
        run_case("memchr unavailable next byte retains observed prefix", EmuSummaryKind::MEMCHR,
                 {1, 2}, {source, 3, 3}, 0, 2, false, true);
        run_case("memchr source permission failure", EmuSummaryKind::MEMCHR, {1}, {source, 1, 1}, 0,
                 0, false, true, uint32_t(HybridSegPerm::WRITE));
        run_case("memchr unmapped source", EmuSummaryKind::MEMCHR, {1}, {0x9000, 1, 1}, 0, 0,
                 false);
        run_case("memchr address-boundary overflow", EmuSummaryKind::MEMCHR, {1},
                 {maximum_address, 1, 2}, 0, 0, false, true);

        run_case("strnlen unterminated bounded array", EmuSummaryKind::STRNLEN, {'a', 'b', 'c'},
                 {source, 3}, 3, 3);
        run_case("strnlen includes NUL in consumed bytes", EmuSummaryKind::STRNLEN,
                 {'a', 'b', 'c', 0}, {source, 4}, 3, 4);
        run_case("strnlen empty string and unmapped unused tail", EmuSummaryKind::STRNLEN, {0},
                 {source, 4096}, 0, 1);
        run_case("strnlen counts encoded bytes", EmuSummaryKind::STRNLEN, {0xC3, 0xA9, 0},
                 {source, 3}, 2, 3);
        run_case("strnlen excludes a NUL beyond the bound", EmuSummaryKind::STRNLEN, {'a', 'b', 0},
                 {source, 2}, 2, 2);
        run_case("strnlen zero bound reads no address", EmuSummaryKind::STRNLEN, {0},
                 {maximum_address, 0}, 0, 0);
        run_case("strnlen exact model cap", EmuSummaryKind::STRNLEN, {0}, {source, cap}, 0, 1);
        run_case("strnlen over model cap rejects even an early NUL", EmuSummaryKind::STRNLEN, {0},
                 {source, cap + 1}, 0, 0, false);
        run_case("strnlen unavailable next byte retains observed prefix", EmuSummaryKind::STRNLEN,
                 {'a', 'b'}, {source, 3}, 0, 2, false, true);
    }
}

void test_byte_search_scope_transitions(const RaxApi *api)
{
    struct ExpectedRead
    {
        uint64_t address;
        uint32_t size;
        uint64_t preview;
    };
    struct AbiCase
    {
        HybridArch arch;
        bool windows_x64;
        const char *name;
    };
    for (const AbiCase abi : {AbiCase{HybridArch::ARM64, false, "AAPCS64"},
                              AbiCase{HybridArch::X86_64, false, "SysV x86-64"},
                              AbiCase{HybridArch::X86_64, true, "Windows x86-64"}})
    {
        auto run_case = [&](const char *label, const ProgramImage &image, EmuSummaryKind kind,
                            const std::vector<uint64_t> &arguments, uint64_t expected_result,
                            const std::vector<ExpectedRead> &expected_reads, bool strict = false,
                            bool success = true, bool permission_failure = false)
        {
            const int prior_failures = failures;
            const char *name = kind == EmuSummaryKind::MEMCHR ? "memchr" : "strnlen";
            EmuDriver driver(api, image, strict, abi.windows_x64, {{0x2000, kind, name}});
            check(driver.can_discover(), "scope-transition driver must initialize");
            if (!driver.can_discover())
                return;
            EmuInput input;
            input.args = arguments;
            input.seed = 0xDEF;
            input.run_id = 9;
            EmuEvents events;
            EmuOutcome outcome;
            check(driver.emulate_from(image.entries.front().start, image.entries.front().end,
                                      short_run_config(), events, &outcome, true, input.seed,
                                      input.run_id, &input),
                  "scope-transition summary must produce an outcome");
            check(outcome.returned == success && outcome.environment_model_failure == !success &&
                      outcome.permission_violation == permission_failure &&
                      outcome.summarized_calls == (success ? 1u : 0u) &&
                      !outcome.consumed_context_complete,
                  "scope transitions must retain exact summary outcome classification");
            const auto written =
                std::find_if(events.data.begin(), events.data.end(), [](const DataAcc &access)
                             { return access.kind == RAX_MEM_WRITE && access.addr == 0x4000; });
            check(success ? written != events.data.end() && written->value == expected_result
                          : written == events.data.end(),
                  "scope transitions must preserve the guest result or stop before continuation");
            check(events.consumed_image_reads.size() == expected_reads.size(),
                  "scope transitions must preserve every consumed image range");
            std::vector<DataAcc> recorded_reads;
            for (const auto &access : events.data)
                if (access.kind == RAX_MEM_READ && access.scope == DataScope::IMAGE)
                    recorded_reads.push_back(access);
            check(recorded_reads.size() == expected_reads.size(),
                  "scope transitions must preserve each image read's data record");
            for (size_t i = 0; i < expected_reads.size(); ++i)
            {
                const auto &expected = expected_reads[i];
                if (i < events.consumed_image_reads.size())
                {
                    const auto &read = events.consumed_image_reads[i];
                    check(
                        read.addr == expected.address && read.size == expected.size &&
                            read.run_id == input.run_id && read.seed == input.seed,
                        "split dependencies must preserve exact addresses, lengths, and run provenance");
                }
                if (i < recorded_reads.size())
                {
                    const auto &read = recorded_reads[i];
                    check(read.addr == expected.address && read.size == expected.size &&
                              read.value == expected.preview &&
                              read.from == (abi.arch == HybridArch::ARM64 ? 0x1008u : 0x1007u),
                          "each split scope must retain its own byte preview and call source");
                }
            }
            if (failures != prior_failures)
                std::cerr << "  scope-transition case: " << abi.name << ": " << label << '\n';
        };
        const auto padding = byte_search_image(abi.arch, {'a', 'b'}, uint32_t(HybridSegPerm::READ));
        run_case("memchr image to engine padding", padding, EmuSummaryKind::MEMCHR, {0x3000, 0, 3},
                 0x3002, {{0x3000, 2, 0x6261}});
        run_case("strnlen image to engine padding", padding, EmuSummaryKind::STRNLEN, {0x3000, 3},
                 2, {{0x3000, 2, 0x6261}});
        run_case("memchr engine padding to image", padding, EmuSummaryKind::MEMCHR,
                 {0x2FFF, 'b', 3}, 0x3001, {{0x3000, 2, 0x6261}});
        // Neither page-padding range belongs to the image. A later failed read
        // must retain both initialized image ranges reached before the failure.
        run_case("memchr padding followed by an unmapped page", padding, EmuSummaryKind::MEMCHR,
                 {0x3000, 0xFE, 0x2001}, 0,
                 {{0x3000, 2, 0x6261}, {0x4000, 8, UINT64_C(0xA5A5A5A5A5A5A5A5)}}, false, false);

        auto adjacent =
            byte_search_image(abi.arch, {'a', 'b', 'c', 'd', 0}, uint32_t(HybridSegPerm::READ));
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
        run_case("memchr image to padding to image", gap, EmuSummaryKind::MEMCHR, {0x3000, 'd', 6},
                 0x3004, {{0x3000, 2, 0x6261}, {0x3003, 2, 0x6463}});
        run_case("memchr strict gap retains observed image prefix", gap, EmuSummaryKind::MEMCHR,
                 {0x3000, 'd', 6}, 0, {{0x3000, 2, 0x6261}}, true, false, true);
    }
}

void test_data_trace_completeness(const RaxApi *api)
{
    auto image = branch_image();
    std::vector<uint8_t> code{0x50}; // push rax
    for (unsigned i = 0; i < 10; ++i)
        code.insert(code.end(), {0x48, 0xFF, 0x04, 0x24}); // inc qword [rsp]
    code.insert(code.end(), {0x58, 0xC3});                 // pop rax; ret
    std::copy(code.begin(), code.end(), image.segs[0].bytes.begin());
    image.entries[0].end = image.lo + code.size();
    image.entries[0].chunks = {{image.lo, image.entries[0].end}};
    image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
    image.content_hash = hybrid_program_content_hash(image);
    EmuDriver driver(api, image, true);
    auto cfg = short_run_config();
    cfg.max_insns = 128;
    EmuEvents complete;
    EmuOutcome outcome;
    check(driver.emulate_from(image.lo, image.entries[0].end, cfg, complete, &outcome),
          "RMW complete trace runs");
    check(outcome.returned && outcome.data_trace_complete && complete.data.size() > 13,
          "RMW read/write trace is complete");
    cfg.max_insns = 13;
    EmuEvents capped;
    check(driver.emulate_from(image.lo, image.entries[0].end, cfg, capped, &outcome),
          "RMW capped trace runs");
    check(capped.data.size() == 13 && outcome.data_trace_truncated && !outcome.data_trace_complete,
          "data quota exhaustion cannot masquerade as a complete trace");
    // A non-strict run can read zero-filled mapped page padding outside the image
    // and synthetic arenas. Such filtered events must prevent completeness.
    image = branch_image();
    code = {0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00, 0xC3};
    image.segs[0].bytes = code;
    image.segs[0].mask.assign(1, 0xff);
    image.hi = image.segs[0].end = image.lo + code.size();
    image.entries[0].end = image.hi;
    image.entries[0].chunks = {{image.lo, image.hi}};
    image.entries[0].byte_hash = hybrid_function_byte_hash(image, image.entries[0]);
    image.content_hash = hybrid_program_content_hash(image);
    EmuDriver padding(api, image, false);
    EmuEvents filtered;
    cfg.max_insns = 128;
    check(padding.emulate_from(image.lo, image.hi, cfg, filtered, &outcome), "padding read runs");
    check(outcome.data_trace_filtered && !outcome.data_trace_complete,
          "filtered data events cannot yield completeness");
}

void test_arm64_memory_and_accounting(const RaxApi *api)
{
    // mov x0,#0x1122; str x0,[sp]; ldr x1,[sp]; ret
    const ProgramImage image = arm64_image({0x40, 0x24, 0x82, 0xD2, 0xE0, 0x03, 0x00, 0xF9, 0xE1,
                                            0x03, 0x40, 0xF9, 0xC0, 0x03, 0x5F, 0xD6});
    EmuEvents events;
    EmuOutcome outcome;
    check(run_direct(api, image, {}, &events, &outcome), "ARM64 memory test must run");
    check(outcome.returned, "ARM64 memory test must return through sentinel");
    check(outcome.attempted_steps_valid && outcome.attempted_steps == outcome.instruction_count,
          "normal ARM64 run must expose an exact attempted-step count");
    check(outcome.memory_observation_requested && outcome.memory_observation_available,
          "ARM64 memory-hook capability must be reported explicitly");
    check(outcome.consumed_context_complete,
          "ARM64 run with working memory hooks must be context-complete");
    check(outcome.data_trace_complete && !outcome.data_trace_truncated &&
              !outcome.data_trace_filtered,
          "complete direct data trace must be reported separately from dependencies");
    check(events.execution.size() == 4, "ARM64 code hook must report four physical instructions");
    for (const ExecPoint &point : events.execution)
        check(point.size == 4, "ARM64 code dependency width must be four bytes, not one");
    size_t reads = 0;
    size_t writes = 0;
    for (const DataAcc &access : events.data)
    {
        if (access.kind == RAX_MEM_READ)
            ++reads;
        if (access.kind == RAX_MEM_WRITE)
            ++writes;
    }
    check(reads == 1 && writes == 1, "ARM64 data hooks must distinguish one load and one store");

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
    for (size_t index = 0; index < 4; ++index)
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
    check(evidence.summary.executed_instruction_addresses == 4 &&
              evidence.summary.static_instructions == 4 &&
              evidence.summary.executed_addresses_without_static_record == 0,
          "coverage must compare physical ARM64 PCs against a physical denominator");
    check(evidence.summary.static_analysis_truncated,
          "coverage summaries must expose a truncated static denominator");
    check(evidence.summary.ida_instruction_heads == 3 && evidence.summary.ida_macro_heads == 1 &&
              evidence.summary.ida_macro_components == 2,
          "IDA macro heads and physical components must remain separate metrics");
    check(evidence.summary.decoder_comparisons == 2 &&
              evidence.summary.decoder_disagreements == 1 &&
              evidence.summary.decoder_disagreement_flags == 1,
          "decoder reports must separate comparisons, unique sites, and flags");
    check(evidence.summary.context_identity_ranges == 1 &&
              evidence.summary.context_identity_bytes == 16,
          "contiguous ARM64 instruction dependencies must merge into one 16-byte range");
    check(evidence.summary.memory_observation_available_runs == 1 &&
              evidence.summary.context_incomplete_runs == 0,
          "evidence summary must retain memory capability and completeness");
}

void test_arm64_external_boundaries(const RaxApi *api)
{
    // mov x0,#42; mov x8,#0x2000; save LR; blr x8; restore LR; ret
    const ProgramImage image =
        arm64_image({0x40, 0x05, 0x80, 0xD2, 0x08, 0x00, 0x84, 0xD2, 0xE9, 0x03, 0x1E, 0xAA,
                     0x00, 0x01, 0x3F, 0xD6, 0xFE, 0x03, 0x09, 0xAA, 0xC0, 0x03, 0x5F, 0xD6},
                    {}, true);

    EmuEvents modeled_events;
    EmuOutcome modeled;
    check(run_direct(api, image,
                     {EmuCallSummary{0x2000, EmuSummaryKind::RETURN_ARG0, "_objc_retain"}},
                     &modeled_events, &modeled),
          "modeled Objective-C external call must run");
    check(modeled.summarized_calls == 1, "objc_retain summary must execute exactly once");
    check(modeled.returned, "objc_retain summary must resume at LR and reach the return sentinel");
    check(modeled.attempted_steps_valid && modeled.instruction_count == modeled.attempted_steps,
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
                     {EmuCallSummary{0x2000, EmuSummaryKind::UNMODELED, "_objc_msgSend"}},
                     &unknown_events, &unknown),
          "unmodeled external boundary must produce a run outcome");
    check(unknown.unmodeled_external && unknown.external_target == 0x2000 &&
              unknown.external_name == "_objc_msgSend" && !unknown.returned,
          "unmodeled external must stop cleanly with target and symbol provenance");
    check(unknown.stop_reason != RAX_STOP_COUNT &&
              unknown.instruction_count < short_run_config().max_insns &&
              unknown.attempted_steps_valid &&
              unknown.attempted_steps == unknown.instruction_count &&
              !unknown.consumed_context_complete,
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
    const ProgramImage image = arm64_image({0x00, 0x00, 0x00, 0x00});
    EmuEvents events;
    EmuOutcome outcome;
    check(run_direct(api, image, {}, &events, &outcome),
          "ARM64 undefined-instruction boundary must remain a reportable run");
    check(outcome.stop_reason != RAX_STOP_COUNT &&
              outcome.instruction_count < short_run_config().max_insns,
          "ARM64 exception handling must stop before the instruction budget");
    check(outcome.escaped_image || outcome.stop_reason == RAX_STOP_EXCEPTION,
          "ARM64 first fault must be classified as image escape or backend exception");
    check(!outcome.consumed_context_complete,
          "application exception/image escape must never be proof-complete");
    if (outcome.escaped_image)
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
    check(outcome.stop_reason == RAX_STOP_STOPPED && outcome.stop_reason != RAX_STOP_ERROR,
          "unmodeled FS access must stop through the host hook, not engine-error");
    check(outcome.external_target == image.lo &&
              outcome.external_name == "unmodeled memory or translation dependency",
          "TLS boundary must retain the faulting instruction and classification");
    check(!outcome.consumed_context_complete,
          "unmodeled TLS state must never become proof-quality evidence");
}

void test_arm64_function_boundary(const RaxApi *api)
{
    // bl 0x1010; mov x0,#7; ret; nop; callee: b callee
    ProgramImage image = arm64_image({0x04, 0x00, 0x00, 0x94, 0xE0, 0x00, 0x80, 0xD2, 0xC0, 0x03,
                                      0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0x14});
    image.entries.front().end = 0x100C;
    image.entries.front().chunks = {FuncChunk{0x1000, 0x100C}};
    image.entries.front().byte_hash = hybrid_function_byte_hash(image, image.entries.front());
    image.content_hash = hybrid_program_content_hash(image);

    EmuEvents events;
    EmuOutcome outcome;
    check(run_direct(api, image, {}, &events, &outcome),
          "ARM64 unmodeled internal call must produce a bounded run outcome");
    check(outcome.function_boundary && outcome.function_boundary_kind == ExecEdge::Kind::Call &&
              outcome.function_boundary_source == 0x1000 &&
              outcome.function_boundary_target == 0x1010 && !outcome.returned,
          "internal call must stop at the selected-function source/target boundary");
    check(outcome.stop_reason == RAX_STOP_STOPPED &&
              outcome.instruction_count < short_run_config().max_insns &&
              !outcome.consumed_context_complete,
          "function boundary must stop before recursive callee execution");
    check(events.execution.size() == 1 && events.execution.front().pc == 0x1000,
          "callee entry must not enter selected-function execution evidence");
    check(std::none_of(events.execution.begin(), events.execution.end(),
                       [](const ExecPoint &point) { return point.pc == 0x1010; }),
          "unmodeled callee body must never execute");
    check(events.edges.size() == 1 && events.edges.front().from == 0x1000 &&
              events.edges.front().to == 0x1010 &&
              events.edges.front().kind == ExecEdge::Kind::Call,
          "the boundary call target must remain available as positive edge evidence");
}

std::map<uint64_t, uint64_t> stack_store_values(const EmuEvents &events)
{
    std::map<uint64_t, uint64_t> result;
    for (const DataAcc &access : events.data)
        if (access.kind == RAX_MEM_WRITE && access.scope == DataScope::STACK)
            result[access.from] = access.value;
    return result;
}

void test_objc_entry_abi(const RaxApi *api)
{
    HybridFunctionProfile profile =
        hybrid_function_profile_from_name("-[AppDelegate valueForIndex:]");
    // str x0,[sp]; str x1,[sp,#8]; str x2,[sp,#16]; ret
    const ProgramImage image = arm64_image({0xE0, 0x03, 0x00, 0xF9, 0xE1, 0x07, 0x00, 0xF9, 0xE2,
                                            0x0B, 0x00, 0xF9, 0xC0, 0x03, 0x5F, 0xD6},
                                           profile);
    EmuEvents seeded_events;
    EmuOutcome seeded_outcome;
    check(run_direct(api, image, {}, &seeded_events, &seeded_outcome, UINT64_C(0x123456789ABCDEF0)),
          "Objective-C deterministic entry must run");
    check(seeded_outcome.synthetic_entry_context && !seeded_outcome.consumed_context_complete,
          "synthetic Objective-C hidden arguments must be marked proof-ineligible");
    const auto seeded = stack_store_values(seeded_events);
    check(seeded.size() == 3, "Objective-C entry must expose x0/x1/x2 stores");
    if (seeded.size() == 3)
    {
        check(seeded.at(0x1000) != 0 && seeded.at(0x1004) == seeded.at(0x1000) + 0x200,
              "Objective-C self and selector placeholders must be mapped and distinct");
        check(seeded.at(0x1008) != seeded.at(0x1000) && seeded.at(0x1008) != seeded.at(0x1004),
              "deterministic explicit argument must begin at x2");
    }

    EmuInput solver_input;
    solver_input.seed = 7;
    solver_input.run_id = 1;
    solver_input.positional_argument_offset = 2;
    solver_input.args = {UINT64_C(0xFEEDFACE)};
    EmuEvents replay_events;
    EmuOutcome replay_outcome;
    check(run_direct(api, image, {}, &replay_events, &replay_outcome, solver_input.seed,
                     &solver_input),
          "Objective-C explicit-argument replay must run");
    check(replay_outcome.synthetic_entry_context && !replay_outcome.consumed_context_complete,
          "source-level replay still depends on synthetic self/_cmd context");
    const auto replay = stack_store_values(replay_events);
    check(replay.size() == 3 && replay.at(0x1008) == UINT64_C(0xFEEDFACE),
          "Objective-C solver argument zero must map to physical x2");
    if (replay.size() == 3)
        check(replay.at(0x1000) != 0 && replay.at(0x1004) == replay.at(0x1000) + 0x200,
              "source-level replay must not overwrite self or _cmd");

    EmuInput callsite_input;
    callsite_input.seed = 9;
    callsite_input.run_id = 2;
    callsite_input.arg_overrides = {
        {0, UINT64_C(0x11110000)},
        {1, UINT64_C(0x22220000)},
        {2, UINT64_C(0x33330000)},
    };
    EmuEvents callsite_events;
    EmuOutcome callsite_outcome;
    check(run_direct(api, image, {}, &callsite_events, &callsite_outcome, callsite_input.seed,
                     &callsite_input),
          "Objective-C observed call-site state must run");
    check(!callsite_outcome.synthetic_entry_context && callsite_outcome.consumed_context_complete,
          "observed self and _cmd must remove the synthetic-entry assumption");
    const auto callsite = stack_store_values(callsite_events);
    check(callsite.size() == 3 && callsite.at(0x1000) == UINT64_C(0x11110000) &&
              callsite.at(0x1004) == UINT64_C(0x22220000) &&
              callsite.at(0x1008) == UINT64_C(0x33330000),
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
    check(config.timeout_ms == kHybridHardTimeoutMs, "timeout override must respect the hard cap");
    check(config.explore_runs == 32, "run corpus must respect hard cap");
    check(config.max_image_bytes == (1ull << 20), "image cap must have 1 MiB floor");
    set_environment("CHERNOBOG_RAX_MAX_INSNS", nullptr);
    set_environment("CHERNOBOG_RAX_TIMEOUT_MS", nullptr);
    set_environment("CHERNOBOG_RAX_EXPLORE_RUNS", nullptr);
    set_environment("CHERNOBOG_RAX_MAX_IMAGE_BYTES", nullptr);
}

void test_identity_comparison()
{
    const std::vector<uint8_t> expected{0xAA, 0xBB, 0xCC};
    const std::vector<uint8_t> fully_loaded{0x07};

    // IDA does not assign semantics to the five padding bits above a 3-byte
    // request. A live mask that leaves those bits set must still compare equal.
    check(
        hybrid_compare_identity_bytes(expected, fully_loaded, expected, std::vector<uint8_t>{0xFF})
            .matches(),
        "identity comparison must ignore mask padding bits");

    std::vector<uint8_t> unloaded_payload = expected;
    unloaded_payload[1] = 0x11;
    check(hybrid_compare_identity_bytes(expected, std::vector<uint8_t>{0x05}, unloaded_payload,
                                        std::vector<uint8_t>{0xFD})
              .matches(),
          "identity comparison must ignore payload at uninitialized addresses");

    const IdentityComparison loaded_state =
        hybrid_compare_identity_bytes(expected, std::vector<uint8_t>{0x05}, expected, fully_loaded);
    check(loaded_state.mismatch == IdentityMismatchKind::LOADED_STATE && loaded_state.offset == 1,
          "identity comparison must detect initialized-state changes");

    std::vector<uint8_t> changed = expected;
    changed[2] ^= 0x01;
    const IdentityComparison byte_value =
        hybrid_compare_identity_bytes(expected, fully_loaded, changed, fully_loaded);
    check(byte_value.mismatch == IdentityMismatchKind::BYTE_VALUE && byte_value.offset == 2,
          "identity comparison must detect loaded-byte changes");
}

MemoryBytes runtime_bytes(uint64_t address, const char *value, uint32_t run_id, uint64_t seed,
                          DataScope scope = DataScope::IMAGE, bool terminate = true)
{
    MemoryBytes bytes;
    bytes.addr = address;
    bytes.scope = scope;
    bytes.run_id = run_id;
    bytes.seed = seed;
    while (*value != '\0')
        bytes.bytes.push_back(uint8_t(*value++));
    if (terminate)
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

void test_temporal_heap_uses(const RaxApi *api)
{
    // Executed x86-64: allocate a seed-dependent padding block, allocate a
    // buffer, decrypt/use/erase/free, then allocate/use/erase/free at reused VA.
    // The return-address and RMW reads are real backend events, not fake hooks.
    std::vector<uint8_t> code{0x53}; // push rbx
    auto emit = [&](std::initializer_list<uint8_t> bytes)
    { code.insert(code.end(), bytes.begin(), bytes.end()); };
    auto scalar = [&](uint64_t value, size_t width)
    {
        for (size_t i = 0; i < width; ++i)
            code.push_back(uint8_t(value >> (8 * i)));
    };
    auto call = [&](uint64_t target)
    {
        const uint64_t site = 0x1000 + code.size();
        emit({0xE8});
        scalar(uint32_t(target - (site + 5)), 4);
        return site;
    };
    call(0x2000); // padding allocation: size comes from input RDI
    std::vector<uint64_t> use_sites, rmw_sites;
    const uint64_t key = UINT64_C(0x5A5A5A5A5A5A5A5A);
    for (uint64_t plaintext : {UINT64_C(0x0021746572636573),  // "secret!\0"
                               UINT64_C(0x0021646E6F636573)}) // "second!\0"
    {
        emit({0xBF, 16, 0, 0, 0});
        call(0x2000);             // malloc(16)
        emit({0x48, 0x89, 0xC3}); // mov rbx,rax
        emit({0x48, 0xBA});
        scalar(plaintext ^ key, 8);
        emit({0x48, 0x89, 0x13}); // mov [rbx],rdx
        emit({0x48, 0xBA});
        scalar(key, 8);
        rmw_sites.push_back(0x1000 + code.size());
        emit({0x48, 0x31, 0x13});          // xor qword [rbx],rdx
        emit({0x48, 0x89, 0xDF});          // mov rdi,rbx
        use_sites.push_back(call(0x2010)); // strlen
        emit({0x48, 0x89, 0xDF, 0x31, 0xF6, 0xBA, 16, 0, 0, 0});
        call(0x2030); // memset(buffer,0,16)
        emit({0x48, 0x89, 0xDF});
        call(0x2020); // free
    }
    emit({0x5B, 0xC3}); // pop rbx; ret
    ProgramImage image = arm64_image(code, {}, true);
    image.arch = HybridArch::X86_64;
    image.hi = image.segs.back().end = 0x2040;
    image.segs.back().bytes.assign(0x40, 0);
    image.segs.back().mask.assign(8, 0xFF);
    image.content_hash = hybrid_program_content_hash(image);
    const std::vector<EmuCallSummary> summaries{{0x2000, EmuSummaryKind::ALLOCATE, "malloc"},
                                                {0x2010, EmuSummaryKind::STRLEN, "strlen"},
                                                {0x2020, EmuSummaryKind::DEALLOCATE, "free"},
                                                {0x2030, EmuSummaryKind::MEMSET, "memset"}};
    EmuDriver driver(api, image, true, false, summaries);
    check(driver.can_discover(), "temporal fixture backend must initialize");
    {
        using namespace chernobog::vm;
        const NativeDecoder decoder =
            [api](uint64_t ea, const uint8_t *bytes, size_t count, rax_decoded &decoded)
        { return api->decode(RAX_ARCH_X86, RAX_MODE_64, ea, bytes, count, &decoded) == RAX_OK; };
        auto region_image = image;
        region_image.entries[0].end = 0x1001;
        region_image.entries[0].chunks = {{0x1000, 0x1001}};
        region_image.content_hash = hybrid_program_content_hash(region_image);
        EmuDriver regional(api, region_image, true, false, summaries);
        auto region = plan_native_region(region_image, api, 0x1000, 4096, decoder);
        HybridConfig cfg = short_run_config();
        cfg.max_insns = 256;
        EmuInput input;
        input.args = {16};
        input.seed = 0x93;
        input.run_id = 7;
        EmuEvents events;
        EmuOutcome outcome;
        check(
            regional.emulate_region_temporal(region, cfg, events, outcome, decoder, &input) &&
                outcome.returned && outcome.native_temporal_requested &&
                outcome.native_temporal_complete && !outcome.temporal_capture_complete &&
                !outcome.conclusive() && !outcome.consumed_context_complete &&
                !outcome.data_trace_complete && outcome.summarized_calls == 9,
            "modeled region crosses owner bounds under explicit temporal scope without proof promotion");
        check(events.allocations.size() == 3 &&
                  events.allocations[1].address == events.allocations[2].address &&
                  events.allocations[1].generation != events.allocations[2].generation,
              "modeled region retains allocation reuse generations");
        size_t observed = 0;
        for (const auto &use : events.uses)
            if (use.callee == 0x2010)
            {
                const std::string wanted = observed++ == 0 ? "secret!" : "second!";
                check(use.context == 0x1000 && use.seed == input.seed &&
                          use.run_id == input.run_id && use.bytes.size() == 8 &&
                          use.bytes.back() == 0 &&
                          std::equal(wanted.begin(), wanted.end(), use.bytes.begin()),
                      "modeled region preserves exact use bytes and selected-entry context");
            }
        check(observed == 2, "modeled region observes both erased uses");
        check(outcome.native_temporal_prefix_complete && outcome.native_temporal_prefix_end &&
                  std::all_of(events.data.begin(), events.data.end(), [&](const auto &access)
                              { return access.sequence < outcome.native_temporal_prefix_end; }),
              "sentinel return bounds the completed temporal prefix");
        const uint64_t frontier = 0x1000 + code.size() - 1;
        const NativeDecoder stop_before_ret =
            [&, frontier](uint64_t ea, const uint8_t *bytes, size_t count, rax_decoded &decoded)
        { return ea != frontier && decoder(ea, bytes, count, decoded); };
        auto prefix_region = plan_native_region(region_image, api, 0x1000, 4096, stop_before_ret);
        EmuEvents prefix_events;
        EmuOutcome prefix_outcome;
        check(
            regional.emulate_region_temporal(prefix_region, cfg, prefix_events, prefix_outcome,
                                             stop_before_ret, &input) &&
                prefix_outcome.native_temporal_prefix_complete &&
                !prefix_outcome.native_temporal_complete && !prefix_outcome.returned &&
                prefix_outcome.region_boundary && prefix_outcome.stop_pc == frontier &&
                prefix_outcome.stop_reason == RAX_STOP_STOPPED &&
                prefix_events.execution.back().pc == frontier - 1 &&
                prefix_events.execution.back().sequence < prefix_outcome.native_temporal_prefix_end,
            "completed modeled uses survive a later pre-instruction frontier without return promotion");
        for (size_t i = 0; i < prefix_events.uses.size(); ++i)
            check(i < events.uses.size() &&
                      prefix_events.uses[i].witness_key() == events.uses[i].witness_key() &&
                      prefix_events.uses[i].sequence < prefix_outcome.native_temporal_prefix_end,
                  "prefix keeps exact original use witnesses before its exclusive cutoff");
        auto truncated_config = cfg;
        truncated_config.max_runtime_bytes = 1;
        prefix_region = plan_native_region(region_image, api, 0x1000, 4096, stop_before_ret);
        prefix_events = {};
        prefix_outcome = {};
        check(regional.emulate_region_temporal(prefix_region, truncated_config, prefix_events,
                                               prefix_outcome, stop_before_ret, &input) &&
                  prefix_outcome.temporal_capture_truncated &&
                  !prefix_outcome.native_temporal_prefix_complete &&
                  prefix_outcome.native_temporal_prefix_end == 0,
              "a truncated temporal ledger cannot acquire prefix completeness");
        for (unsigned variant = 0; variant < 4; ++variant)
        {
            auto thunk_image = region_image;
            auto &text = thunk_image.segs[0];
            text.end = 0x1900;
            text.bytes.resize(0x900, 0xcc);
            text.mask.assign(0x120, 0xff);
            // First malloc call goes through one native JMP. A plain incoming JMP
            // and a two-instruction thunk are separate negative controls.
            text.bytes[1] = variant == 1 ? 0xe9 : 0xe8;
            const uint32_t call_displacement = 0x1800 - (0x1001 + 5);
            for (unsigned byte = 0; byte < 4; ++byte)
                text.bytes[2 + byte] = uint8_t(call_displacement >> (8 * byte));
            auto thunk_input = input;
            if (variant == 3)
            {
                text.bytes[1] = 0xff;
                text.bytes[2] = 0xd0; // call rax; target admitted on observation
                text.bytes[3] = text.bytes[4] = text.bytes[5] = 0x90;
                thunk_input.register_overrides.push_back({RAX_X86_REG_RAX, 0x1800});
            }
            const size_t offset = 0x800 + (variant == 2 ? 1 : 0);
            if (variant == 2)
                text.bytes[0x800] = 0x90;
            text.bytes[offset] = 0xe9;
            const uint32_t jump_displacement = uint32_t(0x2000 - (0x1000 + offset + 5));
            for (unsigned byte = 0; byte < 4; ++byte)
                text.bytes[offset + 1 + byte] = uint8_t(jump_displacement >> (8 * byte));
            thunk_image.content_hash = hybrid_program_content_hash(thunk_image);
            EmuDriver thunk_driver(api, thunk_image, true, false, summaries);
            auto thunk_region = plan_native_region(thunk_image, api, 0x1000, 4096, decoder);
            EmuEvents thunk_events;
            EmuOutcome thunk_outcome;
            check(
                thunk_driver.emulate_region_temporal(thunk_region, cfg, thunk_events, thunk_outcome,
                                                     decoder, &thunk_input) &&
                    (variant == 0 || variant == 3 ? (thunk_outcome.native_temporal_complete &&
                                                     thunk_outcome.summarized_calls == 9)
                                                  : (!thunk_outcome.native_temporal_complete &&
                                                     thunk_outcome.summarized_calls == 0 &&
                                                     thunk_outcome.unmodeled_external)),
                "one-instruction import thunk requires observed CALL and preserved return provenance");
        }
        region = plan_native_region(region_image, api, 0x1000, 4096, decoder);
        events = {};
        outcome = {};
        check(regional.emulate_region_walk(region, cfg, events, outcome, decoder, 64, &input) &&
                  !outcome.returned && !outcome.native_temporal_requested &&
                  !outcome.native_temporal_complete && !outcome.native_temporal_prefix_complete &&
                  outcome.native_temporal_prefix_end == 0 && outcome.summarized_calls == 0 &&
                  events.uses.empty(),
              "ordinary native walk cannot silently enable environment models");
        region = plan_native_region(region_image, api, 0x1000, 4096, decoder);
        events = {};
        outcome = {};
        cfg.max_insns = 8;
        check(regional.emulate_region_temporal(region, cfg, events, outcome, decoder, &input) &&
                  !outcome.returned && !outcome.native_temporal_complete &&
                  !outcome.native_temporal_prefix_complete &&
                  outcome.native_temporal_prefix_end == 0,
              "modeled region instruction exhaustion cannot become complete temporal evidence");
        input.native_objects.push_back({0, 0, {0}});
        events = {};
        outcome = {};
        check(!regional.emulate_region_temporal(region, cfg, events, outcome, decoder, &input) &&
                  events.execution.empty() && !outcome.native_temporal_complete,
              "modeled region rejects caller scratch objects overlapping its heap contract");
    }
    TargetEvidence evidence;
    evidence.scope.function_start = 0x1000;
    evidence.model_contract = summaries;
    std::vector<uint64_t> addresses;
    for (uint32_t run_id = 0; run_id < 3; ++run_id)
    {
        EmuInput input;
        input.run_id = run_id;
        input.seed = 0x93 + run_id;
        input.args = {uint64_t(16u << run_id)};
        HybridConfig cfg = short_run_config();
        cfg.max_insns = 256;
        EmuEvents events;
        RunObservation run;
        run.ran = driver.emulate_from(0x1000, image.entries[0].end, cfg, events, &run.outcome, true,
                                      input.seed, run_id, &input);
        run.provenance.run_id = run_id;
        run.provenance.seed = input.seed;
        check(run.ran && run.outcome.returned && run.outcome.temporal_capture_complete &&
                  run.outcome.external_model_used && !run.outcome.consumed_context_complete,
              "modeled temporal fixture must complete without acquiring universal-proof status");
        check(events.allocations.size() == 3, "all allocations must retain their lifetimes");
        if (events.allocations.size() == 3)
        {
            const auto &first = events.allocations[1];
            const auto &second = events.allocations[2];
            addresses.push_back(first.address);
            check(first.address == second.address && first.id != second.id &&
                      first.generation == 1 && second.generation == 2 && !first.live &&
                      !second.live && first.released < second.allocated,
                  "freed storage must be reused with distinct ordered allocation generations");
            bool erased = false;
            for (const auto &written : events.final_writes)
                if (written.addr == first.address && written.bytes.size() >= 8)
                    erased = std::all_of(written.bytes.begin(), written.bytes.begin() + 8,
                                         [](uint8_t byte) { return byte == 0; });
            check(erased, "the final heap bytes must be erased despite retained use values");
        }
        size_t modeled = 0, rmw = 0;
        for (const auto &use : events.uses)
        {
            if (use.callee == 0x2010)
            {
                ++modeled;
                check(use.status == UseCaptureStatus::EXACT && use.bytes.size() == 8 &&
                          use.producer == UseProducer::MODELED_ARGUMENT && use.argument == 0 &&
                          use.model_kind == uint8_t(EmuSummaryKind::STRLEN),
                      "strlen must capture the exact consumed NUL-terminated argument");
            }
            const auto found = std::find(rmw_sites.begin(), rmw_sites.end(), use.site);
            if (found != rmw_sites.end())
            {
                ++rmw;
                const uint64_t plain = found == rmw_sites.begin() ? UINT64_C(0x0021746572636573)
                                                                  : UINT64_C(0x0021646E6F636573);
                uint64_t observed = 0;
                for (size_t i = 0; i < use.bytes.size() && i < 8; ++i)
                    observed |= uint64_t(use.bytes[i]) << (8 * i);
                check(
                    use.producer == UseProducer::EXECUTED_READ && observed == (plain ^ key),
                    "RMW read snapshots must retain pre-write ciphertext, not post-write plaintext");
            }
        }
        check(modeled == 2 && rmw == 2,
              "fixture must observe both modeled uses and executed RMW reads");
        evidence.runs.push_back(run);
        evidence.events.merge_from(events);
    }
    check(addresses.size() == 3 && addresses[0] != addresses[1] && addresses[1] != addresses[2],
          "padding inputs must change actual heap addresses across runs");
    evidence.events.normalize();
    check(std::is_sorted(evidence.events.uses.begin(), evidence.events.uses.end(),
                         [](const auto &left, const auto &right)
                         {
                             return std::tie(left.run_id, left.seed, left.sequence) <
                                    std::tie(right.run_id, right.seed, right.sequence);
                         }),
          "normalized snapshots must retain per-run chronological order");
    const auto candidates = hybrid_consensus_use_strings(evidence);
    check(candidates.size() == 2, "both erased heap strings must survive semantic-use consensus");
    for (size_t i = 0; i < candidates.size() && i < 2; ++i)
        check(candidates[i].value == (i == 0 ? "secret!" : "second!") &&
                  candidates[i].use.site == use_sites[i] && candidates[i].witnesses.size() == 3 &&
                  candidates[i].eligible_runs == 3,
              "use consensus must preserve site, plaintext and all address-independent witnesses");
    check(hybrid_consensus_runtime_strings(evidence).empty(),
          "temporal heap values must not become final image literals");

    const size_t before = evidence.events.uses.size();
    evidence.events.merge_from(evidence.events);
    evidence.events.normalize();
    check(evidence.events.uses.size() == before &&
              hybrid_consensus_use_strings(evidence).size() == 2,
          "normalization must remove exact duplicates without losing use order or generations");
    auto missing = evidence;
    missing.runs[2].outcome.temporal_observation_available = false;
    check(hybrid_consensus_use_strings(missing).empty(),
          "an unavailable run must not disappear from the corpus");

    HybridConfig limited = short_run_config();
    limited.max_insns = 256;
    limited.max_runtime_bytes = 1;
    EmuInput input;
    input.args = {16};
    EmuEvents events;
    EmuOutcome outcome;
    check(driver.emulate_from(0x1000, image.entries[0].end, limited, events, &outcome, true, 0, 0,
                              &input) &&
              outcome.returned && outcome.temporal_capture_truncated &&
              !outcome.temporal_capture_complete,
          "capture byte exhaustion must leave execution intact and report incomplete evidence");
    size_t retained = 0;
    for (const auto &use : events.uses)
        retained += use.bytes.size();
    check(retained <= 1, "the temporal byte cap must be independent of the final-write cap");

    // An invalid modeled operation must stop before a fabricated return, even
    // when runtime-string recording is disabled. Reuse the final freed pointer.
    code.resize(code.size() - 2);
    const size_t prefix_size = code.size();
    for (uint64_t target : {uint64_t(0x2010), uint64_t(0x2020)})
    {
        code.resize(prefix_size);
        call(target);
        emit({0x5B, 0xC3});
        auto invalid_image = image;
        invalid_image.segs[0].bytes = code;
        invalid_image.segs[0].end = 0x1000 + code.size();
        invalid_image.segs[0].mask.assign((code.size() + 7) / 8, 0xFF);
        invalid_image.entries[0].end = invalid_image.segs[0].end;
        invalid_image.entries[0].chunks[0].end = invalid_image.segs[0].end;
        EmuDriver invalid_driver(api, invalid_image, true, false, summaries);
        auto cfg = limited;
        cfg.want_runtime_strings = false;
        EmuEvents invalid_events;
        EmuOutcome invalid_outcome;
        check(
            invalid_driver.emulate_from(0x1000, invalid_image.entries[0].end, cfg, invalid_events,
                                        &invalid_outcome, true, 0, 0, &input) &&
                invalid_outcome.environment_model_failure && !invalid_outcome.returned &&
                !invalid_outcome.temporal_capture_complete && invalid_events.uses.empty(),
            "use-after-free and double-free summaries must stop independently of capture settings");
    }
    const std::vector<uint8_t> overlap_bytes{'s', 'e', 'c', 'r', 'e', 't', '!', 0, 'X'};
    const auto overlap_image =
        byte_search_image(HybridArch::X86_64, overlap_bytes,
                          uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::WRITE));
    EmuDriver overlap_driver(api, overlap_image, true, false,
                             {{0x2000, EmuSummaryKind::MEMMOVE, "memmove"}});
    EmuInput overlap_input;
    overlap_input.args = {0x3001, 0x3000, 8};
    EmuEvents overlap_events;
    EmuOutcome overlap_outcome;
    check(overlap_driver.emulate_from(0x1000, overlap_image.entries[0].end, short_run_config(),
                                      overlap_events, &overlap_outcome, true, 0, 0,
                                      &overlap_input) &&
              overlap_outcome.returned && overlap_outcome.temporal_capture_complete,
          "overlapping modeled copy must execute with complete temporal evidence");
    const auto source_use = std::find_if(overlap_events.uses.begin(), overlap_events.uses.end(),
                                         [](const auto &use) { return use.callee == 0x2000; });
    const auto destination_write =
        std::find_if(overlap_events.data.begin(), overlap_events.data.end(), [](const auto &access)
                     { return access.kind == RAX_MEM_WRITE && access.addr == 0x3001; });
    check(source_use != overlap_events.uses.end() &&
              destination_write != overlap_events.data.end() && source_use->argument == 1 &&
              source_use->sequence < destination_write->sequence &&
              source_use->bytes ==
                  std::vector<uint8_t>(overlap_bytes.begin(), overlap_bytes.begin() + 8),
          "copy-source use must retain pre-overlap bytes and precede the destination write");
}

void test_runtime_string_consensus()
{
    TargetEvidence evidence;
    add_memory_run(&evidence, 0, 0x10);
    add_memory_run(&evidence, 1, 0x20);
    add_memory_run(&evidence, 2, 0x30, false);
    evidence.events.final_writes.push_back(runtime_bytes(0x4000, "frida-server", 0, 0x10));
    evidence.events.final_writes.push_back(runtime_bytes(0x4000, "frida-server", 1, 0x20));
    evidence.events.final_writes.push_back(runtime_bytes(0x5000, "only-one-run", 0, 0x10));
    evidence.events.final_writes.push_back(
        runtime_bytes(0x6000, "unterminated", 0, 0x10, DataScope::IMAGE, false));
    evidence.events.final_writes.push_back(
        runtime_bytes(0x6000, "unterminated", 1, 0x20, DataScope::IMAGE, false));
    evidence.events.final_writes.push_back(
        runtime_bytes(0x7000, "stack-only", 0, 0x10, DataScope::STACK));
    evidence.events.final_writes.push_back(
        runtime_bytes(0x7000, "stack-only", 1, 0x20, DataScope::STACK));

    const std::vector<RuntimeStringCandidate> candidates =
        hybrid_consensus_runtime_strings(evidence);
    check(candidates.size() == 1,
          "runtime strings must require identical terminated image bytes in every observable run");
    if (candidates.size() == 1)
    {
        check(candidates[0].address == 0x4000 && candidates[0].value == "frida-server" &&
                  candidates[0].observations == 2 && candidates[0].eligible_runs == 2 &&
                  candidates[0].runs == std::vector<uint32_t>({0, 1}),
              "runtime string consensus must retain address, value, and run provenance");
    }

    TargetEvidence conflict = evidence;
    conflict.events.final_writes.back() = runtime_bytes(0x4000, "different", 1, 0x20);
    conflict.events.final_writes.push_back(runtime_bytes(0x4000, "different", 1, 0x20));
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
                            rax_analysis *summary, rax_analysis_effect *effects, size_t capacity,
                            size_t *required)
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
    const auto truncated =
        hybrid_analyze_instruction_effects(&api, image, segment.start + 1, RAX_MODE_64, 16);
    check(truncated.valid() && smir_input_calls == 2,
          "truncated backing storage must bound both SMIR calls");
    segment.mask[0] = 3;
    expected_smir_size = 1;
    const auto hole =
        hybrid_analyze_instruction_effects(&api, image, segment.start + 1, RAX_MODE_64, 16);
    check(hole.valid(), "SMIR input must stop at the first unloaded byte");
    const size_t calls = smir_input_calls;
    segment.bytes.clear();
    const auto empty =
        hybrid_analyze_instruction_effects(&api, image, segment.start, RAX_MODE_64, 16);
    check(empty.status == SmirStatus::UNMAPPED && smir_input_calls == calls,
          "empty backing storage must not reach the SMIR backend");
    segment.bytes.assign(32, 0x90);
    segment.mask.assign(4, 255);
    expected_smir_bytes = segment.bytes.data();
    expected_smir_size = 16;
    check(hybrid_analyze_instruction_effects(&api, image, segment.start, RAX_MODE_64, 32).valid(),
          "SMIR must cap even larger offered windows at 16 bytes");
    expected_smir_size = 3;
    check(hybrid_analyze_instruction_effects(&api, image, segment.start, RAX_MODE_64, 3).valid(),
          "SMIR must retain the caller's narrower chunk bound");
}

void test_decoder_and_smir(const RaxApi *api, const ProgramImage &image)
{
    const SegImage &segment = image.segs.front();
    const uint64_t branch = image.lo + 2;
    const uint8_t *bytes = segment.bytes.data() + 2;
    const DecoderDecodeResult decoded =
        hybrid_decode_one(api->decode, RAX_ARCH_X86, RAX_MODE_64, branch, bytes, 11);
    check(decoded.status == DecoderDecodeStatus::Valid, "rax must decode x86 conditional");
    check(decoded.instruction.flow == RAX_FLOW_COND_BRANCH,
          "conditional decode flow classification");
    check(decoded.instruction.target == image.lo + 10, "conditional decode direct target");
    check(decoded.instruction.fallthrough == image.lo + 4, "conditional decode fallthrough");

    DecoderInstruction ida = decoded.instruction;
    DecoderComparison same = hybrid_compare_decoders(ida, decoded.instruction);
    check(same.comparable && !same.size_disagreement && !same.flow_disagreement &&
              !same.target_disagreement && !same.fallthrough_disagreement,
          "identical decoder projections must compare equal");
    ida.fallthrough++;
    check(hybrid_compare_decoders(ida, decoded.instruction).fallthrough_disagreement,
          "fallthrough disagreement must be visible");

    const SmirInstructionAnalysis smir =
        hybrid_analyze_instruction_effects(api, image, image.lo + 10, RAX_MODE_64, 3);
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
    function.chunks = {FuncChunk{function.start, function.end}};
    function.byte_hash = hybrid_function_byte_hash(image, function);
    image.content_hash = hybrid_program_content_hash(image);

    auto immutable = std::make_shared<const ProgramImage>(std::move(image));
    RaxWorkerOptions options;
    options.api = api;
    options.image = immutable;
    options.strict_perms = true;
    EmulationWorkerPool pool(1, hybrid_make_rax_worker_factory(std::move(options)), 1);
    check(pool.wait_for_initialization(std::chrono::seconds(2)),
          "cancellation worker must initialize");

    EmulationJob job;
    job.function = immutable->entries.front();
    job.config = HybridConfig{};
    job.config.max_insns = kHybridHardMaxInstructions;
    job.config.timeout_ms = kHybridHardTimeoutMs;
    job.runs.push_back(EmulationRunRequest{});
    check(pool.try_submit(std::move(job)), "loop job submission");
    for (size_t attempt = 0; attempt < 100000 && pool.stats().running == 0; ++attempt)
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
    if (!result.runs.empty())
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

    EmulationWorkerPool pool(1, hybrid_make_rax_worker_factory(std::move(options)), 1);
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
    check(result.runs[0].outcome.consumed_context_complete &&
              result.runs[1].outcome.consumed_context_complete,
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
    branch.rax = hybrid_decode_one(api->decode, RAX_ARCH_X86, RAX_MODE_64, branch.address,
                                   immutable->segs.front().bytes.data() + 2, 11);
    branch.comparison = hybrid_compare_decoders(branch.ida, branch.rax.instruction);
    static_result.instructions.push_back(branch);

    std::vector<ConcreteInput> inputs;
    for (const EmulationRunRequest &request : job.runs)
    {
        ConcreteInput input;
        input.origin = InputOrigin::Z3_MODEL;
        input.input = request.input;
        input.label = "test model";
        inputs.push_back(std::move(input));
    }
    const TargetEvidence evidence = hybrid_build_target_evidence(
        *immutable, immutable->entries.front(), immutable->lo + 2, static_result, inputs, result);
    check(evidence.summary.completed_runs == 2, "evidence must retain run provenance");
    check(evidence.branches.size() == 2, "two conditional outcomes must be reconstructed");
    const BranchClaimCheck always_taken = evidence.check_branch_claim(immutable->lo + 2, true);
    const BranchClaimCheck always_fallthrough =
        evidence.check_branch_claim(immutable->lo + 2, false);
    check(always_taken.verdict == BranchClaimVerdict::MIXED &&
              always_taken.falsifies_universal_claim(),
          "fallthrough run must falsify always-taken claim");
    check(always_fallthrough.verdict == BranchClaimVerdict::MIXED &&
              always_fallthrough.falsifies_universal_claim(),
          "taken run must falsify always-fallthrough claim");
    TargetEvidence incomplete_evidence = evidence;
    for (BranchObservation &observation : incomplete_evidence.branches)
        observation.consumed_context_complete = false;
    const BranchClaimCheck incomplete_claim =
        incomplete_evidence.check_branch_claim(immutable->lo + 2, true);
    check(incomplete_claim.verdict == BranchClaimVerdict::MIXED &&
              !incomplete_claim.falsifies_universal_claim() &&
              incomplete_claim.opposing_context_complete == 0,
          "context-incomplete observations must never veto a universal claim");
    check(evidence.function_identity.size() == 1,
          "evidence must retain exact current-function bytes");
    check(!evidence.context_identity.empty() && evidence.summary.context_identity_bytes != 0,
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
    if (api != nullptr)
    {
        ProgramImage image = branch_image();
        check(image.function_at(image.lo + 12) != nullptr, "complete function chunk membership");
        test_decoder_and_smir(api, image);
        test_inflight_cancellation(api);
        test_worker_and_evidence(api, std::move(image));
        test_x86_tls_environment_boundary(api);
        test_arm64_memory_and_accounting(api);
        test_data_trace_completeness(api);
        test_arm64_external_boundaries(api);
        test_bounded_byte_search_summaries(api);
        test_byte_search_scope_transitions(api);
        test_arm64_application_boundary(api);
        test_arm64_function_boundary(api);
        test_objc_entry_abi(api);
        test_temporal_heap_uses(api);
        test_native_regions(api);
    }
    if (failures != 0)
    {
        std::cerr << failures << " hybrid test(s) failed\n";
        return 1;
    }
    std::cout << "hybrid tests passed\n";
    return 0;
}
