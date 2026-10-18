// Cross-project regression corpus shared with Assist function_analysis_rax_tests.cpp.
#include <hybrid/emu_driver.hpp>
#include <hybrid/evidence.hpp>
#include <hybrid/decoder_core.hpp>
#include <set>
#include <hybrid/rax_loader.hpp>
#include <cstdlib>
#include <algorithm>
#include <initializer_list>
#include <iostream>
using namespace chernobog::hybrid;
struct LinkedRax
{
    bool available;
    RaxApi api;
};
void check(bool value, const char *message)
{
    if (!value)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}
void immediate(std::vector<std::uint8_t> &bytes, std::uint64_t value)
{
    for (unsigned shift = 0; shift != 64; shift += 8)
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

// Minimal x86 emitter for position-dependent test functions at a fixed base.
struct Code
{
    std::uint64_t base = 0x1000;
    std::vector<std::uint8_t> bytes;
    [[nodiscard]] std::uint64_t here() const { return base + bytes.size(); }
    void raw(std::initializer_list<std::uint8_t> values) { bytes.insert(bytes.end(), values); }
    void imm32(std::uint32_t value)
    {
        for (unsigned shift = 0; shift != 32; shift += 8)
            bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void imm64(std::uint64_t value) { immediate(bytes, value); }
    void call(std::uint64_t target)
    {
        bytes.push_back(0xe8);
        imm32(static_cast<std::uint32_t>(target - (here() + 4)));
    }
};

ProgramImage function_image(HybridArch arch, const Code &code, std::uint64_t function_end,
                            std::initializer_list<std::uint64_t> returns = {})
{
    ProgramImage image;
    image.arch = arch;
    image.lo = 0x1000;
    image.hi = 0x4000;
    SegImage text;
    text.start = 0x1000;
    text.end = 0x2000;
    text.perm = 5;
    text.bitness = arch == HybridArch::X86_64 ? 2 : 1;
    text.bytes.assign(4096, 0xcc);
    text.mask.assign(512, 255);
    std::copy(code.bytes.begin(), code.bytes.end(), text.bytes.begin());
    for (const auto address : returns)
        text.bytes[address - text.start] = 0xc3;
    SegImage data = text;
    data.start = 0x3000;
    data.end = 0x4000;
    data.perm = 6;
    std::fill(data.bytes.begin(), data.bytes.end(), 0);
    image.segs = {text, data};
    FuncRange function;
    function.start = code.base;
    function.end = function_end;
    function.chunks = {{function.start, function.end}};
    image.entries = {function};
    image.content_hash = hybrid_program_content_hash(image);
    return image;
}

struct Corpus
{
    TargetEvidence evidence;
    std::vector<EmuOutcome> outcomes;
};

// The same four-run corpus shape Assist schedules for automatic analysis.
Corpus run_corpus(const LinkedRax &linked, const ProgramImage &image,
                  const std::vector<EmuCallSummary> &summaries = {})
{
    Corpus corpus;
    const auto &function = image.entries.front();
    EmuDriver driver(&linked.api, image, true, false, summaries);
    check(driver.can_discover(), "test corpus driver can discover");
    HybridConfig config;
    config.max_insns = 200000;
    config.timeout_ms = 1000;
    config.max_runtime_bytes = 1u << 20;
    EmulationJobResult job;
    job.function_start = function.start;
    std::vector<ConcreteInput> inputs;
    for (std::uint32_t id = 0; id != 4; ++id)
    {
        EmulationRunResult run;
        run.run_id = id;
        run.seed = id * UINT64_C(0x9E3779B97F4A7C15) + 1;
        run.ran = driver.emulate_from(function.start, function.end, config, run.events,
                                      &run.outcome, true, run.seed, id);
        check(run.ran, "corpus run executed");
        corpus.outcomes.push_back(run.outcome);
        job.merged.merge_from(run.events);
        job.runs.push_back(std::move(run));
        ConcreteInput input;
        input.input.run_id = id;
        input.input.seed = job.runs.back().seed;
        inputs.push_back(input);
    }
    job.merged.normalize();
    corpus.evidence =
        hybrid_build_target_evidence(image, function, function.start, {}, inputs, job, summaries);
    return corpus;
}
// Explicit machine-code sentinels distinguish pre-instruction stops from
// observing a callee after it has already changed memory.
void prefix_architecture_regressions(const LinkedRax &linked)
{
    for (const auto arch : {HybridArch::X86_32, HybridArch::X86_64, HybridArch::ARM64})
    {
        constexpr std::uint64_t callee = 0x1800;
        Code code;
        if (arch == HybridArch::ARM64)
        {
            code.imm32(0xd2860000); // mov x0, #0x3000
            code.imm32(0x940001ff); // bl 0x1800 from 0x1004
            code.imm32(0xd65f03c0); // ret
        }
        else if (arch == HybridArch::X86_32)
        {
            code.raw({0x68});
            code.imm32(0x3000); // push text
            code.call(callee);
            code.raw({0x83, 0xc4, 0x04, 0xc3});
        }
        else
        {
            code.raw({0x48, 0xbf});
            code.imm64(0x3000); // mov rdi, text
            code.call(callee);
            code.raw({0xc3});
        }
        auto image = function_image(arch, code, code.here(), {callee});
        if (arch == HybridArch::ARM64)
            image.segs.front().bitness = 2;
        const std::string text = "archtext";
        std::copy(text.begin(), text.end(), image.segs[1].bytes.begin());
        const std::vector<std::uint8_t> sentinel =
            arch == HybridArch::ARM64
                ? std::vector<std::uint8_t>{0x1f, 0x00, 0x00, 0x39, 0xc0, 0x03, 0x5f, 0xd6}
            : arch == HybridArch::X86_32
                ? std::vector<std::uint8_t>{0xc6, 0x05, 0x00, 0x30, 0x00, 0x00, 0, 0xc3}
                : std::vector<std::uint8_t>{0xc6, 0x07, 0, 0xc3};
        std::copy(sentinel.begin(), sentinel.end(), image.segs[0].bytes.begin() + 0x800);
        const auto corpus = run_corpus(linked, image);
        for (const auto &run : corpus.evidence.runs)
        {
            check(run.outcome.temporal_prefix_complete && run.outcome.stop_pc == callee &&
                      !run.outcome.returned && !run.outcome.consumed_context_complete,
                  "architecture call stop retains only a prefix observation");
        }
        check(std::none_of(corpus.evidence.events.execution.begin(),
                           corpus.evidence.events.execution.end(),
                           [=](const auto &point) { return point.pc == callee; }) &&
                  std::none_of(corpus.evidence.events.data.begin(),
                               corpus.evidence.events.data.end(),
                               [=](const auto &event) { return event.from == callee; }),
              "callee sentinel has no execution or memory event before the call stop");
        const auto uses = hybrid_consensus_use_strings(corpus.evidence, 4, 4096, true);
        check(uses.size() == 1 && uses.front().value == text && uses.front().use.argument == 0 &&
                  uses.front().prefix_runs == 4 &&
                  hybrid_consensus_use_strings(corpus.evidence).empty(),
              "integer register or stack argument is available only to prefix inspection");
        // Execute the exact sentinel independently to prove it is observable.
        auto control = image;
        control.entries.front().start = callee;
        control.entries.front().end = callee + sentinel.size();
        control.entries.front().chunks = {{callee, callee + sentinel.size()}};
        EmuInput input;
        input.arg_overrides.push_back({0, 0x3000});
        HybridConfig config;
        config.max_insns = 100;
        EmuEvents events;
        EmuOutcome outcome;
        EmuDriver driver(&linked.api, control, true, false);
        check(driver.emulate_from(callee, control.entries.front().end, config, events, &outcome,
                                  true, 0, 0, &input),
              "sentinel control executes");
        check(std::any_of(events.data.begin(), events.data.end(),
                          [=](const auto &event)
                          {
                              return event.from == callee && event.kind == RAX_MEM_WRITE &&
                                     event.addr == 0x3000;
                          }),
              "callee sentinel writes in the independent control");
    }
}

int main()
{
    const auto *api = rax_load();
    const LinkedRax linked{api != nullptr, api ? *api : RaxApi{}};
    check(linked.available, "linked RAX ABI available");
    check(linked.api.decode == &rax_decode && linked.api.analyze == &rax_analyze,
          "shared decoder/SMIR entry points");
    prefix_architecture_regressions(linked);
    ProgramImage image;
    image.arch = HybridArch::X86_64;
    image.lo = 0x1000;
    image.hi = 0x4000;
    SegImage code;
    code.start = 0x1000;
    code.end = 0x2000;
    code.perm = 5;
    code.bitness = 2;
    code.bytes.assign(4096, 0);
    code.mask.assign(512, 255);
    SegImage data = code;
    data.start = 0x3000;
    data.end = 0x4000;
    data.perm = 6;
    std::vector<std::uint8_t> instructions{0x48, 0xbf}; // movabs rdi, data
    immediate(instructions, data.start);
    instructions.insert(instructions.end(),
                        {0x48, 0x8b, 0x07, 0x48, 0xb8});   // read initial data; movabs rax,string
    immediate(instructions, UINT64_C(0x7478657474736574)); // "testtext"
    instructions.insert(instructions.end(), {0x48, 0x89, 0x07, 0xc6, 0x47, 0x08, 0, 0xc3});
    std::copy(instructions.begin(), instructions.end(), code.bytes.begin());
    image.segs = {code, data};
    FuncRange function;
    function.start = code.start;
    function.end = code.start + instructions.size();
    function.chunks = {{function.start, function.end}};
    image.entries = {function};
    image.content_hash = hybrid_program_content_hash(image);
    EmuDriver driver(&linked.api, image, true, false);
    check(driver.can_discover(), "x86-64 stepping and baseline context supported");
    HybridConfig config;
    config.max_insns = 200000;
    config.timeout_ms = 1000;
    config.max_runtime_bytes = 1u << 20;
    EmulationJobResult job;
    job.function_start = function.start;
    std::vector<ConcreteInput> inputs;
    for (std::uint32_t id = 0; id != 4; ++id)
    {
        EmulationRunResult run;
        run.run_id = id;
        run.seed = id * UINT64_C(0x9E3779B97F4A7C15);
        run.ran = driver.emulate_from(function.start, function.end, config, run.events,
                                      &run.outcome, true, run.seed, id);
        check(run.ran && run.outcome.returned, "each deterministic run returns");
        bool read_initial_zero = false;
        for (const auto &access : run.events.data)
            if (access.kind == RAX_MEM_READ && access.addr == data.start)
                read_initial_zero |= access.value == 0;
        check(read_initial_zero, "baseline restore resets prior run stores before next input");
        check(!run.events.final_writes.empty(), "runtime byte writes captured");
        job.merged.merge_from(run.events);
        job.runs.push_back(std::move(run));
        ConcreteInput input;
        input.input.run_id = id;
        input.input.seed = job.runs.back().seed;
        inputs.push_back(input);
    }
    job.merged.normalize();
    const auto evidence =
        hybrid_build_target_evidence(image, function, function.start, {}, inputs, job);
    const auto strings = hybrid_consensus_runtime_strings(evidence);
    check(strings.size() == 1 && strings.front().value == "testtext",
          "cross-run runtime string consensus");
    check(image.segs[1].bytes == data.bytes, "guest stores never mutate captured IDB bytes");
    ProgramImage branch_image = image;
    auto &branch_bytes = branch_image.segs[0].bytes;
    std::fill(branch_bytes.begin(), branch_bytes.end(), 0);
    std::vector<std::uint8_t> branch_code{0x48, 0xb8}; // mov rax, target A
    immediate(branch_code, 0x1100);
    branch_code.insert(branch_code.end(), {0x48, 0x85, 0xff, 0x75, 0x0a, 0x48, 0xb8});
    immediate(branch_code, 0x1120);                      // zero input takes this target B
    branch_code.insert(branch_code.end(), {0xff, 0xe0}); // same indirect jump for both inputs
    std::copy(branch_code.begin(), branch_code.end(), branch_bytes.begin());
    branch_bytes[0x100] = 0xc3;
    branch_bytes[0x120] = 0xc3;
    branch_image.entries.front().end = 0x1140;
    branch_image.entries.front().chunks = {{0x1000, 0x1140}};
    EmuDriver branches(&linked.api, branch_image, true, false);
    std::set<std::uint64_t> targets;
    bool executed_fallthrough[2]{};
    for (unsigned index = 0; index != 2; ++index)
    {
        EmuInput input;
        input.args = {index};
        EmuEvents events;
        EmuOutcome outcome;
        check(branches.emulate_from(0x1000, 0x1140, config, events, &outcome, true, index, index,
                                    &input),
              "explicit-input branch execution");
        check(outcome.returned, "both input paths return");
        for (const auto &edge : events.edges)
            if (edge.from == 0x1019)
                targets.insert(edge.to);
        for (const auto &point : events.execution)
            executed_fallthrough[index] |= point.pc == 0x100f;
    }
    check(targets == std::set<std::uint64_t>{0x1100, 0x1120},
          "one indirect site retains different input-specific targets");
    check(executed_fallthrough[0] && !executed_fallthrough[1],
          "taken and fallthrough paths retain distinct execution evidence");
    ProgramImage looping = branch_image;
    looping.segs[0].bytes[0] = 0xeb;
    looping.segs[0].bytes[1] = 0xfe;
    EmuDriver loop(&linked.api, looping, true, false);
    EmuEvents limited;
    EmuOutcome limit;
    config.max_insns = 10;
    check(loop.emulate_from(0x1000, 0x1140, config, limited, &limit),
          "bounded looping execution ran");
    check(!limit.returned && !limit.conclusive(),
          "instruction-budget exhaustion cannot establish non-return");
    const std::uint8_t jump[] = {0xeb, 0x02};
    const auto decoded =
        hybrid_decode_one(linked.api.decode, RAX_ARCH_X86, RAX_MODE_64, 0x1000, jump, 2);
    check(decoded.status == DecoderDecodeStatus::Valid, "shared stateless decoder runs");
    auto other = decoded.instruction;
    other.size += 1;
    other.target += 1;
    const auto disagreement = hybrid_compare_decoders(decoded.instruction, other);
    check(disagreement.size_disagreement && disagreement.target_disagreement,
          "decoder disagreement preserves size and target distinctions");

    // Use-time heap strings: decrypted into a modeled allocation, consumed by
    // a modeled strlen, then erased and freed before return. Final memory has
    // no plaintext; the use snapshot retains the bytes the call consumed.
    {
        constexpr std::uint64_t malloc_stub = 0x1800, strlen_stub = 0x1810, memset_stub = 0x1820,
                                free_stub = 0x1830;
        Code code;
        code.raw({0xbf});
        code.imm32(32); // mov edi, 32
        code.call(malloc_stub);
        code.raw({0x48, 0x89, 0xc3}); // mov rbx, rax
        const std::uint64_t key = UINT64_C(0x5a5a5a5a5a5a5a5a);
        code.raw({0x48, 0xb8});
        code.imm64(UINT64_C(0x77202c6f6c6c6548) ^ key); // "Hello, w"
        code.raw({0x48, 0xba});
        code.imm64(key);
        code.raw({0x48, 0x31, 0xd0, 0x48, 0x89, 0x03}); // xor rax, rdx; mov [rbx], rax
        code.raw({0x48, 0xb8});
        code.imm64(UINT64_C(0x00000021646c726f) ^ key);       // "orld!"
        code.raw({0x48, 0x31, 0xd0, 0x48, 0x89, 0x43, 0x08}); // xor rax, rdx; mov [rbx+8], rax
        code.raw({0x48, 0x89, 0xdf});                         // mov rdi, rbx
        const auto strlen_site = code.here();
        code.call(strlen_stub);
        code.raw({0x48, 0x89, 0xdf, 0x31, 0xf6, 0xba});
        code.imm32(16); // memset(rbx, 0, 16)
        code.call(memset_stub);
        code.raw({0x48, 0x89, 0xdf});
        code.call(free_stub);
        code.raw({0xc3});
        const auto image = function_image(HybridArch::X86_64, code, code.here());
        const std::vector<EmuCallSummary> summaries = {
            {malloc_stub, EmuSummaryKind::ALLOCATE, "malloc"},
            {strlen_stub, EmuSummaryKind::STRLEN, "strlen"},
            {memset_stub, EmuSummaryKind::MEMSET, "memset"},
            {free_stub, EmuSummaryKind::DEALLOCATE, "free"}};
        const auto corpus = run_corpus(linked, image, summaries);
        for (const auto &outcome : corpus.outcomes)
            check(outcome.returned && outcome.temporal_capture_complete &&
                      outcome.temporal_prefix_complete,
                  "modeled heap lifetime runs return with a complete temporal ledger");
        const auto uses = hybrid_consensus_use_strings(corpus.evidence);
        check(uses.size() == 1 && uses.front().value == "Hello, world!",
              "erased heap plaintext survives as a use snapshot");
        const auto &use = uses.front().use;
        check(use.producer == UseProducer::MODELED_ARGUMENT && use.site == strlen_site &&
                  use.callee == strlen_stub && use.argument == 0 && use.scope == DataScope::HEAP &&
                  use.object_callee == malloc_stub && use.offset == 0 && use.object_size == 32,
              "use identity retains the consuming call, argument and allocation origin");
        check(uses.front().eligible_runs == 4 && uses.front().witnesses.size() == 4 &&
                  uses.front().prefix_runs == 0,
              "every scheduled run agrees on the use");
        bool freed = false;
        for (const auto &allocation : corpus.evidence.events.allocations)
            freed |= allocation.callee == malloc_stub && !allocation.live &&
                     allocation.released > use.sequence;
        check(freed, "allocation lifetime records the release after the use");
        check(hybrid_consensus_runtime_strings(corpus.evidence).empty(),
              "final-memory strings cannot see the erased plaintext");
    }

    // Call-prefix boundary text: a stack string passed to an unmodeled callee.
    // The run stops before the callee executes; upstream function publication
    // needs a return, so only explicit inspection-prefix admission publishes it.
    {
        constexpr std::uint64_t callee = 0x1800;
        Code code;
        code.raw({0x48, 0x83, 0xec, 0x28}); // sub rsp, 0x28
        code.raw({0x48, 0xb8});
        code.imm64(UINT64_C(0x67736d6b63617473)); // "stackmsg"
        code.raw({0x48, 0x89, 0x04, 0x24});       // mov [rsp], rax
        code.raw({0xc6, 0x44, 0x24, 0x08, 0x00}); // mov byte [rsp+8], 0
        code.raw({0x48, 0x89, 0xe7});             // mov rdi, rsp
        code.raw({0xbe});
        code.imm32(0x3000); // mov esi, data (all zero: no text)
        const auto site = code.here();
        code.call(callee);
        code.raw({0x48, 0x83, 0xc4, 0x28, 0xc3});
        const auto image = function_image(HybridArch::X86_64, code, code.here(), {callee});
        const auto corpus = run_corpus(linked, image);
        for (const auto &outcome : corpus.outcomes)
        {
            check(outcome.function_boundary && !outcome.returned &&
                      !outcome.temporal_capture_complete,
                  "unmodeled callee stops the function run");
            check(outcome.stop_valid && outcome.stop_reason == RAX_STOP_STOPPED &&
                      outcome.stop_pc == callee,
                  "the stop precedes the callee's first instruction");
            check(outcome.temporal_prefix_complete && outcome.prefix_call_source == site &&
                      outcome.prefix_call_target == callee,
                  "prefix ledger identifies the call boundary");
        }
        check(hybrid_consensus_use_strings(corpus.evidence).empty(),
              "upstream contract publishes nothing without a return");
        const auto uses = hybrid_consensus_use_strings(corpus.evidence, 4, 4096, true);
        check(uses.size() == 1 && uses.front().value == "stackmsg",
              "call-time argument text published under prefix admission");
        const auto &use = uses.front().use;
        check(use.producer == UseProducer::BOUNDARY_ARGUMENT && use.site == site &&
                  use.callee == callee && use.argument == 0 && use.scope == DataScope::STACK &&
                  uses.front().prefix_runs == 4,
              "boundary use retains site, callee, argument slot and prefix provenance");
    }

    // A jump out of the function is not a call boundary: no argument capture.
    {
        Code code;
        code.raw({0x48, 0x89, 0xe7, 0xe9});
        code.imm32(static_cast<std::uint32_t>(0x1800 - (code.here() + 4)));
        const auto image = function_image(HybridArch::X86_64, code, code.here(), {0x1800});
        const auto corpus = run_corpus(linked, image);
        for (const auto &outcome : corpus.outcomes)
            check(outcome.function_boundary && !outcome.temporal_prefix_complete &&
                      outcome.prefix_call_target == 0,
                  "a tail transfer is not an admitted call prefix");
        check(hybrid_consensus_use_strings(corpus.evidence, 4, 4096, true).empty(),
              "no boundary text without a call");
    }

    // Native byte loop: an inline strlen over a stack string. Each executed
    // one-byte read is a scalar witness; the stream reconstructs the text.
    {
        Code code;
        code.raw({0x48, 0xb8});
        code.imm64(UINT64_C(0x0067666564636261)); // "abcdefg\0"
        code.raw({0x48, 0x89, 0x44, 0x24, 0xf0}); // mov [rsp-16], rax
        code.raw({0x48, 0x8d, 0x7c, 0x24, 0xf0}); // lea rdi, [rsp-16]
        code.raw({0x31, 0xc9});                   // xor ecx, ecx
        const auto loop = code.here();
        code.raw({0x0f, 0xb6, 0x04, 0x0f});             // movzx eax, byte [rdi+rcx]
        code.raw({0x48, 0xff, 0xc1, 0x84, 0xc0, 0x75}); // inc rcx; test al, al; jnz loop
        code.bytes.push_back(static_cast<std::uint8_t>(loop - (code.here() + 1)));
        code.raw({0xc3});
        const auto image = function_image(HybridArch::X86_64, code, code.here());
        const auto corpus = run_corpus(linked, image);
        const auto streams = hybrid_consensus_native_read_strings(corpus.evidence);
        check(streams.size() == 1 && streams.front().value == "abcdefg" &&
                  streams.front().use.producer == UseProducer::EXECUTED_READ_STREAM &&
                  streams.front().use.site == loop && streams.front().read_fragments.size() == 4 &&
                  streams.front().read_fragments.front().size() == 8,
              "inline byte loop reconstructs one stream with per-run scalar witnesses");
        const auto all = hybrid_consensus_use_strings(corpus.evidence);
        check(std::count_if(
                  all.begin(), all.end(), [](const auto &candidate)
                  { return candidate.use.producer == UseProducer::EXECUTED_READ_STREAM; }) == 1,
              "use-string consensus includes derived streams");
    }

    // x86-32 INC preserves CF. Upstream carries a workaround for a pinned RAX
    // whose 40h..4Fh dispatcher dropped the preserved carry; this is the probe.
    {
        Code code;
        code.raw({0xf9, 0x40, 0x72, 0x01, 0xc3, 0xc3}); // stc; inc eax; jc +1; ret; ret
        const auto image = function_image(HybridArch::X86_32, code, code.here());
        EmuDriver driver(&linked.api, image, true, false);
        check(driver.can_discover(), "x86-32 discovery available");
        EmuEvents events;
        EmuOutcome outcome;
        check(driver.emulate_from(0x1000, code.here(), config, events, &outcome, true, 0, 0),
              "x86-32 carry probe ran");
        bool taken = false, fallthrough = false;
        for (const auto &point : events.execution)
        {
            taken |= point.pc == 0x1005;
            fallthrough |= point.pc == 0x1004;
        }
        check(outcome.returned && taken && !fallthrough, "INC keeps the carry set by STC");
        Code clear;
        clear.raw({0xf8, 0x40, 0x72, 0x01, 0xc3, 0xc3}); // clc; inc eax; jc +1; ret; ret
        const auto control = function_image(HybridArch::X86_32, clear, clear.here());
        EmuDriver control_driver(&linked.api, control, true, false);
        EmuEvents control_events;
        EmuOutcome control_outcome;
        check(control_driver.emulate_from(0x1000, clear.here(), config, control_events,
                                          &control_outcome, true, 0, 0),
              "x86-32 carry control ran");
        taken = fallthrough = false;
        for (const auto &point : control_events.execution)
        {
            taken |= point.pc == 0x1005;
            fallthrough |= point.pc == 0x1004;
        }
        check(control_outcome.returned && fallthrough && !taken,
              "INC keeps the carry cleared by CLC");
    }
    std::cout << "shared RAX: baseline isolation, strings, divergent targets, branch paths, "
                 "incomplete execution and decoder comparison, temporal heap/boundary/stream "
                 "strings and x86-32 carry passed\n";
}
