#include "deobf/handlers/mba_smt_microcode.hpp"
#include "deobf/analysis/mba_smt_internal.hpp"
#include "deobf/analysis/mba_cobra.hpp"
#include "mba_cobra_fixtures.hpp"
#include "chernobog/build_provenance.hpp"
#include <cstdio>
#include <cstring>
#include "common/hexrays_handshake.hpp"

using namespace chernobog::mba_smt;
namespace
{
void assign_value(minsn_t &instruction, const mop_t &value)
{
    if (value.t == mop_d && value.d)
    {
        instruction.opcode = value.d->opcode;
        instruction.l = value.d->l;
        instruction.r = value.d->r;
    }
    else
    {
        instruction.opcode = m_mov;
        instruction.l = value;
        instruction.r.erase();
    }
}
void initialize(MicrocodeAdapter &adapter, const Program &program)
{
    adapter.program = program;
    for (size_t i = 0; i < program.widths.size(); ++i)
    {
        const auto reg = static_cast<mreg_t>(mr_first + 32 * i);
        const int bytes = static_cast<int>(program.widths[i] / 8);
        adapter.registers.push_back({reg, bytes, 0});
        mop_t operand;
        operand.make_reg(reg, bytes);
        adapter.available.emplace_back(variable(i, program.widths[i]), operand);
    }
}
size_t nodes(const Term &term) { return term ? 1 + nodes(term->left) + nodes(term->right) : 0; }
qstring boolean(bool value) { return value ? "true" : "false"; }
int positive(Backend backend, Profile profile, qstring &output)
{
    int failures = 0;
    bool first = true;
    output = "[";
    for (const auto &fixture : fixtures::make())
    {
        if (!first)
            output += ",";
        first = false;
        const auto started = std::chrono::steady_clock::now();
        Options options = profile == Profile::Deep ? Options::deep() : Options{};
        options.backend = backend;
        options.snapshot = {17, 0};
        options.max_invariants = 0;
        const auto &source_term = fixture.program.blocks[0].statements[0].value;
        minsn_t original(0x1000);
        MicrocodeAdapter adapter(nullptr, nullptr, &original);
        initialize(adapter, fixture.program);
        assign_value(original, adapter.emit_operand(source_term, original.ea));
        original.d.make_reg(mr_first + 2048, static_cast<int>(source_term->bits / 8));
        const minsn_t snapshot(original);
        const auto lifted_source = adapter.translate_instruction(&original);
        const bool source_matches = key(lifted_source) == key(source_term);
        Analysis analysis(fixture.program, options);
        const auto proposals = analysis.run();
        bool candidate_unsat = !proposals.empty() && bool(proposals.front().proof);
        bool emitted_unsat = false, applied = false, frame = false;
        Term emitted;
        SnapshotToken current = options.snapshot;
        size_t emitted_cost = microcode_expression_cost(&original);
        if (candidate_unsat)
        {
            const auto &proposal = proposals.front();
            minsn_t replacement(snapshot);
            const auto emission_started = std::chrono::steady_clock::now();
            assign_value(replacement, adapter.emit_operand(proposal.replacement, original.ea));
            frame = verify_emitted_instruction_frame(snapshot, replacement);
            const auto receipt = MicrocodeEmissionProof::prove(
                analysis, *proposal.proof, replacement,
                [&](const minsn_t &temporary)
                {
                    emitted = adapter.translate_instruction(&temporary);
                    analysis.record_emission(static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - emission_started)
                            .count()));
                    return emitted;
                });
            emitted_unsat = bool(receipt);
            emitted_cost = microcode_expression_cost(&replacement);
            if (receipt)
                applied = commit_microcode_replacement(original, snapshot, replacement, analysis,
                                                       *receipt, options.snapshot, current);
        }
        const auto &statistics = analysis.statistics().cobra;
        const auto emitted_nodes = emitted ? nodes(emitted) : nodes(source_term);
        bool passed = source_matches;
        if (backend == Backend::Cobra)
        {
            passed = passed && candidate_unsat && proposals.front().proof->from_cobra() &&
                     emitted_unsat && frame && applied && emitted &&
                     cost(emitted) < cost(source_term) &&
                     emitted_cost < microcode_expression_cost(&snapshot) &&
                     emitted_nodes <= fixture.max_nodes;
            if (fixture.half_cost)
                passed = passed && emitted && 2 * cost(emitted) <= cost(source_term) &&
                         2 * emitted_cost <= microcode_expression_cost(&snapshot);
            if (fixture.empty_support)
                passed =
                    passed && emitted && emitted->op == Op::Constant && variables(emitted).empty();
            if (fixture.inner_width)
                passed = passed &&
                         (statistics.proved_widths & (UINT64_C(1) << (fixture.inner_width / 8))) &&
                         (statistics.proved_widths & (UINT64_C(1) << (source_term->bits / 8)));
        }
        if (!applied && !same_microcode_instruction(original, snapshot))
            passed = false;
        if (!passed)
            ++failures;
        output.cat_sprnt(
            "{\"fixture\":\"%s\",\"width\":%u,\"passed\":%s,\"has_candidate\":%s,\"candidate_unsat\":%s,\"emitted_unsat\":%s,\"frame\":%s,\"applied\":%s,\"source_matches\":%s,\"term_input_cost\":%zu,\"term_output_cost\":%zu,\"emitted_input_cost\":%zu,\"emitted_output_cost\":%zu,\"output_nodes\":%zu,\"canonical_support_empty\":%s,\"proved_widths\":%llu,\"scratch_peak_bytes\":%zu,\"generation_ns\":%llu,\"elapsed_ns\":%llu,\"process_peak_rss_bytes\":%llu}",
            fixture.id, source_term->bits, boolean(passed).c_str(),
            boolean(candidate_unsat).c_str(), boolean(candidate_unsat).c_str(),
            boolean(emitted_unsat).c_str(), boolean(frame).c_str(), boolean(applied).c_str(),
            boolean(source_matches).c_str(), cost(source_term),
            emitted ? cost(emitted) : cost(source_term), microcode_expression_cost(&snapshot),
            emitted_cost, emitted_nodes, boolean(emitted && variables(emitted).empty()).c_str(),
            static_cast<unsigned long long>(statistics.proved_widths),
            statistics.scratch_peak_bytes,
            static_cast<unsigned long long>(statistics.generation_ns),
            static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::steady_clock::now() - started)
                                                .count()),
            static_cast<unsigned long long>(cobra_backend::process_peak_rss_bytes()));
    }
    output += "]";
    return failures;
}
void number(cexpr_t &node, uint64_t value, const tinfo_t &type)
{
    node.op = cot_num;
    node.n = new cnumber_t;
    node.n->assign(value, type.get_size(), type_unsigned);
    node.type = type;
    node.ea = 0x1000;
}
int ctree_faults(qstring &output)
{
    int failures = 0;
    for (int fault = 0; fault < 9; ++fault)
    {
        auto time = std::chrono::steady_clock::time_point{};
        bool cancelled = false;
        detail::SessionTestHooks hooks;
        hooks.now = [&] { return time; };
        struct Restore
        {
            detail::SessionTestHooks *old;
            ~Restore() { detail::session_test_hooks = old; }
        } restore{detail::session_test_hooks};
        detail::session_test_hooks = &hooks;
        const auto type = get_int_type_by_width_and_sign(1, type_unsigned);
        cexpr_t original;
        original.op = cot_add;
        original.type = type;
        original.ea = 0x1000;
        original.x = new cexpr_t;
        number(*original.x, 1, type);
        original.y = new cexpr_t;
        number(*original.y, 0, type);
        const cexpr_t snapshot(original);
        cexpr_t replacement;
        number(replacement, 1, type);
        cexpr_t target;
        target.op = cot_obj;
        target.obj_ea = 0x2000;
        target.type = type;
        const cexpr_t saved_target(target);
        Program program;
        program.widths = {8};
        program.blocks.resize(1);
        program.blocks[0].statements.push_back(
            Statement::assign(0, expression(Op::Add, constant(1, 8), constant(0, 8))));
        Options options;
        options.backend = fault == 4 || fault == 6 ? Backend::Cobra : Backend::Legacy;
        options.budget_ms = 100;
        options.snapshot = {23, 0};
        options.max_invariants = 0;
        options.cancelled = [&] { return cancelled; };
        Analysis analysis(program, options);
        auto candidate =
            analysis.prove_candidate(0, 0, constant(1, 8), options.backend == Backend::Cobra);
        if (fault == 6 || fault == 7)
        {
            time += std::chrono::milliseconds(5);
            hooks.after_query = [&](const char *purpose, const z3::check_result &observed)
            {
                if (std::string(purpose) == "MBA emitted replacement mismatch" &&
                    observed == z3::unsat)
                {
                    if (fault == 6)
                        cancelled = true;
                    else
                        time += std::chrono::milliseconds(150);
                }
            };
        }
        const auto receipt = candidate
                                 ? CtreeEmissionProof::prove(
                                       analysis, *candidate, replacement,
                                       [](const cexpr_t &temporary)
                                       {
                                           return constant(temporary.numval(),
                                                           unsigned(temporary.type.get_size() * 8));
                                       })
                                 : nullptr;
        SnapshotToken current = options.snapshot;
        bool applied = false;
        if (receipt)
        {
            if (fault == 8)
                replacement.n->assign(2, 1, type_unsigned);
            if (fault == 1)
                cancelled = true;
            if (fault == 2)
                target.obj_ea += 1;
            if (fault == 3)
                replacement.type = get_int_type_by_width_and_sign(1, type_signed);
            if (fault == 5)
                ++current.mutation_epoch;
            if (fault == 0 || fault == 4)
                time += std::chrono::milliseconds(150);
            applied =
                commit_ctree_replacement(original, snapshot, replacement, analysis, *receipt,
                                         options.snapshot, current, &target, &saved_target, true);
        }
        const bool expected = fault == 0;
        bool passed = applied == expected && (applied || original.compare(snapshot) == 0);
        if (fault == 2 || fault == 3)
            passed = passed && analysis.statistics().cancel_stage ==
                                   RejectReason::EmittedDestinationOrFrameMismatch;
        if (fault == 6 || fault == 7)
            passed = passed && !receipt &&
                     analysis.statistics().cancel_stage == RejectReason::PostProofExpiry;
        if (!passed)
            ++failures;
        output.cat_sprnt(
            ",{\"route\":\"ctree\",\"fault\":%d,\"kind\":\"%s\",\"passed\":%s,\"rejected\":%s,\"expected_apply\":%s,\"mutations\":%u,\"stage\":%u,\"overshoot_ns\":%llu}",
            fault, expected ? "control" : "negative", boolean(passed).c_str(),
            boolean(!applied).c_str(), boolean(expected).c_str(), unsigned(applied),
            unsigned(analysis.statistics().cancel_stage),
            static_cast<unsigned long long>(analysis.statistics().deadline_overshoot_ns));
    }
    return failures;
}
int faults(qstring &output)
{
    int failures = 0;
    bool first = true;
    output = "[";
    for (int fault = 0; fault < 19; ++fault)
    {
        const auto fixture = fixtures::make()[fault == 14 ? 9 : 0];
        auto time = std::chrono::steady_clock::time_point{};
        bool cancelled = false;
        detail::SessionTestHooks hooks;
        hooks.now = [&] { return time; };
        struct Restore
        {
            detail::SessionTestHooks *old;
            ~Restore() { detail::session_test_hooks = old; }
        } restore{detail::session_test_hooks};
        detail::session_test_hooks = &hooks;
        Options options;
        options.backend = Backend::Cobra;
        options.snapshot = {19, 0};
        options.budget_ms = 100;
        options.max_invariants = 0;
        options.cancelled = [&] { return cancelled; };
        minsn_t original(0x1000);
        MicrocodeAdapter adapter(nullptr, nullptr, &original);
        initialize(adapter, fixture.program);
        assign_value(original, adapter.emit_operand(fixture.program.blocks[0].statements[0].value,
                                                    original.ea));
        original.d.make_reg(mr_first + 2048,
                            int(fixture.program.blocks[0].statements[0].value->bits / 8));
        const minsn_t snapshot(original);
        Analysis analysis(fixture.program, options);
        const auto proposals = analysis.run();
        bool applied = false, rejected = false;
        if (!proposals.empty() && proposals.front().proof)
        {
            minsn_t replacement(snapshot);
            assign_value(replacement,
                         adapter.emit_operand(proposals.front().replacement, original.ea));
            if (fault == 5 || fault == 6)
            {
                time += std::chrono::milliseconds(5);
                hooks.after_query = [&](const char *purpose, const z3::check_result &observed)
                {
                    if (std::string(purpose) == "MBA emitted replacement mismatch" &&
                        observed == z3::unsat)
                    {
                        if (fault == 5)
                            cancelled = true;
                        else
                            time += std::chrono::milliseconds(150);
                    }
                };
            }
            if (fault == 9)
            {
                replacement.opcode = m_mov;
                replacement.l.make_number(1, 1);
                replacement.r.erase();
            }
            if (fault == 14)
                replacement.opcode = m_xds;
            if (fault == 15)
            {
                replacement.opcode = m_shl;
                replacement.l = adapter.emit_operand(proposals.front().replacement, original.ea);
                replacement.r.make_number(1, 1);
            }
            if (fault == 16)
                ++replacement.l.size;
            if (fault == 17)
            {
                replacement.opcode = m_ldx;
                replacement.l.make_number(0, 8);
                replacement.r.make_number(0x2000, 8);
            }
            const auto receipt = MicrocodeEmissionProof::prove(
                analysis, *proposals.front().proof, replacement, [&](const minsn_t &temporary)
                { return adapter.translate_instruction(&temporary); });
            SnapshotToken current = options.snapshot;
            std::unique_ptr<minsn_t> before;
            if (receipt)
            {
                if (fault == 18)
                {
                    replacement.opcode = m_mov;
                    replacement.l.make_number(1, 1);
                    replacement.r.erase();
                }
                if (fault == 0)
                    replacement.d.r += 1;
                if (fault == 1)
                    replacement.d.size += 1;
                if (fault == 2)
                    replacement.iprops ^= 1;
                if (fault == 3)
                    replacement.ea += 1;
                if (fault == 4)
                    ++current.mutation_epoch;
                if (fault == 7)
                    time += std::chrono::milliseconds(150);
                if (fault == 8)
                    cancelled = true;
                if (fault == 10)
                    replacement.opcode = m_jcnd;
                if (fault == 11)
                {
                    replacement.l.erase();
                    replacement.l.t = mop_v;
                    replacement.l.g = 0x2000;
                    replacement.l.size = 1;
                }
                if (fault == 12)
                    original.l.make_number(0, 1);
                before = std::make_unique<minsn_t>(original);
                Program current_domain = fixture.program;
                if (fault == 13)
                    current_domain.blocks[0].statements[0].value = constant(0, 8);
                applied = commit_microcode_replacement(
                    original, snapshot, replacement, analysis, *receipt, options.snapshot, current,
                    [&] { return same_program(fixture.program, current_domain); });
            }
            rejected =
                !applied && same_microcode_instruction(original, before ? *before : snapshot);
            if (fault < 4 || fault == 10 || fault == 11)
                rejected = rejected && analysis.statistics().cancel_stage ==
                                           RejectReason::EmittedDestinationOrFrameMismatch;
            if (fault == 5 || fault == 6)
                rejected = rejected && analysis.statistics().last_solver_observed == 2 &&
                           !analysis.statistics().last_solver_usable && !receipt &&
                           analysis.statistics().cancel_stage == RejectReason::PostProofExpiry;
            if (fault >= 14 && fault <= 17)
                rejected = rejected && !receipt;
            if (fault == 6)
                rejected = rejected && analysis.statistics().deadline_overshoot_ns == 55000000;
        }
        if (!rejected)
            ++failures;
        if (!first)
            output += ",";
        first = false;
        output.cat_sprnt(
            "{\"fault\":%d,\"rejected\":%s,\"mutations\":%u,\"stage\":%u,\"overshoot_ns\":%llu}",
            fault, boolean(rejected).c_str(), unsigned(applied),
            unsigned(analysis.statistics().cancel_stage),
            static_cast<unsigned long long>(analysis.statistics().deadline_overshoot_ns));
    }
    failures += ctree_faults(output);
    output += "]";
    return failures;
}
}
#if defined(_WIN32)
#define CHERNOBOG_SDK_EXPORT __declspec(dllexport)
#else
#define CHERNOBOG_SDK_EXPORT __attribute__((visibility("default")))
#endif
extern "C" CHERNOBOG_SDK_EXPORT int chernobog_mba_cobra_sdk_bridge(int backend, int profile,
                                                                   char *buffer, size_t capacity)
{
    if (!buffer || capacity < 1024 || backend < 0 || backend > 1 || profile < 0 || profile > 2)
        return -1;
    try
    {
        if (!chernobog::hexrays::handshake())
            return -2;
        qstring rows;
        const int failures = profile == 2
                                 ? faults(rows)
                                 : positive(backend ? Backend::Cobra : Backend::Legacy,
                                            profile ? Profile::Deep : Profile::Normal, rows);
        qstring report;
        report.sprnt(
            "{\"schema_version\":1,\"boundary\":\"sdk_emitted\",\"backend\":\"%s\",\"profile\":\"%s\",\"revision\":\"%s\",\"source_fingerprint\":\"%s\",\"vendor_tree\":\"%s\",\"manifest_sha256\":\"%s\",\"failures\":%d,\"rows\":%s}",
            backend ? "cobra" : "legacy",
            profile == 2 ? "Faults"
            : profile    ? "Deep"
                         : "Normal",
            chernobog::build_provenance::revision, chernobog::build_provenance::source_fingerprint,
            chernobog::build_provenance::cobra_tree, fixtures::manifest_sha256, failures,
            rows.c_str());
        if (report.length() + 1 > capacity)
            return -3;
        std::memcpy(buffer, report.c_str(), report.length() + 1);
        return failures;
    }
    catch (const std::exception &error)
    {
        qsnprintf(buffer, capacity, "{\"failures\":1,\"error\":\"sdk_bridge_exception\"}");
        return -4;
    }
}
