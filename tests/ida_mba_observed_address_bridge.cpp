#include "deobf/analysis/ast_builder.h"

#include <dlfcn.h>
#include <memory>

namespace
{
using namespace chernobog::ast;

template <class Function> Function symbol(void *handle, const char *name)
{
    return reinterpret_cast<Function>(dlsym(handle, name));
}

struct CaseResult
{
    bool keys_differ = false;
    bool strict_differs = false;
    bool copies_preserved = false;
    bool accepted = false;
    MatchFailureKind failure = MatchFailureKind::None;
};
} // namespace

extern "C" int chernobog_mba_observed_address_bridge(const char *plugin_path, const mop_t *source,
                                                     char *output, size_t capacity)
{
    const auto fail = [&](int code, const char *reason)
    {
        qsnprintf(output, capacity, "{\"passed\":false,\"reason\":\"%s\"}", reason);
        return code;
    };
    if (!plugin_path || !source || !output || capacity < 512)
        return 1;
    if (!init_hexrays_plugin())
        return fail(2, "hexrays_unavailable");
    if (source->t != mop_a || !source->a || source->a->t == mop_z || source->size <= 0 ||
        source->size > 8)
        return fail(3, "source_invalid");
    void *handle = dlopen(plugin_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle)
        return fail(4, "plugin_load_failed");
    const auto key = symbol<MopKey (*)(const mop_t &, AstBuildReport *)>(
        handle, "_ZN9chernobog3ast6MopKey8from_mopERK5mop_tPNS0_14AstBuildReportE");
    const auto equal = symbol<bool (*)(const mop_t &, const mop_t &, MatchFailure *)>(
        handle, "_ZN9chernobog3ast17mops_equal_strictERK5mop_tS3_PNS0_12MatchFailureE");
    const auto build = symbol<AstPtr (*)(const minsn_t *, AstBuildReport *)>(
        handle, "_ZN9chernobog3ast12minsn_to_astEPK7minsn_tPNS0_14AstBuildReportE");
    const auto match = symbol<bool (*)(const AstBase *, const AstBase *, MatchBindings &,
                                       MatchFailure *)>(
        handle,
        "_ZN9chernobog3ast13match_patternEPKNS0_7AstBaseES3_RNS0_13MatchBindingsEPNS0_12MatchFailureE");
    if (!key || !equal || !build || !match)
        return fail(5, "plugin_symbols_missing");
    try
    {
        const auto variable = make_leaf("x_0");
        const auto pattern = make_node(m_sub, variable, variable);
        const int original_input = source->a->insize;
        const int original_output = source->a->outsize;
        const mop_t original = *source;
        const auto run_case = [&](bool change_input)
        {
            minsn_t root(BADADDR);
            root.opcode = m_sub;
            root.l = *source;
            root.r = *source;
            root.d.make_reg(200, source->size);
            if (change_input)
                root.r.a->insize = original_input == 4 ? 8 : 4;
            else
                root.r.a->outsize = original_output == 4 ? 8 : 4;
            CaseResult result;
            result.keys_differ = !(key(root.l, nullptr) == key(root.r, nullptr));
            result.strict_differs = !equal(root.l, root.r, nullptr);
            AstBuildReport report;
            const AstPtr candidate = build(&root, &report);
            const auto node = std::dynamic_pointer_cast<AstNode>(candidate);
            if (!node || !node->left || !node->right || report.status != AstBuildStatus::Complete)
                return result;
            result.copies_preserved =
                equal(node->left->mop, root.l, nullptr) && equal(node->right->mop, root.r, nullptr);
            MatchBindings bindings;
            MatchFailure failure;
            result.accepted = match(pattern.get(), candidate.get(), bindings, &failure);
            result.failure = failure.kind;
            return result;
        };
        const CaseResult input = run_case(true);
        const CaseResult output_case = run_case(false);
        const bool source_preserved = equal(*source, original, nullptr) &&
                                      source->a->insize == original_input &&
                                      source->a->outsize == original_output;
        const bool input_rejected = input.keys_differ && input.strict_differs &&
                                    input.copies_preserved && !input.accepted &&
                                    input.failure == MatchFailureKind::AddressInputSize;
        const bool output_rejected = output_case.keys_differ && output_case.strict_differs &&
                                     output_case.copies_preserved && !output_case.accepted &&
                                     output_case.failure == MatchFailureKind::AddressOutputSize;
        const int status = input_rejected && output_rejected && source_preserved ? 0 : 6;
        const auto boolean = [](bool value) { return value ? "true" : "false"; };
        const long long stack_offset =
            source->a->t == mop_S && source->a->s ? static_cast<long long>(source->a->s->off) : 0;
        qsnprintf(output, capacity,
                  "{\"passed\":%s,\"reason\":\"%s\",\"source_kind\":%d,"
                  "\"referent_kind\":%d,\"source_size\":%d,\"input_extent\":%d,"
                  "\"output_extent\":%d,\"stack_offset\":%lld,\"source_preserved\":%s,"
                  "\"input_key_distinct\":%s,\"input_strict_differs\":%s,"
                  "\"input_copies_preserved\":%s,\"input_matches\":%s,"
                  "\"input_failure\":%d,\"output_key_distinct\":%s,"
                  "\"output_strict_differs\":%s,\"output_copies_preserved\":%s,"
                  "\"output_matches\":%s,\"output_failure\":%d}",
                  boolean(status == 0), status == 0 ? "complete" : "extent_match_failed",
                  int(source->t), int(source->a->t), source->size, original_input, original_output,
                  stack_offset, boolean(source_preserved), boolean(input.keys_differ),
                  boolean(input.strict_differs), boolean(input.copies_preserved),
                  boolean(input.accepted), int(input.failure), boolean(output_case.keys_differ),
                  boolean(output_case.strict_differs), boolean(output_case.copies_preserved),
                  boolean(output_case.accepted), int(output_case.failure));
        return status;
    }
    catch (...)
    {
        return fail(7, "bridge_exception");
    }
}
