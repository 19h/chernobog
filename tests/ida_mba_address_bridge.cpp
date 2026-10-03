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

void address(mop_t &operand, int input_size, int output_size)
{
    mop_t referent;
    referent.make_reg(100, 4);
    operand.t = mop_a;
    operand.a = new mop_addr_t(referent, input_size, output_size);
    operand.size = 8;
}

struct CaseResult
{
    bool keys_differ = false;
    bool operands_differ = false;
    bool copies_preserved = false;
    bool pattern_matches = false;
    MatchFailureKind failure = MatchFailureKind::None;
};
} // namespace

extern "C" int chernobog_mba_address_bridge(const char *plugin_path, char *output, size_t capacity)
{
    const auto fail = [&](int code, const char *reason)
    {
        qsnprintf(output, capacity, "{\"passed\":false,\"reason\":\"%s\"}", reason);
        return code;
    };
    if (!plugin_path || !output || capacity < 512)
        return 1;
    if (!init_hexrays_plugin())
        return fail(2, "hexrays_unavailable");
    void *handle = dlopen(plugin_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle)
        return fail(3, "plugin_load_failed");
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
        return fail(4, "plugin_symbols_missing");
    try
    {
        const auto variable = make_leaf("x_0");
        const auto pattern = make_node(m_sub, variable, variable);
        const auto run_case = [&](int input_size, int output_size)
        {
            minsn_t root(BADADDR);
            root.opcode = m_sub;
            address(root.l, 4, 0);
            address(root.r, input_size, output_size);
            root.d.make_reg(200, 8);
            CaseResult result;
            result.keys_differ = !(key(root.l, nullptr) == key(root.r, nullptr));
            result.operands_differ = !equal(root.l, root.r, nullptr);
            AstBuildReport build_report;
            const AstPtr candidate = build(&root, &build_report);
            const auto node = std::dynamic_pointer_cast<AstNode>(candidate);
            if (!node || !node->left || !node->right ||
                build_report.status != AstBuildStatus::Complete)
                return result;
            result.copies_preserved =
                equal(node->left->mop, root.l, nullptr) && equal(node->right->mop, root.r, nullptr);
            MatchBindings bindings;
            MatchFailure failure;
            result.pattern_matches = match(pattern.get(), candidate.get(), bindings, &failure);
            result.failure = failure.kind;
            return result;
        };
        const CaseResult same = run_case(4, 0);
        const CaseResult input = run_case(8, 0);
        const CaseResult output_case = run_case(4, 8);
        const bool same_ok = !same.keys_differ && !same.operands_differ && same.copies_preserved &&
                             same.pattern_matches && same.failure == MatchFailureKind::None;
        const bool input_ok = input.keys_differ && input.operands_differ &&
                              input.copies_preserved && !input.pattern_matches &&
                              input.failure == MatchFailureKind::AddressInputSize;
        const bool output_ok = output_case.keys_differ && output_case.operands_differ &&
                               output_case.copies_preserved && !output_case.pattern_matches &&
                               output_case.failure == MatchFailureKind::AddressOutputSize;
        const int status = !same_ok ? 5 : !input_ok ? 6 : !output_ok ? 7 : 0;
        const char *reason = status == 5   ? "equal_control_failed"
                             : status == 6 ? "input_extent_binding_failed"
                             : status == 7 ? "output_extent_binding_failed"
                                           : "complete";
        const auto boolean = [](bool value) { return value ? "true" : "false"; };
        qsnprintf(output, capacity,
                  "{\"passed\":%s,\"reason\":\"%s\",\"key_bytes\":%zu,"
                  "\"equal_matches\":%s,\"input_key_distinct\":%s,"
                  "\"input_operands_differ\":%s,\"input_copies_preserved\":%s,"
                  "\"input_matches\":%s,\"input_failure\":%d,"
                  "\"output_key_distinct\":%s,\"output_operands_differ\":%s,"
                  "\"output_copies_preserved\":%s,\"output_matches\":%s,"
                  "\"output_failure\":%d}",
                  boolean(status == 0), reason, sizeof(MopKey), boolean(same.pattern_matches),
                  boolean(input.keys_differ), boolean(input.operands_differ),
                  boolean(input.copies_preserved), boolean(input.pattern_matches),
                  int(input.failure), boolean(output_case.keys_differ),
                  boolean(output_case.operands_differ), boolean(output_case.copies_preserved),
                  boolean(output_case.pattern_matches), int(output_case.failure));
        return status;
    }
    catch (...)
    {
        return fail(8, "bridge_exception");
    }
}
