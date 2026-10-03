#include "deobf/analysis/ast_builder.h"

#include <cstdio>
#include <dlfcn.h>
#include <memory>

namespace
{
using chernobog::ast::AstBuildReport;
using chernobog::ast::AstNode;
using chernobog::ast::AstPtr;
using chernobog::ast::MatchFailure;
using chernobog::ast::MopKey;

template <class Function> Function symbol(void *handle, const char *name)
{
    return reinterpret_cast<Function>(dlsym(handle, name));
}

void nested(mop_t &operand, mreg_t left, mreg_t right, mreg_t destination)
{
    auto *instruction = new minsn_t(BADADDR);
    instruction->opcode = m_add;
    instruction->l.make_reg(left, 4);
    instruction->r.make_reg(right, 4);
    instruction->d.make_reg(destination, 4);
    operand.t = mop_d;
    operand.d = instruction;
    operand.size = 4;
}
} // namespace

extern "C" int chernobog_mba_collision_bridge(const char *plugin_path, char *output,
                                              size_t capacity)
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
    void *handle = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return fail(3, "plugin_load_failed");
    const auto key = symbol<MopKey (*)(const mop_t &, AstBuildReport *)>(
        handle, "_ZN9chernobog3ast6MopKey8from_mopERK5mop_tPNS0_14AstBuildReportE");
    const auto equal = symbol<bool (*)(const mop_t &, const mop_t &, MatchFailure *)>(
        handle, "_ZN9chernobog3ast17mops_equal_strictERK5mop_tS3_PNS0_12MatchFailureE");
    const auto build = symbol<AstPtr (*)(const minsn_t *, AstBuildReport *)>(
        handle, "_ZN9chernobog3ast12minsn_to_astEPK7minsn_tPNS0_14AstBuildReportE");
    if (!key)
        return fail(4, "key_symbol_missing");
    if (!equal)
        return fail(4, "equal_symbol_missing");
    if (!build)
        return fail(4, "build_symbol_missing");
    try
    {
        minsn_t root(BADADDR);
        root.opcode = m_sub;
        root.d.size = 4;
        nested(root.l, 100, 101, 102);
        nested(root.r, 100, 101, 103);
        const MopKey first = key(root.l, nullptr);
        const MopKey second = key(root.r, nullptr);
        if (!first.complete || !(first == second) || equal(root.l, root.r, nullptr))
            return fail(5, "collision_fixture_invalid");
        AstBuildReport report;
        const AstPtr result = build(&root, &report);
        const auto node = std::dynamic_pointer_cast<AstNode>(result);
        const auto left = node ? std::dynamic_pointer_cast<AstNode>(node->left) : nullptr;
        const auto right = node ? std::dynamic_pointer_cast<AstNode>(node->right) : nullptr;
        if (!node || !left || !right || left == right || left->dst_mop.t != mop_r ||
            right->dst_mop.t != mop_r || left->dst_mop.r != 102 || right->dst_mop.r != 103 ||
            !equal(left->mop, root.l, nullptr) || !equal(right->mop, root.r, nullptr))
            return fail(6, "ast_collision_merge");
        qsnprintf(output, capacity,
                  "{\"passed\":true,\"key_bytes\":%zu,\"left_dest\":%d,"
                  "\"right_dest\":%d,\"distinct_children\":true,"
                  "\"copied_operands_equal\":true,\"ast_visits\":%zu}",
                  sizeof(MopKey), int(left->dst_mop.r), int(right->dst_mop.r), report.visits);
    }
    catch (...)
    {
        return fail(7, "bridge_exception");
    }
    dlclose(handle);
    return 0;
}
