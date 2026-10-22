#pragma once
#include "../deobf_types.h"
#include <array>

//--------------------------------------------------------------------------
// Conservative indirect-branch resolution.
//
// An m_ijmp stores its selector in r and its offset expression in d.  This
// handler proves exact singleton or conditional target sets from that actual
// expression. Read-only tables may be evaluated over a bounded correlated
// input domain. Shared-frame fragments are projected into the decompilation
// flowchart without changing their IDB function ownership or native bytes.
//--------------------------------------------------------------------------
class indirect_branch_handler_t
{
  public:
    static bool detect(mbl_array_t *mba);
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);
    static bool take_projection_restart(ea_t function);
    static void clear_projections();
    static void restore_projected_function(mba_t *mba);
    static void adjust_fragment_stack(mba_t *mba, stkpnts_t *points);
    static bool is_projected_return(const codegen_t &codegen);
    static int apply_generated_projections(mba_t *mba);
    static std::optional<std::array<ea_t, 2>> proven_targets(ea_t function, ea_t site);
    // Explicit IDB recovery: 0 previews, 1 creates ownerless regions, 3 also
    // selects proven entries overlapping unprotected ownerless code items.
    static qstring recover_regions(ea_t function, unsigned flags);
    static int extend_flowchart(qflow_chart_t *flowchart, bitset_t *reachable, mba_t *mba);
#if IDA_SDK_VERSION >= 940
    static int extend_flowchart(qflow_chart_ea_t *flowchart, bitset_t *reachable, mba_t *mba);
#endif
};
