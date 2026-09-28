"""Inspect PUSH/RET admission and native callback work in an existing IDB."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_pro
import ida_ua
import idautils


def statistic(name):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_stats()." + name)
    return int(value.i64)


report = {"schema": 1, "errors": [], "statistics": {}, "counts": {}}
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    for name in (
        "push_return_targets",
        "proof_revalidation_calls",
        "proof_revalidation_checks",
        "proof_revalidation_skipped",
        "function_updates_scoped",
        "function_updates_global",
        "post_scan_heads",
        "post_scan_functions",
    ):
        report["statistics"][name] = statistic(name)
    counts = {"code_heads": 0, "push_heads": 0, "push_ret_pairs": 0}
    pair_owners = {}
    owner_heads = {}
    owner_extents = {}
    for ea in idautils.Heads():
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        counts["code_heads"] += 1
        assert counts["code_heads"] <= 1_000_000
        owner = ida_funcs.get_func(ea)
        owner_key = "ownerless" if owner is None else hex(owner.start_ea)
        owner_heads[owner_key] = owner_heads.get(owner_key, 0) + 1
        if owner is not None:
            owner_extents[owner_key] = [hex(owner.start_ea), hex(owner.end_ea)]
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0 or insn.itype != ida_allins.NN_push:
            continue
        counts["push_heads"] += 1
        ret = ida_ua.insn_t()
        if ida_ua.decode_insn(ret, ea + insn.size) > 0 and ret.itype == ida_allins.NN_retn:
            counts["push_ret_pairs"] += 1
            pair_owners[owner_key] = pair_owners.get(owner_key, 0) + 1
    report["counts"] = counts
    report["pair_owners"] = sorted(pair_owners.items(), key=lambda row: (-row[1], row[0]))[:32]
    report["owner_heads"] = {key: owner_heads[key] for key, _ in report["pair_owners"]}
    report["owner_extents"] = {
        key: owner_extents[key] for key, _ in report["pair_owners"] if key in owner_extents
    }
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "pushret_latency.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][pushret-latency] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
