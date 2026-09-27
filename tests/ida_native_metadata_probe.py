"""Exercise live IDA metadata updates and code-inventory invalidation."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua

report = {"passed": False, "checks": [], "errors": [], "observations": {}}
FIELDS = (
    "enabled",
    "ran",
    "function_updates_scoped",
    "function_updates_global",
    "proof_revalidation_calls",
    "proof_revalidation_checks",
    "proof_revalidation_skipped",
    "proof_metadata_reuses",
    "item_topology_invalidations",
)


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def address(name):
    for label in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing fixture symbol " + name)


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value


def stats():
    value = evaluate("chernobog_native_stats()")
    result = {}
    for name in FIELDS:
        field = ida_expr.idc_value_t()
        assert not ida_expr.get_idcv_attr(field, value, name)
        result[name] = int(field.i64)
    return result


def facts(root):
    rows = json.loads(evaluate(f"chernobog_native_evidence({root})").c_str())["records"]
    return {
        row["publication"]: row
        for row in rows
        if row["kind"] == "setcc-value"
        and row["fresh"] == "true"
        and row.get("publication", "0") != "0"
    }


def update_flags(root, flag=ida_funcs.FUNC_LIB):
    function = ida_funcs.get_func(root)
    flags = function.flags
    function.flags ^= flag
    assert ida_funcs.update_func(function)
    function = ida_funcs.get_func(root)
    function.flags = flags
    assert ida_funcs.update_func(function)


def settle(root):
    function = ida_funcs.get_func(root)
    ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    root = address("df_equal")
    settle(root)
    initial = facts(root)
    assert initial, "initial value proof"
    report["observations"]["initial"] = initial
    before = stats()
    check("read-only snapshot enabled", before["enabled"] == 1 and before["ran"] == 0)
    check("repeat snapshot does not run analysis", before == stats())

    update_flags(root)
    after = stats()
    report["observations"]["related_update"] = {"before": before, "after": after}
    check(
        "related function update scoped",
        after["function_updates_scoped"] > before["function_updates_scoped"],
    )
    check(
        "related value metadata reused",
        after["proof_metadata_reuses"] > before["proof_metadata_reuses"],
    )
    check(
        "related update has no global fallback",
        after["function_updates_global"] == before["function_updates_global"],
    )
    check("related value publication retained", facts(root) == initial)

    before = stats()
    update_flags(root, ida_funcs.FUNC_SP_READY)
    after = stats()
    report["observations"]["sp_ready_update"] = {"before": before, "after": after}
    check(
        "SP-ready attribute update reuses ordinary value proof",
        after["proof_metadata_reuses"] > before["proof_metadata_reuses"],
    )
    check("SP-ready attribute preserves value publication", facts(root) == initial)

    before = stats()
    update_flags(address("df_memory_target"))
    after = stats()
    report["observations"]["unrelated_update"] = {"before": before, "after": after}
    check(
        "unrelated proofs skipped",
        after["proof_revalidation_skipped"] > before["proof_revalidation_skipped"],
    )
    check("unrelated value publication retained", facts(root) == initial)

    before = stats()
    evaluate("chernobog_native_analysis()")
    after = stats()
    check(
        "explicit analysis still rechecks proofs",
        after["proof_revalidation_checks"] > before["proof_revalidation_checks"],
    )
    check("explicit analysis keeps valid publication", set(facts(root)) == set(initial))

    function = ida_funcs.get_func(root)
    original_end = function.end_ea
    next_root = address("df_different")
    padding = ida_ua.insn_t()
    padding_size = ida_ua.decode_insn(padding, original_end)
    assert 0 < padding_size <= 15 and original_end + padding_size <= next_root
    raw = ida_bytes.get_bytes(root, next_root - root)
    assert ida_funcs.set_func_end(root, original_end + padding_size)
    assert ida_bytes.del_items(original_end, ida_bytes.DELIT_SIMPLE, padding_size)
    settle(root)
    assert not ida_bytes.is_code(ida_bytes.get_flags(original_end)), "padding remains unknown"
    padding_facts = facts(root)
    assert padding_facts, "value proof with unknown padding"
    before = stats()
    assert ida_ua.create_insn(original_end) == padding_size
    after = stats()
    report["observations"]["code_creation"] = {"before": before, "after": after}
    check(
        "new code item synchronously invalidates owner value proofs",
        after["item_topology_invalidations"] > before["item_topology_invalidations"],
    )
    check("new code item revokes old publication", not set(padding_facts).intersection(facts(root)))
    settle(root)
    restored = facts(root)
    report["observations"]["new_inventory_facts"] = restored
    control_root = address("df_flags")
    control = facts(control_root)
    assert control, "independent value proof"
    before = stats()
    assert ida_ua.create_insn(original_end) == padding_size
    after = stats()
    check(
        "unchanged code creation does not invalidate",
        after["item_topology_invalidations"] == before["item_topology_invalidations"],
    )
    check("unchanged code creation retains publication", facts(root) == restored)
    check("unchanged code creation retains independent proof", facts(control_root) == control)
    assert ida_funcs.set_func_end(root, original_end)
    settle(root)
    check("restored ownership can republish original value proof", bool(facts(root)))
    check("fixture bytes unchanged", ida_bytes.get_bytes(root, next_root - root) == raw)
    report["passed"] = not report["errors"]
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    tb = error.__traceback__
    report["exception_frames"] = []
    while tb:
        report["exception_frames"].append(
            {"function": tb.tb_frame.f_code.co_name, "line": tb.tb_lineno}
        )
        tb = tb.tb_next

(Path(os.environ["IDAUSR"]).parent / "native_metadata.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][native-metadata] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
