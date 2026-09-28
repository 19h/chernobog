"""Check oversized-owner abstention and same-IDB tail invalidation in IDA."""

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
import idautils


def address(name):
    for symbol in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, symbol)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing symbol " + name)


def inspect(root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_condition_diagnostics({root})"
    )
    return json.loads(value.c_str())


def site_decision(root):
    result = inspect(root)
    rows = [row for row in result["records"] if row["kind"] == "setcc"]
    assert result["available"] and len(rows) == 1
    return rows[0]["decision"], rows[0]["support_count"]


def heads(root):
    return len(list(idautils.FuncItems(root)))


report = {"schema": 1, "checks": [], "errors": []}


def check(name, passed):
    report["checks"].append({"case": name, "passed": bool(passed)})
    if not passed:
        report["errors"].append(name)


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    root, filler = address("cache_condition"), address("cache_filler")
    function = ida_funcs.get_func(root)
    extra = ida_funcs.get_func(filler)
    assert function is not None and function.start_ea == root
    assert extra is not None and extra.start_ea == filler
    filler_end = extra.end_ea
    report["baseline"] = {"heads": heads(root), "decision": site_decision(root)}
    check("small owned graph decides false", report["baseline"]["decision"][0] == "false")
    assert ida_funcs.del_func(filler)
    assert ida_funcs.append_func_tail_ea(root, filler, filler_end)
    report["oversized"] = {"heads": heads(root), "decision": site_decision(root)}
    check("owner exceeds graph inventory", report["oversized"]["heads"] > 4096)
    check("oversized owner abstains", report["oversized"]["decision"][0] == "unknown")
    check("repeat oversized query agrees", site_decision(root) == report["oversized"]["decision"])
    check("oversized owner is one head over limit", report["oversized"]["heads"] == 4097)
    pair = filler + 8
    report["pair_before"] = (ida_bytes.get_bytes(pair, 2) or b"").hex()
    assert report["pair_before"] == "9090", "pair bytes"
    assert ida_bytes.del_items(pair, ida_bytes.DELIT_SIMPLE, 2), "delete two NOP heads"
    ida_bytes.patch_bytes(pair, b"\x66\x90")
    assert ida_bytes.get_bytes(pair, 2) == b"\x66\x90", "patch two-byte NOP"
    assert ida_ua.create_insn(pair) == 2, "create two-byte NOP"
    report["at_limit"] = {"heads": heads(root), "decision": site_decision(root)}
    check("item edit reaches exact graph limit", report["at_limit"]["heads"] == 4096)
    check("item edit invalidates rejection", report["at_limit"]["decision"][0] == "false")
    assert ida_funcs.remove_func_tail_ea(root, filler)
    assert ida_funcs.append_func_tail_ea(root, filler, filler_end)
    report["at_limit_after_tail_refresh"] = {
        "heads": heads(root),
        "decision": site_decision(root),
    }
    check(
        "item edit agrees with independent topology refresh",
        report["at_limit_after_tail_refresh"] == report["at_limit"],
    )
    assert ida_bytes.del_items(pair, ida_bytes.DELIT_SIMPLE, 2)
    ida_bytes.patch_bytes(pair, b"\x90\x90")
    assert ida_bytes.get_bytes(pair, 2) == b"\x90\x90"
    assert ida_ua.create_insn(pair) == 1
    assert ida_ua.create_insn(pair + 1) == 1
    report["item_restored"] = {"heads": heads(root), "decision": site_decision(root)}
    check("item restoration returns to abstention", report["item_restored"] == report["oversized"])
    report["tail_before_removal"] = {
        "owner": hex(ida_funcs.get_func(filler).start_ea),
        "chunks": [[hex(first), hex(end)] for first, end in idautils.Chunks(root)],
    }
    assert ida_funcs.remove_func_tail_ea(root, filler), report["tail_before_removal"]
    report["restored"] = {"heads": heads(root), "decision": site_decision(root)}
    check("tail removal restores graph decision", report["restored"]["decision"][0] == "false")
    check("tail removal restores original support", report["restored"] == report["baseline"])
    assert ida_funcs.append_func_tail_ea(root, filler, filler_end)
    report["readded"] = {"heads": heads(root), "decision": site_decision(root)}
    check("tail readdition restores abstention", report["readded"] == report["oversized"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "oversized_owner_cache.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][oversized-owner-cache] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
