"""Measure use-string yield without forcing ownership or completing stopped runs."""

import json
import os
from pathlib import Path
import sys
import time

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_pro
import ida_ua

sys.dont_write_bytecode = True


def evaluate(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression), "IDC failure"
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    return result.i64 if result.vtype == ida_expr.VT_INT64 else result.num


report = {"schema": 1, "passed": False, "errors": [], "candidates": []}
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "decompiler unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    target = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
    function = ida_funcs.get_func(target)
    report["entry"] = hex(target)
    report["entry_owner"] = hex(function.start_ea) if function else None
    started = time.perf_counter_ns()
    report["explore_result"] = int(evaluate(f"chernobog_rax_explore({target})"))
    report["explore_elapsed_ns"] = time.perf_counter_ns() - started
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    report["view"] = {
        key: value for key, value in view.items() if key not in ("events", "edges", "claims")
    }
    count = int(evaluate(f"chernobog_rax_use_string_count({target})"))
    assert 0 <= count <= 128, "candidate quota exceeded"
    for index in range(count):
        expression = f"chernobog_rax_use_string({target}, {index})"
        report["candidates"].append(
            {
                field: evaluate(expression + "." + field)
                for field in (
                    "ok",
                    "value",
                    "site",
                    "occurrence",
                    "producer",
                    "model_kind",
                    "read_count",
                    "first_sequence",
                    "last_sequence",
                    "observed_bytes",
                    "observations",
                    "eligible_runs",
                )
            }
        )
    # Decode the reported stop only; do not create code or extend any function.
    report["stops"] = []
    for run in view.get("runs", []):
        site = int(run["site"], 0)
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, site) if site else 0
        owner = ida_funcs.get_func(site) if site else None
        report["stops"].append(
            {
                "run": run["run"],
                "seed": run["seed"],
                "site": hex(site),
                "owner": hex(owner.start_ea) if owner else None,
                "bytes": (ida_bytes.get_bytes(site, size) or b"").hex() if size > 0 else "",
                "mnemonic": instruction.get_canon_mnem() if size > 0 else "",
            }
        )
    report["display"] = {"status": "unavailable", "annotations": []}
    if function and function.start_ea == target:
        failure = ida_hexrays.hexrays_failure_t()
        started = time.perf_counter_ns()
        cfunc = ida_hexrays.decompile(target, failure, ida_hexrays.DECOMP_NO_CACHE)
        report["display"]["elapsed_ns"] = time.perf_counter_ns() - started
        if cfunc:
            report["display"].update(
                status="decompiled",
                annotations=[
                    ida_lines.tag_remove(line.line)
                    for line in cfunc.get_pseudocode()
                    if "rax-use(" in ida_lines.tag_remove(line.line)
                ],
            )
        else:
            report["display"].update(status="failed", failure_code=int(failure.code))
    report["passed"] = True
except BaseException as error:
    # Host exception messages may contain identifying installation paths.
    report["errors"].append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "protected_strings.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][protected-strings] " + ("PASS" if report["passed"] else "FAIL")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
