"""Capture every admitted synthetic shadow instruction state without IDB edits."""

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_pro
import ida_segment
import idautils

ROOT = 0x430000
SHADOW = Path(os.environ["CHERNOBOG_SHADOW_FILE"])
EXPECTED_SHA256 = os.environ["CHERNOBOG_SHADOW_SHA256"]


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        add((int(segment.start_ea), int(segment.end_ea), int(segment.bitness), int(segment.perm)))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            function = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    None if function is None else int(function.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                )
            )
            refs = sorted(
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                for ref in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            assert references <= 2097152
            add(refs)
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        function = ida_funcs.get_func(ea)
        add((ea, int(function.flags), list(idautils.Chunks(ea))))
    add(list(idautils.Names()))
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


def api(name, *args):
    value = ida_expr.idc_value_t()
    expression = name + "(" + ",".join(str(arg) for arg in args) + ")"
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


report = {"checks": [], "errors": []}


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    raw = SHADOW.read_bytes()
    assert len(raw) == 65536
    report["shadow_sha256"] = hashlib.sha256(raw).hexdigest()
    assert report["shadow_sha256"] == EXPECTED_SHA256
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    result = api("chernobog_vm_trace_candidate_shadow_states", ROOT, 0, json.dumps(str(SHADOW)))
    report["capture"] = result
    report["inventory_after"] = inventory()
    check("shadow state capture available", result["available"] and result["ran"])
    check(
        "synthetic shadow scope retained",
        result["runtime_shadow"]
        and result["shadow_instruction_states"]
        and result["synthetic_entry"]
        and result["scope"] == "native-candidate-region"
        and not result["function_evidence_published"]
        and not result["vm_identity_proved"],
    )
    check(
        "bounded instruction states complete",
        result["native_state_capture_requested"]
        and result["native_state_capture_complete"]
        and result["instruction_count"] == 4096
        and len(result["execution"]) == 4096
        and result["stop"] == "instruction-budget",
    )
    execution = {row["sequence"]: row for row in result["execution"]}
    sampled = [row for row in result["states"] if row["kind"] == "native instruction entry"]
    check(
        "every entered instruction has exact-sequence state",
        len(sampled) == len(execution)
        and len({row["sequence"] for row in sampled}) == len(sampled)
        and all(
            row["sequence"] in execution
            and row["site"] == execution[row["sequence"]]["site"]
            and len(row["registers"].split(";")) == 18
            for row in sampled
        ),
    )
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "shadow_states.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][shadow-states] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
