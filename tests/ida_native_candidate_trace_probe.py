"""Inspect synthetic execution from a protected executable data-head root."""

import hashlib
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_pro
import ida_segment
import idautils

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_CANDIDATE_ROOT"], 0)
CODE = int(os.environ["CHERNOBOG_CANDIDATE_CODE_CONTROL"], 0)
NONEXEC = int(os.environ["CHERNOBOG_CANDIDATE_NONEXEC_CONTROL"], 0)


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
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    report["ordinary"] = api("chernobog_vm_trace", ROOT, 0)
    report["ordinary_code"] = api("chernobog_vm_trace", CODE, 0)
    report["candidate"] = api("chernobog_vm_trace_candidate", ROOT, 0)
    report["explicit_empty_input"] = api(
        "chernobog_vm_trace_candidate_input", ROOT, 0, json.dumps('{"args":[],"objects":[]}')
    )
    report["controls"] = {
        "data_tail": api("chernobog_vm_trace_candidate", ROOT + 1, 0),
        "code_head": api("chernobog_vm_trace_candidate", CODE, 0),
        "nonexecutable": api("chernobog_vm_trace_candidate", NONEXEC, 0),
        "invalid_input": api("chernobog_vm_trace_candidate_input", ROOT, 0, json.dumps("{}")),
    }
    report["inventory_after"] = inventory()
    candidate = report["candidate"]
    check(
        "synthetic candidate is distinct from ordinary function capture",
        not report["ordinary"]["available"]
        and candidate["available"]
        and candidate["scope"] == "native-candidate-region"
        and candidate["candidate_decode"]
        and candidate["synthetic_entry"]
        and candidate["root"] == hex(ROOT)
        and candidate["function_evidence_published"] is False
        and candidate["vm_identity_proved"] is False,
    )
    check(
        "ordinary owned-function trace retains its prior contract",
        report["ordinary_code"]["available"]
        and report["ordinary_code"]["scope"] == "native-region"
        and report["ordinary_code"]["function"] == hex(CODE)
        and "candidate_decode" not in report["ordinary_code"]
        and "root" not in report["ordinary_code"],
    )
    check(
        "candidate retains bounded plan and explicit execution outcome",
        0 < candidate["planned_heads"] <= 4096
        and candidate["address_bits"] == 64
        and isinstance(candidate["ran"], bool)
        and isinstance(candidate["stop"], str)
        and candidate["heads"][0]["site"] == hex(ROOT),
    )
    check(
        "explicit empty input follows the separate candidate API",
        report["explicit_empty_input"]["available"]
        and report["explicit_empty_input"]["explicit_input"] is True
        and report["explicit_empty_input"]["scope"] == "native-candidate-region",
    )
    check(
        "invalid roots and input abstain",
        all(not row["available"] for row in report["controls"].values())
        and all(
            report["controls"][key]["reason"] == "not_unlabeled_executable_data_head"
            for key in ("data_tail", "code_head", "nonexecutable")
        )
        and report["controls"]["invalid_input"]["reason"] == "invalid bounded native input",
    )
    check(
        "native candidate capture preserves checked IDB inventory",
        report["inventory_before"] == report["inventory_after"],
    )
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "candidate_trace.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][candidate-trace] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
