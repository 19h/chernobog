"""Inspect the restored supplied VMP hello window through the native shadow API."""

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

ROOT = 0x100001440
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])


def inventory():
    segment = ida_segment.getseg(ROOT)
    if segment is None:
        raise RuntimeError("missing main segment")
    data, mask = ida_bytes.get_bytes_and_mask(segment.start_ea, segment.end_ea - segment.start_ea)
    checked = []
    for ea in (ROOT, ROOT + 22, ROOT + 28):
        flags = ida_bytes.get_full_flags(ea)
        owner = ida_funcs.get_func(ea)
        checked.append(
            {
                "site": hex(ea),
                "flags": int(flags),
                "head": bool(ida_bytes.is_head(flags)),
                "data": bool(ida_bytes.is_data(flags)),
                "unknown": bool(ida_bytes.is_unknown(flags)),
                "loaded": bool(ida_bytes.is_loaded(ea)),
                "owner": None if owner is None else hex(owner.start_ea),
                "item_end": hex(ida_bytes.get_item_end(ea)),
                "incoming": [
                    [hex(ref.frm), int(ref.type), bool(ref.iscode)] for ref in idautils.XrefsTo(ea)
                ],
            }
        )
    return {
        "segment": {
            "start": hex(segment.start_ea),
            "end": hex(segment.end_ea),
            "permissions": int(segment.perm),
            "bitness": int(segment.bitness),
        },
        "bytes_mask_sha256": hashlib.sha256(data + mask).hexdigest(),
        "sites": checked,
    }


def api(name, *args):
    result = ida_expr.idc_value_t()
    call = name + "(" + ",".join(str(value) for value in args) + ")"
    if ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, call):
        raise RuntimeError("IDC call failed")
    return json.loads(result.c_str())


report = {"checks": [], "errors": []}


def check(label, condition):
    passed = bool(condition)
    report["checks"].append({"case": label, "passed": passed})
    if not passed:
        report["errors"].append(label)


try:
    window = WINDOW.read_bytes()
    if len(window) != 40:
        raise RuntimeError("unexpected runtime window length")
    report["window_sha256"] = hashlib.sha256(window).hexdigest()
    if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
        raise RuntimeError("plugin load failed")
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    loaded = [bool(ida_bytes.is_loaded(ROOT + offset)) for offset in range(len(window))]
    current = [
        ida_bytes.get_byte(ROOT + offset) if loaded[offset] else None
        for offset in range(len(window))
    ]
    report["overlay_oracle"] = {
        "newly_loaded": sum(not value for value in loaded),
        "changed_loaded": sum(
            loaded[offset] and current[offset] != value for offset, value in enumerate(window)
        ),
    }
    report["shadow"] = api("chernobog_vm_trace_candidate_shadow", ROOT, 0, json.dumps(str(WINDOW)))
    report["controls"] = {
        "ordinary_candidate": api("chernobog_vm_trace_candidate", ROOT, 0),
        "interior_unloaded": api(
            "chernobog_vm_trace_candidate_shadow", ROOT + 1, 0, json.dumps(str(WINDOW))
        ),
        "literal_without_code_xref": api(
            "chernobog_vm_trace_candidate_shadow", ROOT + 28, 0, json.dumps(str(WINDOW))
        ),
        "existing_code": api(
            "chernobog_vm_trace_candidate_shadow", 0x100001436, 0, json.dumps(str(WINDOW))
        ),
        "missing_shadow": api(
            "chernobog_vm_trace_candidate_shadow",
            ROOT,
            0,
            json.dumps(str(WINDOW.parent / "missing-window.bin")),
        ),
        "oversized_shadow": api(
            "chernobog_vm_trace_candidate_shadow",
            ROOT,
            0,
            json.dumps(os.environ["CHERNOBOG_VMP_HELLO_OVERSIZED"]),
        ),
    }
    report["inventory_after"] = inventory()
    result = report["shadow"]
    expected_available = os.environ.get("CHERNOBOG_VMP_HELLO_EXPECT_AVAILABLE", "1") == "1"
    check(
        "packed entry root is code referenced, unloaded and ownerless",
        report["inventory_before"]["sites"][0]["unknown"]
        and not report["inventory_before"]["sites"][0]["loaded"]
        and report["inventory_before"]["sites"][0]["owner"] is None
        and any(row[2] for row in report["inventory_before"]["sites"][0]["incoming"]),
    )
    if expected_available:
        check(
            "restored code and literal shadow admitted ephemerally",
            result["available"]
            and result["runtime_shadow"]
            and result["shadow_unloaded_entry"]
            and result["shadow_bytes"] == 40
            and result["shadow_newly_loaded_bytes"] == 34
            and result["shadow_changed_bytes"] == 4
            and result["shadow_segments"] == 2
            and result["shadow_newly_loaded_bytes"] == report["overlay_oracle"]["newly_loaded"]
            and result["shadow_changed_bytes"] == report["overlay_oracle"]["changed_loaded"]
            and result["scope"] == "native-candidate-region"
            and not result["function_evidence_published"]
            and not result["vm_identity_proved"],
        )
        check(
            "bounded graph and call frontier explicit",
            result["planned_heads"] == 9
            and result["instruction_count"] == 6
            and result["stop"] == "environment-model-failure"
            and result["execution"][0]["site"] == hex(ROOT)
            and any(row["site"] == "0x100001456" for row in result["heads"])
            and all(
                window[int(row["site"], 16) - ROOT : int(row["site"], 16) - ROOT + int(row["size"])]
                == bytes.fromhex(row["bytes"])
                for row in result["heads"]
            )
            and any(
                row["site"] == "0x100001456" and row["reason"] == "indirect_targets_not_enumerated"
                for row in result["frontiers"]
            ),
        )
    else:
        check(
            "prior plugin abstains at unloaded protected main",
            not result["available"] and result["reason"] == "not_unlabeled_executable_data_head",
        )
    check(
        "unsupported roots and files abstain",
        all(not row["available"] for row in report["controls"].values()),
    )
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_shadow.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][vmp-hello-shadow] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
