"""Four-seed named-model native state and local VM transition capture."""

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_expr
import ida_idaapi
import ida_loader
import ida_name
import ida_pro

sys.dont_write_bytecode = True
report = {"passed": False, "runs": [], "errors": []}


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    label = os.environ["CHERNOBOG_VARIANT_LABEL"]
    entry = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
    bindings = []
    for name in ("_malloc", "_memset", "_free"):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert address != ida_idaapi.BADADDR
        bindings.append({"address": hex(address), "name": name})
    request = json.dumps({"args": [], "objects": []})
    models = json.dumps(bindings)

    def capture(seed, sampled):
        name = "chernobog_vm_trace_temporal_check" if sampled else "chernobog_vm_trace_temporal"
        return evaluate(f"{name}({entry},{seed},{json.dumps(request)},{json.dumps(models)})")

    for seed in (0, 1, 17, 0xC0FFEE):
        trace = capture(seed, True)
        view = trace["native_observations"]
        candidates = trace["native_vm_candidates"]
        samples = [
            state for state in trace["states"] if state["kind"] == "native instruction entry"
        ]
        partial = sum(len(state["registers"].split(";")) < 18 for state in samples)
        verdicts = [
            {
                key: row.get(key)
                for key in (
                    "site",
                    "read",
                    "dispatch",
                    "target",
                    "path",
                    "internal_transfers",
                    "semantic_validation",
                    "transition_reason",
                    "transition_queries",
                    "accesses_captured",
                    "entry_vip",
                    "output_vip",
                    "entry_key",
                    "output_key",
                    "entry_dispatch_base",
                    "output_dispatch_base",
                )
            }
            for row in view["records"]
        ]
        result = {
            "seed": hex(seed),
            "available": trace["available"],
            "ran": trace["ran"],
            "instruction_count": trace["instruction_count"],
            "execution_count": len(trace["execution"]),
            "state_count": len(trace["states"]),
            "sample_count": len(samples),
            "partial_samples": partial,
            "sample_requested": trace["native_state_capture_requested"],
            "sample_complete": trace["native_state_capture_complete"],
            "temporal_complete": trace["native_temporal_complete"],
            "prefix_complete": trace["native_temporal_prefix_complete"],
            "data_complete": trace["data_trace_complete"],
            "function_published": trace["function_evidence_published"],
            "vm_identity_proved": trace["vm_identity_proved"],
            "image_hash": trace["image_hash"],
            "candidate_count": len(candidates["records"]),
            "candidate_limited": candidates["limited"],
            "view_available": view["available"],
            "view_reason": view["reason"],
            "path_limited": view["path_limited"],
            "candidate_visits": view["candidate_visits"],
            "transition_attempts": view["transition_attempts"],
            "queries": view["queries"],
            "verdicts": verdicts,
        }
        report["runs"].append(result)
        assert trace["available"] and trace["ran"] and result["sample_requested"]
        assert result["sample_count"] == result["execution_count"]
        assert not result["function_published"] and not result["vm_identity_proved"]
        assert not result["candidate_limited"] and not result["path_limited"]
        assert all(
            row["semantic_validation"] != "modeled transition counterexample" for row in verdicts
        )
        if label.startswith(("original", "mutation")):
            assert result["temporal_complete"]
            assert result["candidate_count"] == result["candidate_visits"] == 0
            assert result["view_available"] and not verdicts
        else:
            assert not result["temporal_complete"]
            if not result["view_available"]:
                assert not result["prefix_complete"] and not result["sample_complete"]
                assert result["candidate_visits"] == result["queries"] == 0
                assert (
                    result["view_reason"]
                    == "complete native instruction-entry or temporal event prefix required"
                )
        if label == "virtualization-0" and seed == 0:
            target = [row for row in verdicts if row["site"] == "0x1000d64db"]
            assert len(target) == 1
            row = target[0]
            assert row["read"] == "0x1000d64ea" and row["dispatch"] == "0x10008ef17"
            assert row["target"] == "0x100007031"
            assert row["semantic_validation"] == "corroborated for captured transition"
            assert row["transition_queries"] == "2" and row["accesses_captured"] == "5"
            assert row["path"] == "complete captured native path"
            assert row["internal_transfers"] == "exact captured witnesses"
            assert int(row["entry_vip"], 16) - int(row["output_vip"], 16) == 4
        plain = capture(seed, False)
        result["comparison"] = {
            "execution": [point["site"] for point in plain["execution"]]
            == [point["site"] for point in trace["execution"]],
            "heads": plain["heads"] == trace["heads"],
            "edges": plain["edges"] == trace["edges"],
            "data": plain["data"] == trace["data"],
            "candidates": len(plain["native_vm_candidates"]["records"])
            == result["candidate_count"],
        }
        assert all(result["comparison"].values())
    report["passed"] = True
except Exception as error:
    report["errors"].append(type(error).__name__)
finally:
    (Path(os.environ["IDAUSR"]).parent / "vm_temporal_state.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print("[chernobog][vm_temporal_state] " + ("PASS" if report["passed"] else "FAIL"))
    ida_pro.qexit(0 if report["passed"] else 1)
