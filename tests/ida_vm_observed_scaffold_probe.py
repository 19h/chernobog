"""Read-only executed VM scaffold check on the pinned protected fixture."""

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
import ida_name
import ida_pro
import ida_ua

sys.dont_write_bytecode = True
result = {"passed": False, "errors": []}


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value.c_str() if value.vtype == ida_expr.VT_STR else value.num


def inventory():
    sites = []
    for address in (0x1000D64DB, 0x1000D64E2, 0x1000D64E6, 0x1000D64E9, 0x1000D64EA):
        flags = ida_bytes.get_full_flags(address)
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, address)
        owner = ida_funcs.get_func(address)
        sites.append(
            {
                "site": hex(address),
                "owner": hex(owner.start_ea) if owner else None,
                "code_head": bool(ida_bytes.is_code(flags) and ida_bytes.is_head(flags)),
                "loaded": bool(ida_bytes.is_loaded(address)),
                "decoded_size": size,
                "bytes": ida_bytes.get_bytes(address, size).hex() if size else None,
            }
        )
    return sites


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    result["before"] = inventory()
    entry = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
    bindings = []
    for name in ("_malloc", "_memset", "_free"):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert address != ida_idaapi.BADADDR
        bindings.append({"address": hex(address), "name": name})
    request = json.dumps({"args": [], "objects": []})
    models = json.dumps(bindings)
    trace = json.loads(
        evaluate(
            f"chernobog_vm_trace_temporal({entry},0,{json.dumps(request)},{json.dumps(models)})"
        )
    )
    view = trace["native_vm_candidates"]
    result["trace"] = {
        key: trace[key]
        for key in (
            "available",
            "ran",
            "native_temporal_complete",
            "native_temporal_prefix_complete",
            "function_evidence_published",
            "vm_identity_proved",
            "instruction_count",
            "region_identity",
            "image_hash",
        )
    }
    result["view"] = view
    matching = [
        row
        for row in view["records"]
        if row["site"] == "0x1000d64db"
        and row["dispatch"] == "0x10008ef17"
        and row["read"] == "0x1000d64ea"
    ]
    result["matching"] = matching
    result["after"] = inventory()
    assert result["before"] == result["after"]
    assert all(
        row["owner"] is None and not row["code_head"] and row["loaded"] and row["decoded_size"]
        for row in result["before"]
    )
    assert trace["available"] and trace["ran"] and view["available"]
    assert trace["native_temporal_prefix_complete"]
    assert not trace["native_temporal_complete"]
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert len(matching) == 1
    row = matching[0]
    assert row["read_bits"] == "32" and row["direction"] == "backward"
    assert row["vip_register"] == "11" and row["value_register"] == "0"
    assert row["key_register"] == "8" and row["dispatch_base_register"] == "10"
    assert row["truth"] == "observed local candidate"
    assert row["observed_target"] == "0x100007031"
    assert row["vm_identity"] == "unknown" and row["other_entries"] == "unknown"
    assert row["region_identity"] == trace["region_identity"]
    result["passed"] = True
except Exception as error:
    result["errors"].append(type(error).__name__)
finally:
    (Path(os.environ["IDAUSR"]).parent / "vm_observed_scaffold.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n"
    )
    print("[chernobog][vm_observed_scaffold] " + ("PASS" if result["passed"] else "FAIL"))
    ida_pro.qexit(0 if result["passed"] else 1)
