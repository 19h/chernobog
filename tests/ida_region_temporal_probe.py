"""Explicit modeled-region capture and rejection controls on paired strings."""
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_ua

sys.dont_write_bytecode = True
records, errors, traces = [], [], []


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value.c_str() if value.vtype == ida_expr.VT_STR else value.num


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
    bindings = []
    for name in ("_malloc", "_memset", "_free"):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert address != ida_idaapi.BADADDR, "named environment missing"
        bindings.append({"address": hex(address), "name": name})

    def capture(models, seed=0, args=None):
        request = json.dumps({"args": [], "objects": []} if args is None else args)
        models = models if isinstance(models, str) else json.dumps(models)
        return json.loads(evaluate(f"chernobog_vm_trace_temporal({target},{seed},{json.dumps(request)},{json.dumps(models)})"))

    before = evaluate(f"chernobog_evidence_view({target})")
    for seed in (0, 1, 17, 0xC0FFEE):
        trace = capture(bindings, seed)
        traces.append(trace)
        check("available explicit region", trace.get("available") and trace["native_temporal_requested"] and trace["ran"])
        check("separate publication contract", not trace["function_evidence_published"]
              and not trace["vm_identity_proved"] and not trace["temporal_capture_complete"])
        check("bound model identities", trace["environment_bindings"]
              and {(r["address"], r["name"]) for r in trace["environment_bindings"]}
              == {(r["address"], r["name"]) for r in bindings})
        if trace["native_temporal_complete"]:
            registers = {int(r["reg"]): int(r["value"], 0) for r in trace["final_registers"]}
            check("independent native byte oracle", registers.get(0x100) == int.from_bytes(b"secret!\0", "little")
                  and registers.get(0x102) == int.from_bytes(b"second!\0", "little"))
            check("completed allocation lifetimes", len(trace["allocations"]) == 2
                  and all(r["live"] == "false" and int(r["released"]) > int(r["allocated"])
                          for r in trace["allocations"]))
            check("completed modeled stack", trace["reached_sentinel"] and trace["sp_valid"] and trace["sp_delta"] == 8
                  and trace["summarized_calls"] == 6 and not trace["data_trace_complete"])
        else:
            check("incomplete capture remains explicit", not trace["reached_sentinel"])
            instruction = ida_ua.insn_t()
            site = int(trace["stop_pc"], 0)
            size = ida_ua.decode_insn(instruction, site)
            trace["rejected_instruction"] = {"site": hex(site), "bytes": (ida_bytes.get_bytes(site, size) or b"").hex(),
                "mnemonic": instruction.get_canon_mnem() if size > 0 else "",
                "operand_bytes": ida_ua.get_dtype_size(instruction.Op1.dtype) if size > 0 else 0}
            check("undefined BSWAP16 retains boundary", trace["rejected_instruction"]["mnemonic"] == "bswap"
                  and trace["rejected_instruction"]["operand_bytes"] == 2
                  and trace["region_boundary"] and not trace["temporal_capture_complete"])
        if os.environ.get("CHERNOBOG_EXPECT_RETURN") == "1":
            check("positive control complete", trace["native_temporal_complete"])
    check("no ordinary evidence publication", evaluate(f"chernobog_evidence_view({target})") == before)
    invalid = ["{", "[" * 3 + "]" * 3, [], bindings * 11,
               [bindings[0], bindings[0]], [dict(bindings[0], extra=1)],
               [dict(bindings[0], name="unknown_model")], [dict(bindings[0], address="0xffffffffffffffff")],
               [dict(bindings[0], address="0x10000000000000000")],
               [dict(bindings[0], address="0x0")]]
    for models in invalid:
        check("invalid binding rejected", capture(models).get("available") is False)
    check("overlapping caller object rejected", capture(bindings, args={"args": ["0x0"],
        "objects": [{"argument": 0, "offset": 0, "bytes": "00"}]}).get("available") is False)
    old = bindings[0]["name"]
    ea = int(bindings[0]["address"], 0)
    assert ida_name.set_name(ea, "_chernobog_renamed_binding")
    check("renamed binding rejected", capture(bindings).get("available") is False)
    assert ida_name.set_name(ea, old)
except BaseException as error:
    errors.append(type(error).__name__)

report = {"records": records, "errors": errors, "traces": traces}
(Path(os.environ["IDAUSR"]).parent / "region_temporal.json").write_text(json.dumps(report, indent=2) + "\n")
line = "[chernobog][region-temporal] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
