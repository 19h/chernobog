"""Check live SHLD/SHRD decoding and production abstract-state proofs."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua
import idautils

POSITIVE = (
    "ds_shld_register",
    "ds_shrd_register",
    "ds_shld_carry",
    "ds_shrd_overflow",
    "ds_zero_count",
    "ds_alias",
    "ds_shld_64",
    "ds_shrd_64",
    "ds_count_alias",
    "ds_memory",
    "ds_preserve_unrelated",
    "ds_preserve_disjoint_memory",
)
NEGATIVE = ("ds_unknown_count", "ds_unknown_count_upper", "ds_undefined_count")


def address(name):
    for candidate in (name, "_" + name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing fixture symbol " + name)


def evidence(root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_evidence({root})"
    )
    return json.loads(value.c_str())


def main():
    output = Path(os.environ["IDAUSR"]).parent
    report = {"passed": False, "errors": [], "cases": {}}
    try:
        assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
        ida_auto.auto_wait()
        for name in POSITIVE + NEGATIVE:
            root = address(name)
            assert ida_funcs.get_func(root) or ida_funcs.add_func(root)
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(function.start_ea, function.end_ea)
            decoded = []
            for ea in idautils.FuncItems(root):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea) > 0 and insn.itype in (
                    ida_allins.NN_shld,
                    ida_allins.NN_shrd,
                ):
                    decoded.append(
                        {
                            "itype": int(insn.itype),
                            "operands": [
                                {"type": int(op.type), "dtype": int(op.dtype)}
                                for op in (insn.Op1, insn.Op2, insn.Op3)
                            ],
                        }
                    )
            assert len(decoded) == 1, (name, decoded)
            view = evidence(root)
            assert view["available"], (name, view)
            proofs = [
                row
                for row in view["records"]
                if row["kind"] == "setcc-value"
                and row["truth"] == "native-proof"
                and row["fresh"] == "true"
            ]
            report["cases"][name] = {"decoded": decoded, "proofs": proofs}
            if name in POSITIVE:
                assert len(proofs) == 1 and proofs[0]["value"] == "0x1", (name, proofs)
            else:
                assert not proofs, (name, proofs)
        report["passed"] = True
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    (output / "double_shift.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][double-shift] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
    ida_pro.qexit(0 if report["passed"] else 1)


main()
