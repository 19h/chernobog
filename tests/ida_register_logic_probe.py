"""Compare production register-logic facts in fresh paired IDA runs."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import idautils

NEW = (
    "rl_and_zero",
    "rl_or_nonzero",
    "rl_xor_sign",
    "rl_test_zero",
    "rl_test_nonzero",
    "rl_and_chain",
    "rl_or_chain",
    "rl_xor_chain",
    "rl_self_and",
    "rl_two_and",
    "rl_two_or",
    "rl_two_xor",
    "rl_two_test",
)
STABLE = ("rl_self_xor",)
UNKNOWN = ("rl_test_unknown", "rl_or_unknown", "rl_two_test_unknown")


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("fixture symbol missing: " + name)


def inspect(ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_native_evidence({ea})")
    return json.loads(value.c_str())


def inventory(ea):
    return [
        (
            site,
            ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)),
            ida_bytes.get_cmt(site, True),
            ida_bytes.get_cmt(site, False),
        )
        for site in idautils.FuncItems(ea)
    ]


def main():
    output = Path(os.environ["IDAUSR"]).parent
    result = {"passed": False, "errors": [], "captures": {}}
    try:
        assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
        ida_auto.auto_wait()
        improved = os.environ["CHERNOBOG_EXPECT_REGISTER_LOGIC"] == "1"
        for name in NEW + STABLE + UNKNOWN:
            ea = address(name)
            before = inventory(ea)
            capture = inspect(ea)
            result["captures"][name] = capture
            assert capture["available"]
            assert before == inventory(ea)
            assert capture == inspect(ea)
            proofs = [
                row
                for row in capture["records"]
                if row["kind"] == "setcc-value"
                and row["truth"] == "native-proof"
                and row["fresh"] == "true"
            ]
            expected = int(name in STABLE or (improved and name in NEW))
            assert len(proofs) == expected, (name, proofs)
            assert all(row["value"] == "0x1" and row["width_bits"] == "8" for row in proofs)
        result["passed"] = True
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    (output / "register_logic.json").write_text(json.dumps(result, indent=2) + "\n")
    print("[chernobog][register-logic] " + ("PASS" if result["passed"] else "FAIL"), flush=True)
    ida_pro.qexit(0 if result["passed"] else 1)


main()
