"""Inspect live partial-result status facts in fresh x86 IDA databases."""

import json
import os
from pathlib import Path
import traceback

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

POSITIVE = (
    "ps_or_nonzero",
    "ps_or_sign",
    "ps_or_parity",
    "ps_xor_sign",
    "ps_and_sign",
    "ps_test_zero",
    "ps_test_nonzero",
    "ps_test_same_sign",
)
NEGATIVE = ("ps_or_unknown", "ps_test_unknown")


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
        improved = os.environ["CHERNOBOG_EXPECT_PARTIAL_STATUS"] == "1"
        for name in POSITIVE + NEGATIVE:
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
            expected = int(improved and name in POSITIVE)
            assert len(proofs) == expected, (name, proofs)
            assert all(row["value"] == "0x1" and row["width_bits"] == "8" for row in proofs)
        root = address("ps_and_sign")
        function = ida_funcs.get_func(root)
        assert function
        start, end = function.start_ea, function.end_ea
        sites = [
            site
            for site in idautils.FuncItems(root)
            if ida_bytes.get_bytes(site, 3) == bytes.fromhex("83e101")
        ]
        assert len(sites) == 1, (sites, inventory(root))
        site = sites[0]
        try:
            ida_bytes.patch_bytes(site, bytes.fromhex("f085c9"))
            assert ida_bytes.get_bytes(site, 3) == bytes.fromhex("f085c9")
            ida_auto.plan_and_wait(start, end)
            instruction = ida_ua.insn_t()
            decoded = ida_ua.decode_insn(instruction, site)
            result["locked_decode"] = {
                "size": decoded,
                "mnemonic": instruction.get_canon_mnem() if decoded else None,
                "auxpref": int(instruction.auxpref) if decoded else None,
            }
            assert decoded == 3 and instruction.get_canon_mnem() == "test"
            assert instruction.auxpref & 1  # intel.hpp aux_lock
            altered = inspect(root)
            result["captures"]["locked_test"] = altered
            assert not any(
                row["kind"] == "setcc-value" and row["truth"] == "native-proof"
                for row in altered["records"]
            )
        finally:
            ida_bytes.patch_bytes(site, bytes.fromhex("83e101"))
            ida_auto.plan_and_wait(start, end)
        restored = inspect(root)
        result["captures"]["restored"] = restored
        assert len(
            [
                row
                for row in restored["records"]
                if row["kind"] == "setcc-value" and row["truth"] == "native-proof"
            ]
        ) == int(improved)
        result["passed"] = True
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
        result["traceback"] = traceback.format_exc()
    (output / "partial_status.json").write_text(json.dumps(result, indent=2) + "\n")
    print("[chernobog][partial-status] " + ("PASS" if result["passed"] else "FAIL"), flush=True)
    ida_pro.qexit(0 if result["passed"] else 1)


main()
