"""Capture nested MBA reductions, retaining the 32-bit arithmetic boundary."""

import json
import os
import re
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_typeinf

FUNCTIONS = (
    "mba_nested_1",
    "mba_nested_2",
    "mba_nested_3",
    "mba_nested_combined",
    "mba_nested_solve",
    "mba_nested_caller",
)


def evaluate(expression):
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if error:
        raise RuntimeError(str(error))
    return result.c_str() if result.vtype == ida_expr.VT_STR else result.num


def address(name):
    for symbol in (name, "_" + name):
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, symbol)
        if result != ida_idaapi.BADADDR:
            return result
    raise RuntimeError("Missing function: " + name)


def main():
    report = {"functions": [], "errors": []}
    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays is unavailable")
        if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
            raise RuntimeError("The requested plugin did not load")

        for name in FUNCTIONS:
            prototype = f"unsigned __int64 {name}(unsigned int x, unsigned int y, unsigned int z);"
            if not ida_typeinf.apply_cdecl(None, address(name), prototype):
                raise RuntimeError("Could not apply fixture prototype: " + name)

        evaluate("chernobog_activate()")
        evaluate('chernobog_set_option("rax", 0)')
        evaluate('chernobog_set_option("mba_smt", 1)')
        selected = os.environ.get("CHERNOBOG_MBA_NESTED_FUNCTIONS")
        names = tuple(selected.split(",")) if selected else FUNCTIONS
        if (
            not names
            or len(set(names)) != len(names)
            or any(name not in FUNCTIONS for name in names)
        ):
            raise RuntimeError("Invalid nested MBA function selection")
        for name in names:
            entry = address(name)
            function = ida_funcs.get_func(entry)
            original = ida_bytes.get_bytes(entry, function.end_ea - entry)
            captures = {}
            statistics = {}
            for profile, api in (
                ("normal", "chernobog_deobfuscate_text"),
                ("deep", "chernobog_deep_deobfuscate_text"),
            ):
                text = evaluate(f"{api}({entry})")
                body = text.partition("{")[2] if text else ""
                if not body or re.search(r"[&|^~]|\bmba_nested_\w+\s*\(", body):
                    report["errors"].append(f"Nested MBA remains in {name} ({profile}): {text}")
                captures[profile] = text
                statistics[profile] = json.loads(evaluate(f"chernobog_mba_smt_stats({entry})"))
            if ida_bytes.get_bytes(entry, len(original)) != original:
                raise RuntimeError("Native instructions changed: " + name)
            report["functions"].append(
                {"name": name, "captures": captures, "statistics": statistics}
            )
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")

    output = Path(os.environ["IDAUSR"]).parent / "mba_nested.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["errors"]:
        print("[chernobog][mba-nested] FAIL " + "; ".join(report["errors"]), flush=True)
    else:
        print(f"[chernobog][mba-nested] PASS functions={len(report['functions'])}", flush=True)
    ida_pro.qexit(int(bool(report["errors"])))


if __name__ == "__main__":
    main()
