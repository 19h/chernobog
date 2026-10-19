"""Check caller-context specialization and refusal cases in an isolated IDB."""

import json
import os
import re
from pathlib import Path

import ida_auto
import ida_expr
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_name
import ida_pro


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


def check_constant(text, expected):
    match = re.search(r"\breturn\s+(true|false|0x[0-9a-f]+|\d+)[uUlL]*\s*;", text, re.IGNORECASE)
    if not match:
        raise RuntimeError("Expected constant return " + str(expected))
    literal = match[1].lower()
    value = {"true": 1, "false": 0}.get(literal)
    if value is None:
        value = int(literal, 0)
    if value != expected:
        raise RuntimeError("Expected constant return " + str(expected))


def validate_capture(name, text, constants, retained):
    if name in constants:
        check_constant(text, constants[name])
    if name in retained and not re.search(r"\b" + re.escape(retained[name]) + r"\s*\(", text):
        raise RuntimeError("Observable or varying call was removed: " + name)
    if name in ("mba_call_loop", "mba_call_address_escaped") and re.search(
        r"return\s+(?:0x[0-9a-f]+|\d+)[uUlL]*\s*;", text, re.IGNORECASE
    ):
        raise RuntimeError("Loop-entry value escaped into the loop exit")
    if name in ("main", "block_decrypt_strings") and re.search(
        r"\b(?:mba_transform_[12]|opaque_predicate_[12])\s*\(", text
    ):
        raise RuntimeError("A constant helper call remains in " + name)
    if name == "block_decrypt_strings" and re.search(r"0x9E432F2E|2655203118", text, re.IGNORECASE):
        raise RuntimeError("The impossible helper comparison remains")


def main():
    report = {"functions": [], "errors": []}
    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays is unavailable")
        if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
            raise RuntimeError("Requested plugin did not load")
        evaluate("chernobog_activate()")
        evaluate('chernobog_set_option("rax", 0)')
        evaluate('chernobog_set_option("mba_smt", 1)')
        use_views = os.environ.get("CHERNOBOG_MBA_CALL_VIEWS") == "1"
        if use_views:
            evaluate('chernobog_set_option("auto", 1)')

        constants = {
            "mba_call_xor_constants": 0,
            "mba_call_selector_constants": 27,
            "mba_call_quotient_constants": 3,
            "mba_call_product_constants": 0x75FAAFFD,
            "mba_call_invariant_quotient": 42,
            "mba_call_invariant_nonzero": 1,
            "mba_call_shared_arguments": 0,
            "mba_call_narrow_result": 0x45,
        }
        retained = {
            "mba_call_varying": "opaque_predicate_1",
            "mba_call_impure": "mba_call_impure_helper",
            "mba_call_memory": "mba_call_load_helper",
            "mba_call_address_escaped": "mba_call_mutate_helper",
        }
        names = (
            ("main", "block_decrypt_strings")
            if os.environ.get("CHERNOBOG_MBA_CALL_PROBE") == "foo"
            else tuple(constants) + tuple(retained) + ("mba_call_loop",)
        )
        for name in names:
            entry = address(name)
            captures = {}
            report["functions"].append({"name": name, "captures": captures})
            profiles = (
                (("view", None),)
                if use_views
                else (
                    ("normal", "chernobog_deobfuscate_text"),
                    ("deep", "chernobog_deep_deobfuscate_text"),
                )
            )
            for profile, api in profiles:
                if use_views:
                    view = ida_hexrays.open_pseudocode(entry, 0)
                    if view is None:
                        raise RuntimeError("Pseudocode view did not open")
                    text = str(view.cfunc)
                else:
                    text = evaluate(f"{api}({entry})")
                captures[profile] = text
                try:
                    validate_capture(name, text, constants, retained)
                except RuntimeError as error:
                    report["errors"].append(f"{name}/{profile}: {error}")

        if not use_views and os.environ.get("CHERNOBOG_MBA_CALL_PROBE") != "foo":
            evaluate('chernobog_set_option("mba_smt", 0)')
            entry = address("mba_call_xor_constants")
            disabled = evaluate(f"chernobog_deobfuscate_text({entry})")
            if not re.search(r"\bmba_transform_2\s*\(", disabled):
                report["errors"].append("The MBA disable option did not preserve the helper call")
            report["disabled"] = disabled
            evaluate('chernobog_set_option("mba_smt", 1)')
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")

    output = Path(os.environ["IDAUSR"]).parent / "mba_calls.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["errors"]:
        print("[chernobog][mba-calls] FAIL " + "; ".join(report["errors"]), flush=True)
        ida_pro.qexit(1)
    print(f"[chernobog][mba-calls] PASS functions={len(report['functions'])}", flush=True)
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()
