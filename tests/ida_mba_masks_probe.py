"""Capture masked flag updates and preserve overlapping XOR and store effects."""

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

PROTOTYPES = {
    "mba_mask_value": "unsigned int mba_mask_value(unsigned int flags, signed char input);",
    "mba_mask_overlap": "unsigned int mba_mask_overlap(unsigned int flags, signed char input);",
    "mba_mask_store": "void mba_mask_store(unsigned int *flags, signed char input);",
    "mba_mask_volatile_store": (
        "void mba_mask_volatile_store(volatile unsigned int *flags, signed char input);"
    ),
    "mba_mask_observe": "void mba_mask_observe(int low, int high);",
}


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


def validate(name, text):
    if not text or "{" not in text:
        raise RuntimeError("Empty pseudocode: " + name)
    body = text.partition("{")[2]
    if name in ("mba_mask_value", "mba_mask_store"):
        if "^" in body or not re.search(r"0xFFFFFFB7|4294967223|-73[uUlL]*|~\s*(?:0x48|72)", body):
            raise RuntimeError("The flag update still has split masks or overlapping XOR: " + name)
        if name == "mba_mask_store" and len(re.findall(r"\binput\s*&\s*1\b", body)) > 1:
            raise RuntimeError("The store did not reuse the available low flag")
    if name == "mba_mask_overlap" and "^" not in body:
        raise RuntimeError("Overlapping flag bits lost their XOR")
    if name in ("mba_mask_store", "mba_mask_volatile_store"):
        if "mba_mask_observe(" not in body or not re.search(r"\*flags\s*=", body):
            raise RuntimeError("The observer call or destination store disappeared: " + name)
        if "if (" not in body:
            raise RuntimeError("The conditional update became unconditional: " + name)


def main():
    report = {"functions": [], "errors": []}
    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays is unavailable")
        if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
            raise RuntimeError("The requested plugin did not load")
        for name, prototype in PROTOTYPES.items():
            if not ida_typeinf.apply_cdecl(None, address(name), prototype):
                raise RuntimeError("Could not apply fixture prototype: " + name)
        evaluate("chernobog_activate()")
        evaluate('chernobog_set_option("rax", 0)')
        evaluate('chernobog_set_option("mba_smt", 1)')

        for name in tuple(PROTOTYPES)[:-1]:
            entry = address(name)
            function = ida_funcs.get_func(entry)
            original = ida_bytes.get_bytes(entry, function.end_ea - entry)
            evaluate('chernobog_set_option("mba_smt", 0)')
            baseline = evaluate(f"chernobog_deobfuscate_text({entry})")
            evaluate('chernobog_set_option("mba_smt", 1)')
            captures = {}
            for profile, api in (
                ("normal", "chernobog_deobfuscate_text"),
                ("deep", "chernobog_deep_deobfuscate_text"),
            ):
                text = evaluate(f"{api}({entry})")
                captures[profile] = text
                try:
                    validate(name, text)
                    if name == "mba_mask_volatile_store":
                        before = len(re.findall(r"\*flags\b", baseline))
                        after = len(re.findall(r"\*flags\b", text))
                        if before != after:
                            raise RuntimeError("The volatile destination access count changed")
                except RuntimeError as error:
                    report["errors"].append(f"{profile}: {error}")
            if ida_bytes.get_bytes(entry, len(original)) != original:
                raise RuntimeError("Native instructions changed: " + name)
            report["functions"].append({"name": name, "baseline": baseline, "captures": captures})
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")

    output = Path(os.environ["IDAUSR"]).parent / "mba_masks.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["errors"]:
        print("[chernobog][mba-masks] FAIL " + "; ".join(report["errors"]), flush=True)
    else:
        print(f"[chernobog][mba-masks] PASS functions={len(report['functions'])}", flush=True)
    ida_pro.qexit(int(bool(report["errors"])))


if __name__ == "__main__":
    main()
