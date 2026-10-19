"""Exercise semantic MBA APIs and scoped profiles in a fresh fixture database."""

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

FIXTURE_FUNCTIONS = (
    "mba_smt_semantic32",
    "mba_smt_quadratic",
    "mba_smt_alias",
    "mba_transform_2",
    "mba_transform_1",
    "opaque_predicate_2",
    "opaque_predicate_1",
)


def evaluate(expression):
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if error:
        raise RuntimeError(str(error))
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    return result.num


def find_function(name):
    for symbol in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, symbol)
        if address != ida_idaapi.BADADDR:
            return address
    raise RuntimeError("Missing fixture function: " + name)


def capture_function(name):
    address = find_function(name)
    function = ida_funcs.get_func(address)
    original_bytes = ida_bytes.get_bytes(address, function.end_ea - address)

    normal = evaluate(f"chernobog_deobfuscate_text({address})")
    normal_stats = json.loads(evaluate(f"chernobog_mba_smt_stats({address})"))

    deep = evaluate(f"chernobog_deep_deobfuscate_text({address})")
    deep_stats = json.loads(evaluate(f"chernobog_mba_smt_stats({address})"))

    restored = evaluate(f"chernobog_deobfuscate_text({address})")
    restored_stats = json.loads(evaluate(f"chernobog_mba_smt_stats({address})"))

    if not normal or not deep or not restored:
        raise RuntimeError("Decompilation failed: " + name)
    if normal_stats["budget_ms"] != 1000 or restored_stats["budget_ms"] != 1000:
        raise RuntimeError("Normal analysis profile was not restored: " + name)
    if deep_stats["budget_ms"] != 30000:
        raise RuntimeError("Deep analysis profile was not applied: " + name)
    if ida_bytes.get_bytes(address, len(original_bytes)) != original_bytes:
        raise RuntimeError("Native instructions changed during expression simplification: " + name)

    returns_zero = re.search(r"\breturn\s+0\s*;", deep) is not None
    if name == "mba_smt_semantic32" and (deep_stats["applied"] == 0 or "37" in deep):
        raise RuntimeError("The encoded arithmetic was not simplified")
    if name == "mba_smt_quadratic":
        if not returns_zero or deep_stats["applied"] == 0 or deep_stats["invariants"] == 0:
            raise RuntimeError("The memory-backed polynomial invariant was not used")
    if name == "mba_smt_alias" and returns_zero:
        raise RuntimeError("Unknown pointer aliases were treated as disjoint")
    if name == "mba_transform_2" and ("^" not in deep or "*" in deep):
        raise RuntimeError("The symbolic byte expression was not reduced to XOR")
    if name == "mba_transform_1" and deep.count("~") > 1:
        raise RuntimeError("The symbolic Boolean selector was not reduced")
    if name == "opaque_predicate_2" and "+" in deep:
        raise RuntimeError("Complemented symbolic words were not reduced")
    if name == "opaque_predicate_1":
        for pseudocode in (normal, deep, restored):
            if "/" in pseudocode:
                raise RuntimeError("The two-valued unsigned quotient was not reduced")
            if not re.search(r"0x50000000|1342177280", pseudocode):
                raise RuntimeError(
                    "The quotient comparison was not reduced to its two relevant bits"
                )
            if re.search(r"0xAB597BD5|0xF8057219", pseudocode, re.IGNORECASE):
                raise RuntimeError("The quotient still contains its redundant mask or threshold")

    return {
        "name": name,
        "normal": normal_stats,
        "deep": deep_stats,
        "restored": restored_stats,
        "pseudocode": deep,
        "normal_pseudocode": normal,
        "restored_pseudocode": restored,
    }


def main():
    report = {"functions": [], "errors": []}
    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays is unavailable")
        if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
            raise RuntimeError("Requested plugin artifact did not load")
        if not evaluate("chernobog_activate()"):
            raise RuntimeError("Plugin activation failed")

        evaluate('chernobog_set_option("rax", 0)')
        evaluate('chernobog_set_option("mba_smt", 1)')
        selected = os.environ.get("CHERNOBOG_MBA_PROBE_FUNCTIONS")
        functions = tuple(selected.split(",")) if selected else FIXTURE_FUNCTIONS
        if len(set(functions)) != len(functions) or any(
            name not in FIXTURE_FUNCTIONS for name in functions
        ):
            raise RuntimeError("Invalid MBA fixture function selection")
        for name in functions:
            report["functions"].append(capture_function(name))

        applied = sum(
            row[profile]["applied"]
            for row in report["functions"]
            for profile in ("normal", "deep", "restored")
        )
        if applied == 0:
            raise RuntimeError("No semantic MBA rewrite was observed in the native fixtures")
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")

    output = Path(os.environ["IDAUSR"]).parent / "mba_smt.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if report["errors"]:
        print("[chernobog][mba-smt] FAIL " + "; ".join(report["errors"]), flush=True)
        ida_pro.qexit(1)
    else:
        print(f"[chernobog][mba-smt] PASS functions={len(report['functions'])}", flush=True)
        ida_pro.qexit(0)


if __name__ == "__main__":
    main()
