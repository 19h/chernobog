"""Check the extracted GreProtectSpriteContent field update in a copied IDB."""

import hashlib
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
import idautils


def evaluate(expression):
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if error:
        raise RuntimeError(str(error))
    return result.c_str() if result.vtype == ida_expr.VT_STR else result.num


def find_function():
    name = os.environ.get("CHERNOBOG_MBA_FLAG_FUNCTION", "GreProtectSpriteContent")
    entry = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if entry != ida_idaapi.BADADDR:
        return entry
    for entry in idautils.Functions():
        if name in ida_name.get_name(entry):
            return entry
    entry = int(os.environ.get("CHERNOBOG_MBA_FLAG_ADDRESS", "0x140248AA0"), 0)
    function = ida_funcs.get_func(entry)
    if function and function.start_ea == entry:
        return entry
    raise RuntimeError("The requested flag-store function is absent")


def instruction_hash(entry):
    digest = hashlib.sha256()
    for start, end in idautils.Chunks(entry):
        data = ida_bytes.get_bytes(start, end - start)
        if data is None:
            raise RuntimeError("A function chunk is unavailable")
        digest.update(start.to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def flag_stores(text):
    statements = re.finditer(
        r"(?P<lhs>[^;\n]*(?:0x94|148)[^;\n=]*)\s*=(?!=)\s*(?P<rhs>[^;]+);",
        text,
        re.IGNORECASE,
    )
    return [match.group(0).strip() for match in statements]


def main():
    report = {"captures": {}, "stores": {}, "statistics": {}, "errors": []}
    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays is unavailable")
        if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
            raise RuntimeError("The requested plugin did not load")
        entry = find_function()
        report["entry"] = hex(entry)
        report["name"] = ida_name.get_name(entry)
        report["instruction_sha256"] = instruction_hash(entry)
        evaluate("chernobog_activate()")
        evaluate('chernobog_set_option("rax", 0)')

        for profile, enabled, api in (
            ("baseline", 0, "chernobog_deobfuscate_text"),
            ("normal", 1, "chernobog_deobfuscate_text"),
            ("deep", 1, "chernobog_deep_deobfuscate_text"),
        ):
            evaluate(f'chernobog_set_option("mba_smt", {enabled})')
            text = evaluate(f"{api}({entry})")
            if not text:
                raise RuntimeError("Decompilation failed: " + profile)
            stores = flag_stores(text)
            report["captures"][profile] = text
            report["stores"][profile] = stores
            report["statistics"][profile] = json.loads(
                evaluate(f"chernobog_mba_smt_stats({entry})")
            )
            if len(stores) != 1:
                report["errors"].append(f"{profile}: expected exactly one 0x94 field store")
            elif profile != "baseline":
                rhs = stores[0].split("=", 1)[1]
                if not re.fullmatch(
                    r"\s*\(?v\d+\s*&\s*~0x48u\)?\s*\|\s*\(?v\d+\s*<<\s*3\)?"
                    r"\s*\|\s*\(?v\d+\s*<<\s*6\)?\s*;",
                    rhs,
                    re.IGNORECASE,
                ):
                    report["errors"].append(
                        f"{profile}: expected a clear mask followed by two local flag shifts"
                    )
        report["instruction_bytes_unchanged"] = (
            instruction_hash(entry) == report["instruction_sha256"]
        )
        if not report["instruction_bytes_unchanged"]:
            report["errors"].append("Native instructions changed")
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")

    output = Path(os.environ["IDAUSR"]).parent / "mba_flag_store.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["errors"]:
        print("[chernobog][mba-flag-store] FAIL " + "; ".join(report["errors"]), flush=True)
    else:
        print("[chernobog][mba-flag-store] PASS", flush=True)
    ida_pro.qexit(int(bool(report["errors"])))


if __name__ == "__main__":
    main()
