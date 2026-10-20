"""Check caller-context specialization and refusal cases in an isolated IDB."""

import json
import os
import re
import time
from pathlib import Path

import ida_auto
import ida_expr
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_kernwin
import ida_name
import ida_pro

ACTIVE_TIMERS = []


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
    returns = re.findall(r"\breturn\s+([^;]+);", text)
    if not returns:
        raise RuntimeError("Expected constant return " + str(expected))
    for expression in returns:
        match = re.fullmatch(r"(true|false|0x[0-9a-f]+|\d+)[uUlL]*", expression, re.IGNORECASE)
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
    if name == "mba_context_empty_branch" and re.search(
        r"\b(?:opaque_predicate_2|mba_context_observe)\s*\(", text
    ):
        raise RuntimeError("The impossible loop-body branch remains")
    symbolic = {
        "mba_context_symbolic_identity",
        "mba_context_symbolic_xor",
        "mba_context_symbolic_selector",
        "mba_context_nested_calls",
        "mba_context_symbolic_add",
        "mba_context_symbolic_shift",
        "mba_context_symbolic_signed",
        "mba_context_symbolic_byte_math",
    }
    if name in symbolic and re.search(
        r"\b(?:mba_transform_[12]|mba_smt_semantic32|mba_call_narrow_helper|mba_context_signed_helper|mba_context_byte_math_helper)\s*\(",
        text,
    ):
        raise RuntimeError("A reducible symbolic call remains in " + name)
    if name in symbolic and not re.search(r"\breturn\s+[^;]*[a-zA-Z_][^;]*;", text):
        raise RuntimeError("The symbolic result disappeared in " + name)
    if (
        name == "mba_context_symbolic_signed"
        and len(re.findall(r"\((?:unsigned\s+)?(?:__int\d+|int|char)\)", text)) > 2
    ):
        raise RuntimeError("Redundant integer cast chains remain in " + name)
    if name in (
        "mba_context_symbolic_xor",
        "mba_context_symbolic_selector",
        "mba_context_nested_calls",
    ):
        if "^" not in text:
            raise RuntimeError("The symbolic XOR was not emitted in " + name)
    if name in ("mba_context_join_different", "mba_context_overwrite", "mba_context_old_value"):
        returns = re.findall(r"\breturn\s+([^;]+);", text)
        if not returns or all(re.fullmatch(r"(?:0|false)[uUlL]*", value) for value in returns):
            raise RuntimeError("A changing symbolic value collapsed in " + name)
    if (
        name.startswith("mba_context_")
        and name
        in {
            "mba_context_return_range",
            "mba_context_known_bits",
            "mba_context_join_equal",
            "mba_context_join_different",
            "mba_context_old_value",
        }
        and not re.search(r"\bmba_context_observe\s*\(", text)
    ):
        raise RuntimeError("The observer side effect disappeared in " + name)


def finish(report, deferred=False):
    output = Path(os.environ["IDAUSR"]).parent / "mba_calls.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["errors"]:
        print("[chernobog][mba-calls] FAIL " + "; ".join(report["errors"]), flush=True)
    else:
        print(f"[chernobog][mba-calls] PASS functions={len(report['functions'])}", flush=True)
    code = int(bool(report["errors"]))
    if deferred:
        # IDAPython teardown unregisters timers. Leave the timer callback first
        # so it does not try to take the timer lock that this callback holds.
        def exit_request():
            ida_pro.qexit(code)
            return False

        ida_kernwin.execute_ui_requests((exit_request,))
    else:
        ida_pro.qexit(code)


def start_view_probe(report, names, constants, retained):
    # Let the GUI finish each navigation before checking the deferred update.
    # Revisit the functions backwards to catch stale viewer/MBA ownership.
    visits = tuple(names) + tuple(reversed(names))
    state = {"index": 0, "widget": None, "deadline": 0}

    def tick():
        try:
            if state["index"] == len(visits):
                finish(report, deferred=True)
                return -1
            name = visits[state["index"]]
            if state["widget"] is None:
                print("[chernobog][mba-calls] Opening " + name, flush=True)
                view = ida_hexrays.open_pseudocode(address(name), 0)
                if view is None:
                    raise RuntimeError("Pseudocode view did not open")
                view.cfunc.verify(ida_hexrays.ALLOW_UNUSED_LABELS, True)
                state["widget"] = view.ct
                state["deadline"] = time.monotonic() + 30
                print("[chernobog][mba-calls] Opened " + name, flush=True)
                return 50

            view = ida_hexrays.get_widget_vdui(state["widget"])
            if view is None or view.cfunc is None:
                raise RuntimeError("Pseudocode view disappeared")
            if view.cfunc.entry_ea != address(name):
                raise RuntimeError("Pseudocode view displays the wrong function")
            text = str(view.cfunc)
            try:
                validate_capture(name, text, constants, retained)
            except RuntimeError:
                if time.monotonic() < state["deadline"]:
                    return 50
                raise
            report["functions"].append({"name": name, "captures": {"view": text}})
            state["index"] += 1
            state["widget"] = None
            return 50
        except Exception as error:
            report["errors"].append(f"{type(error).__name__}: {error}")
            finish(report, deferred=True)
            return -1

    timer = ida_kernwin.register_timer(50, tick)
    if timer is None:
        raise RuntimeError("Could not register the GUI probe timer")
    ACTIVE_TIMERS.append(timer)


def main():
    report = {"functions": [], "errors": []}
    try:
        ida_auto.auto_wait()
        manifest_path = os.environ.get("CHERNOBOG_MBA_FIXTURE_TYPES")
        if manifest_path:
            import ida_typeinf

            manifest = json.loads(Path(manifest_path).read_text())
            for name, declaration in manifest["prototypes"].items():
                # Keep the native carrier when a narrow source annotation
                # prevents the SDK from reconstructing its signed return.
                if name in manifest["native_abi_inferred"]:
                    continue
                entry = next(
                    (
                        ida_name.get_name_ea(ida_idaapi.BADADDR, symbol)
                        for symbol in (name, "_" + name)
                        if ida_name.get_name_ea(ida_idaapi.BADADDR, symbol) != ida_idaapi.BADADDR
                    ),
                    ida_idaapi.BADADDR,
                )
                if entry == ida_idaapi.BADADDR or not ida_typeinf.apply_cdecl(
                    None, entry, declaration
                ):
                    raise RuntimeError("Cannot apply frozen fixture prototype: " + name)
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
            "mba_context_return_range": 42,
            "mba_context_known_bits": 0,
            "mba_context_empty_branch": 0,
            "mba_context_branch_equal": 0,
            "mba_context_false_edge": 0,
            "mba_context_join_equal": 0,
            "mba_context_guard_overflow": 0,
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
            else tuple(constants)
            + tuple(retained)
            + (
                "mba_call_loop",
                "mba_context_effectful_argument",
                "mba_context_symbolic_identity",
                "mba_context_symbolic_xor",
                "mba_context_symbolic_selector",
                "mba_context_nested_calls",
                "mba_context_symbolic_add",
                "mba_context_symbolic_shift",
                "mba_context_symbolic_signed",
                "mba_context_symbolic_byte_math",
                "mba_context_join_different",
                "mba_context_overwrite",
                "mba_context_old_value",
            )
        )
        selected = os.environ.get("CHERNOBOG_MBA_CALL_FUNCTIONS")
        if selected:
            requested = tuple(name.strip() for name in selected.split(",") if name.strip())
            if set(requested) - set(names):
                raise RuntimeError("Unknown caller fixture requested")
            names = requested
        if use_views:
            start_view_probe(report, names, constants, retained)
            return
        for name in names:
            entry = address(name)
            captures = {}
            report["functions"].append({"name": name, "captures": captures})
            for profile, api in (
                ("normal", "chernobog_deobfuscate_text"),
                ("deep", "chernobog_deep_deobfuscate_text"),
            ):
                print(f"[chernobog][mba-calls] {name}/{profile}", flush=True)
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

    finish(report)


if __name__ == "__main__":
    main()
